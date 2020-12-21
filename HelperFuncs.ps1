#  Requirements
# *  DSInternals module,  PSGallery or https://github.com/MichaelGrafnetter/DSInternals
# *  Hashcat installation
# *  Haveibeenpwned.com  NTLM list

Function Get-ADHashes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ScriptBlock] $Filter
    )

    $rootdse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE",$null,$null,[System.DirectoryServices.AuthenticationTypes]::Anonymous) -ErrorAction Stop
    $NBName = (Get-ADDomain).NetBIOSName

    if(!($users = Get-ADUser -Filter $filter))
    {    
        Write-Warning "No users matched filter"
    }
    else
    {
        Write-Host ("Filter matched {0} Users.  Will retrieve hashes." -f $users.Count)    
    }

    # Get DS data for users,  organize in a hashtable so that other functions can perform lookups into the data
    $retrievedUsers = @{}
    foreach($u in $users)
    {
        $retrievedUsers[$u.DistinguishedName] = Get-ADReplAccount -SamAccountName $u.SamAccountName  -Server $rootdse.Properties["dnsHostName"].Value  -Domain $NBName
    }

    return $retrievedUsers
}

Function Group-UsersByHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]  $retrievedUsers  # 
    )

    # build a hashtable of objects keyed by password hashes 
    $retrievedHashes = @{}

    foreach($r in $retrievedUsers.Values )
    {
        $hash = [System.BitConverter]::ToString($r.NTHash).Replace("-","")
    
        if($retrievedHashes[$hash])
        {
            $retrievedHashes[$hash].Users += $r.SamAccountName  # hash already seen - link another username to it
        }
        else
        {
            # first time seeing this hash
            $retrievedHashes[$hash] = [pscustomobject]@{
                Condition = $null
                Context = $null
                Users = @($r.SamAccountName)
            }
        }
    }

    return $retrievedHashes
}

function Test-HashesForPasswordSharing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $UserReplicas   # from Get-ADHashes - logic below assumes both the user and the user's manager are in this set.  Don't use this function if you are only analyzing recent password changes
    )
    
    foreach($replicatedUser in $UserReplicas)
    {
        $userHash = [System.BitConverter]::ToString($replicatedUser.NTHash).Replace("-","")

        # find the manager of $replicatedUser
        $aduser =  Get-ADObject -Properties manager -LDAPFilter ("(&(objectCategory=person)(sAMAccountName={0}))" -f $replicatedUser.sAMAccountName)

        if($adUser -eq $null -or $replicatedUser.Enabled -ne $true)
        {    continue      }

        ## check for hash matches (password re-use)
        if($aduser.Manager -ne $null -and $aduser.manager -ne $replicatedUser.DistinguishedName -and $replicatedUser.NTHash -eq $replicatedUser[$aduser.Manager].NTHash)
        {
            [pscustomobject] @{
                SamAccountName = $replicatedUser.sAMAccountName
                Hash = $userhash
                Detection = "shared"
                Context =  $replicatedUser[$aduser.Manager].SamAccountName
            }
        }
    }
}

#  Group-UsersByHash
function Test-HashesWithHashcat($hashesToTest, $hashcatDir)
{
    $scratchFile = [IO.Path]::Combine( $env:TMP, ("hcu-{0}.txt" -f (Get-Random -Minimum 1000 -Maximum 9999)))
    $outputFile = [IO.Path]::Combine( $env:TMP, ("hcu-{0}.txt" -f (Get-Random -Minimum 1000 -Maximum 9999)))

    # output hashes for processing by hashcat
    $hashesToTest.Keys | Out-File -Encoding ascii -FilePath $scratchFile
    $null | Out-File -Encoding ascii -FilePath $outputFile

    Push-Location $hashcatDir

    .\hashcat.exe  -m 1000 -O --outfile $outputfile $scratchFile wordlists\Top353Million-probable-v2.txt -r rules\best64.rule --potfile-disable

    # hashcat-ing complete,  import the cracked results
    $itemCount = 0
    foreach($crack in (Import-Csv $outputFile -Delimiter ":" -Header "hash","result"))
    {
        $itemCount++
        $hashesToTest[$crack.hash].Condition = "weak"
        $hashesToTest[$crack.hash].Context = $crack.result        
    }
    
    Remove-Item -Force $scratchFile
    Remove-Item -Force $outputFile

    Pop-Location

    return $itemCount
}


function Test-HashesAgainstList($HashesToTest, $BadHashesFile)
{
    $badHashesFileInfo = Get-Item $BadHashesFile
    # borrowed from https://github.com/DGG-IT/Match-ADHashes/blob/master/Match-ADHashes.ps1

    $frHashDictionary = New-Object System.IO.StreamReader($badHashesFileInfo) 

    #Iterate through the list (of banned hashes) checking each hash against the hashes pulled from users
    $itemCount = 0
    while (($lineHashDictionary = $frHashDictionary.ReadLine()) -ne $null) 
    {
        $data = $lineHashDictionary.Split(":")
        $badHash = $data[0].ToUpper()
           
        $matchedHash = $hashesToTest[$badHash]     
        if($matchedHash.Users.Count -gt 0 -and $matchedHash.Condition -eq $null)  # ignore previously-classified hashes
        {
            $itemCount++
            $matchedHash.Condition = "leaked"
            $matchedHash.Context = $badHashesFileInfo.Name
        }
    }

    $frHashDictionary.Close()

    return $itemCount
}


function Get-FlattenHashResults ($TestedHashes)
{
    foreach($hash in $TestedHashes.Keys)
    {
        $testResult = $TestedHashes[$hash]

        if($testResult.Condition -ne $null)
        {
            foreach($username in $testResult.Users)
            {
                [pscustomobject] @{
                    SamAccountName = $username
                    Hash = $hash
                    Detection = $testResult.Condition
                    Context =  $testResult.Context
                }
            }
        }
    }
}