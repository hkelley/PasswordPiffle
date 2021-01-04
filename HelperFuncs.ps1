#  Requirements
# *  DSInternals module v4.4.1,  PSGallery or https://github.com/MichaelGrafnetter/DSInternals
# *  Hashcat installation
# *  Haveibeenpwned.com  NTLM list

Function Get-ADHashesAsTestSet {
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
        $repl = Get-ADReplAccount -SamAccountName $u.SamAccountName  -Server $rootdse.Properties["dnsHostName"].Value  -Domain $NBName

        $retrievedUsers[$u.samaccountname] = [pscustomobject] @{
            Replica = $repl
            Condition = $null
            Context = $null            
        }
    }

    return $retrievedUsers
}


function Test-HashesWithHashcat{
    [CmdletBinding()]
    param(
          [Parameter(Mandatory)] $TestSet   # from Get-ADHashes
        , [Parameter(Mandatory)] $HashcatDir
    )


    # build a hashtable of username keyed by password hashes 
    $hashesToTest = @{}

    foreach($v in ($TestSet.Values | ?{$_.Condition -eq $null} ) )
    {
        $hash = [System.BitConverter]::ToString($v.Replica.NTHash).Replace("-","")
    
        if($hashesToTest[$hash])
        {
            # existing hash - add another user to the list of names
            $hashesToTest[$hash].Users += $v.Replica.SamAccountName  # hash already seen - link another username to it
        }
        else
        {
            # first time seeing this hash - add new object
            $hashesToTest[$hash] = [pscustomobject]@{
                Users = @($v.replica.SamAccountName)
            }
        }
    }

    $scratchFile = [IO.Path]::Combine( $env:TMP, ("hcu-{0}.txt" -f (Get-Random -Minimum 1000 -Maximum 9999)))
    $outputFile = [IO.Path]::Combine( $env:TMP, ("hcu-{0}.txt" -f (Get-Random -Minimum 1000 -Maximum 9999)))

    # output hashes for processing by hashcat
    $hashesToTest.Keys | Out-File -Encoding ascii -FilePath $scratchFile
    $null | Out-File -Encoding ascii -FilePath $outputFile

    Push-Location $hashcatDir

    .\hashcat.exe  -m 1000 -O --outfile $outputfile $scratchFile wordlists\Top353Million-probable-v2.txt -r rules\best64.rule --potfile-disable

    # hashcat-ing complete,  import the cracked results
    foreach($crack in (Import-Csv $outputFile -Delimiter ":" -Header "hash","result"))
    {
        foreach($user in $hashesToTest[$crack.hash].Users)
        {
            $TestSet[$user].Condition = "weak"
            $TestSet[$user].Context = $crack.result
        }
    }
    
    Remove-Item -Force $scratchFile
    Remove-Item -Force $outputFile

    Pop-Location
}


function Test-HashesAgainstList {
    [CmdletBinding()]
    param(
          [Parameter(Mandatory)] $TestSet   # from Get-ADHashes
        , [Parameter(Mandatory)] [System.IO.FileInfo] $BadHashesSortedFile  
    )

    # Get only the values we haven't already marked
    $testSubset = $TestSet.Values | ?{$_.Condition -eq $null} 
    
    $testResults = $testSubset.Replica | Test-PasswordQuality -WeakPasswordHashesSortedFile $BadHashesSortedFile.FullName

    foreach($failedUser in $testResults.WeakPassword)
    {
        $TestSet[$failedUser].Condition = "leaked"
        $TestSet[$failedUser].Context = $BadHashesSortedFile.BaseName
    }    
}


function Test-HashesForPasswordSharing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $TestSet   # from Get-ADHashes - logic below assumes both the user and the user's manager are in this replica.  Don't use this function if you are only analyzing recent password changes.
    )
    
    foreach($t in $TestSet)
    {
        $userHash = [System.BitConverter]::ToString($t.Replica.NTHash).Replace("-","")

        # find the manager of this user
        $aduser =  Get-ADObject -Properties manager -LDAPFilter ("(&(objectCategory=person)(sAMAccountName={0}))" -f $t.ReplicatedUser.sAMAccountName)

        if($adUser -eq $null -or $replicatedUser.Enabled -ne $true)
        {    continue      }

        ## check for hash matches (password re-use between user and manager)
        if($aduser.Manager -ne $null -and $aduser.manager -ne $replicatedUser.DistinguishedName -and $replicatedUser.NTHash -eq $replicatedUser[$aduser.Manager].NTHash)
        {
            # return this 
            [pscustomobject] @{
                SamAccountName = $replicatedUser.sAMAccountName
                Hash = $userhash
                Detection = "shared"
                Context =  $replicatedUser[$aduser.Manager].SamAccountName
            }
        }
    }
}


function Get-FlattenedResults
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $TestSet   # from Get-ADHashes - logic below assumes both the user and the user's manager are in this replica.  Don't use this function if you are only analyzing recent password changes.
    )

    foreach($user in $TestSet.Keys)
    {
        $testResult = $TestSet[$user]

        if($testResult.Condition -ne $null)
        {
            [pscustomobject] @{
                SamAccountName = $user
                Hash = [System.BitConverter]::ToString($testResult.Replica.NTHash).Replace("-","")
                Detection = $testResult.Condition
                Context =  $testResult.Context
            }
        }
    }
}