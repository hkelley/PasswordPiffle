#  Requirements
# *  DSInternals module v4.4.1,  PSGallery or https://github.com/MichaelGrafnetter/DSInternals
# *  Hashcat installation
# *  Haveibeenpwned.com  sorted-by-NTLM-hash list

# Minimum Permissions to pull password hashes from a DC (online)
# - The “DS-Replication-Get-Changes” extended right
#   CN: DS-Replication-Get-Changes
#   GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
# - The “Replicating Directory Changes All” extended right
#   CN: DS-Replication-Get-Changes-All
#   GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2

Function Format-NTHash {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $NTHash
    )

    return [System.BitConverter]::ToString($NTHash).Replace("-","")
}

Function Get-ADHashesAsTestSet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ScriptBlock] $Filter
    )

    $rootdse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE",$null,$null,[System.DirectoryServices.AuthenticationTypes]::Anonymous) -ErrorAction Stop
    $NBName = (Get-ADDomain).NetBIOSName

    if(!($users = Get-ADUser -Filter $filter -Properties PasswordLastSet))
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
            PasswordLastSet = $u.PasswordLastSet
        }
    }

    return $retrievedUsers
}


function Test-HashesWithHashcat{
    [CmdletBinding()]
    param(
          [Parameter(Mandatory)] $TestSet   # from Get-ADHashes
        , [Parameter(Mandatory)] [string] $HashcatDir
        ,                        [switch] $ShowOutput
    )


    # build a hashtable of username keyed by password hashes 
    $hashesToTest = @{}

    foreach($v in ($TestSet.Values | ?{$_.Condition -eq $null} ) )
    {
        $hash = Format-NTHash -NTHash $v.Replica.NTHash
    
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

    $jobName = "hcu-{0}" -f (Get-Random -Minimum 1000 -Maximum 9999)
    $scratchFile = [IO.Path]::Combine( $env:TMP, ("{0}-i.txt" -f $jobName))
    $outputFile = [IO.Path]::Combine( $env:TMP, ("{0}-o.txt" -f  $jobName))

    # output hashes for processing by hashcat
    $hashesToTest.Keys | Out-File -Encoding ascii -FilePath $scratchFile
    $null | Out-File -Encoding ascii -FilePath $outputFile

    Push-Location $hashcatDir

    $hashcatOutput = .\hashcat.exe  -m 1000 -O --session $jobName --outfile $outputfile $scratchFile wordlists\Top353Million-probable-v2.txt -r rules\best64.rule --potfile-disable
    if($ShowOutput)
    {
        $hashcatOutput
    }

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



function Test-HashesForPasswordReuse {
    [CmdletBinding()]
    param(
          [Parameter(Mandatory)] $TestSet   # from Get-ADHashes
        , [Parameter(Mandatory = $false)] [int] $Lookback = 5
        , [Parameter(Mandatory = $false)] [int] $MaxUsage = 4
    )

    foreach($t in $TestSet.Values)
    {
        if($t.Replica.NTHashHistory -eq $null)
        {
            break # no password history
        }

        $userHash =   Format-NTHash -NTHash $t.Replica.NTHash


        ## Test for password-re-use across time (same account).  Skip the urrent and most-recent previous password, look for more chronic offenders
        $reuseCount = 0
        foreach($i in 2..($Lookback))
        {
            if( $t.Replica.NTHashHistory[$i] -eq $null)
            {
                break
            }

            $oldHash = Format-NTHash -NTHash $t.Replica.NTHashHistory[$i]
            if($oldHash -eq $userHash)
            {
                $reuseCount++
            }
        }

        if($reuseCount -ge $MaxUsage)
        {
                # mark as bad
                $t.Condition = "re-use"
                $t.Context =  "{0}:{1}" -f $reuseCount,$Lookback
        }
    }
}

function Test-HashesForPasswordSharing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $TestSet   # from Get-ADHashes - logic below assumes both the user and the user's manager are in this replica.  Don't use this function if you are only analyzing recent password changes.
    )
    
    foreach($t in $TestSet.Values)
    {
        $userHash =   Format-NTHash -NTHash $t.Replica.NTHash

        # find the manager of this user
        $aduser =  Get-ADUser -Properties manager -LDAPFilter ("(&(objectCategory=person)(sAMAccountName={0}))" -f $t.Replica.sAMAccountName)

        if($adUser -eq $null -or $aduser.Enabled -ne $true)
        {    continue      }

        if($aduser.Manager -gt "" -and $aduser.Manager -ne $aduser.DistinguishedName -and ($adManager = Get-ADUser $aduser.Manager -Properties displayName,mail) -and $TestSet.ContainsKey($adManager.SamAccountName))
        {
            $managerHash =  Format-NTHash -NTHash $TestSet[$adManager.SamAccountName].Replica.NTHash

            if($userHash -eq $managerHash)
            {
                # mark as bad
                $t.Condition = "shared"
                $t.Context =  "{0} <{1}>" -f $adManager.displayName,$adManager.mail
            }
        }
    }
}


function Get-FlattenedResults
{
    [CmdletBinding()]
    param(
          [Parameter(Mandatory)] $TestSet   # from Get-ADHashes - logic below assumes both the user and the user's manager are in this replica.  Don't use this function if you are only analyzing recent password changes.
        , [Parameter(Mandatory = $false)] [switch] $ReturnAll
    )

    foreach($user in $TestSet.Keys)
    {
        $testResult = $TestSet[$user]

        if($testResult.Condition -ne $null -or $ReturnAll)
        {
            if($testResult.PasswordLastSet -ne $null)
            {
                $PasswordLastSetUTC = $testResult.PasswordLastSet.ToUniversalTime()
            }

            [pscustomobject] @{
                SamAccountName = $user
                Hash = [System.BitConverter]::ToString($testResult.Replica.NTHash).Replace("-","")
                Detection = $testResult.Condition
                Context =  $testResult.Context
                PasswordLastSetUTC = $PasswordLastSetUTC
            }
        }
    }
}