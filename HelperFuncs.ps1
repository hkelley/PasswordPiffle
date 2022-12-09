#  Requirements
# *  DSInternals module v4.4.1,  PSGallery or https://github.com/MichaelGrafnetter/DSInternals
# *  Hashcat https://hashcat.net/hashcat/
# *  Haveibeenpwned.com  sorted-by-NTLM-hash list
# *  Install-Module -Name Posh-SSH   # if using separate hashcat server

# Minimum Permissions to pull password hashes from a DC (online)
# - The “DS-Replication-Get-Changes” extended right
#   CN: DS-Replication-Get-Changes
#   GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
# - The “Replicating Directory Changes All” extended right   (this is necessary to get the hashes)
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
        , [Parameter(Mandatory)] [string] $DC
        , [Parameter(Mandatory=$false)] [pscredential]  $Credential = [System.Management.Automation.PSCredential]::Empty
    )
    
    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
    
    $credsplat = @{}
    if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
        $credsplat['Credential'] = $Credential
    }

    # $rootdse = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DC/rootdse",$null,$null,[System.DirectoryServices.AuthenticationTypes]::Anonymous) -ErrorAction Stop 
    $NBName = (Get-ADDomain -Server $DC   @credsplat).NetBIOSName

    if(!($users = @(Get-ADUser -Server $DC -Filter $filter -Properties PasswordLastSet   @credsplat)))
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
        $repl = Get-ADReplAccount  -Server $DC  -SamAccountName $u.SamAccountName  -Domain $NBName  @credsplat

        if(!($repl.NTHash))
        {
            Write-Warning ("NTHash of {0} is null" -f $u.SamAccountName)
            continue
        }

        $retrievedUsers[$u.samaccountname] = [pscustomobject] @{
            Replica = $repl
            Condition = $null
            Context = $null
            PasswordLastSet = $u.PasswordLastSet
        }
    }

    return $retrievedUsers
}


$reHex = [regex] '\$HEX\[(?<hexcodes>[\da-f]+)\]'

function Get-StringFromHex ($hexcodes)
{
    $outString = ""

    $chars = $hexcodes.ToCharArray()

    for($i=0; $i -lt $chars.count; $i = $i+2 )
    {
        $charHex = $chars[$i..($i + 1)] -join "" 
    
        $outString += [char] [CONVERT]::toint16($charHex,16) 
    }

    $outString
}

function Test-HashesWithHashcat{
    [CmdletBinding()]
    param(
          [Parameter(Mandatory = $true)] $TestSet   # from Get-ADHashes
        , [Parameter(Mandatory = $false)] [string] $HashcatHost
        , [Parameter(Mandatory = $false)] [pscredential] $HashcatHostCred
        , [Parameter(Mandatory = $true)] [string] $HashcatDir
        , [Parameter(Mandatory = $false)] [string] $HashcatOptions
        , [Parameter(Mandatory = $true)] [string] $WordList 
        , [Parameter(Mandatory = $true)] [string] $Rules                        
        , [Parameter(Mandatory = $false)] [switch] $ShowOutput
        , [Parameter(Mandatory = $false)] [int] $TimeoutHours = 6
    )

    # build a hashtable of username keyed by password hashes 
    $hashesToTest = @{}

    # Test anything that hasn't already been confirmed to be weak,  "Condition -eq $null"
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
    $scratchFile = [IO.FileInfo] [IO.Path]::Combine( $env:TMP, ("{0}.input" -f $jobName))
    $outputFile = [IO.FileInfo] [IO.Path]::Combine( $env:TMP, ("{0}.output" -f  $jobName))
    $logFile = [IO.FileInfo] [IO.Path]::Combine( $env:TMP, ("{0}.log" -f  $jobName))

    # output hashes for processing by hashcat
    $hashesToTest.Keys | Out-File -Encoding ascii -FilePath $scratchFile
    $null | Out-File -Encoding ascii -FilePath $outputFile

    $hashcatOutput = "NO HASHCAT OUTPUT"

    $stopwatch =  [system.diagnostics.stopwatch]::StartNew()

    if(![string]::IsNullOrWhiteSpace($HashcatHost) -and $HashcatHostCred -ne $null)
    {   
        # remote hashcat (e.g.,  Linux host with GPU)
        $timeoutOptions = @{
            ConnectionTimeout = 60
            OperationTimeout = 60        
        }

        $session = New-SSHSession -ComputerName $HashcatHost -Credential $HashcatHostCred  -AcceptKey @timeoutOptions
        
        # Transfer the hashes to crack
        Set-SCPItem -ComputerName $HashcatHost -Credential $HashcatHostCred -Path $scratchFile.FullName -Destination "~" -NewName $scratchFile.Name -AcceptKey -Verbose   @timeoutOptions

		# crack hashes and add to potfile
        $cmd = "{0}hashcat  -m 1000 -O {6} --session {1} {2} --rules-file {3} {4} 1>{5}  2>&1 " -f $HashcatDir,$jobName,$scratchFile.Name,$($HashcatDir + $Rules),$($HashcatDir + $WordList),$logFile.Name,$HashcatOptions
        $result = Invoke-SSHCommand -SSHSession $session -Command $cmd  -TimeOut (60*60*$TimeoutHours)
        if((0..1) -notcontains $result.ExitStatus)   # https://github.com/hashcat/hashcat/blob/master/docs/status_codes.txt
        {
            Write-Warning ("Error raised on remote server by command: {0}" -f $cmd)
            $result | fl *
            
            Get-SCPItem -ComputerName $HashcatHost -Credential $HashcatHostCred -Path $logFile.Name -PathType File -Destination $logFile.Directory.FullName -AcceptKey  @timeoutOptions

            Write-Warning ("Hashcat log below:")
            Get-Content $logFile.FullName | Write-Host

            throw "HashcatException"
        }

		# export results
        $cmd = "{0}hashcat -m 1000 --show --outfile {1} {2};  ls -l {1}" -f $HashcatDir,$outputFile.Name,$scratchFile.Name 
        $result = Invoke-SSHCommand -SSHSession $session -Command $cmd  -TimeOut (60*60*$TimeoutHours) 
        if((0..1) -notcontains $result.ExitStatus)   # https://github.com/hashcat/hashcat/blob/master/docs/status_codes.txt
        {
            Write-Warning ("Error raised on remote server by command: {0}" -f $cmd)
            $result | fl *
            
            Get-SCPItem -ComputerName $HashcatHost -Credential $HashcatHostCred -Path $logFile.Name -PathType File -Destination $logFile.Directory.FullName -AcceptKey  @timeoutOptions

            Write-Warning ("Hashcat log below:")
            Get-Content $logFile.FullName | Write-Host

            throw "HashcatException"
        }
        
        # Retrieve the results.   Default operation timeout is 5s so bump it up a bit
        Remove-Item $outputFile   # clean up existing output file
        Get-SCPItem -ComputerName $HashcatHost -Credential $HashcatHostCred -Path $outputFile.Name -PathType File -Destination $outputFile.Directory.FullName  -AcceptKey -Verbose  @timeoutOptions
        Get-SCPItem -ComputerName $HashcatHost -Credential $HashcatHostCred -Path $logFile.Name -PathType File -Destination $logFile.Directory.FullName -AcceptKey -Verbose  @timeoutOptions
 
        # Clean up temp files
        $result = Invoke-SSHCommand -SSHSession $session -Command ("rm {0}*" -f $jobName)
        
        Remove-SSHSession $session | Out-Null
    }
    else
    {
        # local hashcat

        PUSHD $HashcatDir

		# crack hashes and add to potfile
        $cmd = "{0}hashcat  -m 1000 -O --session {1} {2} --rules-file {3} {4}  1>{5} 2>&1" -f $HashcatDir,$jobName,$scratchFile.FullName,$($Rules),$($WordList),$logFile.FullName
        Write-Warning $cmd
        $result = Invoke-Expression -Command $cmd 

		# export results to file
        $cmd = "{0}hashcat  -m 1000 --show --outfile {1} {2}" -f $HashcatDir,$outputFile.FullName,$scratchFile.FullName
        Write-Warning $cmd
        $result = Invoke-Expression -Command $cmd 

        POPD
    }

    $stopwatch.Stop()

    $hashcatOutput = Get-Content $logFile.FullName

    Write-Host ("`nHashcat processing time: {0:n0} minutes" -f $stopwatch.Elapsed.TotalMinutes)

    if($ShowOutput)
    {
        Write-Host "Hashcat output below:`n"
        $hashcatOutput | Write-Host
    }

    # hashcat-ing complete,  import the cracked results
    foreach($crack in (Import-Csv $outputFile -Delimiter ":" -Header "hash","result"))
    {
        if(-not $hashesToTest[$crack.hash])
        {
            Write-Verbose ("Skipping over unmatched hash (probably from potfile cache): {0}" -f $crack.hash)
            continue  
        }

        foreach($user in $hashesToTest[$crack.hash].Users)
        {
            $TestSet[$user].Condition = "weak"

            if($crack.result -match $reHex)
            {
                $crack.result = Get-StringFromHex -hexcodes $Matches.hexcodes
            }

            $TestSet[$user].Context = $crack.result
        }
    }
    
    Remove-Item -Force $scratchFile
    Remove-Item -Force $outputFile
    Remove-Item -Force $logFile
}


function Test-HashesAgainstList {
    [CmdletBinding()]
    param(
          [Parameter(Mandatory)] $TestSet   # from Get-ADHashes
        , [Parameter(Mandatory)] [System.IO.FileInfo] $BadHashesSortedFile  
    )

    # Get only the values we haven't already marked
    if($testSubset = $TestSet.Values | ?{$_.Condition -eq $null} )
    {
        $testResults = $testSubset.Replica | Test-PasswordQuality -WeakPasswordHashesSortedFile $BadHashesSortedFile.FullName
    }

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
        , [Parameter(Mandatory)] $DC
    )

    $hashIndex = @{}
    $conditionPrefix = "shared"

    foreach($t in $TestSet.Values)
    {
        $userHash =   Format-NTHash -NTHash $t.Replica.NTHash

        # find the manager of this user
        $aduser =  Get-ADUser -Server $DC -Properties manager -LDAPFilter ("(&(objectCategory=person)(sAMAccountName={0}))" -f $t.Replica.sAMAccountName)

        if($adUser -eq $null -or $aduser.Enabled -ne $true)
        {    continue      }

        # Check for manager re-use
        if($aduser.Manager -gt "" -and $aduser.Manager -ne $aduser.DistinguishedName -and ($adManager = Get-ADUser -Server $DC $aduser.Manager -Properties displayName,mail) -and $TestSet.ContainsKey($adManager.SamAccountName))
        {
            $managerHash =  Format-NTHash -NTHash $TestSet[$adManager.SamAccountName].Replica.NTHash

            if($userHash -eq $managerHash)
            {
                # mark as bad
                $t.Condition = "$conditionPrefix-manager"
                $t.Context =  "{0} <{1}>" -f $adManager.displayName,$adManager.mail
            }
        }

        # build the hashtable for global de-dup in the next stage
        if($hashIndex[$userHash])
        {
            $hashIndex[$userHash] += $t
        }
        else
        {
            $hashIndex[$userHash] = @($t)
        }
    }

    # Global hash sharing detection
    foreach($set in $hashIndex.Values)
    {
        if($set.Count -ge 2)
        {
            # Loop over users that don't already have a detection
            foreach($t in $set | ?{-not $_.Condition})
            {
                $t.Condition = "$conditionPrefix-global"
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