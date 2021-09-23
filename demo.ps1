# dotsource the functions
. Z:\_Active\PasswordPiffle\HelperFuncs.ps1

## get the hashes via online pull from a domain controller
$filter = {enabled -eq $true -and objectcategory -eq "person"}
$testset = Get-ADHashesAsTestSet -Filter $filter

## First, try to crack, this way we can see the weak values

# MODE A:  Using a remote (Linux) server over SSH.  This allows you more flexibility with cloud-provided GPUs
Test-HashesWithHashcat -TestSet $testset -ShowOutput -HashcatHost $HashcatHost -HashcatHostCred $HashcatCred  -HashcatDir "/opt/hashcat-6.2.4/" -WordList "wordlists/40GB_CleanUpFile.txt" -Rules "rules/OneRuleToRuleThemAll.rule" 

# MODE B:  Local hashcat on Windows
Test-HashesWithHashcat -TestSet $testset -ShowOutput               -HashcatDir "E:\Utils\Hashcat\" -WordList "wordlists\40GB_CleanUpFile.txt" -Rules "rules\best64.rule" 


## Second, check for the presence on a banned list
Test-HashesAgainstList -TestSet $testset -BadHashesSortedFile E:\Utils\haveibeenpwned.com\pwned-passwords-ntlm-ordered-by-hash-v7.txt

## Third,  look for accounts that re-use the same password between manager and report  (lazy IT people who use same password for admin ID)
Test-HashesForPasswordSharing $testset

## Fourth, find people who are using the same password over and over again,  even though it should be rotating (probably have a buddy in IT resetting it for them)
Test-HashesForPasswordReuse $testset

## Raw results for further processing  (resets, email to users, etc.)
Get-FlattenedResults -TestSet $testset

# Counts based on condition
$testset.Values | ?{$_.condition -ne $null }  | Group-Object condition

