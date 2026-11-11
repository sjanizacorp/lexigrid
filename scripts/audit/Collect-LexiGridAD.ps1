<#
Read-only Active Directory observation collector for LexiGrid.
Author: Shahryar Jahangir, Aniza Inc.
Requires Windows PowerShell/PowerShell with the RSAT ActiveDirectory module.
No Set-*, Add-*, Remove-*, Enable-* or Disable-* directory operations are used.
The operator must review the scope and securely upload the resulting snapshot.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Server,
    [Parameter(Mandatory=$true)][string]$OutputPath,
    [ValidateRange(1,30)][int]$EventLookbackDays = 7,
    [switch]$IncludeSecurityEvents
)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory -ErrorAction Stop
$errors = [System.Collections.Generic.List[string]]::new()
$users = [System.Collections.Generic.List[object]]::new()
if (Test-Path -LiteralPath $OutputPath) { throw 'OutputPath already exists. Choose a new evidence filename; existing files are not overwritten.' }
$policies = @{}
$domain = Get-ADDomain -Server $Server
$default = Get-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -Server $Server
function Read-Bool($Value) { if ($null -eq $Value) { return $null }; return [bool]$Value }
function Read-Int($Value) { if ($null -eq $Value) { return $null }; return [int]$Value }
function Convert-Policy($Policy, [string]$Identity) {
    return [ordered]@{
        Identity = $Identity
        MinPasswordLength = (Read-Int $Policy.MinPasswordLength)
        ReversibleEncryptionEnabled = (Read-Bool $Policy.ReversibleEncryptionEnabled)
        LockoutThreshold = (Read-Int $Policy.LockoutThreshold)
        ComplexityEnabled = (Read-Bool $Policy.ComplexityEnabled)
        PasswordHistoryCount = (Read-Int $Policy.PasswordHistoryCount)
    }
}
$policies['default'] = Convert-Policy $default 'default'
$allUsers = @(Get-ADUser -Server $Server -Filter { Enabled -eq $true } -Properties PasswordNotRequired,DoesNotRequirePreAuth,TrustedForDelegation,PasswordNeverExpires)
foreach ($user in $allUsers) {
    $effective = 'default'
    try {
        $resultant = Get-ADUserResultantPasswordPolicy -Identity $user -Server $Server
        if ($null -ne $resultant) {
            $effective = [string]$resultant.ObjectGUID
            if (-not $policies.ContainsKey($effective)) { $policies[$effective] = Convert-Policy $resultant $effective }
        }
    } catch {
        $effective = 'unavailable'
        $errors.Add('Could not read an enabled account resultant password policy.')
    }
    # Hash identity to permit consistent counts without exporting account names.
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $subject = ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes([string]$user.SID)))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
    $users.Add([ordered]@{
        SubjectHash = $subject
        EffectivePolicy = $effective
        PasswordNotRequired = (Read-Bool $user.PasswordNotRequired)
        DoesNotRequirePreAuth = (Read-Bool $user.DoesNotRequirePreAuth)
        TrustedForDelegation = (Read-Bool $user.TrustedForDelegation)
        PasswordNeverExpires = (Read-Bool $user.PasswordNeverExpires)
    })
}
$eventCounts = @{}
$eventComplete = $false
$since = (Get-Date).ToUniversalTime().AddDays(-$EventLookbackDays)
if ($IncludeSecurityEvents) {
    try {
        # Read only the explicitly specified server; this is not a forest-wide log audit.
        $events = @(Get-WinEvent -ComputerName $Server -FilterHashtable @{LogName='Security';Id=4624,4625,4720,4722,4726,4728;StartTime=$since} -ErrorAction Stop)
        foreach ($event in $events) {
            $key = [string]$event.Id
            if (-not $eventCounts.ContainsKey($key)) { $eventCounts[$key] = 0 }
            $eventCounts[$key]++
        }
        $eventComplete = $true
    } catch { $errors.Add('Security event read unavailable or no matching events. Event results remain insufficient evidence.') }
}
$snapshot = [ordered]@{
    source = 'active_directory'
    collector_version = 'lexigrid-ad-v1'
    collected_at = (Get-Date).ToUniversalTime().ToString('o')
    server = $Server
    domain = $domain.DNSRoot
    complete = ($errors.Count -eq 0)
    event_collection_complete = $eventComplete
    observation_start = $since.ToString('o')
    scope = 'Enabled accounts and effective password policies in the specified domain; optional events from the specified server only.'
    limitations = @('Operator-submitted snapshot; LexiGrid cannot authenticate its origin from a hash alone.','Logon timestamps/events are a bounded observation, not a penetration test or proof of all safeguard effectiveness.','No sensitive account names, credentials or event message bodies are included.')
    errors = $errors.ToArray()
    datasets = [ordered]@{
        enabled_users = $users.ToArray()
        effective_password_policies = @($policies.Values)
        security_event_counts = $eventCounts
    }
}
# Only the requested local evidence output is written; AD settings remain unchanged.
$json = $snapshot | ConvertTo-Json -Depth 12
[System.IO.File]::WriteAllText($OutputPath, $json, [System.Text.UTF8Encoding]::new($false))
Write-Output ('Saved read-only snapshot: ' + $OutputPath)
Write-Output ('Enabled accounts: ' + $allUsers.Count + '; effective policies: ' + $policies.Count + '; collection gaps: ' + $errors.Count)
