# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_c9520cc4-f89a-4303-8e7e-8ceee228af03  (1 rule(s)) ---------------------
# Intent:    Attacker disabling Windows Firewall by setting the EnableFirewall registry value
# Rules:     c9520cc4-f89a-4303-8e7e-8ceee228af03
# Archetype: IT admin workflow

$firewallPolicyPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall'

# Check if firewall policy path exists, create if needed for demonstration
if (-not (Test-Path $firewallPolicyPath)) {
    New-Item -Path $firewallPolicyPath -Force | Out-Null
}

# Navigate to the Domain Profile policy path
$domainProfilePath = Join-Path $firewallPolicyPath 'DomainProfile'
if (-not (Test-Path $domainProfilePath)) {
    New-Item -Path $domainProfilePath -Force | Out-Null
}

# Simulate policy remediation cycle: temporarily disable, then restore
# This represents IT admin validating policy enforcement mechanisms
Write-Host 'Starting firewall policy compliance check...'
Start-Sleep -Seconds 1

# Set EnableFirewall to 0 (disabled state) - this triggers the detection
Set-ItemProperty -Path $domainProfilePath -Name 'EnableFirewall' -Value 0 -Type DWord -Force
Write-Host 'Firewall policy temporarily disabled for remediation verification'
Start-Sleep -Seconds 2

# Restore firewall to enabled state (this is the remediation)
Set-ItemProperty -Path $domainProfilePath -Name 'EnableFirewall' -Value 1 -Type DWord -Force
Write-Host 'Firewall policy re-enabled and compliance verified'

# Clean up: remove the test registry key if it was created for this exercise
if (Test-Path $domainProfilePath) {
    Remove-Item -Path $domainProfilePath -Force -ErrorAction SilentlyContinue
}
if (Test-Path $firewallPolicyPath) {
    Remove-Item -Path $firewallPolicyPath -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_c9520cc4-f89a-4303-8e7e-8ceee228af03  (1 rule(s)) ---------------------
# Intent:    Attacker disabling Windows Firewall by setting the EnableFirewall registry value
# Rules:     c9520cc4-f89a-4303-8e7e-8ceee228af03
# Archetype: Software installer/updater workflow

# Simulate enterprise security software installer configuring firewall policies
# This is realistic behavior during deployment of network management tools

$firewallPolicyPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall'
$standardProfilePath = Join-Path $firewallPolicyPath 'StandardProfile'

# Ensure policy path exists for software installation context
if (-not (Test-Path $firewallPolicyPath)) {
    New-Item -Path $firewallPolicyPath -Force | Out-Null
}

if (-not (Test-Path $standardProfilePath)) {
    New-Item -Path $standardProfilePath -Force | Out-Null
}

Write-Host 'Network management client starting installation...'

# Store current firewall state for restoration
$currentState = $null
try {
    $currentState = (Get-ItemProperty -Path $standardProfilePath -Name 'EnableFirewall' -ErrorAction SilentlyContinue).EnableFirewall
} catch {
    $currentState = 1  # Default to enabled if not found
}

Write-Host "Current EnableFirewall state: $currentState"

# Installation phase: temporarily disable firewall policy to allow installer operations
Write-Host 'Configuring firewall policies for installation phase...'
Set-ItemProperty -Path $standardProfilePath -Name 'EnableFirewall' -Value 0 -Type DWord -Force
Write-Host 'Firewall policy disabled during installation'

# Simulate installation work
Start-Sleep -Seconds 2
Write-Host 'Installation components deploying...'
Start-Sleep -Seconds 1

# Post-installation: restore firewall policy to previous state
Write-Host 'Restoring firewall policy configuration...'
Set-ItemProperty -Path $standardProfilePath -Name 'EnableFirewall' -Value 1 -Type DWord -Force
Write-Host 'Firewall policy restored to enabled state'

# Clean up temporary policy configuration
if (Test-Path $standardProfilePath) {
    Remove-Item -Path $standardProfilePath -Force -ErrorAction SilentlyContinue
}
if (Test-Path $firewallPolicyPath) {
    Remove-Item -Path $firewallPolicyPath -Force -ErrorAction SilentlyContinue
}

Write-Host 'Installation and firewall policy restoration completed'

# -- Cluster: singleton_c9520cc4-f89a-4303-8e7e-8ceee228af03  (1 rule(s)) ---------------------
# Intent:    Attacker disabling Windows Firewall by setting the EnableFirewall registry value
# Rules:     c9520cc4-f89a-4303-8e7e-8ceee228af03
# Archetype: User-driven workflow

# User-driven firewall troubleshooting workflow
# IT support technician diagnosing network connectivity issues

$firewallPolicyPath = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall'
$publicProfilePath = Join-Path $firewallPolicyPath 'PublicProfile'

# Ensure paths exist
if (-not (Test-Path $firewallPolicyPath)) {
    New-Item -Path $firewallPolicyPath -Force | Out-Null
}

if (-not (Test-Path $publicProfilePath)) {
    New-Item -Path $publicProfilePath -Force | Out-Null
}

Write-Host 'Network connectivity troubleshooting initiated...'
Write-Host 'Ticket: Customer reports intermittent connectivity issues'

# Diagnostic phase 1: Disable firewall policy to test if firewall is causing connectivity problems
Write-Host 'Step 1: Disabling firewall policy for diagnostic testing...'
Set-ItemProperty -Path $publicProfilePath -Name 'EnableFirewall' -Value 0 -Type DWord -Force

Write-Host 'Firewall policy disabled. Running connectivity diagnostics...'
Start-Sleep -Seconds 3

# Simulate ping or connectivity test
$testResult = 'Connectivity test: PASS'
Write-Host $testResult

# Diagnostic phase 2: Re-enable firewall policy
Write-Host 'Step 2: Connectivity confirmed. Re-enabling firewall policy...'
Set-ItemProperty -Path $publicProfilePath -Name 'EnableFirewall' -Value 1 -Type DWord -Force
Write-Host 'Firewall policy re-enabled'

# Verification
Start-Sleep -Seconds 1
Write-Host 'Troubleshooting complete. Firewall policy verified as operational.'

# Clean up temporary diagnostic configuration
if (Test-Path $publicProfilePath) {
    Remove-Item -Path $publicProfilePath -Force -ErrorAction SilentlyContinue
}
if (Test-Path $firewallPolicyPath) {
    Remove-Item -Path $firewallPolicyPath -Force -ErrorAction SilentlyContinue
}


# ===========================================================================
# Export Sysmon events to corpus/benign/
# ===========================================================================

$exportDir   = Join-Path (Get-Location) 'corpus\benign'
$processDir  = Join-Path $exportDir 'process'
$networkDir  = Join-Path $exportDir 'network'
$registryDir = Join-Path $exportDir 'registry'
New-Item -ItemType Directory -Force -Path $processDir, $networkDir, $registryDir | Out-Null

function Export-SysmonEvent {
    param($Event, $Eid)
    $p   = $Event.Properties
    $obj = [ordered]@{
        Channel     = 'Microsoft-Windows-Sysmon/Operational'
        EventID     = $Eid
        TimeCreated = $Event.TimeCreated.ToString('o')
    }
    if ($Eid -eq 1) {
        if ($p.Count -gt 4)  { $obj['Image']            = [string]$p[4].Value  }
        if ($p.Count -gt 10) { $obj['CommandLine']       = [string]$p[10].Value }
        if ($p.Count -gt 20) { $obj['ParentImage']       = [string]$p[20].Value }
        if ($p.Count -gt 21) { $obj['ParentCommandLine'] = [string]$p[21].Value }
        if ($p.Count -gt 3)  { $obj['ProcessId']         = [string]$p[3].Value  }
        if ($p.Count -gt 19) { $obj['ParentProcessId']   = [string]$p[19].Value }
        if ($p.Count -gt 12) { $obj['User']              = [string]$p[12].Value }
        if ($p.Count -gt 11) { $obj['CurrentDirectory']  = [string]$p[11].Value }
        if ($p.Count -gt 16) { $obj['IntegrityLevel']    = [string]$p[16].Value }
        if ($p.Count -gt 9)  { $obj['OriginalFileName']  = [string]$p[9].Value  }
    } elseif ($Eid -eq 3) {
        if ($p.Count -gt 4)  { $obj['Image']               = [string]$p[4].Value  }
        if ($p.Count -gt 6)  { $obj['Protocol']            = [string]$p[6].Value  }
        if ($p.Count -gt 7)  { $obj['Initiated']           = [string]$p[7].Value  }
        if ($p.Count -gt 9)  { $obj['SourceIp']            = [string]$p[9].Value  }
        if ($p.Count -gt 11) { $obj['SourcePort']          = [string]$p[11].Value }
        if ($p.Count -gt 14) { $obj['DestinationIp']       = [string]$p[14].Value }
        if ($p.Count -gt 15) { $obj['DestinationHostname'] = [string]$p[15].Value }
        if ($p.Count -gt 16) { $obj['DestinationPort']     = [string]$p[16].Value }
    } elseif ($Eid -eq 11) {
        if ($p.Count -gt 4) { $obj['Image']          = [string]$p[4].Value }
        if ($p.Count -gt 6) { $obj['TargetFilename'] = [string]$p[6].Value }
    } elseif ($Eid -eq 12) {
        if ($p.Count -gt 1) { $obj['EventType']    = [string]$p[1].Value }
        if ($p.Count -gt 5) { $obj['Image']        = [string]$p[5].Value }
        if ($p.Count -gt 6) { $obj['TargetObject'] = [string]$p[6].Value }
    } elseif ($Eid -eq 13) {
        if ($p.Count -gt 1) { $obj['EventType']    = [string]$p[1].Value }
        if ($p.Count -gt 5) { $obj['Image']        = [string]$p[5].Value }
        if ($p.Count -gt 6) { $obj['TargetObject'] = [string]$p[6].Value }
        if ($p.Count -gt 7) { $obj['Details']      = [string]$p[7].Value }
    }
    return $obj
}

$startTime = if ($env:CORPUS_START_TIME) {
    [datetime]::Parse($env:CORPUS_START_TIME)
} else {
    (Get-Date).AddMinutes(-30)
}

$eidMap = @{
    1  = $processDir
    11 = $processDir
    3  = $networkDir
    12 = $registryDir
    13 = $registryDir
}

foreach ($eid in $eidMap.Keys) {
    $outFile = Join-Path $eidMap[$eid] ('targeted_' + $iterationId + '_eid' + $eid + '.jsonl')
    try {
        Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-Sysmon/Operational'
            Id        = $eid
            StartTime = $startTime
        } -ErrorAction SilentlyContinue |
        ForEach-Object {
            Export-SysmonEvent -Event $_ -Eid $eid | ConvertTo-Json -Compress
        } | Out-File -Append -Encoding utf8 $outFile
        $n = if (Test-Path $outFile) { (Get-Content $outFile | Measure-Object -Line).Lines } else { 0 }
        Write-Host ('EID ' + $eid + ': ' + $n + ' events -> ' + $outFile)
    } catch {
        Write-Host ('EID ' + $eid + ': error - ' + $_.Exception.Message)
    }
}

Write-Host ('Export complete for iteration: ' + $iterationId)
