# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 2
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_2b3ffc9c-a54c-41c9-8601-cdace311c92e  (1 rule(s)) ---------------------
# Intent:    Attacker disabling Windows Firewall via registry policy commands to evade networ
# Rules:     2b3ffc9c-a54c-41c9-8601-cdace311c92e
# Archetype: IT admin workflow

$auditLogPath = Join-Path $env:TEMP 'firewall_policy_audit.txt'
$policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile'
$domainPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'

# Document current firewall policy state for audit purposes
Add-Content -Path $auditLogPath -Value "Firewall Policy Audit - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Add-Content -Path $auditLogPath -Value "================================================================"

# Query current firewall enabled state across profiles
try {
  if (Test-Path $policyPath) {
    $stdValue = Get-ItemProperty -Path $policyPath -Name 'EnableFirewall' -ErrorAction SilentlyContinue
    Add-Content -Path $auditLogPath -Value "StandardProfile EnableFirewall: $($stdValue.EnableFirewall)"
  }
} catch {}

try {
  if (Test-Path $domainPolicyPath) {
    $domainValue = Get-ItemProperty -Path $domainPolicyPath -Name 'EnableFirewall' -ErrorAction SilentlyContinue
    Add-Content -Path $auditLogPath -Value "DomainProfile EnableFirewall: $($domainValue.EnableFirewall)"
  }
} catch {}

# Update firewall policy using registry command-line tool
# This simulates admin making policy changes via standard registry modification
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" /v EnableFirewall /t REG_DWORD /d 1 /f 2>&1 | Out-Null

# Use PowerShell to verify policy application
$verifyCmd = 'powershell.exe -NoProfile -Command "Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile -Name EnableFirewall -ErrorAction SilentlyContinue | Select-Object EnableFirewall"'
Invoke-Expression $verifyCmd 2>&1 | Out-Null

# Query via command line to document final state (demonstrates monitoring via CLI)
cmd /c "reg query HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile /v EnableFirewall" 2>&1 | Out-Null

# Clean up audit log
if (Test-Path $auditLogPath) { Remove-Item -Path $auditLogPath -Force }

# -- Cluster: singleton_2b3ffc9c-a54c-41c9-8601-cdace311c92e  (1 rule(s)) ---------------------
# Intent:    Attacker disabling Windows Firewall via registry policy commands to evade networ
# Rules:     2b3ffc9c-a54c-41c9-8601-cdace311c92e
# Archetype: Software installer/updater workflow

$configLogPath = Join-Path $env:TEMP 'config_firewall_settings.log'
$tempRegPath = 'HKLM:\SOFTWARE\Temp_SecurityConfig'

# Simulate security tool installer verifying Windows Firewall policy
# This is typical behavior of endpoint protection, MDM, or network management tools

# Create temporary configuration registry location
try {
  if (-not (Test-Path $tempRegPath)) {
    New-Item -Path $tempRegPath -Force | Out-Null
  }
} catch {}

# Installer queries current firewall state using command-line registry tool
# (Enterprise tools often verify policy state before applying configurations)
cmd /c "reg query HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile /v EnableFirewall" 2>&1 | Tee-Object -FilePath $configLogPath | Out-Null

# Tool applies its firewall policy configuration via PowerShell registry command
# Setting EnableFirewall to 1 (enabled) as part of standard deployment
try {
  $fwPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile'
  if (-not (Test-Path $fwPolicyPath)) {
    New-Item -Path $fwPolicyPath -Force | Out-Null
  }

  Set-ItemProperty -Path $fwPolicyPath -Name 'EnableFirewall' -Value 1 -Type DWord -ErrorAction SilentlyContinue
  Set-ItemProperty -Path $fwPolicyPath -Name 'DoNotAllowExceptions' -Value 0 -Type DWord -ErrorAction SilentlyContinue
} catch {}

# Verify policy application success
Invoke-Expression "Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile -Name EnableFirewall -ErrorAction SilentlyContinue" 2>&1 | Out-Null

# Document configuration completion
Add-Content -Path $configLogPath -Value "Configuration applied at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

# Clean up temporary registry and log
try {
  if (Test-Path $tempRegPath) {
    Remove-Item -Path $tempRegPath -Force -Recurse -ErrorAction SilentlyContinue
  }
} catch {}

if (Test-Path $configLogPath) { Remove-Item -Path $configLogPath -Force }


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
