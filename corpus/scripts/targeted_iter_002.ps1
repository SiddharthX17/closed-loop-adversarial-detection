# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   3  |  Feasible: 2  |  Variants: 6
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# SKIPPED variant 'IT admin workflow': blocked pattern: hidden window ('-windowstyle hidden')

# SKIPPED variant 'Software installer/updater workflow': blocked pattern: hidden window ('-windowstyle hidden')

# SKIPPED variant 'User-driven workflow': blocked pattern: hidden window ('-windowstyle hidden')

# -- Cluster: singleton_e66d7887-58d4-4941-955e-0f9501b53347  (1 rule(s)) ---------------------
# Intent:    Detect base64-encoded payloads staged in HKCU registry hives for later execution
# Rules:     e66d7887-58d4-4941-955e-0f9501b53347
# Archetype: IT admin workflow

# Legitimate administrative configuration staging for scheduled task
# Scenario: IT admin creating an automated backup verification routine

$registryPath = 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
$valueName = 'BackupVerifyConfig'

# Base64-encoded configuration string representing legitimate task metadata
# This would normally come from a management tool or configuration system
$legitimateConfig = 'VmVyaWZ5QmFja3VwSW50ZWdyaXR5QXV0b21hdGVk'

# Create registry path if it doesn't exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Stage the base64 configuration in registry
New-ItemProperty -Path $registryPath -Name $valueName -Value $legitimateConfig -PropertyType String -Force | Out-Null

# Verify the registry value was written (admin would validate their work)
Get-ItemProperty -Path $registryPath -Name $valueName | Select-Object -ExpandProperty $valueName

# Create a scheduled task that references this registry configuration
# This is realistic: tasks often read their parameters from registry
$taskName = 'SystemMaintenanceVerification'
$taskPath = '\\Microsoft\\Windows\\System32'

# Simulate the task reading the registry value and using it
$taskAction = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument '-Command "Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\ NT\CurrentVersion\Winlogon -Name BackupVerifyConfig"'

# Register the task (this would trigger additional registry operations)
Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger (New-ScheduledTaskTrigger -AtLogon) -Force -ErrorAction SilentlyContinue | Out-Null

# Clean up
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $registryPath -Name $valueName -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_e66d7887-58d4-4941-955e-0f9501b53347  (1 rule(s)) ---------------------
# Intent:    Detect base64-encoded payloads staged in HKCU registry hives for later execution
# Rules:     e66d7887-58d4-4941-955e-0f9501b53347
# Archetype: Software installer/updater workflow

# Realistic browser or plugin installer storing encoded configuration
# Scenario: Mozilla Firefox portable configuration setup

$registryPath = 'HKCU:\Software\Mozilla\Firefox\Profiles\Default'
$valueName = 'ExtensionMetadata'

# Base64-encoded extension configuration (realistic for browser plugins)
$extensionConfig = 'RXh0ZW5zaW9uQ29uZmlndXJhdGlvbkRhdGFWMTA='

# Create Firefox registry path
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Write the encoded configuration (installers do this during setup)
New-ItemProperty -Path $registryPath -Name $valueName -Value $extensionConfig -PropertyType String -Force | Out-Null

# Installer would verify the write
$verifyValue = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue
if ($verifyValue.$valueName) {
    Write-Host 'Configuration staged successfully'
}

# Also simulate Adobe Reader doing the same under its registry branch
$adobePath = 'HKCU:\Software\Adobe\Reader\DC\Trust\PluginWhitelist'
if (-not (Test-Path $adobePath)) {
    New-Item -Path $adobePath -Force | Out-Null
}

$adobePluginConfig = 'QWRvYmVQbHVnaW5Db25maWd1cmF0aW9u'
New-ItemProperty -Path $adobePath -Name 'PluginSettings' -Value $adobePluginConfig -PropertyType String -Force | Out-Null

# Verify Adobe configuration
Get-ItemProperty -Path $adobePath -Name 'PluginSettings' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'PluginSettings'

# Also test Google registry path (realistic for Chrome/Google Drive)
$googlePath = 'HKCU:\Software\Google\Chrome\Preferences'
if (-not (Test-Path $googlePath)) {
    New-Item -Path $googlePath -Force | Out-Null
}

$chromeConfig = 'Q2hyb21lUHJlZmVyZW5jZXNDb25maWd1cmF0aW9u'
New-ItemProperty -Path $googlePath -Name 'Extensions' -Value $chromeConfig -PropertyType String -Force | Out-Null

# Clean up all test registrations
Remove-ItemProperty -Path $registryPath -Name $valueName -Force -ErrorAction SilentlyContinue
Remove-Item -Path $registryPath -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $adobePath -Name 'PluginSettings' -Force -ErrorAction SilentlyContinue
Remove-Item -Path $adobePath -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $googlePath -Name 'Extensions' -Force -ErrorAction SilentlyContinue
Remove-Item -Path $googlePath -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_e66d7887-58d4-4941-955e-0f9501b53347  (1 rule(s)) ---------------------
# Intent:    Detect base64-encoded payloads staged in HKCU registry hives for later execution
# Rules:     e66d7887-58d4-4941-955e-0f9501b53347
# Archetype: User-driven workflow

# User installing and configuring a portable utility that uses registry for settings
# Scenario: Developer tool (like Git Bash or Node.js integration) storing encoded config

$registryPath = 'HKCU:\Software\Classes\CLSID\{9999AAAA-BBBB-CCCC-DDDD-000000000000}'
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Base64-encoded development tool configuration (realistic for dev utilities)
$devToolConfig = 'RGV2ZWxvcG1lbnRUb29sQ29uZmlndXJhdGlvblN0cmluZw=='
New-ItemProperty -Path $registryPath -Name 'Config' -Value $devToolConfig -PropertyType String -Force | Out-Null

# Verify configuration was written
$storedConfig = Get-ItemProperty -Path $registryPath -Name 'Config' -ErrorAction SilentlyContinue
if ($storedConfig) {
    Write-Host 'Development tool configuration loaded'
}

# Simulate the utility reading the configuration later
$retrievedConfig = Get-ItemProperty -Path $registryPath -Name 'Config' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'Config'

# Test WOW6432Node path for 32-bit application on 64-bit system
$wow6432Path = 'HKCU:\Software\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers'
if (-not (Test-Path $wow6432Path)) {
    New-Item -Path $wow6432Path -Force | Out-Null
}

$appCompatConfig = 'QXBwQ29tcGF0aWJpbGl0eUZsYWdzQ29uZmlndXJhdGlvbg=='
New-ItemProperty -Path $wow6432Path -Name 'PortableAppSettings' -Value $appCompatConfig -PropertyType String -Force | Out-Null

# Retrieve and verify the AppCompat configuration
Get-ItemProperty -Path $wow6432Path -Name 'PortableAppSettings' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'PortableAppSettings'

# Simulate Policies path for enterprise tools that use GPO-like registry areas
$policiesPath = 'HKCU:\Software\Policies\EnterpriseApp\Settings'
if (-not (Test-Path $policiesPath)) {
    New-Item -Path $policiesPath -Force | Out-Null
}

$policyConfig = 'RW50ZXJwcmlzZVBvbGljeUNvbmZpZ3VyYXRpb24='
New-ItemProperty -Path $policiesPath -Name 'StoredConfig' -Value $policyConfig -PropertyType String -Force | Out-Null

# Verify the policy configuration
Get-ItemProperty -Path $policiesPath -Name 'StoredConfig' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'StoredConfig'

# Clean up all test registry entries
Remove-ItemProperty -Path $registryPath -Name 'Config' -Force -ErrorAction SilentlyContinue
Remove-Item -Path $registryPath -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $wow6432Path -Name 'PortableAppSettings' -Force -ErrorAction SilentlyContinue
Remove-Item -Path $wow6432Path -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $policiesPath -Name 'StoredConfig' -Force -ErrorAction SilentlyContinue
Remove-Item -Path $policiesPath -Force -ErrorAction SilentlyContinue

# SKIPPED cluster singleton_17c277a0-618f-4fca-aa29-e679bcfc4d97: JSON parse error: Unterminated string starting at: line 39 column 17 (char 8194)

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
