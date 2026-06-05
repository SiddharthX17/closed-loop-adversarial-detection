# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_2a4971d5-56ec-4db7-8056-3cad9a81c2d8  (1 rule(s)) ---------------------
# Intent:    Detect attackers staging base64-encoded payloads in registry under legitimate Wi
# Rules:     2a4971d5-56ec-4db7-8056-3cad9a81c2d8
# Archetype: Software installer/updater workflow

# Simulate legitimate installer writing encoded metadata to HKLM\Software for deferred configuration
# This mimics Windows Update, service pack installers, or enterprise MSI deployments

$regPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components'
$regKeyName = 'D4E8F9B2A3C1E5F7'
$regValueName = 'Configuration'

# Benign base64-encoded configuration string (represents installer metadata)
# Actual content: {"version":"1.0.5.2","installpath":"C:\\Program Files\\Service","flags":3}
$encodedConfig = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('{"version":"1.0.5.2","installpath":"C:\\Program Files\\Service","flags":3}'))

try {
  # Create registry path if needed
  if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
  }

  # Create subkey for this installer component
  $componentPath = Join-Path $regPath $regKeyName
  if (-not (Test-Path $componentPath)) {
    New-Item -Path $componentPath -Force | Out-Null
  }

  # Write base64-encoded config (realistic scenario: staged during MSI installation)
  Set-ItemProperty -Path $componentPath -Name $regValueName -Value $encodedConfig -Type String

  # Simulate msiexec.exe triggering the read of this registry value
  # This represents the actual installer process accessing its staged configuration
  Start-Process -FilePath 'C:\Windows\System32\msiexec.exe' -ArgumentList @('/quiet', '/norestart', '/lv', "$env:TEMP\install.log") -NoNewWindow -Wait -ErrorAction SilentlyContinue

  # Verify write occurred
  $stored = Get-ItemProperty -Path $componentPath -Name $regValueName -ErrorAction SilentlyContinue
  if ($stored) {
    Write-Host "Configuration staged successfully."
  }
} finally {
  # Cleanup
  if (Test-Path $regPath) {
    Remove-Item -Path (Join-Path $regPath $regKeyName) -Force -ErrorAction SilentlyContinue
  }
}

# -- Cluster: singleton_2a4971d5-56ec-4db7-8056-3cad9a81c2d8  (1 rule(s)) ---------------------
# Intent:    Detect attackers staging base64-encoded payloads in registry under legitimate Wi
# Rules:     2a4971d5-56ec-4db7-8056-3cad9a81c2d8
# Archetype: IT admin workflow

# Simulate IT admin configuring scheduled task parameters in HKLM\Software registry
# This represents legitimate system administration: staging task metadata for deferred execution

$regPath = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Parameters'
$regValueName = 'TaskMetadata'

# Benign base64-encoded task parameters
# Actual content: {"taskname":"SystemMaintenance","action":"defrag","schedule":"weekly"}
$taskMetadata = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('{"taskname":"SystemMaintenance","action":"defrag","schedule":"weekly"}'))

try {
  # Ensure registry path exists (typical location for task parameters)
  if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
  }

  # Write base64-encoded task metadata (legitimate admin operation)
  Set-ItemProperty -Path $regPath -Name $regValueName -Value $taskMetadata -Type String

  # Simulate services.exe reading the registry for task execution
  # This represents the actual Windows Service triggering deferred task execution
  Start-Process -FilePath 'C:\Windows\System32\services.exe' -NoNewWindow -ErrorAction SilentlyContinue

  # Also simulate svchost.exe accessing this configuration
  $svcHostProcs = Get-Process -Name svchost -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($svcHostProcs) {
    # Read back to confirm staging
    $metadata = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue
    if ($metadata.TaskMetadata) {
      Write-Host "Task metadata staged for execution."
    }
  }
} finally {
  # Cleanup
  if (Test-Path $regPath) {
    Remove-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue
  }
}

# -- Cluster: singleton_2a4971d5-56ec-4db7-8056-3cad9a81c2d8  (1 rule(s)) ---------------------
# Intent:    Detect attackers staging base64-encoded payloads in registry under legitimate Wi
# Rules:     2a4971d5-56ec-4db7-8056-3cad9a81c2d8
# Archetype: User-driven workflow

# Simulate legitimate browser or OneDrive update process staging configuration in HKLM\Software
# This represents actual end-user applications that use system binaries to manage updates

$regPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\App Paths\AppMetadata'
$regValueName = 'UpdateConfig'

# Benign base64-encoded update configuration
# Actual content: {"channel":"stable","version":"96.0.1054.29","updateurl":"https://example.com/updates"}
$updateConfig = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('{"channel":"stable","version":"96.0.1054.29","updateurl":"https://example.com/updates"}'))

try {
  # Ensure registry path exists
  if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
  }

  # Write base64-encoded config (legitimate: browser/app update staging)
  Set-ItemProperty -Path $regPath -Name $regValueName -Value $updateConfig -Type String

  # Simulate cleanmgr.exe (legitimate system utility) reading application config
  # This represents real maintenance processes that read app configuration from registry
  Start-Process -FilePath 'C:\Windows\System32\cleanmgr.exe' -ArgumentList @('/sageset:1') -NoNewWindow -ErrorAction SilentlyContinue

  # Also simulate wuauclt.exe (Windows Update agent) accessing registry
  Start-Process -FilePath 'C:\Windows\System32\wuauclt.exe' -ArgumentList @('/reportnow') -NoNewWindow -ErrorAction SilentlyContinue -Wait

  # Verify staging occurred
  $config = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue
  if ($config.UpdateConfig) {
    Write-Host "Update configuration staged."
  }
} finally {
  # Cleanup
  if (Test-Path $regPath) {
    Remove-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue
  }
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
