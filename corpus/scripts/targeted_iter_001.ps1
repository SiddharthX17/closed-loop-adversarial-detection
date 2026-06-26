# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_f9b133df-d434-4b17-946e-d95458dcf87c  (1 rule(s)) ---------------------
# Intent:    Detecting attempts to access Windows credential hive files (SAM, SYSTEM, SECURIT
# Rules:     f9b133df-d434-4b17-946e-d95458dcf87c
# Archetype: IT admin workflow

$vssPath = '\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1'
$backupDir = Join-Path $env:TEMP 'registry_backup_2024'
if (-not (Test-Path $backupDir)) {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
}

# Simulate backup utility scanning VSS snapshots for registry files
$registryHives = @('config\sam', 'config\system', 'config\security')
foreach ($hive in $registryHives) {
    $vssHivePath = Join-Path $vssPath $hive
    $backupPath = Join-Path $backupDir ($hive.Replace('\\', '_'))

    # Use robocopy which is a standard Windows backup utility
    # This command would legitimately scan VSS paths during backup operations
    $cmd = "robocopy.exe $vssPath $backupDir /L /S 2>&1"
    $output = cmd /c $cmd
}

# Also simulate using reg.exe query against VSS paths (common in enterprise backup tools)
Write-Host "Scanning registry hives via VSS for backup purposes"
$regCommand = "reg.exe query HKLM\\SYSTEM\\CurrentControlSet 2>&1"
cmd /c $regCommand | Out-Null

# Clean up
if (Test-Path $backupDir) {
    Remove-Item -Path $backupDir -Recurse -Force
}

# -- Cluster: singleton_f9b133df-d434-4b17-946e-d95458dcf87c  (1 rule(s)) ---------------------
# Intent:    Detecting attempts to access Windows credential hive files (SAM, SYSTEM, SECURIT
# Rules:     f9b133df-d434-4b17-946e-d95458dcf87c
# Archetype: Software installer/updater workflow

$backupAppPath = Join-Path $env:ProgramFiles 'BackupSoftware'
$backupBinPath = Join-Path $backupAppPath 'backup_engine.exe'

# Create a mock backup application directory structure
if (-not (Test-Path $backupAppPath)) {
    New-Item -ItemType Directory -Path $backupAppPath -Force | Out-Null
}

# Create a benign executable placeholder
@'
echo Backup Engine v2.1.5
exit /b 0
'@ | Set-Content -Path (Join-Path $backupAppPath 'backup_engine.bat')

# Simulate backup software accessing credential hives through VSS
# Real backup solutions enumerate VSS snapshots and attempt to read registry hives
$vssPath = '\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1'
$hives = @('config\sam', 'config\system', 'config\security')

foreach ($hive in $hives) {
    $fullPath = Join-Path $vssPath $hive
    # Simulate the backup software command-line invocation
    # This mimics real backup tools that reference VSS paths in their process execution
    $backupCmd = "cmd /c echo Backing up registry hive: $fullPath"
    Invoke-Expression $backupCmd 2>&1 | Out-Null
}

# Clean up
if (Test-Path $backupAppPath) {
    Remove-Item -Path $backupAppPath -Recurse -Force
}

# -- Cluster: singleton_f9b133df-d434-4b17-946e-d95458dcf87c  (1 rule(s)) ---------------------
# Intent:    Detecting attempts to access Windows credential hive files (SAM, SYSTEM, SECURIT
# Rules:     f9b133df-d434-4b17-946e-d95458dcf87c
# Archetype: User-driven workflow

$recoveryScriptPath = Join-Path $env:TEMP 'system_recovery_2024.ps1'
$recoveryLogPath = Join-Path $env:TEMP 'recovery_log.txt'

# Create a legitimate recovery script that accesses VSS paths
$recoveryScript = @'
# System Recovery Script - Backing up critical system state
$vssPath = '\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1'
$registryHives = @('config\\sam', 'config\\system', 'config\\security')

foreach ($hive in $registryHives) {
    $fullPath = Join-Path $vssPath $hive
    # Log hive paths for backup manifest
    Add-Content -Path '"$env:TEMP\\recovery_log.txt"' -Value "Processing: $fullPath"
}
'@

Set-Content -Path $recoveryScriptPath -Value $recoveryScript

# Execute the recovery script (simulating user-initiated system backup)
& powershell.exe -ExecutionPolicy Bypass -File $recoveryScriptPath 2>&1 | Out-Null

# Clean up
if (Test-Path $recoveryScriptPath) {
    Remove-Item -Path $recoveryScriptPath -Force
}
if (Test-Path $recoveryLogPath) {
    Remove-Item -Path $recoveryLogPath -Force
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
