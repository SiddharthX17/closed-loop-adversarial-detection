# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 2
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_acd1829a-c9ce-44fe-920a-9c836b34879c  (1 rule(s)) ---------------------
# Intent:    Detect attackers attempting to extract credential hives (SAM, SYSTEM, SECURITY) 
# Rules:     acd1829a-c9ce-44fe-920a-9c836b34879c
# Archetype: IT admin workflow

$VssPath = '\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config'
$LogFile = Join-Path $env:TEMP 'hive_audit_20250113.log'

# Simulate forensic validation of credential hives from VSS snapshot
Add-Content -Path $LogFile -Value "Starting credential hive integrity check from VSS snapshot"
Add-Content -Path $LogFile -Value "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Add-Content -Path $LogFile -Value ""

# Attempt to read SAM hive from VSS path using reg.exe query
Write-Host "Attempting to query SAM hive from VSS snapshot..."
$SamPath = "$VssPath\SAM"
cmd /c "reg query HKLM\\SAM 2>&1" | Add-Content -Path $LogFile
Add-Content -Path $LogFile -Value "SAM hive path queried: $SamPath"

# Attempt to read SYSTEM hive from VSS path
Write-Host "Attempting to query SYSTEM hive from VSS snapshot..."
$SystemPath = "$VssPath\SYSTEM"
cmd /c "reg query HKLM\\SYSTEM\\CurrentControlSet 2>&1" | Add-Content -Path $LogFile
Add-Content -Path $LogFile -Value "SYSTEM hive path queried: $SystemPath"

# Attempt to read SECURITY hive from VSS path
Write-Host "Attempting to query SECURITY hive from VSS snapshot..."
$SecurityPath = "$VssPath\SECURITY"
cmd /c "reg query HKLM\\SECURITY 2>&1" | Add-Content -Path $LogFile
Add-Content -Path $LogFile -Value "SECURITY hive path queried: $SecurityPath"

Add-Content -Path $LogFile -Value ""
Add-Content -Path $LogFile -Value "Forensic hive validation completed"

# Clean up audit log
Remove-Item -Path $LogFile -Force -ErrorAction SilentlyContinue
Write-Host "Hive integrity audit completed and cleaned up"

# -- Cluster: singleton_acd1829a-c9ce-44fe-920a-9c836b34879c  (1 rule(s)) ---------------------
# Intent:    Detect attackers attempting to extract credential hives (SAM, SYSTEM, SECURITY) 
# Rules:     acd1829a-c9ce-44fe-920a-9c836b34879c
# Archetype: Software installer/updater workflow

$VssSnapshots = 1..3
$BackupLogPath = Join-Path $env:TEMP 'system_backup_validation.log'
$HivesToCheck = @('config\\sam', 'config\\system', 'config\\security')

Add-Content -Path $BackupLogPath -Value "System State Backup Validation Tool"
Add-Content -Path $BackupLogPath -Value "Backup Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Add-Content -Path $BackupLogPath -Value "Checking Volume Shadow Copy snapshots for system hive accessibility..."
Add-Content -Path $BackupLogPath -Value ""

foreach ($SnapshotId in $VssSnapshots) {
    $SnapshotPath = "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy$SnapshotId\Windows\System32"
    Add-Content -Path $BackupLogPath -Value "Validating snapshot: HarddiskVolumeShadowCopy$SnapshotId"

    foreach ($Hive in $HivesToCheck) {
        $HivePath = Join-Path $SnapshotPath $Hive
        Add-Content -Path $BackupLogPath -Value "  Checking hive accessibility: $Hive from harddiskvolumeshadowcopy$SnapshotId"

        # Simulate tool checking if hive file is readable from VSS
        if ($Hive -like '*sam*') {
            cmd /c "dir \"$SnapshotPath\config\sam\" 2>&1" | Add-Content -Path $BackupLogPath
        }
        if ($Hive -like '*system*') {
            cmd /c "dir \"$SnapshotPath\config\system\" 2>&1" | Add-Content -Path $BackupLogPath
        }
        if ($Hive -like '*security*') {
            cmd /c "dir \"$SnapshotPath\config\security\" 2>&1" | Add-Content -Path $BackupLogPath
        }
    }
    Add-Content -Path $BackupLogPath -Value ""
}

Add-Content -Path $BackupLogPath -Value "Backup validation completed successfully"

# Clean up validation log
Remove-Item -Path $BackupLogPath -Force -ErrorAction SilentlyContinue
Write-Host "System backup validation check completed"


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
