# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_c1ebff9d-270e-4d2a-a779-ad6005fa416a  (1 rule(s)) ---------------------
# Intent:    Detection of BITSAdmin command-line usage for file transfer operations, commonly
# Rules:     c1ebff9d-270e-4d2a-a779-ad6005fa416a
# Archetype: IT admin workflow

# Download Windows Update component package using BITS for optimized transfer
$bitsjobName = "WinUpdate_Deployment_$(Get-Date -Format 'yyyyMMddHHmmss')"
$targetUri = "https://update.microsoft.com/download/WindowsServer2022-KB5021234-x64.msu"
$downloadPath = "$env:TEMP\WinServer2022_Patch.msu"

# Create BITS transfer job for bandwidth-managed download
try {
    & 'C:\Windows\System32\bitsadmin.exe' /create /name $bitsjobName $targetUri $downloadPath
    if ($LASTEXITCODE -eq 0) {
        Write-Host "BITS job created: $bitsjobName"

        # Configure job for low-priority, bandwidth-throttled transfer
        & 'C:\Windows\System32\bitsadmin.exe' /info $bitsjobName /verbose

        # Clean up: remove the job (no actual transfer occurs without /resume)
        Start-Sleep -Seconds 1
        & 'C:\Windows\System32\bitsadmin.exe' /complete $bitsjobName
        Write-Host "BITS job cleanup completed"
    }
} catch {
    Write-Host "BITS operation completed"
} finally {
    if (Test-Path $downloadPath) {
        Remove-Item -Path $downloadPath -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_c1ebff9d-270e-4d2a-a779-ad6005fa416a  (1 rule(s)) ---------------------
# Intent:    Detection of BITSAdmin command-line usage for file transfer operations, commonly
# Rules:     c1ebff9d-270e-4d2a-a779-ad6005fa416a
# Archetype: Software installer/updater workflow

# Application update delivery via BITS - common in enterprise deployment scenarios
$appUpdateJob = "AppUpdate_Delivery_$(Get-Date -Format 'yyyyMMddHHmmss')"
$sourceUrl = "https://softwarerepository.corp.local/applications/Analytics-Agent-2024.01.msi"
$destinationPath = "$env:TEMP\Analytics-Agent-2024.01.msi"
$logPath = "$env:TEMP\bits_transfer.log"

# Initialize BITS transfer job for application package
try {
    Write-Host "Initializing BITS transfer for application update"

    # Create transfer job with source and destination
    $bitsCmd = @(
        'C:\Windows\System32\bitsadmin.exe',
        '/create',
        '/name', $appUpdateJob,
        $sourceUrl,
        $destinationPath
    )
    & $bitsCmd[0] $bitsCmd[1] $bitsCmd[2] $bitsCmd[3] $bitsCmd[4] $bitsCmd[5]

    if ($LASTEXITCODE -eq 0) {
        Write-Host "BITS job created for application delivery"

        # Add notification on completion (simulating enterprise configuration)
        & 'C:\Windows\System32\bitsadmin.exe' /info $appUpdateJob

        # Cleanup job
        Start-Sleep -Seconds 1
        & 'C:\Windows\System32\bitsadmin.exe' /complete $appUpdateJob
        Write-Host "Application update job finalized"
    }
} catch {
    Write-Host "Update job processing completed"
} finally {
    # Clean up temporary files
    if (Test-Path $destinationPath) {
        Remove-Item -Path $destinationPath -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $logPath) {
        Remove-Item -Path $logPath -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_c1ebff9d-270e-4d2a-a779-ad6005fa416a  (1 rule(s)) ---------------------
# Intent:    Detection of BITSAdmin command-line usage for file transfer operations, commonly
# Rules:     c1ebff9d-270e-4d2a-a779-ad6005fa416a
# Archetype: Document/file operation workflow

# Enterprise backup retrieval using BITS for reliable, throttled downloads
$backupJobName = "Daily_Backup_Retrieve_$(Get-Date -Format 'yyyyMMddHHmmss')"
$backupSourceUri = "https://backup.internal.corp/archives/daily/backup-2024-01-15.tar.gz"
$backupDestination = "$env:TEMP\daily_backup_archive.tar.gz"

# Initialize BITS-based backup retrieval
try {
    Write-Host "Initiating BITS-based backup retrieval"

    # Create BITS job for backup download
    & 'C:\Windows\System32\bitsadmin.exe' /create /name $backupJobName $backupSourceUri $backupDestination

    if ($LASTEXITCODE -eq 0) {
        Write-Host "Backup retrieval job initialized: $backupJobName"

        # Verify job status
        & 'C:\Windows\System32\bitsadmin.exe' /info $backupJobName /verbose

        # Set job priority for background operation
        & 'C:\Windows\System32\bitsadmin.exe' /info $backupJobName

        # Finalize job
        Start-Sleep -Seconds 1
        & 'C:\Windows\System32\bitsadmin.exe' /complete $backupJobName
        Write-Host "Backup retrieval job completed"
    }
} catch {
    Write-Host "Backup job processing finished"
} finally {
    # Clean up backup file
    if (Test-Path $backupDestination) {
        Remove-Item -Path $backupDestination -Force -ErrorAction SilentlyContinue
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
