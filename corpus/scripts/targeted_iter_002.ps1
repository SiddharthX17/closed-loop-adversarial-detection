# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_a7f4e708-9258-426b-9a66-f9eafc3ab9c4  (1 rule(s)) ---------------------
# Intent:    Attackers using BITS transfers to download and execute payloads, or using bitsad
# Rules:     a7f4e708-9258-426b-9a66-f9eafc3ab9c4
# Archetype: IT admin workflow

# Admin task: Download corporate backup manifest using bitsadmin
# BITS is often used by admins for bandwidth-aware file transfers

$jobName = 'Corp-Backup-Manifest-' + (Get-Date -Format yyyyMMdd-HHmmss)
$localPath = Join-Path $env:TEMP 'backup_manifest.txt'
$sourceUrl = 'https://intranet.corp.local/backups/manifest.txt'

try {
    # Create a BITS transfer job for the file
    $cmd = @(
        'bitsadmin.exe',
        '/create',
        $jobName,
        $sourceUrl,
        $localPath
    )
    & $cmd[0] $cmd[1] $cmd[2] $cmd[3] $cmd[4]

    # Add file to the job
    $addCmd = @(
        'bitsadmin.exe',
        '/addfile',
        $jobName,
        $sourceUrl,
        $localPath
    )
    & $addCmd[0] $addCmd[1] $addCmd[2] $addCmd[3] $addCmd[4]

    # Resume the job to begin transfer
    $resumeCmd = @(
        'bitsadmin.exe',
        '/resume',
        $jobName
    )
    & $resumeCmd[0] $resumeCmd[1] $resumeCmd[2]

    # Wait for completion (with timeout)
    $timeout = 30
    $elapsed = 0
    while ($elapsed -lt $timeout) {
        $infoCmd = @(
            'bitsadmin.exe',
            '/info',
            $jobName,
            '/verbose'
        )
        $jobInfo = & $infoCmd[0] $infoCmd[1] $infoCmd[2] $infoCmd[3]
        if ($jobInfo -match 'Transferred') {
            Start-Sleep -Seconds 2
            break
        }
        Start-Sleep -Seconds 1
        $elapsed += 1
    }

    # Clean up: Complete and remove the job
    $completeCmd = @(
        'bitsadmin.exe',
        '/complete',
        $jobName
    )
    & $completeCmd[0] $completeCmd[1] $completeCmd[2] 2>$null

} catch {
    Write-Host 'BITS job error: ' $_
} finally {
    # Ensure cleanup
    bitsadmin.exe /resume $jobName 2>$null
    bitsadmin.exe /complete $jobName 2>$null
    Remove-Item -Path $localPath -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_a7f4e708-9258-426b-9a66-f9eafc3ab9c4  (1 rule(s)) ---------------------
# Intent:    Attackers using BITS transfers to download and execute payloads, or using bitsad
# Rules:     a7f4e708-9258-426b-9a66-f9eafc3ab9c4
# Archetype: Software installer/updater workflow

# Enterprise installer: Download application component update using PowerShell BitsTransfer
# BITS transfers are common in software deployment and update workflows

$componentName = 'Enterprise-App-Update-' + (Get-Date -Format yyyyMMdd-HHmmss)
$downloadPath = Join-Path $env:TEMP 'appupdate_component.zip'
$sourceUri = 'https://updates.corp.local/components/v2.1.5/runtime.zip'

try {
    # Create a new BITS transfer job via PowerShell
    $bitsJob = New-BitsTransfer -Name $componentName -Source $sourceUri -Destination $downloadPath -ErrorAction Stop

    # Start the transfer
    Resume-BitsTransfer -BitsJob $bitsJob -ErrorAction Stop

    # Wait for job completion with timeout
    $timeout = 30
    $elapsed = 0
    while ($elapsed -lt $timeout) {
        $jobState = Get-BitsTransfer -BitsJob $bitsJob | Select-Object -ExpandProperty JobState
        if ($jobState -eq 'Transferred') {
            break
        }
        if ($jobState -eq 'Suspended' -or $jobState -eq 'Error') {
            Resume-BitsTransfer -BitsJob $bitsJob -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 1
        $elapsed += 1
    }

    # Complete the job
    Complete-BitsTransfer -BitsJob $bitsJob -ErrorAction SilentlyContinue

} catch {
    Write-Host 'BITS transfer error: ' $_
} finally {
    # Cleanup
    Get-BitsTransfer -Name $componentName -ErrorAction SilentlyContinue | Remove-BitsTransfer -ErrorAction SilentlyContinue
    Remove-Item -Path $downloadPath -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_a7f4e708-9258-426b-9a66-f9eafc3ab9c4  (1 rule(s)) ---------------------
# Intent:    Attackers using BITS transfers to download and execute payloads, or using bitsad
# Rules:     a7f4e708-9258-426b-9a66-f9eafc3ab9c4
# Archetype: Document/file operation workflow

# Document retrieval: Download large report archive using bitsadmin with retry configuration
# Enterprises use BITS for large file downloads with automatic retry and bandwidth management

$reportName = 'Q3-Financial-Report-Archive'
$jobName = $reportName + '-' + (Get-Date -Format yyyyMMdd-HHmmss)
$destPath = Join-Path $env:TEMP 'Q3_report_archive.tar'
$sourceUrl = 'https://reports.corp.local/archives/2024/q3_financials.tar'

try {
    # Create BITS job for the large file
    bitsadmin.exe /create $jobName $sourceUrl $destPath

    # Set minimum retry delay for network resilience
    bitsadmin.exe /setminretrydelay $jobName 300

    # Set notification command to execute on job completion (administrative scenario)
    $notifyCmd = 'cmd.exe /c echo download complete'
    bitsadmin.exe /setnotifycmdline $jobName $notifyCmd

    # Add the file
    bitsadmin.exe /addfile $jobName $sourceUrl $destPath

    # Begin the transfer
    bitsadmin.exe /resume $jobName

    # Monitor transfer progress
    $timeout = 30
    $elapsed = 0
    while ($elapsed -lt $timeout) {
        $statusOutput = bitsadmin.exe /info $jobName /verbose
        if ($statusOutput -match 'Transferred') {
            Start-Sleep -Seconds 1
            break
        }
        Start-Sleep -Seconds 2
        $elapsed += 2
    }

    # Complete and cleanup
    bitsadmin.exe /complete $jobName 2>$null

} catch {
    Write-Host 'File transfer error: ' $_
} finally {
    # Ensure all jobs are removed
    bitsadmin.exe /resume $jobName 2>$null
    bitsadmin.exe /complete $jobName 2>$null
    Remove-Item -Path $destPath -Force -ErrorAction SilentlyContinue
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
