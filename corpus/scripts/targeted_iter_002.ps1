# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_106829ff-43e0-44ad-b410-2717151efd71  (1 rule(s)) ---------------------
# Intent:    Attackers use BITS (Background Intelligent Transfer Service) jobs to download fi
# Rules:     106829ff-43e0-44ad-b410-2717151efd71
# Archetype: IT admin workflow

# IT admin: Download a large software package using BITS for resilient transfer
# BITS is commonly used in enterprise environments for zero-touch provisioning,
# software distribution, and OS updates because it resumes on connection loss.

$jobName = 'SoftwareDistribution_Q4_Deployment'
$sourceUrl = 'https://download.example.com/software/release-2024-q4.zip'
$destPath = Join-Path $env:TEMP 'release-2024-q4.zip'

try {
    # Create a BITS transfer job (standard admin task)
    & bitsadmin.exe /create /name $jobName /type Download
    Start-Sleep -Milliseconds 500

    # Add the file to download
    & bitsadmin.exe /addfile $jobName $sourceUrl $destPath
    Start-Sleep -Milliseconds 500

    # Configure a local completion notification (logging success for audit trail)
    $notifyScript = Join-Path $env:TEMP 'deployment-notify.cmd'
    @'>
cmd /c @echo BITS transfer completed at %time% >> C:\Windows\Temp\deployment-audit.log
'@ | Set-Content -Path $notifyScript -Force

    & bitsadmin.exe /setnotifycmdline $jobName $notifyScript ""
    Start-Sleep -Milliseconds 500

    # Resume the transfer (normal operational flow)
    & bitsadmin.exe /resume $jobName
    Start-Sleep -Milliseconds 500

    # Wait briefly for transfer to process
    Start-Sleep -Seconds 2

    # Complete the job
    & bitsadmin.exe /complete $jobName
    Start-Sleep -Milliseconds 500

    # Verify the transfer completed
    if (Test-Path -Path $destPath) {
        Write-Host "[INFO] BITS transfer completed successfully. File: $destPath"
    } else {
        Write-Host "[WARNING] File not found; transfer may have failed (expected in CI environment)."
    }
}
catch {
    Write-Host "[ERROR] BITS operation failed: $_"
}
finally {
    # Cleanup: Remove BITS job and temporary files
    & bitsadmin.exe /remove $jobName /force 2>$null

    if (Test-Path -Path $notifyScript) { Remove-Item -Path $notifyScript -Force }
    if (Test-Path -Path $destPath) { Remove-Item -Path $destPath -Force }
    if (Test-Path -Path 'C:\Windows\Temp\deployment-audit.log') { Remove-Item -Path 'C:\Windows\Temp\deployment-audit.log' -Force }
}

# -- Cluster: singleton_106829ff-43e0-44ad-b410-2717151efd71  (1 rule(s)) ---------------------
# Intent:    Attackers use BITS (Background Intelligent Transfer Service) jobs to download fi
# Rules:     106829ff-43e0-44ad-b410-2717151efd71
# Archetype: Software installer/updater workflow

# Software deployment framework: Use BITS for reliable application staging
# Enterprise deployment systems often prefer BITS for bandwidth-friendly,
# resumable downloads of large application packages.

$deploymentJobName = 'AppDeploy_VLCMediaPlayer_v3.0.21'
$appSourceUrl = 'https://downloads.example.com/apps/vlc-3.0.21-win64.exe'
$stagingPath = Join-Path $env:TEMP 'vlc-3.0.21-win64.exe'

try {
    # Create BITS job for application download
    & bitsadmin.exe /create /name $deploymentJobName /type Download
    Start-Sleep -Milliseconds 500

    # Add the application binary to the job
    & bitsadmin.exe /addfile $deploymentJobName $appSourceUrl $stagingPath
    Start-Sleep -Milliseconds 500

    # Set completion notification to invoke the installer
    $installerScript = Join-Path $env:TEMP 'app-deployment-install.cmd'
    @'>
cmd /c echo Installation of VLC started >> C:\Windows\Temp\app-deployment.log
'@ | Set-Content -Path $installerScript -Force

    & bitsadmin.exe /setnotifycmdline $deploymentJobName $installerScript ""
    Start-Sleep -Milliseconds 500

    # Resume the BITS transfer
    & bitsadmin.exe /resume $deploymentJobName
    Start-Sleep -Milliseconds 500

    # Wait for download to process
    Start-Sleep -Seconds 2

    # Complete the BITS job
    & bitsadmin.exe /complete $deploymentJobName
    Start-Sleep -Milliseconds 500

    Write-Host "[INFO] Application deployment via BITS completed."
}
catch {
    Write-Host "[ERROR] Deployment job failed: $_"
}
finally {
    # Cleanup: Ensure BITS job is removed and temporary files are cleaned
    & bitsadmin.exe /remove $deploymentJobName /force 2>$null

    if (Test-Path -Path $installerScript) { Remove-Item -Path $installerScript -Force }
    if (Test-Path -Path $stagingPath) { Remove-Item -Path $stagingPath -Force }
    if (Test-Path -Path 'C:\Windows\Temp\app-deployment.log') { Remove-Item -Path 'C:\Windows\Temp\app-deployment.log' -Force }
}

# -- Cluster: singleton_106829ff-43e0-44ad-b410-2717151efd71  (1 rule(s)) ---------------------
# Intent:    Attackers use BITS (Background Intelligent Transfer Service) jobs to download fi
# Rules:     106829ff-43e0-44ad-b410-2717151efd71
# Archetype: User-driven workflow

# User workflow: Download a large media file using BITS through a sync client
# Corporate file-sharing and backup systems often use BITS internally for
# efficient, resumable downloads without requiring user awareness.

$userDownloadJob = 'ContentSync_Archive_2024Q4'
$contentUrl = 'https://share.example.com/media/project-archive-2024-q4.tar.gz'
$downloadDest = Join-Path $env:TEMP 'project-archive-2024-q4.tar.gz'

try {
    # Create BITS job for content download
    & bitsadmin.exe /create /name $userDownloadJob /type Download
    Start-Sleep -Milliseconds 500

    # Add file to transfer
    & bitsadmin.exe /addfile $userDownloadJob $contentUrl $downloadDest
    Start-Sleep -Milliseconds 500

    # Set completion callback to log download completion
    $completionLog = Join-Path $env:TEMP 'content-sync-complete.cmd'
    @'>
cmd /c echo Archive downloaded: %date% %time% >> C:\Windows\Temp\sync-events.log
'@ | Set-Content -Path $completionLog -Force

    & bitsadmin.exe /setnotifycmdline $userDownloadJob $completionLog ""
    Start-Sleep -Milliseconds 500

    # Resume transfer
    & bitsadmin.exe /resume $userDownloadJob
    Start-Sleep -Milliseconds 500

    # Wait for processing
    Start-Sleep -Seconds 2

    # Complete the job
    & bitsadmin.exe /complete $userDownloadJob
    Start-Sleep -Milliseconds 500

    Write-Host "[INFO] User content download via BITS completed."
}
catch {
    Write-Host "[ERROR] Content sync failed: $_"
}
finally {
    # Cleanup
    & bitsadmin.exe /remove $userDownloadJob /force 2>$null

    if (Test-Path -Path $completionLog) { Remove-Item -Path $completionLog -Force }
    if (Test-Path -Path $downloadDest) { Remove-Item -Path $downloadDest -Force }
    if (Test-Path -Path 'C:\Windows\Temp\sync-events.log') { Remove-Item -Path 'C:\Windows\Temp\sync-events.log' -Force }
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
