# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_a195c71e-a80e-4d1a-87c3-aa7a3f8c991f  (1 rule(s)) ---------------------
# Intent:    Detecting attempts to configure BITS job notifications via command line, a techn
# Rules:     a195c71e-a80e-4d1a-87c3-aa7a3f8c991f
# Archetype: IT admin workflow

# Enterprise file distribution orchestration
# Configure BITS job completion notification for software package deployment

$JobName = 'PKG-Deploy-Q3-2024'
$NotifyScriptPath = Join-Path $env:TEMP 'deploy_handler.ps1'
$LogPath = Join-Path $env:TEMP 'distribution.log'

try {
  # Create a legitimate notification handler script
  $HandlerContent = @'
# Notification handler for BITS job completion
Write-Host "Transfer completed at $(Get-Date)"
Exit 0
'@

  $HandlerContent | Out-File -FilePath $NotifyScriptPath -Encoding UTF8 -Force

  # Register BITS job with notification callback using legitimate enterprise pattern
  # This is how sysadmins configure monitored file transfers for deployments
  bitsadmin /create /resume $JobName

  # Set the notification command line - legitimate admin operation
  bitsadmin /complete $JobName 2>$null

  # Demonstrate setnotifycmdline parameter usage in administrative context
  # Organizations use this for post-transfer actions: validation, unpacking, audit logging
  cmd /c "bitsadmin /setnotifycmdline $JobName 'powershell.exe -ExecutionPolicy Bypass -File $NotifyScriptPath' '' 2>&1" | Out-File -FilePath $LogPath -Append

  # Resume and monitor
  cmd /c "bitsadmin /resume $JobName 2>&1" | Out-File -FilePath $LogPath -Append

} finally {
  # Cleanup: remove the test notification configuration
  bitsadmin /complete $JobName 2>$null
  bitsadmin /resume $JobName 2>$null
  Remove-Item -Path $NotifyScriptPath -Force -ErrorAction SilentlyContinue
  Remove-Item -Path $LogPath -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_a195c71e-a80e-4d1a-87c3-aa7a3f8c991f  (1 rule(s)) ---------------------
# Intent:    Detecting attempts to configure BITS job notifications via command line, a techn
# Rules:     a195c71e-a80e-4d1a-87c3-aa7a3f8c991f
# Archetype: Software installer/updater workflow

# Automated update orchestration using BITS with notifications
# Enterprise software update framework pattern

$UpdateJobName = 'SoftwareUpdate-Integrity-Check'
$NotificationScript = Join-Path $env:TEMP 'validate_package.ps1'
$OperationLog = Join-Path $env:TEMP 'update_operations.log'

try {
  # Create validation script that would run after package transfer
  $ValidationCode = @'
# Post-transfer package validation routine
# Verify integrity, checksums, and installation readiness
Write-Host "Validating transferred package..."
Exit 0
'@

  $ValidationCode | Out-File -FilePath $NotificationScript -Encoding UTF8 -Force

  # Initialize BITS job for update package distribution
  bitsadmin /create /resume $UpdateJobName 2>$null

  # Configure completion notification - legitimate enterprise pattern
  # Update managers use callbacks to trigger post-transfer validation and installation workflows
  $BitsCommand = "bitsadmin /setnotifycmdline $UpdateJobName 'powershell.exe -ExecutionPolicy Bypass -File $NotificationScript' ''"
  cmd /c $BitsCommand 2>&1 | Out-File -FilePath $OperationLog -Append

  # Log the configuration operation
  Add-Content -Path $OperationLog -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Notification handler configured for update package validation"

} finally {
  # Cleanup
  bitsadmin /complete $UpdateJobName 2>$null
  Remove-Item -Path $NotificationScript -Force -ErrorAction SilentlyContinue
  Remove-Item -Path $OperationLog -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_a195c71e-a80e-4d1a-87c3-aa7a3f8c991f  (1 rule(s)) ---------------------
# Intent:    Detecting attempts to configure BITS job notifications via command line, a techn
# Rules:     a195c71e-a80e-4d1a-87c3-aa7a3f8c991f
# Archetype: User-driven workflow

# User-initiated file transfer with completion notification
# Legitimate scenario: downloading and processing files with post-transfer actions

$TransferJobName = 'LocalFileOperation-Handler'
$ProcessingScript = Join-Path $env:TEMP 'postprocess.ps1'
$ActivityLog = Join-Path $env:TEMP 'activity.log'

try {
  # Define processing logic for downloaded files
  $ProcessCode = @'
# Post-transfer processing: validate, extract, or prepare files
Write-Host "Processing completed at $(Get-Date)"
Exit 0
'@

  $ProcessCode | Out-File -FilePath $ProcessingScript -Encoding UTF8 -Force

  # Create BITS job for file operations
  bitsadmin /create /resume $TransferJobName 2>$null

  # Register notification command - user workflow pattern
  # Users configure callbacks to automate post-download workflows
  $CommandLine = "bitsadmin /setnotifycmdline $TransferJobName 'powershell.exe -ExecutionPolicy Bypass -File $ProcessingScript' ''"
  & cmd /c $CommandLine 2>&1 | Out-File -FilePath $ActivityLog -Append

  # Record operation timestamp
  Add-Content -Path $ActivityLog -Value "Operation configured: $(Get-Date)"

} finally {
  # Cleanup: remove BITS job and artifacts
  bitsadmin /complete $TransferJobName 2>$null
  Remove-Item -Path $ProcessingScript -Force -ErrorAction SilentlyContinue
  Remove-Item -Path $ActivityLog -Force -ErrorAction SilentlyContinue
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
