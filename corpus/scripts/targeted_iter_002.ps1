# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   2  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_4da457f9-03de-41ff-824c-ef0cd1761275  (1 rule(s)) ---------------------
# Intent:    Detects BITS job lifecycle management operations (create, add file, resume, set 
# Rules:     4da457f9-03de-41ff-824c-ef0cd1761275
# Archetype: IT admin workflow

# IT administrator using BITS for reliable background transfer of compliance data
# This simulates a real scenario where a sysadmin script orchestrates critical file downloads

$jobName = 'ComplianceReportDownload_' + (Get-Date -Format 'yyyyMMdd')
$tempDir = [System.IO.Path]::GetTempPath()
$localPath = Join-Path $tempDir 'compliance_report.zip'
$notifyScript = Join-Path $tempDir 'notify_completion.ps1'

try {
  # Create a simple notification script (legitimate cleanup mechanism)
  @'
Write-Host 'Compliance report download completed'
'@ | Out-File -FilePath $notifyScript -Encoding ASCII -Force

  # Create BITS job for reliable background download
  # This mirrors real admin scripts that use BITS for critical file transfers
  bitsadmin.exe /create /name $jobName

  # Add the file to transfer
  # Using a legitimate internal destination (localhost simulates corporate HTTP server)
  bitsadmin.exe /addfile $jobName 'http://127.0.0.1/compliance_report.zip' $localPath

  # Set retry timing for network reliability
  bitsadmin.exe /setminretrydelay $jobName 60

  # Configure completion notification
  bitsadmin.exe /setnotifycmdline $jobName $notifyScript ''

  # Resume the job to begin transfer
  bitsadmin.exe /resume $jobName

  # Allow job to attempt for a brief period
  Start-Sleep -Seconds 3

  # Complete the job (cleanup)
  bitsadmin.exe /complete $jobName

  Write-Host 'BITS job lifecycle completed'
}
catch {
  Write-Host "Error during BITS operation: $_"
}
finally {
  # Cleanup: remove temp notification script
  if (Test-Path $notifyScript) {
    Remove-Item -Path $notifyScript -Force -ErrorAction SilentlyContinue
  }

  # Cleanup: remove temp file if it was created
  if (Test-Path $localPath) {
    Remove-Item -Path $localPath -Force -ErrorAction SilentlyContinue
  }
}

# -- Cluster: singleton_4da457f9-03de-41ff-824c-ef0cd1761275  (1 rule(s)) ---------------------
# Intent:    Detects BITS job lifecycle management operations (create, add file, resume, set 
# Rules:     4da457f9-03de-41ff-824c-ef0cd1761275
# Archetype: Software installer/updater workflow

# Enterprise deployment agent using BITS for patch distribution
# Simulates realistic enterprise software update orchestration

$deploymentId = 'Deploy_' + (Get-Random -Minimum 10000 -Maximum 99999)
$tempDir = [System.IO.Path]::GetTempPath()
$patchFile = Join-Path $tempDir "patch_KB5034441.exe"
$logFile = Join-Path $tempDir "deployment_$deploymentId.log"

try {
  # Initialize deployment log
  "Deployment started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File -FilePath $logFile -Encoding ASCII

  # Create BITS job for patch distribution
  bitsadmin.exe /create /name $deploymentId

  # Add patch file to download queue
  # In real scenarios, this would be from an internal patch server or CDN
  bitsadmin.exe /addfile $deploymentId 'http://127.0.0.1/patches/KB5034441.exe' $patchFile

  # Configure retry behavior for unstable networks
  bitsadmin.exe /setminretrydelay $deploymentId 30

  # Set completion notification to log deployment status
  bitsadmin.exe /setnotifycmdline $deploymentId "cmd /c echo Patch downloaded >> $logFile"

  # Resume transfer
  bitsadmin.exe /resume $deploymentId

  # Wait for initial transfer attempt
  Start-Sleep -Seconds 2

  # Complete job
  bitsadmin.exe /complete $deploymentId

  # Log completion
  "Deployment completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" | Out-File -FilePath $logFile -Encoding ASCII -Append
}
catch {
  "Deployment error: $_" | Out-File -FilePath $logFile -Encoding ASCII -Append
}
finally {
  # Cleanup temporary files
  if (Test-Path $patchFile) {
    Remove-Item -Path $patchFile -Force -ErrorAction SilentlyContinue
  }
  if (Test-Path $logFile) {
    Remove-Item -Path $logFile -Force -ErrorAction SilentlyContinue
  }
}

# -- Cluster: singleton_4da457f9-03de-41ff-824c-ef0cd1761275  (1 rule(s)) ---------------------
# Intent:    Detects BITS job lifecycle management operations (create, add file, resume, set 
# Rules:     4da457f9-03de-41ff-824c-ef0cd1761275
# Archetype: Document/file operation workflow

# User/service retrieving large shared document using BITS background transfer
# Realistic scenario: accessing archived company records or training materials

$documentJob = 'RetrieveArchive_' + (Get-Date -Format 'yyyyMMdd_HHmmss')
$downloadDir = Join-Path $env:TEMP 'documents'
$archiveFile = Join-Path $downloadDir 'Q3_Training_Materials.zip'
$statusLog = Join-Path $downloadDir 'transfer_log.txt'

try {
  # Ensure download directory exists
  if (-not (Test-Path $downloadDir)) {
    New-Item -ItemType Directory -Path $downloadDir -Force | Out-Null
  }

  # Create BITS job for document retrieval
  bitsadmin.exe /create /name $documentJob

  # Add document archive to job
  # Simulates downloading from internal document repository
  bitsadmin.exe /addfile $documentJob 'http://127.0.0.1/docs/Q3_Training_Materials.zip' $archiveFile

  # Configure reasonable retry behavior
  bitsadmin.exe /setminretrydelay $documentJob 45

  # Set notification to update transfer log on completion
  $notifyCmd = "cmd /c echo Transfer completed at %date% %time% >> $statusLog"
  bitsadmin.exe /setnotifycmdline $documentJob $notifyCmd ''

  # Start the transfer
  bitsadmin.exe /resume $documentJob

  # Allow transfer attempt
  Start-Sleep -Seconds 3

  # Finalize the job
  bitsadmin.exe /complete $documentJob

  Write-Host 'Document transfer workflow completed'
}
catch {
  Write-Host "Error: $_"
}
finally {
  # Cleanup: remove temporary files and logs
  if (Test-Path $downloadDir) {
    Remove-Item -Path $downloadDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# SKIPPED cluster singleton_efb1170e-2737-4c5d-9c86-8d0dd3c8bd78: LLM response truncated at max_tokens (4096)

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
