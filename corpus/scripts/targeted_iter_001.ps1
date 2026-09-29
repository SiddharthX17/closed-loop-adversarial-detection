# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 2
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_241ac331-aa8d-40de-9945-e9164c7a23e2  (1 rule(s)) ---------------------
# Intent:    Detect when a service (services.exe or svchost.exe) spawns a child process that 
# Rules:     241ac331-aa8d-40de-9945-e9164c7a23e2
# Archetype: IT admin workflow

# Create a mock remote server backup share path simulation
# This represents a legitimate backup agent writing via administrative shares

# Start a dummy service process context simulation
# In real scenarios, Windows Backup Service (svchost.exe) spawns robocopy
# to enumerate and copy files from remote admin shares.

$backupRoot = $env:TEMP + "\backup_staging"
if (-not (Test-Path $backupRoot)) {
    New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
}

# Simulate a backup job that would reference admin shares
# The command line legitimately contains \\server\admin$\ paths
$serverName = "dummy-backup-srv"
$remoteAdminShare = "\\\\${serverName}\\admin$\\"
$remoteC = "\\\\${serverName}\\c$\\"
$remoteIPC = "\\\\${serverName}\\ipc$\\"

# Create backup manifest documenting remote paths that would be accessed
$manifestPath = Join-Path $backupRoot "backup_manifest.txt"
@"
Backup Manifest - Administrative Shares Access Log
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Backup Job ID: BackupSet-20240115-Full

Configured remote backup sources:
  Source 1: $remoteAdminShare
  Source 2: $remoteC
  Source 3: $remoteIPC

These paths are accessed by the backup service during incremental backup operations.
"@ | Out-File -FilePath $manifestPath -Encoding ASCII

# Simulate Windows Backup invoking a copy operation to these shares
# The robocopy invocation would appear with the admin share paths in CommandLine
# This is realistic backup software behavior
$robocopyCmd = "robocopy.exe \"$remoteAdminShare\" \"$backupRoot\\admin_share\" /E /Z /NFL /NDL /NJS /NJH /NP /TEE"
Write-Host "[Backup Service] Executing backup job with remote paths..."
Write-Host "Command: $robocopyCmd"

# In actual operation, svchost.exe would spawn robocopy
# We simulate the logging and manifest creation that occurs
$jobLog = Join-Path $backupRoot "backup_job.log"
@"
[$(Get-Date -Format 'HH:mm:ss')] Backup Service initiated
[$(Get-Date -Format 'HH:mm:ss')] Connecting to $serverName
[$(Get-Date -Format 'HH:mm:ss')] Accessing $remoteAdminShare
[$(Get-Date -Format 'HH:mm:ss')] Accessing $remoteC
[$(Get-Date -Format 'HH:mm:ss')] Backup Job Started
[$(Get-Date -Format 'HH:mm:ss')] Enumerated 512 files from remote shares
[$(Get-Date -Format 'HH:mm:ss')] Backup Job Completed
"@ | Out-File -FilePath $jobLog -Encoding ASCII

# Verify files were created
if (Test-Path $manifestPath) {
    Write-Host "[OK] Backup manifest created"
}

# Clean up
Remove-Item -Path $backupRoot -Recurse -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_241ac331-aa8d-40de-9945-e9164c7a23e2  (1 rule(s)) ---------------------
# Intent:    Detect when a service (services.exe or svchost.exe) spawns a child process that 
# Rules:     241ac331-aa8d-40de-9945-e9164c7a23e2
# Archetype: Software installer/updater workflow

# Simulate enterprise software deployment workflow that uses admin shares
# This represents SCCM or similar deployment agent writing to remote admin shares

$deploymentRoot = $env:TEMP + "\deployment_work"
if (-not (Test-Path $deploymentRoot)) {
    New-Item -ItemType Directory -Path $deploymentRoot -Force | Out-Null
}

# Create deployment manifest that references target admin shares
$targetServer = "deploy-target-01"
$deployTargets = @(
    "\\\\${targetServer}\\admin$\\",
    "\\\\${targetServer}\\c$\\",
    "\\\\${targetServer}\\ipc$\\"
)

# Write deployment configuration
$deployConfig = Join-Path $deploymentRoot "deploy_config.xml"
@"
<?xml version=\"1.0\" encoding=\"utf-8\"?>
<DeploymentJob>
  <JobID>DEPLOY-2024-01-15-A</JobID>
  <ServiceAccount>NT AUTHORITY\\SYSTEM</ServiceAccount>
  <Targets>
    <Target path=\"$($deployTargets[0])\" type=\"system\" />
    <Target path=\"$($deployTargets[1])\" type=\"filesystem\" />
    <Target path=\"$($deployTargets[2])\" type=\"ipc\" />
  </Targets>
  <Payload>
    <Package>SystemUpdate-v1.2.3.exe</Package>
    <Hash>a1b2c3d4e5f6g7h8i9j0</Hash>
    <Size>52428800</Size>
  </Payload>
</DeploymentJob>
"@ | Out-File -FilePath $deployConfig -Encoding ASCII

# Simulate the installer writing status to admin shares
$statusLog = Join-Path $deploymentRoot "deployment_log.txt"
@"
Deployment Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Deployment Service PID: 1024
Parent Process: services.exe

Connecting to deployment targets:
  Target 1: $($deployTargets[0]) - Status: CONNECTING
  Target 2: $($deployTargets[1]) - Status: CONNECTING
  Target 3: $($deployTargets[2]) - Status: CONNECTING

Transfer Status:
  Payload stage 1 -> $($deployTargets[0])setup.exe - 25 MB copied
  Payload stage 2 -> $($deployTargets[1])setup.exe - 25 MB copied
  Configuration -> $($deployTargets[2])config.ini - 1.5 KB copied

Deployment Status: COMPLETED
Total Time: 2m 34s
"@ | Out-File -FilePath $statusLog -Encoding ASCII

# Create package manifest
$packageManifest = Join-Path $deploymentRoot "package_manifest.txt"
Get-Content $statusLog | Out-File -FilePath $packageManifest -Encoding ASCII

Write-Host "[Deployment Service] Package distribution to remote admin shares completed"

# Clean up
Remove-Item -Path $deploymentRoot -Recurse -Force -ErrorAction SilentlyContinue


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
