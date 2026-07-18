# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_c3fdf77e-7eeb-4f6b-aab3-df73cc5db9fa  (1 rule(s)) ---------------------
# Intent:    Detecting the use of BITS jobs configured with custom notify commands to achieve
# Rules:     c3fdf77e-7eeb-4f6b-aab3-df73cc5db9fa
# Archetype: IT admin workflow

$LogPath = Join-Path $env:TEMP 'bits_update_ops.log'

# Create a BITS transfer for a legitimate Windows update download
# The notify command will trigger a compliance verification script
$ComplianceScript = Join-Path $env:TEMP 'verify_update_compliance.cmd'

# Create the benign compliance verification script
@'
echo Update installation at %date% %time% >> C:\Windows\Logs\updates.log
echo Compliance check completed successfully
'@ | Out-File -FilePath $ComplianceScript -Encoding ASCII -Force

# Create a BITS job with notification command
# This is legitimate for update orchestration workflows
$JobName = 'UpdateComplianceTransfer'
$DisplayName = 'Windows Update Compliance Download'

try {
    # Remove any existing job with this name
    Get-BitsTransfer -Name $JobName -ErrorAction SilentlyContinue | Remove-BitsTransfer -Force

    # Create the BITS job
    $BitsJob = New-BitsTransfer `
        -Name $JobName `
        -DisplayName $DisplayName `
        -TransferType Download `
        -Priority Foreground

    # Add file to transfer (using a real Windows path)
    $BitsJob | Add-BitsFile `
        -Source 'https://download.windowsupdate.com/d/msdownload/update/software/upd/2024/01/windows10.0-kb5034441-x64_e8d59e5e9c2c1de3c7f8e3b3d6a1e2f4.msu' `
        -Destination (Join-Path $env:TEMP 'kb5034441.msu')

    # Configure the notify command to execute after job completion
    # Using BITS setnotifycmdline parameter for legitimate compliance callback
    $CommandToNotify = "cmd /c `"$ComplianceScript`""

    # Use bitsadmin.exe to set the notify command (alternative approach)
    $JobId = $BitsJob.JobId
    cmd /c "bitsadmin /create /name UpdateComplianceTransfer /type Download"
    cmd /c "bitsadmin /addfile UpdateComplianceTransfer https://download.windowsupdate.com/d/msdownload/update/software/upd/2024/01/windows10.0-kb5034441-x64_e8d59e5e9c2c1de3c7f8e3b3d6a1e2f4.msu $env:TEMP\kb5034441.msu"
    cmd /c "bitsadmin /setnotifycmdline UpdateComplianceTransfer $ComplianceScript null"
    cmd /c "bitsadmin /cancel UpdateComplianceTransfer"

    Add-Content -Path $LogPath -Value "$(Get-Date): BITS job created with compliance notification callback"
}
catch {
    Add-Content -Path $LogPath -Value "$(Get-Date): Error creating BITS job - $_"
}
finally {
    # Cleanup temporary files and BITS jobs
    Get-BitsTransfer -Name $JobName -ErrorAction SilentlyContinue | Remove-BitsTransfer -Force
    Remove-Item -Path $ComplianceScript -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $LogPath -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_c3fdf77e-7eeb-4f6b-aab3-df73cc5db9fa  (1 rule(s)) ---------------------
# Intent:    Detecting the use of BITS jobs configured with custom notify commands to achieve
# Rules:     c3fdf77e-7eeb-4f6b-aab3-df73cc5db9fa
# Archetype: Software installer/updater workflow

$DeploymentLog = Join-Path $env:TEMP 'deployment_operations.log'
$DeploymentStaging = Join-Path $env:TEMP 'deployment_staging'

# Create staging directory for deployment operations
if (-not (Test-Path $DeploymentStaging)) {
    New-Item -ItemType Directory -Path $DeploymentStaging -Force | Out-Null
}

# Define deployment configuration callback script
$ConfigScript = Join-Path $DeploymentStaging 'apply_config.cmd'
@'
echo Configuration applied at %date% %time% >> %APPDATA%\deployment.log
echo Package validation completed
'@ | Out-File -FilePath $ConfigScript -Encoding ASCII -Force

try {
    # Simulate enterprise software deployment with BITS
    # Create multiple BITS jobs for different application components

    # Job 1: Application runtime
    cmd /c "bitsadmin /create /name AppRuntimeDeployment /type Download"
    cmd /c "bitsadmin /addfile AppRuntimeDeployment https://software.company.com/releases/runtime-2024.msi $DeploymentStaging\runtime.msi"
    cmd /c "bitsadmin /setnotifycmdline AppRuntimeDeployment $ConfigScript null"
    cmd /c "bitsadmin /cancel AppRuntimeDeployment"

    # Job 2: Security updates
    cmd /c "bitsadmin /create /name SecurityUpdateDeployment /type Download"
    cmd /c "bitsadmin /addfile SecurityUpdateDeployment https://security.updates.company.com/patches/security-2024-01.exe $DeploymentStaging\security-update.exe"
    cmd /c "bitsadmin /setnotifycmdline SecurityUpdateDeployment $ConfigScript null"
    cmd /c "bitsadmin /cancel SecurityUpdateDeployment"

    Add-Content -Path $DeploymentLog -Value "$(Get-Date): Software deployment BITS jobs configured"
}
catch {
    Add-Content -Path $DeploymentLog -Value "$(Get-Date): Deployment error - $_"
}
finally {
    # Cleanup all deployment artifacts and BITS jobs
    Get-BitsTransfer -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.DisplayName -like '*Deployment*' -or $_.Name -like '*Deployment*') {
            Remove-BitsTransfer -BitsJob $_ -Force -ErrorAction SilentlyContinue
        }
    }

    # Remove staging directory and logs
    Remove-Item -Path $DeploymentStaging -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $DeploymentLog -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_c3fdf77e-7eeb-4f6b-aab3-df73cc5db9fa  (1 rule(s)) ---------------------
# Intent:    Detecting the use of BITS jobs configured with custom notify commands to achieve
# Rules:     c3fdf77e-7eeb-4f6b-aab3-df73cc5db9fa
# Archetype: User-driven workflow

$UserDeploymentLog = Join-Path $env:TEMP 'file_sync.log'
$DownloadStaging = Join-Path $env:TEMP 'downloads_sync'

# Create staging directory
if (-not (Test-Path $DownloadStaging)) {
    New-Item -ItemType Directory -Path $DownloadStaging -Force | Out-Null
}

# Create notification script that will be invoked on BITS job completion
$NotificationScript = Join-Path $DownloadStaging 'notify_completion.cmd'
@'
echo Download completed at %date% %time% >> %USERPROFILE%\Downloads\sync_log.txt
echo File is ready for processing
'@ | Out-File -FilePath $NotificationScript -Encoding ASCII -Force

try {
    # User creates a BITS transfer for a legitimate work-related file download
    # Configure notification to trigger a simple status logging script

    cmd /c "bitsadmin /create /name LargeFileTransfer /type Download"
    cmd /c "bitsadmin /addfile LargeFileTransfer https://media.company.com/sharepoint/Q3_Reports.zip $DownloadStaging\Q3_Reports.zip"
    cmd /c "bitsadmin /setnotifycmdline LargeFileTransfer $NotificationScript null"
    cmd /c "bitsadmin /cancel LargeFileTransfer"

    Add-Content -Path $UserDeploymentLog -Value "$(Get-Date): User-initiated file transfer configured with completion notification"
}
catch {
    Add-Content -Path $UserDeploymentLog -Value "$(Get-Date): File transfer configuration error - $_"
}
finally {
    # Cleanup all BITS jobs and temporary files
    Get-BitsTransfer -ErrorAction SilentlyContinue | ForEach-Object {
        if ($_.Name -like '*FileTransfer*' -or $_.DisplayName -like '*FileTransfer*') {
            Remove-BitsTransfer -BitsJob $_ -Force -ErrorAction SilentlyContinue
        }
    }

    # Remove temporary staging and logs
    Remove-Item -Path $DownloadStaging -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $UserDeploymentLog -Force -ErrorAction SilentlyContinue
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
