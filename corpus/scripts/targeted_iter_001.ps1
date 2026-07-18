# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   2  |  Feasible: 2  |  Variants: 5
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_3661d88b-3700-4f93-b4fe-038f467c1833  (1 rule(s)) ---------------------
# Intent:    Detect masqueraded system processes (svchost, lsass, csrss, etc.) being executed
# Rules:     3661d88b-3700-4f93-b4fe-038f467c1833
# Archetype: IT admin workflow

$assessmentDir = Join-Path $env:TEMP 'SecurityAssessment_2024'
if (Test-Path $assessmentDir) { Remove-Item $assessmentDir -Recurse -Force }
New-Item -ItemType Directory -Path $assessmentDir | Out-Null

try {
    # Copy system executables to non-standard location for analysis
    $sourceExes = @('svchost.exe', 'lsass.exe', 'csrss.exe', 'taskhostw.exe')
    foreach ($exe in $sourceExes) {
        $sourcePath = Join-Path 'C:\Windows\System32' $exe
        if (Test-Path $sourcePath) {
            Copy-Item -Path $sourcePath -Destination (Join-Path $assessmentDir $exe) -Force
        }
    }

    # Execute copied system processes from non-standard directory
    # This exercises the detection logic for process masquerading
    $procPath = Join-Path $assessmentDir 'svchost.exe'
    if (Test-Path $procPath) {
        & $procPath -k LocalSystemNetworkRestricted 2>&1 | Out-Null
    }

    $procPath = Join-Path $assessmentDir 'taskhostw.exe'
    if (Test-Path $procPath) {
        & $procPath 2>&1 | Out-Null
    }

    # Verify detection via command-line activity logs
    Start-Process -FilePath 'powershell.exe' -ArgumentList "-NoProfile -Command `\"& (Join-Path '$assessmentDir' 'svchost.exe') -k LocalServiceNetworkRestricted`\"" -NoNewWindow -PassThru | Wait-Process
}
finally {
    # Clean up temporary assessment artifacts
    if (Test-Path $assessmentDir) {
        Remove-Item $assessmentDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_3661d88b-3700-4f93-b4fe-038f467c1833  (1 rule(s)) ---------------------
# Intent:    Detect masqueraded system processes (svchost, lsass, csrss, etc.) being executed
# Rules:     3661d88b-3700-4f93-b4fe-038f467c1833
# Archetype: Software installer/updater workflow

$stagingDir = Join-Path $env:TEMP 'AppUpdate_Staging'
if (Test-Path $stagingDir) { Remove-Item $stagingDir -Recurse -Force }
New-Item -ItemType Directory -Path $stagingDir | Out-Null

try {
    # Simulate installer creating a staging directory with system process names
    @('winlogon.exe', 'services.exe', 'smss.exe', 'wininit.exe') | ForEach-Object {
        $srcPath = Join-Path 'C:\Windows\System32' $_
        if (Test-Path $srcPath) {
            Copy-Item -Path $srcPath -Destination (Join-Path $stagingDir $_) -Force
        }
    }

    # Application setup may invoke these binaries from staging area
    $setupExe = Join-Path $stagingDir 'wininit.exe'
    if (Test-Path $setupExe) {
        Start-Process -FilePath $setupExe -NoNewWindow -PassThru -Wait
    }

    # Launch another staged executable via indirect command invocation
    $servicesExe = Join-Path $stagingDir 'services.exe'
    if (Test-Path $servicesExe) {
        cmd /c $servicesExe 2>&1 | Out-Null
    }

    # Verify installation by running services from staging directory
    $smsPath = Join-Path $stagingDir 'smss.exe'
    if (Test-Path $smsPath) {
        Start-Process -FilePath 'powershell.exe' -ArgumentList "-NoProfile -Command `\"& '$smsPath'`\"" -NoNewWindow -PassThru -Wait
    }
}
finally {
    # Remove temporary staging directory
    if (Test-Path $stagingDir) {
        Remove-Item $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_3661d88b-3700-4f93-b4fe-038f467c1833  (1 rule(s)) ---------------------
# Intent:    Detect masqueraded system processes (svchost, lsass, csrss, etc.) being executed
# Rules:     3661d88b-3700-4f93-b4fe-038f467c1833
# Archetype: Document/file operation workflow

$analysisDir = Join-Path $env:TEMP 'SystemDiagnostics'
if (Test-Path $analysisDir) { Remove-Item $analysisDir -Recurse -Force }
New-Item -ItemType Directory -Path $analysisDir | Out-Null

try {
    # Collect system process binaries for diagnostic analysis
    $systemProcs = @('lsass.exe', 'csrss.exe', 'taskhostw.exe', 'svchost.exe')
    $procInfo = @()

    foreach ($procName in $systemProcs) {
        $procPath = Join-Path 'C:\Windows\System32' $procName
        if (Test-Path $procPath) {
            $copyDest = Join-Path $analysisDir $procName
            Copy-Item -Path $procPath -Destination $copyDest -Force

            # Log file metadata for compliance reporting
            $fileInfo = Get-Item -Path $copyDest
            $procInfo += [PSCustomObject]@{
                Name = $procName
                Path = $copyDest
                Size = $fileInfo.Length
                Modified = $fileInfo.LastWriteTime
            }
        }
    }

    # Execute collected binaries to verify integrity and functionality
    foreach ($proc in $procInfo) {
        if (Test-Path $proc.Path) {
            Start-Process -FilePath $proc.Path -NoNewWindow -PassThru -Wait -ErrorAction SilentlyContinue
        }
    }

    # Generate diagnostic report with execution data
    $reportPath = Join-Path $env:TEMP 'diagnostics_report.txt'
    $procInfo | ForEach-Object {
        $cmdLine = "& '{0}'" -f $_.Path
        "Process: {0} | Path: {1} | Size: {2}" -f $_.Name, $_.Path, $_.Size | Out-File -FilePath $reportPath -Append
    }

    # Execute from analysis directory to trigger detection
    $csrssPath = Join-Path $analysisDir 'csrss.exe'
    if (Test-Path $csrssPath) {
        Start-Process -FilePath 'powershell.exe' -ArgumentList "-NoProfile -Command `\"& '$csrssPath'`\"" -NoNewWindow -PassThru -Wait
    }
}
finally {
    # Remove analysis directory and diagnostic artifacts
    if (Test-Path $analysisDir) {
        Remove-Item $analysisDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $reportPath) {
        Remove-Item $reportPath -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_3d57d068-bd8d-42af-b383-bc205f34daba  (1 rule(s)) ---------------------
# Intent:    Detect BITS job notification command execution that invokes shell proxies (cmd, 
# Rules:     3d57d068-bd8d-42af-b383-bc205f34daba
# Archetype: IT admin workflow

$BitsJobName = "SoftwareDistribution_Notification"
$NotifyScript = "C:\Windows\System32\cmd.exe /c eventcreate /T INFORMATION /ID 1000 /L Application /SO AdminAudit /D `"BITS job $BitsJobName completed successfully`""

try {
    $ExistingJob = Get-BitsTransfer -Name $BitsJobName -ErrorAction SilentlyContinue
    if ($ExistingJob) {
        Remove-BitsTransfer -BitsJob $ExistingJob -Confirm:$false
    }

    $TransferJob = Add-BitsFile `
        -Source "https://download.microsoft.com/download/sample.exe" `
        -Destination "$env:TEMP\sample.exe" `
        -TransferType Download `
        -Name $BitsJobName `
        -ErrorAction SilentlyContinue

    if ($TransferJob) {
        bitsadmin.exe /setnotifycmdline $BitsJobName $NotifyScript ""
    }
} catch {
    Write-Verbose "BITS configuration for operational audit completed"
}

Get-BitsTransfer -Name $BitsJobName -ErrorAction SilentlyContinue | Remove-BitsTransfer -Confirm:$false

# -- Cluster: singleton_3d57d068-bd8d-42af-b383-bc205f34daba  (1 rule(s)) ---------------------
# Intent:    Detect BITS job notification command execution that invokes shell proxies (cmd, 
# Rules:     3d57d068-bd8d-42af-b383-bc205f34daba
# Archetype: Software installer/updater workflow

$BitsJobName = "PatchManagement_Deployment"
$DeploymentId = [System.Guid]::NewGuid().ToString()
$LogPath = "$env:TEMP\deployment_log_$DeploymentId.txt"

$NotifyCommand = "powershell.exe -NoProfile -Command Add-Content -Path `"$LogPath`" -Value `"Deployment completed at $(Get-Date)\""

try {
    $ExistingJob = Get-BitsTransfer -Name $BitsJobName -ErrorAction SilentlyContinue
    if ($ExistingJob) {
        Remove-BitsTransfer -BitsJob $ExistingJob -Confirm:$false
    }

    $BitsJob = Add-BitsFile `
        -Source "https://catalog.update.microsoft.com/v7/site/Updates/Download.aspx" `
        -Destination "$env:TEMP\update_package.cab" `
        -TransferType Download `
        -Name $BitsJobName `
        -ErrorAction SilentlyContinue

    if ($BitsJob) {
        bitsadmin.exe /setnotifycmdline $BitsJobName $NotifyCommand ""
    }
} catch {
    Write-Verbose "Automated patch deployment notification handler configured"
}

Start-Sleep -Milliseconds 500
Get-BitsTransfer -Name $BitsJobName -ErrorAction SilentlyContinue | Remove-BitsTransfer -Confirm:$false

if (Test-Path $LogPath) {
    Remove-Item -Path $LogPath -Force
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
