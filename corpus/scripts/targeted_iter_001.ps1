# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_b9f1012f-a634-486c-a280-6c4b8dfdf2c4  (1 rule(s)) ---------------------
# Intent:    Detect malicious use of BITS (Background Intelligent Transfer Service) jobs for 
# Rules:     b9f1012f-a634-486c-a280-6c4b8dfdf2c4
# Archetype: IT admin workflow

$tempDir = Join-Path $env:TEMP "patch_staging"
if (-not (Test-Path $tempDir)) {
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
}
$jobName = "WindowsUpdateJob_$(Get-Random)"
try {
    # Create BITS transfer job for downloading a patch manifest from Microsoft
    & bitsadmin.exe /create /name $jobName /priority high

    # Add file transfer to simulate downloading update metadata
    & bitsadmin.exe /transfer $jobName /download /priority high "https://download.microsoft.com/download/Windows10SDK/updates/manifest.xml" (Join-Path $tempDir "manifest.xml")

    # Simulate waiting for transfer to complete
    Start-Sleep -Seconds 2

    # Clean up the job
    & bitsadmin.exe /complete $jobName
    & bitsadmin.exe /delete $jobName
} catch {
    # Ensure cleanup even if error occurs
    & bitsadmin.exe /delete $jobName -ErrorAction SilentlyContinue
}

# Remove staging directory
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_b9f1012f-a634-486c-a280-6c4b8dfdf2c4  (1 rule(s)) ---------------------
# Intent:    Detect malicious use of BITS (Background Intelligent Transfer Service) jobs for 
# Rules:     b9f1012f-a634-486c-a280-6c4b8dfdf2c4
# Archetype: Software installer/updater workflow

$downloadDir = Join-Path $env:TEMP "app_install_files"
if (-not (Test-Path $downloadDir)) {
    New-Item -ItemType Directory -Path $downloadDir -Force | Out-Null
}
$uniqueJobId = "AppComponentFetch_$(Get-Random)"
try {
    # Create BITS job for installer component download
    & bitsadmin.exe /create /name $uniqueJobId /priority high

    # Add files that an installer would legitimately download
    & bitsadmin.exe /addfile $uniqueJobId "https://cdn.example.com/application/component_v2.0.exe" (Join-Path $downloadDir "component.exe")
    & bitsadmin.exe /addfile $uniqueJobId "https://cdn.example.com/application/dependencies.zip" (Join-Path $downloadDir "dependencies.zip")

    # Transfer all queued files
    & bitsadmin.exe /transfer $uniqueJobId /download /priority high

    Start-Sleep -Seconds 1

    # Mark job as complete
    & bitsadmin.exe /complete $uniqueJobId
    & bitsadmin.exe /delete $uniqueJobId
} catch {
    & bitsadmin.exe /delete $uniqueJobId -ErrorAction SilentlyContinue
}

# Clean up downloaded files
Remove-Item -Path $downloadDir -Recurse -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_b9f1012f-a634-486c-a280-6c4b8dfdf2c4  (1 rule(s)) ---------------------
# Intent:    Detect malicious use of BITS (Background Intelligent Transfer Service) jobs for 
# Rules:     b9f1012f-a634-486c-a280-6c4b8dfdf2c4
# Archetype: User-driven workflow

$dataDir = Join-Path $env:TEMP "analytics_data"
if (-not (Test-Path $dataDir)) {
    New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
}
$xferJobName = "DataAcquisition_$(Get-Random)"
try {
    # Create BITS job for data file transfer
    & bitsadmin.exe /create /name $xferJobName /priority normal

    # Add data files from a public cloud storage endpoint
    & bitsadmin.exe /addfile $xferJobName "https://storage.example.com/datasets/q3_analytics.csv" (Join-Path $dataDir "q3_analytics.csv")
    & bitsadmin.exe /addfile $xferJobName "https://storage.example.com/datasets/vendor_list.xlsx" (Join-Path $dataDir "vendor_list.xlsx")

    # Begin transfer
    & bitsadmin.exe /transfer $xferJobName /download /priority normal

    Start-Sleep -Seconds 2

    # Finalize transfer
    & bitsadmin.exe /complete $xferJobName
    & bitsadmin.exe /delete $xferJobName
} catch {
    & bitsadmin.exe /delete $xferJobName -ErrorAction SilentlyContinue
}

# Clean up data staging area
Remove-Item -Path $dataDir -Recurse -Force -ErrorAction SilentlyContinue


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
