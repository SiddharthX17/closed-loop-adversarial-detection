# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 2
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_9330fd1e-2d98-49a1-ba59-9467c06085f4  (1 rule(s)) ---------------------
# Intent:    Detect system process name masquerading — renamed or copied instances of critica
# Rules:     9330fd1e-2d98-49a1-ba59-9467c06085f4
# Archetype: IT admin workflow

$StagingDir = Join-Path $env:TEMP 'forensic_analysis_2024'
if (-not (Test-Path $StagingDir)) {
  New-Item -ItemType Directory -Path $StagingDir | Out-Null
}

# Copy system binaries to staging directory for integrity verification
$SystemBinaries = @(
  'C:\Windows\System32\lsass.exe',
  'C:\Windows\System32\csrss.exe',
  'C:\Windows\System32\services.exe'
)

foreach ($Binary in $SystemBinaries) {
  if (Test-Path $Binary) {
    $FileName = Split-Path -Leaf $Binary
    $StagedPath = Join-Path $StagingDir $FileName
    Copy-Item -Path $Binary -Destination $StagedPath -Force

    # Verify file hash of staged copy against original
    $OriginalHash = (Get-FileHash -Path $Binary -Algorithm SHA256).Hash
    $StagedHash = (Get-FileHash -Path $StagedPath -Algorithm SHA256).Hash

    if ($OriginalHash -eq $StagedHash) {
      Write-Host "Integrity verified for $FileName"
    }
  }
}

# Query process information for system binaries from staged location
Get-Process -ErrorAction SilentlyContinue | Where-Object {
  $_.ProcessName -match '(lsass|csrss|services)'
} | Select-Object ProcessName, Id, StartTime | Out-Null

# Clean up staging directory
Remove-Item -Path $StagingDir -Recurse -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_9330fd1e-2d98-49a1-ba59-9467c06085f4  (1 rule(s)) ---------------------
# Intent:    Detect system process name masquerading — renamed or copied instances of critica
# Rules:     9330fd1e-2d98-49a1-ba59-9467c06085f4
# Archetype: Software installer/updater workflow

$DeploymentCache = Join-Path $env:APPDATA 'EnterpriseDeploymentAgent\bin'
if (-not (Test-Path $DeploymentCache)) {
  New-Item -ItemType Directory -Path $DeploymentCache -Force | Out-Null
}

# Simulate deployment agent extracting and caching system binaries
$BinariesToCache = @(
  @{ Source = 'C:\Windows\System32\winlogon.exe'; Name = 'winlogon.exe' },
  @{ Source = 'C:\Windows\System32\smss.exe'; Name = 'smss.exe' },
  @{ Source = 'C:\Windows\System32\wininit.exe'; Name = 'wininit.exe' }
)

foreach ($BinaryInfo in $BinariesToCache) {
  if (Test-Path $BinaryInfo.Source) {
    $CachedPath = Join-Path $DeploymentCache $BinaryInfo.Name
    Copy-Item -Path $BinaryInfo.Source -Destination $CachedPath -Force

    # Verify cached binary is accessible for deployment dependency check
    $Attributes = (Get-Item -Path $CachedPath).VersionInfo
    Write-Host "Cached $($BinaryInfo.Name) from deployment source"
  }
}

# Deployment agent performs system state assessment
get-childitem -Path $DeploymentCache -Filter '*.exe' | Measure-Object | Select-Object -ExpandProperty Count | Out-Null

# Clean up deployment cache
Remove-Item -Path $DeploymentCache -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Split-Path -Parent $DeploymentCache) -Force -ErrorAction SilentlyContinue


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
