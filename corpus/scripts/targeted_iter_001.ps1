# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   2  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_debd5d6f-b3b9-4525-b453-1523cf5479c5  (1 rule(s)) ---------------------
# Intent:    Detect Windows system binaries being executed from non-canonical paths, which is
# Rules:     debd5d6f-b3b9-4525-b453-1523cf5479c5
# Archetype: IT admin workflow

$tempDir = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName())
[System.IO.Directory]::CreateDirectory($tempDir) | Out-Null
try {
    $sysRoot = $env:SystemRoot
    $system32 = [System.IO.Path]::Combine($sysRoot, 'System32')
    $svcHostSrc = [System.IO.Path]::Combine($system32, 'svchost.exe')
    $svcHostDst = [System.IO.Path]::Combine($tempDir, 'svchost.exe')
    $lsassSrc = [System.IO.Path]::Combine($system32, 'lsass.exe')
    $lsassDst = [System.IO.Path]::Combine($tempDir, 'lsass.exe')
    if ([System.IO.File]::Exists($svcHostSrc)) {
        [System.IO.File]::Copy($svcHostSrc, $svcHostDst, $true)
        & $svcHostDst -? 2>$null | Select-Object -First 5
    }
    if ([System.IO.File]::Exists($lsassSrc)) {
        [System.IO.File]::Copy($lsassSrc, $lsassDst, $true)
        & $lsassDst -? 2>$null | Select-Object -First 5
    }
    $csrssSrc = [System.IO.Path]::Combine($system32, 'csrss.exe')
    $csrssDst = [System.IO.Path]::Combine($tempDir, 'csrss.exe')
    if ([System.IO.File]::Exists($csrssSrc)) {
        [System.IO.File]::Copy($csrssSrc, $csrssDst, $true)
        & $csrssDst -? 2>$null | Select-Object -First 5
    }
} finally {
    if ([System.IO.Directory]::Exists($tempDir)) {
        [System.IO.Directory]::Delete($tempDir, $true)
    }
}

# -- Cluster: singleton_debd5d6f-b3b9-4525-b453-1523cf5479c5  (1 rule(s)) ---------------------
# Intent:    Detect Windows system binaries being executed from non-canonical paths, which is
# Rules:     debd5d6f-b3b9-4525-b453-1523cf5479c5
# Archetype: Software installer/updater workflow

$programFiles = ${env:ProgramFiles}
$stagingDir = [System.IO.Path]::Combine($programFiles, 'DiagnosticStaging')
[System.IO.Directory]::CreateDirectory($stagingDir) | Out-Null
try {
    $sysRoot = $env:SystemRoot
    $system32 = [System.IO.Path]::Combine($sysRoot, 'System32')
    $binaries = @('svchost.exe', 'explorer.exe', 'taskhostw.exe', 'dwm.exe')
    foreach ($binary in $binaries) {
        $srcPath = [System.IO.Path]::Combine($system32, $binary)
        $dstPath = [System.IO.Path]::Combine($stagingDir, $binary)
        if ([System.IO.File]::Exists($srcPath)) {
            [System.IO.File]::Copy($srcPath, $dstPath, $true)
            if ($binary -eq 'taskhostw.exe' -or $binary -eq 'dwm.exe') {
                try {
                    & $dstPath -? 2>$null | Select-Object -First 3
                } catch {
                }
            }
        }
    }
    $system32Bins = Get-ChildItem -Path $stagingDir -Filter '*.exe' -ErrorAction SilentlyContinue
    foreach ($bin in $system32Bins) {
        $fileInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($bin.FullName)
    }
} finally {
    if ([System.IO.Directory]::Exists($stagingDir)) {
        [System.IO.Directory]::Delete($stagingDir, $true)
    }
}

# -- Cluster: singleton_debd5d6f-b3b9-4525-b453-1523cf5479c5  (1 rule(s)) ---------------------
# Intent:    Detect Windows system binaries being executed from non-canonical paths, which is
# Rules:     debd5d6f-b3b9-4525-b453-1523cf5479c5
# Archetype: User-driven workflow

$userTemp = $env:TEMP
$workDir = [System.IO.Path]::Combine($userTemp, 'DiagTools')
[System.IO.Directory]::CreateDirectory($workDir) | Out-Null
try {
    $sysRoot = $env:SystemRoot
    $system32 = [System.IO.Path]::Combine($sysRoot, 'System32')
    $tools = @('spoolsv.exe', 'lsm.exe', 'conhost.exe', 'dllhost.exe', 'searchindexer.exe')
    foreach ($tool in $tools) {
        $src = [System.IO.Path]::Combine($system32, $tool)
        $dst = [System.IO.Path]::Combine($workDir, $tool)
        if ([System.IO.File]::Exists($src)) {
            [System.IO.File]::Copy($src, $dst, $true)
            $properties = Get-Item -Path $dst -ErrorAction SilentlyContinue
            if ($null -ne $properties) {
                $properties.VersionInfo
            }
        }
    }
    Get-ChildItem -Path $workDir -Filter '*.exe' | Measure-Object | Select-Object -ExpandProperty Count
} finally {
    if ([System.IO.Directory]::Exists($workDir)) {
        [System.IO.Directory]::Delete($workDir, $true)
    }
}

# SKIPPED cluster singleton_3f0c9289-4dfa-4b9b-acb7-ff6db50077b7: JSON parse error: Expecting value: line 16 column 31 (char 2403)

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
