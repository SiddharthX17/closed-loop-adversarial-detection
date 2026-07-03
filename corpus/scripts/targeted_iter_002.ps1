# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_d9dc84e1-b34d-407a-8fb4-e5811294eec6  (1 rule(s)) ---------------------
# Intent:    Detect disguised esentutl.exe execution (a legitimate database utility) that has
# Rules:     d9dc84e1-b34d-407a-8fb4-e5811294eec6
# Archetype: IT admin workflow

$ErrorActionPreference = 'SilentlyContinue'
$tempDbPath = Join-Path $env:TEMP 'ad_maint_backup'
if (Test-Path $tempDbPath) { Remove-Item -Path $tempDbPath -Recurse -Force }
New-Item -Path $tempDbPath -ItemType Directory -Force | Out-Null

$esentutlPath = 'C:\Windows\System32\esentutl.exe'

if (Test-Path $esentutlPath) {
  Write-Host 'Running database integrity check on maintenance copy...'
  & $esentutlPath /g 'C:\Windows\System32\ntds.dit' /8 /v | Out-Null

  Write-Host 'Performing recovery mode analysis...'
  & $esentutlPath /r NTDS /d 'C:\Windows\System32' | Out-Null

  Write-Host 'Exporting database statistics...'
  & $esentutlPath /d 'C:\Windows\System32\ntds.dit' | Out-Null
}

if (Test-Path $tempDbPath) {
  Remove-Item -Path $tempDbPath -Recurse -Force
}
Write-Host 'Database maintenance completed'

# -- Cluster: singleton_d9dc84e1-b34d-407a-8fb4-e5811294eec6  (1 rule(s)) ---------------------
# Intent:    Detect disguised esentutl.exe execution (a legitimate database utility) that has
# Rules:     d9dc84e1-b34d-407a-8fb4-e5811294eec6
# Archetype: Software installer/updater workflow

$ErrorActionPreference = 'SilentlyContinue'
$auditLogPath = Join-Path $env:TEMP 'system_audit_log.txt'

Write-Host 'Beginning system tool inventory audit...'

$toolsToAudit = @(
  'C:\Windows\System32\esentutl.exe',
  'C:\Windows\System32\ntdsutil.exe',
  'C:\Windows\System32\dsamain.exe',
  'C:\Windows\System32\csvde.exe'
)

foreach ($tool in $toolsToAudit) {
  if (Test-Path $tool) {
    $fileInfo = Get-Item -Path $tool
    Write-Host "Found: $($fileInfo.Name) at $tool"

    $versionInfo = (Get-Command $tool -ErrorAction SilentlyContinue).Version
    if ($versionInfo) {
      Write-Host "  Version: $versionInfo"
    }

    $prodVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($tool).ProductVersion
    Write-Host "  Product: $prodVersion"

    if ($tool -match 'esentutl') {
      Write-Host 'Running diagnostic on esentutl...'
      & $tool /? 2>&1 | Select-Object -First 3 | Out-Null
    }
  }
}

if (Test-Path $auditLogPath) {
  Remove-Item -Path $auditLogPath -Force
}
Write-Host 'Tool inventory audit completed'

# -- Cluster: singleton_d9dc84e1-b34d-407a-8fb4-e5811294eec6  (1 rule(s)) ---------------------
# Intent:    Detect disguised esentutl.exe execution (a legitimate database utility) that has
# Rules:     d9dc84e1-b34d-407a-8fb4-e5811294eec6
# Archetype: Document/file operation workflow

$ErrorActionPreference = 'SilentlyContinue'
$reportPath = Join-Path $env:TEMP 'db_compliance_report'
if (Test-Path $reportPath) { Remove-Item -Path $reportPath -Recurse -Force }
New-Item -Path $reportPath -ItemType Directory -Force | Out-Null

$esentutlPath = 'C:\Windows\System32\esentutl.exe'
$ntdsPath = 'C:\Windows\System32\ntds.dit'

if (Test-Path $esentutlPath) {
  Write-Host 'Extracting database metadata for compliance documentation...'

  $metadataFile = Join-Path $reportPath 'ntds_metadata.txt'
  & $esentutlPath /m $ntdsPath 2>&1 | Out-File -FilePath $metadataFile -Encoding UTF8

  Write-Host 'Generating database statistics report...'
  $statsFile = Join-Path $reportPath 'ntds_statistics.txt'
  & $esentutlPath /d $ntdsPath 2>&1 | Out-File -FilePath $statsFile -Encoding UTF8

  Write-Host 'Validating database integrity...'
  $validationFile = Join-Path $reportPath 'integrity_check.txt'
  & $esentutlPath /g $ntdsPath /8 /v 2>&1 | Out-File -FilePath $validationFile -Encoding UTF8

  if ((Get-Item $metadataFile -ErrorAction SilentlyContinue).Length -gt 0) {
    Write-Host "Metadata report generated: $(Get-Item $metadataFile).Length bytes"
  }

  Write-Host 'Archiving compliance documentation...'
  $archivePath = Join-Path $env:TEMP 'compliance_archive.zip'
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [System.IO.Compression.ZipFile]::CreateFromDirectory($reportPath, $archivePath, $true)
  Write-Host "Archive created: $archivePath"
}

if (Test-Path $reportPath) {
  Remove-Item -Path $reportPath -Recurse -Force
}
if (Test-Path $archivePath) {
  Remove-Item -Path $archivePath -Force
}
Write-Host 'Database documentation export completed'


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
