# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 2
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_5b3c93c4-af29-4bc4-a955-a76caaaae1c7  (1 rule(s)) ---------------------
# Intent:    Detect system process executables being executed from non-standard directories, 
# Rules:     5b3c93c4-af29-4bc4-a955-a76caaaae1c7
# Archetype: Software installer/updater workflow

$stagingDir = Join-Path -Path $env:TEMP -ChildPath "installer_staging_$(Get-Random)"
$null = New-Item -ItemType Directory -Path $stagingDir -Force

try {
  # Copy system processes to staging directory (simulating installer extraction)
  $systemProcesses = @('svchost.exe', 'services.exe', 'lsass.exe', 'csrss.exe')
  foreach ($proc in $systemProcesses) {
    $sourcePath = Join-Path -Path 'C:\Windows\System32' -ChildPath $proc
    if (Test-Path -Path $sourcePath) {
      Copy-Item -Path $sourcePath -Destination $stagingDir -Force | Out-Null
    }
  }

  # Installer verification: invoke staged svchost.exe to verify service manager availability
  # This is realistic pre-deployment validation that enterprise installers perform
  $stagedSvchost = Join-Path -Path $stagingDir -ChildPath 'svchost.exe'
  if (Test-Path -Path $stagedSvchost) {
    & $stagedSvchost -? 2>&1 | Out-Null
  }

  # Installer verification: invoke staged services.exe to validate service control
  $stagedServices = Join-Path -Path $stagingDir -ChildPath 'services.exe'
  if (Test-Path -Path $stagedServices) {
    & $stagedServices /? 2>&1 | Out-Null
  }

  # Simulate installer pre-flight checks: spawn lsass from staging to test authentication subsystem readiness
  $stagedLsass = Join-Path -Path $stagingDir -ChildPath 'lsass.exe'
  if (Test-Path -Path $stagedLsass) {
    & $stagedLsass -? 2>&1 | Out-Null
  }

  # Simulate installer pre-flight checks: spawn csrss from staging to test client/server subsystem
  $stagedCsrss = Join-Path -Path $stagingDir -ChildPath 'csrss.exe'
  if (Test-Path -Path $stagedCsrss) {
    & $stagedCsrss -? 2>&1 | Out-Null
  }

  Write-Host "Installer staging and verification complete"
} finally {
  # Cleanup: remove staging directory and all staged binaries
  if (Test-Path -Path $stagingDir) {
    Remove-Item -Path $stagingDir -Recurse -Force | Out-Null
  }
}

# -- Cluster: singleton_5b3c93c4-af29-4bc4-a955-a76caaaae1c7  (1 rule(s)) ---------------------
# Intent:    Detect system process executables being executed from non-standard directories, 
# Rules:     5b3c93c4-af29-4bc4-a955-a76caaaae1c7
# Archetype: IT admin workflow

$recoveryDir = Join-Path -Path $env:TEMP -ChildPath "recovery_bin_$(Get-Random)"
$null = New-Item -ItemType Directory -Path $recoveryDir -Force

try {
  # Extract critical system binaries to recovery directory for integrity validation
  $criticalBinaries = @('svchost.exe', 'services.exe', 'lsass.exe', 'smss.exe', 'winlogon.exe', 'wininit.exe')
  foreach ($binary in $criticalBinaries) {
    $sourcePath = Join-Path -Path 'C:\Windows\System32' -ChildPath $binary
    if (Test-Path -Path $sourcePath) {
      Copy-Item -Path $sourcePath -Destination $recoveryDir -Force | Out-Null
    }
  }

  # Admin verification workflow: execute each recovered binary to confirm functional integrity
  # This simulates real administrator validation during disaster recovery scenarios
  foreach ($binary in $criticalBinaries) {
    $recoveredBinary = Join-Path -Path $recoveryDir -ChildPath $binary
    if (Test-Path -Path $recoveredBinary) {
      Write-Host "Validating recovered binary: $binary"
      & $recoveredBinary -? 2>&1 | Out-Null
    }
  }

  # Compute cryptographic hashes of recovered binaries for integrity audit log
  $hashLog = Join-Path -Path $recoveryDir -ChildPath 'integrity_audit.txt'
  foreach ($binary in $criticalBinaries) {
    $recoveredBinary = Join-Path -Path $recoveryDir -ChildPath $binary
    if (Test-Path -Path $recoveredBinary) {
      $hash = Get-FileHash -Path $recoveredBinary -Algorithm SHA256 | Select-Object -ExpandProperty Hash
      Add-Content -Path $hashLog -Value "$binary : $hash"
    }
  }

  Write-Host "Binary recovery and integrity validation completed"
} finally {
  # Cleanup: remove recovery directory and all validated binaries
  if (Test-Path -Path $recoveryDir) {
    Remove-Item -Path $recoveryDir -Recurse -Force | Out-Null
  }
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
