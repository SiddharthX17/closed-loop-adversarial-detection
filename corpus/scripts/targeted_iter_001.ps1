# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_b82b7036-af4f-4267-9656-854b7bcd3e1b  (1 rule(s)) ---------------------
# Intent:    Detect masquerading of Windows critical system binaries (lsass, svchost, csrss, 
# Rules:     b82b7036-af4f-4267-9656-854b7bcd3e1b
# Archetype: Software installer/updater workflow

$installerDir = Join-Path $env:TEMP "ComplianceCheck_$(Get-Random)"
New-Item -ItemType Directory -Path $installerDir -Force | Out-Null

Try {
  # Create a copy of explorer.exe in the installer directory to simulate
  # a legitimate vendor bundling system binaries for version verification
  $explorerSource = "C:\Windows\explorer.exe"
  $explorerDest = Join-Path $installerDir "explorer.exe"
  Copy-Item -Path $explorerSource -Destination $explorerDest -Force

  # Simulate installer performing a system library integrity check
  # by invoking explorer.exe from the non-canonical path
  & $explorerDest /root

  # Pause briefly to ensure Sysmon captures the event
  Start-Sleep -Milliseconds 500

  # Similarly, copy and execute svchost from non-canonical path
  # to simulate service dependency verification during installation
  $svchostSource = "C:\Windows\System32\svchost.exe"
  $svchostDest = Join-Path $installerDir "svchost.exe"
  Copy-Item -Path $svchostSource -Destination $svchostDest -Force

  # Execute with minimal arguments to verify presence
  & $svchostDest -v 2>$null

  Start-Sleep -Milliseconds 500

  # Copy conhost for terminal emulation verification
  $conhostSource = "C:\Windows\System32\conhost.exe"
  $conhostDest = Join-Path $installerDir "conhost.exe"
  Copy-Item -Path $conhostSource -Destination $conhostDest -Force

  & $conhostDest --headless --width 80 --height 24 2>$null

} Finally {
  # Clean up the installer staging directory
  Remove-Item -Path $installerDir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_b82b7036-af4f-4267-9656-854b7bcd3e1b  (1 rule(s)) ---------------------
# Intent:    Detect masquerading of Windows critical system binaries (lsass, svchost, csrss, 
# Rules:     b82b7036-af4f-4267-9656-854b7bcd3e1b
# Archetype: IT admin workflow

$auditDir = Join-Path $env:TEMP "SysAudit_$(Get-Random)"
New-Item -ItemType Directory -Path $auditDir -Force | Out-Null

Try {
  # Simulate configuration management audit by copying critical
  # system binaries to a staging location for checksumming and version verification
  $systemBinaries = @(
    "C:\Windows\System32\lsass.exe",
    "C:\Windows\System32\csrss.exe",
    "C:\Windows\System32\smss.exe",
    "C:\Windows\System32\dwm.exe",
    "C:\Windows\System32\lsm.exe"
  )

  foreach ($binary in $systemBinaries) {
    if (Test-Path $binary) {
      $destPath = Join-Path $auditDir (Split-Path -Leaf $binary)
      Copy-Item -Path $binary -Destination $destPath -Force
    }
  }

  # Admin executes binaries from the audit staging directory
  # to verify system integrity and collect diagnostic metadata
  $csrssAudit = Join-Path $auditDir "csrss.exe"
  $lsassAudit = Join-Path $auditDir "lsass.exe"

  # These will immediately fail due to missing required arguments,
  # but Sysmon will log the process creation from non-canonical path
  & $csrssAudit --debug 2>$null
  Start-Sleep -Milliseconds 300

  & $lsassAudit --version 2>$null
  Start-Sleep -Milliseconds 300

  # Verify binaries were properly copied for audit trail
  $dwmAudit = Join-Path $auditDir "dwm.exe"
  & $dwmAudit /? 2>$null
  Start-Sleep -Milliseconds 300

} Finally {
  # Remove audit staging directory and all copied binaries
  Remove-Item -Path $auditDir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_b82b7036-af4f-4267-9656-854b7bcd3e1b  (1 rule(s)) ---------------------
# Intent:    Detect masquerading of Windows critical system binaries (lsass, svchost, csrss, 
# Rules:     b82b7036-af4f-4267-9656-854b7bcd3e1b
# Archetype: User-driven workflow

$toolkitDir = Join-Path $env:TEMP "PortableToolkit_$(Get-Random)"
New-Item -ItemType Directory -Path $toolkitDir -Force | Out-Null

Try {
  # Simulate a portable application that bundles Windows system tools
  # for cross-platform diagnostic and environment capability detection
  $programFilesDir = Join-Path $toolkitDir "bin"
  New-Item -ItemType Directory -Path $programFilesDir -Force | Out-Null

  # Copy explorer and taskhostw as bundled utilities
  Copy-Item -Path "C:\Windows\explorer.exe" -Destination (Join-Path $programFilesDir "explorer.exe") -Force
  Copy-Item -Path "C:\Windows\System32\taskhostw.exe" -Destination (Join-Path $programFilesDir "taskhostw.exe") -Force
  Copy-Item -Path "C:\Windows\System32\taskhost.exe" -Destination (Join-Path $programFilesDir "taskhost.exe") -Force
  Copy-Item -Path "C:\Windows\System32\spoolsv.exe" -Destination (Join-Path $programFilesDir "spoolsv.exe") -Force

  # Run environment detection sequence
  # These invocations represent the portable app checking system capabilities
  $explorerPath = Join-Path $programFilesDir "explorer.exe"
  & $explorerPath /e,/root 2>$null
  Start-Sleep -Milliseconds 250

  $taskhostwPath = Join-Path $programFilesDir "taskhostw.exe"
  & $taskhostwPath 2>$null
  Start-Sleep -Milliseconds 250

  $spoolsvPath = Join-Path $programFilesDir "spoolsv.exe"
  & $spoolsvPath 2>$null
  Start-Sleep -Milliseconds 250

  # Simulate the toolkit checking for Windows Subsystem components
  $taskhostPath = Join-Path $programFilesDir "taskhost.exe"
  & $taskhostPath /? 2>$null
  Start-Sleep -Milliseconds 250

} Finally {
  # Clean up the portable toolkit directory
  Remove-Item -Path $toolkitDir -Recurse -Force -ErrorAction SilentlyContinue
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
