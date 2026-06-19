# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_2722e9ef-e69d-48bd-9724-5b852326c475  (1 rule(s)) ---------------------
# Intent:    Detect execution of legitimate Windows system binaries that have been renamed or
# Rules:     2722e9ef-e69d-48bd-9724-5b852326c475
# Archetype: IT admin workflow

$stagingDir = Join-Path $env:TEMP 'AdminTools_$(Get-Random)'
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

try {
  # Copy cmd.exe to staging location for offline diagnostics testing
  $cmdSource = 'C:\Windows\System32\cmd.exe'
  $cmdStaged = Join-Path $stagingDir 'cmd.exe'
  Copy-Item -Path $cmdSource -Destination $cmdStaged -Force

  # Copy powershell.exe to staging for script validation testing
  $psSource = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
  $psStaged = Join-Path $stagingDir 'powershell.exe'
  Copy-Item -Path $psSource -Destination $psStaged -Force

  # Copy rundll32.exe for DLL testing procedures
  $dllSource = 'C:\Windows\System32\rundll32.exe'
  $dllStaged = Join-Path $stagingDir 'rundll32.exe'
  Copy-Item -Path $dllSource -Destination $dllStaged -Force

  # Execute staged cmd.exe from non-standard path - simulates admin recovery scenario
  # This generates Sysmon EID 1 with Image pointing outside System32
  & $cmdStaged /c 'systeminfo | findstr /C:"OS" > nul'

  # Execute staged powershell from non-standard location
  # Realistic for validation of portable PowerShell copies
  & $psStaged -NoProfile -Command '[System.Environment]::OSVersion.VersionString | Out-Null'

  # Execute staged rundll32 with legitimate DLL query operation
  # Common during DLL dependency validation by admins
  & $dllStaged shell32.dll,ShellAbout 2>$null

  # Simulate MSIExec parent context by invoking setup operation that may internally call system utilities
  # This tests parent process detection logic
  msiexec /? | Out-Null

} finally {
  # Clean up staging directory
  Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_2722e9ef-e69d-48bd-9724-5b852326c475  (1 rule(s)) ---------------------
# Intent:    Detect execution of legitimate Windows system binaries that have been renamed or
# Rules:     2722e9ef-e69d-48bd-9724-5b852326c475
# Archetype: Software installer/updater workflow

$pkgDir = Join-Path $env:TEMP "AppDeploy_$(Get-Random)"
New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null

try {
  # Create installer package structure
  $binDir = Join-Path $pkgDir 'bin'
  New-Item -ItemType Directory -Path $binDir -Force | Out-Null

  # Stage system utilities in package bin directory
  Copy-Item 'C:\Windows\System32\rundll32.exe' -Destination (Join-Path $binDir 'rundll32.exe') -Force
  Copy-Item 'C:\Windows\System32\regsvr32.exe' -Destination (Join-Path $binDir 'regsvr32.exe') -Force
  Copy-Item 'C:\Windows\System32\mshta.exe' -Destination (Join-Path $binDir 'mshta.exe') -Force
  Copy-Item 'C:\Windows\System32\cscript.exe' -Destination (Join-Path $binDir 'cscript.exe') -Force

  # Create installer manifest script
  $manifestScript = Join-Path $pkgDir 'validate.ps1'
  $scriptContent = @'
# Validation procedure during installation
& $args[0] shell32.dll,ShellAbout 2>$null
& $args[1] /s winhttp.dll 2>$null
Write-Host 'Validation complete' -ErrorAction SilentlyContinue
'@
  Set-Content -Path $manifestScript -Value $scriptContent -Force

  # Execute validation from installer working directory using staged utilities
  # This simulates installation repair, feature update, or compatibility check
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $manifestScript `
    (Join-Path $binDir 'rundll32.exe') `
    (Join-Path $binDir 'regsvr32.exe')

  # Direct execution of staged cscript for legacy COM component registration
  # Common during system service installer procedures
  $cscriptPath = Join-Path $binDir 'cscript.exe'
  & $cscriptPath //? 2>$null

  # Execute mshta from package location for HTML application testing
  $mshtaPath = Join-Path $binDir 'mshta.exe'
  & $mshtaPath about: 2>$null

} finally {
  Remove-Item -Path $pkgDir -Recurse -Force -ErrorAction SilentlyContinue
}

# SKIPPED variant 'User-driven workflow': blocked pattern: hidden window ('-windowstyle hidden')


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
