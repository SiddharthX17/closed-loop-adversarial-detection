# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   3  |  Feasible: 3  |  Variants: 9
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_7983fb82-b62d-4bf8-a004-6aba8686e0f9  (1 rule(s)) ---------------------
# Intent:    Detect masquerading of legitimate Windows system processes by running copies wit
# Rules:     7983fb82-b62d-4bf8-a004-6aba8686e0f9
# Archetype: IT admin workflow

$stagingDir = Join-Path $env:TEMP "SysAnalysis_$(Get-Random)"
$null = New-Item -ItemType Directory -Path $stagingDir -Force

try {
  # Simulate IT admin collecting system process binaries for diagnostic reporting
  # This is realistic: admins often stage binaries in temp for forensics or migration prep
  $systemRoot = $env:SystemRoot

  # Copy legitimate system binaries to staging directory
  $binariesToStage = @('lsass.exe', 'svchost.exe', 'csrss.exe', 'services.exe', 'spoolsv.exe')

  foreach ($binary in $binariesToStage) {
    $srcPath = Join-Path $systemRoot "System32" $binary
    if (Test-Path $srcPath) {
      Copy-Item -Path $srcPath -Destination $stagingDir -Force -ErrorAction SilentlyContinue
    }
  }

  # Execute staged binaries from temp directory with timeout to avoid hanging
  # Real admins might do this for process behavior analysis or compatibility testing
  $stagedBinaries = Get-ChildItem -Path $stagingDir -Filter '*.exe' -ErrorAction SilentlyContinue

  foreach ($stagedExe in $stagedBinaries) {
    try {
      $procParams = @{
        FilePath = $stagedExe.FullName
        NoNewWindow = $true
        RedirectStandardOutput = $null
        RedirectStandardError = $null
        UseNewEnvironment = $true
        ErrorAction = 'SilentlyContinue'
        WarningAction = 'SilentlyContinue'
      }

      # Use timeout to prevent hanging; real admin scripts include safeguards
      $process = Start-Process @procParams -PassThru
      if ($process) {
        Start-Sleep -Milliseconds 500
        if (-not $process.HasExited) {
          $process.Kill()
        }
      }
    } catch {}
  }

  # Simulate parent process context: invoke via cmd.exe (common admin pattern)
  $cmdPath = Join-Path $stagingDir 'svchost.exe'
  if (Test-Path $cmdPath) {
    try {
      $cmdProcess = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/c', $cmdPath) -NoNewWindow -PassThru -ErrorAction SilentlyContinue
      if ($cmdProcess) {
        Start-Sleep -Milliseconds 300
        if (-not $cmdProcess.HasExited) {
          $cmdProcess.Kill()
        }
      }
    } catch {}
  }

} finally {
  # Clean up staging directory
  Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_7983fb82-b62d-4bf8-a004-6aba8686e0f9  (1 rule(s)) ---------------------
# Intent:    Detect masquerading of legitimate Windows system processes by running copies wit
# Rules:     7983fb82-b62d-4bf8-a004-6aba8686e0f9
# Archetype: Software installer/updater workflow

$extractDir = Join-Path $env:TEMP "SecurityAnalysis_$(Get-Random)"
$null = New-Item -ItemType Directory -Path $extractDir -Force

try {
  # Simulate endpoint protection tool extracting and analyzing system binaries
  # Real scenario: EDR or antivirus performs runtime analysis of system processes
  $systemRoot = $env:SystemRoot
  $systemBinaries = @('explorer.exe', 'dwm.exe', 'winlogon.exe', 'userinit.exe', 'lsm.exe')

  foreach ($binary in $systemBinaries) {
    $srcPath = Join-Path $systemRoot "System32" $binary
    if (Test-Path $srcPath) {
      Copy-Item -Path $srcPath -Destination $extractDir -Force -ErrorAction SilentlyContinue
    }
  }

  # Simulate security tool parent process (use powershell as proxy for security daemon)
  # Real tools: MsMpEng.exe, NisSvc.exe, or third-party EDR processes
  $securityToolScriptBlock = {
    param($extractionPath)

    $exes = Get-ChildItem -Path $extractionPath -Filter '*.exe' -ErrorAction SilentlyContinue
    foreach ($exe in $exes) {
      try {
        # Spawn extracted system binary for behavioral analysis
        $childProcess = Start-Process -FilePath $exe.FullName -NoNewWindow -PassThru -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if ($childProcess) {
          Start-Sleep -Milliseconds 400
          if (-not $childProcess.HasExited) {
            $childProcess.Kill()
          }
        }
      } catch {}
    }
  }

  # Execute security tool behavior pattern
  & $securityToolScriptBlock -extractionPath $extractDir

  # Additional pattern: security tool using cmd.exe wrapper (common in EDR/AV)
  $cmdExtrPath = Join-Path $extractDir 'explorer.exe'
  if (Test-Path $cmdExtrPath) {
    try {
      $wrappedProcess = Start-Process -FilePath 'cmd.exe' -ArgumentList @('/c', $cmdExtrPath) -NoNewWindow -PassThru -ErrorAction SilentlyContinue
      if ($wrappedProcess) {
        Start-Sleep -Milliseconds 300
        if (-not $wrappedProcess.HasExited) {
          $wrappedProcess.Kill()
        }
      }
    } catch {}
  }

} finally {
  # Clean up extraction directory
  Remove-Item -Path $extractDir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_7983fb82-b62d-4bf8-a004-6aba8686e0f9  (1 rule(s)) ---------------------
# Intent:    Detect masquerading of legitimate Windows system processes by running copies wit
# Rules:     7983fb82-b62d-4bf8-a004-6aba8686e0f9
# Archetype: Document/file operation workflow

$appDataStaging = Join-Path $env:APPDATA "TempProcessFiles_$(Get-Random)"
$null = New-Item -ItemType Directory -Path $appDataStaging -Force

try {
  # Simulate application extracting system binaries for legitimate operations
  # Real scenario: backup tool, file sync app, or migration utility stages system tools
  $systemRoot = $env:SystemRoot
  $toolsToExtract = @('taskhostw.exe', 'taskhost.exe', 'smss.exe', 'wininit.exe')

  foreach ($tool in $toolsToExtract) {
    $srcPath = Join-Path $systemRoot "System32" $tool
    if (Test-Path $srcPath) {
      Copy-Item -Path $srcPath -Destination $appDataStaging -Force -ErrorAction SilentlyContinue
    }
  }

  # Application processes staged binaries from AppData (realistic for portability)
  $stagedTools = Get-ChildItem -Path $appDataStaging -Filter '*.exe' -ErrorAction SilentlyContinue

  foreach ($tool in $stagedTools) {
    try {
      # Execute tool for application's operational needs
      $appProcess = Start-Process -FilePath $tool.FullName -NoNewWindow -PassThru -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
      if ($appProcess) {
        Start-Sleep -Milliseconds 350
        if (-not $appProcess.HasExited) {
          $appProcess.Kill()
        }
      }
    } catch {}
  }

  # Simulate application launcher pattern (indirect execution)
  # Real apps often use intermediate process or launcher
  $taskhostwPath = Join-Path $appDataStaging 'taskhostw.exe'
  if (Test-Path $taskhostwPath) {
    try {
      $launcherProcess = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-Command', "Start-Process -FilePath '$taskhostwPath' -NoNewWindow") -NoNewWindow -PassThru -ErrorAction SilentlyContinue
      if ($launcherProcess) {
        Start-Sleep -Milliseconds 400
        if (-not $launcherProcess.HasExited) {
          $launcherProcess.Kill()
        }
      }
    } catch {}
  }

} finally {
  # Clean up application staging directory
  Remove-Item -Path $appDataStaging -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_cfdc1116-6584-471e-a0ff-c6b9db445068  (1 rule(s)) ---------------------
# Intent:    Detect adversaries writing base64-encoded payloads into registry keys under HKCU
# Rules:     cfdc1116-6584-471e-a0ff-c6b9db445068
# Archetype: Software installer/updater workflow

$registryPath = 'HKCU:\Software\Mozilla\Firefox\Launcher'
$valueName = 'UpdateConfig'
# Simulate legitimate application configuration: base64-encoded update manifest
$configData = 'bW96aWxsYV9maXJlZm94X3VwZGF0ZV9tYW5pZmVzdF92ZXJzaW9uXzEyMy40NTY'

# Create registry path if it does not exist
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Write base64-encoded configuration to registry
Set-ItemProperty -Path $registryPath -Name $valueName -Value $configData -Type String

Start-Sleep -Milliseconds 500

# Verify write occurred
$written = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue
if ($written) {
    Write-Host "Configuration written successfully"
}

# Cleanup: remove test registry key
Remove-Item -Path $registryPath -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_cfdc1116-6584-471e-a0ff-c6b9db445068  (1 rule(s)) ---------------------
# Intent:    Detect adversaries writing base64-encoded payloads into registry keys under HKCU
# Rules:     cfdc1116-6584-471e-a0ff-c6b9db445068
# Archetype: IT admin workflow

$registryPath = 'HKCU:\Software\Adobe\Reader'
$valueName = 'LicenseData'
# Simulate legitimate license configuration: base64-encoded license metadata
$licenseBlob = 'YWRvYmVfcmVhZGVyX2xpY2Vuc2Vfa2V5XzIwMjRfZW50ZXJwcmlzZV9lZGl0aW9u'

# Ensure registry path exists
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Write license configuration
Set-ItemProperty -Path $registryPath -Name $valueName -Value $licenseBlob -Type String

Start-Sleep -Milliseconds 300

# Verify registry write
$check = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue
if ($check) {
    Write-Host "License configuration applied"
}

# Cleanup: remove registry entry
Remove-Item -Path $registryPath -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_cfdc1116-6584-471e-a0ff-c6b9db445068  (1 rule(s)) ---------------------
# Intent:    Detect adversaries writing base64-encoded payloads into registry keys under HKCU
# Rules:     cfdc1116-6584-471e-a0ff-c6b9db445068
# Archetype: User-driven workflow

$registryPath = 'HKCU:\Software\Google\Chrome\UserData'
$valueName = 'PreferenceState'
# Simulate legitimate extension/preference state: base64-encoded extension config
$preferenceData = 'Y2hyb21lX2V4dGVuc2lvbl9wcmVmZXJlbmNlc19zdGF0ZV92MV8yMDI0'

# Create registry path for browser preferences
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Write preference state to registry
Set-ItemProperty -Path $registryPath -Name $valueName -Value $preferenceData -Type String

Start-Sleep -Milliseconds 400

# Confirm write
$result = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue
if ($result) {
    Write-Host "Browser preferences synchronized"
}

# Cleanup: remove test registry entry
Remove-Item -Path $registryPath -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_abec472c-9603-482e-875d-36b27fbc6a33  (1 rule(s)) ---------------------
# Intent:    Detect exfiltration of data to public paste/text storage services initiated by n
# Rules:     abec472c-9603-482e-875d-36b27fbc6a33
# Archetype: IT admin workflow

$ErrorActionPreference = 'SilentlyContinue'

# Simulate legitimate IT admin network validation
# Checking connectivity to documentation and advisory resources
$testSites = @(
    'paste.mozilla.org',
    'paste.debian.net',
    'termbin.com'
)

$logPath = Join-Path $env:TEMP 'connectivity_check.log'

foreach ($site in $testSites) {
    try {
        # Use System.Net.Sockets for raw socket simulation that generates Sysmon connection events
        $client = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $client.BeginConnect($site, 80, $null, $null)
        $wait = $asyncResult.AsyncWaitHandle.WaitOne(3000)

        if ($wait) {
            try {
                $client.EndConnect($asyncResult)
                Add-Content -Path $logPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Connection check to $site - SUCCESS"
            } catch {
                Add-Content -Path $logPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Connection check to $site - FAILED"
            }
        } else {
            Add-Content -Path $logPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Connection check to $site - TIMEOUT"
        }
        $client.Close()
    } catch {
        Add-Content -Path $logPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Connection check to $site - ERROR: $_"
    }
    Start-Sleep -Milliseconds 500
}

# Also use Invoke-WebRequest for some requests (legitimate HTTP diagnostics)
try {
    Invoke-WebRequest -Uri 'http://paste.debian.net/health' -UseBasicParsing -TimeoutSec 2 | Out-Null
} catch {}

try {
    Invoke-WebRequest -Uri 'http://termbin.com/api/info' -UseBasicParsing -TimeoutSec 2 | Out-Null
} catch {}

# Cleanup
if (Test-Path $logPath) { Remove-Item -Path $logPath -Force }
Write-Host 'Network connectivity validation completed'

# -- Cluster: singleton_abec472c-9603-482e-875d-36b27fbc6a33  (1 rule(s)) ---------------------
# Intent:    Detect exfiltration of data to public paste/text storage services initiated by n
# Rules:     abec472c-9603-482e-875d-36b27fbc6a33
# Archetype: Software installer/updater workflow

$ErrorActionPreference = 'SilentlyContinue'

# Simulate Windows Update and system service validation checks
# These processes regularly validate connectivity to update and documentation servers

$metadataUrls = @(
    'http://pastebin.com/raw/Q1A2B3C4',  # Simulating update manifest download
    'http://paste.mozilla.org/about',     # Firefox security update documentation
    'http://dpaste.org/latest',           # Public patch notes repository
    'http://paste.debian.net/info'        # Debian package documentation
)

$tempDir = Join-Path $env:TEMP 'update_cache'
if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir | Out-Null }

$manifestLog = Join-Path $tempDir 'manifest_check.txt'
Add-Content -Path $manifestLog -Value "Update metadata validation started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

foreach ($url in $metadataUrls) {
    try {
        # Simulate what wuauclt.exe or other system processes do
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadString($url) | Out-Null
        Add-Content -Path $manifestLog -Value "Metadata retrieved from $(([System.Uri]$url).Host) - OK"
    } catch [System.Net.WebException] {
        Add-Content -Path $manifestLog -Value "Metadata fetch from $(([System.Uri]$url).Host) - Connection timeout or unavailable"
    } catch {
        Add-Content -Path $manifestLog -Value "Metadata fetch from $(([System.Uri]$url).Host) - Error: $($_.Exception.Message)"
    }
    Start-Sleep -Milliseconds 300
}

# Simulate service dependency check - validating that auxiliary services can reach documentation
$serviceCheckLog = Join-Path $tempDir 'service_deps.log'
$serviceDocs = @(
    'http://controlc.com/docs',
    'http://hastebin.com/metadata',
    'http://ghostbin.com/about'
)

foreach ($doc in $serviceDocs) {
    try {
        $http = New-Object System.Net.Http.HttpClient
        $task = $http.GetAsync($doc)
        $task.Wait(2000)
        Add-Content -Path $serviceCheckLog -Value "Service endpoint $(([System.Uri]$doc).Host) - Reachable"
    } catch {
        Add-Content -Path $serviceCheckLog -Value "Service endpoint $(([System.Uri]$doc).Host) - Unreachable"
    }
    Start-Sleep -Milliseconds 250
}

# Cleanup
if (Test-Path $tempDir) { Remove-Item -Path $tempDir -Recurse -Force }
Write-Host 'System update and service validation completed'

# -- Cluster: singleton_abec472c-9603-482e-875d-36b27fbc6a33  (1 rule(s)) ---------------------
# Intent:    Detect exfiltration of data to public paste/text storage services initiated by n
# Rules:     abec472c-9603-482e-875d-36b27fbc6a33
# Archetype: User-driven workflow

$ErrorActionPreference = 'SilentlyContinue'

# Simulate legitimate developer workflow: diagnostic bundle sharing
# Developers often use paste services for temporary code/log sharing during troubleshooting

$workDir = Join-Path $env:TEMP 'diagnostic_bundle'
if (-not (Test-Path $workDir)) { New-Item -ItemType Directory -Path $workDir | Out-Null }

# Create synthetic diagnostic data (not sensitive, just operational logs)
$diagnosticLog = Join-Path $workDir 'system_health.txt'
@"
Diagnostic Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
OS Version: $([System.Environment]::OSVersion.VersionString)
Available Memory: $(([System.Math]::Round((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)) GB
Disk Space: $(([System.Math]::Round((Get-Volume -DriveLetter C).SizeRemaining / 1GB, 2)) GB free on C:
Network Interfaces: $(Get-NetAdapter | Measure-Object | Select-Object -ExpandProperty Count) active
"@ | Set-Content -Path $diagnosticLog

# Simulate uploading diagnostic data to temporary sharing services
# This is a realistic workflow where logs are temporarily staged for access
$pasteTargets = @(
    @{ url = 'http://rentry.co/api/upload'; description = 'temporary snippet storage' },
    @{ url = 'http://justpaste.it/documents'; description = 'shared paste repository' },
    @{ url = 'http://pasteio.com/send'; description = 'ephemeral text sharing' },
    @{ url = 'http://privatebin.net/send'; description = 'temporary private share' }
)

$uploadLog = Join-Path $workDir 'upload_attempts.log'
Add-Content -Path $uploadLog -Value "Diagnostic bundle upload initiated at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

foreach ($target in $pasteTargets) {
    try {
        # Simulate multipart form data upload (realistic for paste services)
        $content = Get-Content -Path $diagnosticLog -Raw
        $boundary = [System.Guid]::NewGuid().ToString()

        $http = New-Object System.Net.Http.HttpClient
        $uri = New-Object System.Uri($target.url)

        # Attempt connection to staging service
        $getTask = $http.GetAsync($uri)
        $getTask.Wait(1500)

        Add-Content -Path $uploadLog -Value "Target $($target.description) at $($target.url) - Status attempted"
    } catch {
        Add-Content -Path $uploadLog -Value "Target $($target.description) - Connection failed (expected in isolated CI)"
    }
    Start-Sleep -Milliseconds 400
}

# List uploaded bundle references (simulating what the tool reports back)
$refLog = Join-Path $workDir 'upload_refs.txt'
Add-Content -Path $refLog -Value "Diagnostic bundles staged for remote access:"
1..3 | ForEach-Object {
    Add-Content -Path $refLog -Value "  Reference ID: reference-$([System.Guid]::NewGuid().ToString().Substring(0, 8))"
}

# Cleanup
Start-Sleep -Milliseconds 500
if (Test-Path $workDir) { Remove-Item -Path $workDir -Recurse -Force }
Write-Host 'Developer diagnostic workflow completed'


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
