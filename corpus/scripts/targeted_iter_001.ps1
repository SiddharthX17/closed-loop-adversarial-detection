# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   3  |  Feasible: 3  |  Variants: 9
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_b85f895b-3460-4e0c-bbab-407794e449c6  (1 rule(s)) ---------------------
# Intent:    Detect execution of Windows system binaries (lsass.exe, svchost.exe, cmd.exe, po
# Rules:     b85f895b-3460-4e0c-bbab-407794e449c6
# Archetype: IT admin workflow

$diagFolder = Join-Path $env:TEMP 'SysAdmin_Diag_20250108'
if (-not (Test-Path $diagFolder)) { New-Item -ItemType Directory -Path $diagFolder -Force | Out-Null }

# Stage system diagnostic tools in temporary working area for batch execution
$sourceTools = @(
    @{ Source = 'C:\Windows\System32\cmd.exe'; Dest = 'cmd_local.exe' },
    @{ Source = 'C:\Windows\System32\net.exe'; Dest = 'net_local.exe' },
    @{ Source = 'C:\Windows\System32\reg.exe'; Dest = 'reg_local.exe' },
    @{ Source = 'C:\Windows\System32\sc.exe'; Dest = 'sc_local.exe' }
)

foreach ($tool in $sourceTools) {
    $destPath = Join-Path $diagFolder $tool.Dest
    if (Test-Path $tool.Source) {
        Copy-Item -Path $tool.Source -Destination $destPath -Force
    }
}

# Execute diagnostic commands using locally staged copies
# Real use case: offline compliance checking, diagnostic collection in isolated environment
$diagResult = Join-Path $diagFolder 'diag_output.txt'

$cmdPath = Join-Path $diagFolder 'cmd_local.exe'
if (Test-Path $cmdPath) {
    Start-Process -FilePath $cmdPath -ArgumentList @('/c', 'systeminfo') -RedirectStandardOutput $diagResult -Wait -NoNewWindow
}

$netPath = Join-Path $diagFolder 'net_local.exe'
if (Test-Path $netPath) {
    Start-Process -FilePath $netPath -ArgumentList @('user') -Wait -NoNewWindow
}

$regPath = Join-Path $diagFolder 'reg_local.exe'
if (Test-Path $regPath) {
    Start-Process -FilePath $regPath -ArgumentList @('query', 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\svchost') -Wait -NoNewWindow
}

$scPath = Join-Path $diagFolder 'sc_local.exe'
if (Test-Path $scPath) {
    Start-Process -FilePath $scPath -ArgumentList @('query', 'state=running') -Wait -NoNewWindow
}

# Cleanup staging directory and all copied tools
Start-Sleep -Seconds 2
if (Test-Path $diagFolder) {
    Remove-Item -Path $diagFolder -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_b85f895b-3460-4e0c-bbab-407794e449c6  (1 rule(s)) ---------------------
# Intent:    Detect execution of Windows system binaries (lsass.exe, svchost.exe, cmd.exe, po
# Rules:     b85f895b-3460-4e0c-bbab-407794e449c6
# Archetype: Software installer/updater workflow

$appInstallDir = Join-Path $env:TEMP 'MyApp_Installer_Phase2'
if (-not (Test-Path $appInstallDir)) { New-Item -ItemType Directory -Path $appInstallDir -Force | Out-Null }

# Simulate application installer that bundles system configuration tools
$bundledTools = @(
    @{ Source = 'C:\Windows\System32\powershell.exe'; Dest = 'config_engine.exe' },
    @{ Source = 'C:\Windows\System32\msiexec.exe'; Dest = 'pkg_installer.exe' },
    @{ Source = 'C:\Windows\System32\wevtutil.exe'; Dest = 'log_collector.exe' },
    @{ Source = 'C:\Windows\System32\schtasks.exe'; Dest = 'schedule_mgr.exe' }
)

# Extract bundled tools to installation staging area
foreach ($tool in $bundledTools) {
    $destPath = Join-Path $appInstallDir $tool.Dest
    if (Test-Path $tool.Source) {
        Copy-Item -Path $tool.Source -Destination $destPath -Force
    }
}

# Application initialization: configure system logging
$configScript = Join-Path $appInstallDir 'init_config.ps1'
"Write-Host 'Initializing system configuration...'" | Set-Content -Path $configScript

$pwshPath = Join-Path $appInstallDir 'config_engine.exe'
if (Test-Path $pwshPath) {
    Start-Process -FilePath $pwshPath -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $configScript) -Wait -NoNewWindow
}

# Installer stage 2: query event logs (using bundled tool)
$logPath = Join-Path $appInstallDir 'setup_events.evtx'
$wevtPath = Join-Path $appInstallDir 'log_collector.exe'
if (Test-Path $wevtPath) {
    Start-Process -FilePath $wevtPath -ArgumentList @('query-events', 'System', '/c:5') -Wait -NoNewWindow
}

# Installer stage 3: register scheduled maintenance task
$schPath = Join-Path $appInstallDir 'schedule_mgr.exe'
if (Test-Path $schPath) {
    Start-Process -FilePath $schPath -ArgumentList @('/query', '/tn', 'Microsoft\\Windows\\Defrag\\ScheduledDefrag') -Wait -NoNewWindow
}

# Installer cleanup: remove staging directory
Start-Sleep -Seconds 2
if (Test-Path $appInstallDir) {
    Remove-Item -Path $appInstallDir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_b85f895b-3460-4e0c-bbab-407794e449c6  (1 rule(s)) ---------------------
# Intent:    Detect execution of Windows system binaries (lsass.exe, svchost.exe, cmd.exe, po
# Rules:     b85f895b-3460-4e0c-bbab-407794e449c6
# Archetype: User-driven workflow

$portableToolDir = Join-Path $env:USERPROFILE 'Downloads' 'SecurityKit_Portable'
if (-not (Test-Path $portableToolDir)) { New-Item -ItemType Directory -Path $portableToolDir -Force | Out-Null }

# User downloads and extracts portable tool kit containing system inspection utilities
$toolSet = @(
    @{ Source = 'C:\Windows\System32\tasklist.exe'; Dest = 'tasklist.exe' },
    @{ Source = 'C:\Windows\System32\taskkill.exe'; Dest = 'taskkill.exe' },
    @{ Source = 'C:\Windows\System32\wmic.exe'; Dest = 'wmic.exe' },
    @{ Source = 'C:\Windows\System32\netsh.exe'; Dest = 'netsh.exe' },
    @{ Source = 'C:\Windows\System32\ipconfig.exe'; Dest = 'ipconfig.exe' }
)

foreach ($tool in $toolSet) {
    $destPath = Join-Path $portableToolDir $tool.Dest
    if (Test-Path $tool.Source) {
        Copy-Item -Path $tool.Source -Destination $destPath -Force
    }
}

# User runs portable toolkit operations
$reportDir = Join-Path $portableToolDir 'reports'
if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }

# Inspect running processes
$processReport = Join-Path $reportDir 'processes.txt'
$taskListPath = Join-Path $portableToolDir 'tasklist.exe'
if (Test-Path $taskListPath) {
    Start-Process -FilePath $taskListPath -RedirectStandardOutput $processReport -Wait -NoNewWindow
}

# Check network configuration
$netshPath = Join-Path $portableToolDir 'netsh.exe'
if (Test-Path $netshPath) {
    Start-Process -FilePath $netshPath -ArgumentList @('interface', 'ip', 'show', 'config') -Wait -NoNewWindow
}

# Query network interfaces via WMI
$wmicPath = Join-Path $portableToolDir 'wmic.exe'
if (Test-Path $wmicPath) {
    Start-Process -FilePath $wmicPath -ArgumentList @('nic', 'get', 'Description') -Wait -NoNewWindow
}

# Cleanup: user deletes portable toolkit after use
Start-Sleep -Seconds 2
if (Test-Path $portableToolDir) {
    Remove-Item -Path $portableToolDir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_1ed71a2a-79ac-482a-baef-7ef4cb647b81  (1 rule(s)) ---------------------
# Intent:    Detect attackers staging encoded payloads in registry as part of scheduled task 
# Rules:     1ed71a2a-79ac-482a-baef-7ef4cb647b81
# Archetype: Software installer/updater workflow

$regPath = 'HKCU:\Software\TestInstaller'
$regValue = 'ConfigData'

# Create test registry path
if (-not (Test-Path $regPath)) {
  New-Item -Path $regPath -Force | Out-Null
}

# Simulate realistic base64-encoded configuration data (16+ chars, realistic length)
# This represents serialized installer settings: product ID, version, install paths, etc.
$configPayload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('InstallDir=C:\\Program Files\\TestApp|ProductID=12345|Version=1.0.0|Features=Full'))

# Write as would occur during msiexec installation
Set-ItemProperty -Path $regPath -Name $regValue -Value $configPayload -Type String -Force

# Verify write occurred
$written = Get-ItemProperty -Path $regPath -Name $regValue -ErrorAction SilentlyContinue
if ($written.$regValue -match '^[a-zA-Z0-9+/]{16,}={0,2}$') {
  Write-Host 'Configuration staged in registry during installation'
}

# Simulate additional hex-encoded metadata (product key validation, licensing info)
$hexPayload = '5469616C5678352E31202D206C6973656E7365206D6574616461746120636F6E74656E74'
Set-ItemProperty -Path $regPath -Name 'LicenseData' -Value $hexPayload -Type String -Force

Start-Sleep -Seconds 1

# Cleanup - legitimate installers remove temporary staging data
if (Test-Path $regPath) {
  Remove-Item -Path $regPath -Force -Recurse -ErrorAction SilentlyContinue
}

Write-Host 'Installation configuration workflow completed'

# -- Cluster: singleton_1ed71a2a-79ac-482a-baef-7ef4cb647b81  (1 rule(s)) ---------------------
# Intent:    Detect attackers staging encoded payloads in registry as part of scheduled task 
# Rules:     1ed71a2a-79ac-482a-baef-7ef4cb647b81
# Archetype: IT admin workflow

$regPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
$regValue = 'TempDiagnosticData'

# Simulate administrative task configuration data
# This represents encoded diagnostic settings or WMI event subscription parameters
$diagnosticData = @{
  'DiagnosticFlags' = 'ENABLE_DEEP_SCAN|INCLUDE_NETWORK_ADAPTERS|VERBOSE_LOGGING'
  'ServiceConfig' = 'STARTUP_TYPE=DELAYED|TIMEOUT=30000|RETRY_COUNT=3'
  'Timestamp' = (Get-Date -Format 'o')
}

# Convert to base64 representation (realistic for configuration serialization)
$jsonConfig = $diagnosticData | ConvertTo-Json -Compress
$encodedConfig = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($jsonConfig))

# Write encoded configuration to registry (would be written by svchost or wmiprvse)
Set-ItemProperty -Path $regPath -Name $regValue -Value $encodedConfig -Type String -Force

# Store complementary hex-encoded metadata (binary flags or checksums)
$checksum = [BitConverter]::ToString([System.Text.Encoding]::UTF8.GetBytes('ChecksumValue')).Replace('-', '')
Set-ItemProperty -Path $regPath -Name 'ConfigChecksum' -Value $checksum -Type String -Force

Start-Sleep -Seconds 1

# Administrative cleanup - remove diagnostic staging after processing
Remove-ItemProperty -Path $regPath -Name $regValue -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $regPath -Name 'ConfigChecksum' -ErrorAction SilentlyContinue

Write-Host 'Administrative configuration workflow completed'

# -- Cluster: singleton_1ed71a2a-79ac-482a-baef-7ef4cb647b81  (1 rule(s)) ---------------------
# Intent:    Detect attackers staging encoded payloads in registry as part of scheduled task 
# Rules:     1ed71a2a-79ac-482a-baef-7ef4cb647b81
# Archetype: User-driven workflow

$regPath = 'HKCU:\Software\Microsoft\Accessibility'
$regValue = 'ToolPreferences'

# Simulate user preference data encoded for storage
# This represents realistic preference serialization: magnifier settings, font scales, color themes
$preferences = @{
  'MagnificationLevel' = '2.5'
  'ContrastMode' = 'HIGH'
  'FontScale' = '120'
  'LastUsed' = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
}

# Convert to base64 for storage (realistic preference serialization)
$prefJson = $preferences | ConvertTo-Json -Compress
$encodedPrefs = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($prefJson))

# Write user preferences (simulates utility writing from system32 context)
Set-ItemProperty -Path $regPath -Name $regValue -Value $encodedPrefs -Type String -Force

# Store complementary metadata as hex (font IDs, palette codes)
$fontMetadata = '464F4E545F49443D433A255C5769646F77735C466F6E7473'
Set-ItemProperty -Path $regPath -Name 'FontMetadata' -Value $fontMetadata -Type String -Force

Start-Sleep -Seconds 1

# User preference cleanup
Remove-ItemProperty -Path $regPath -Name $regValue -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $regPath -Name 'FontMetadata' -ErrorAction SilentlyContinue

Write-Host 'User preference workflow completed'

# -- Cluster: singleton_96c4cfbc-baad-4170-9a71-df706ce57e0b  (1 rule(s)) ---------------------
# Intent:    Detect data exfiltration via text sharing and paste sites by monitoring outbound
# Rules:     96c4cfbc-baad-4170-9a71-df706ce57e0b
# Archetype: User-driven workflow

# Developer workflow: accessing shared code snippet via GitHub Gist
$vscodeInstalled = Test-Path "C:\Users\$env:USERNAME\AppData\Local\Programs\Microsoft VS Code\Code.exe"

if ($vscodeInstalled) {
    # Simulate opening VS Code and accessing a Gist URL
    # This generates network connections to gist.github.com and gist.githubusercontent.com
    $gistUrl = "https://gist.github.com/some-user/some-gist-id"

    # Use curl (available on windows-latest) to fetch the Gist HTML page
    # This mimics what VS Code would do when a user pastes a Gist link or the IDE resolves remote content
    Write-Host "Fetching shared code snippet from GitHub Gist..."
    try {
        $response = Invoke-WebRequest -Uri $gistUrl -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            Write-Host "Successfully accessed Gist resource"
        }
    } catch {
        # Network may not be available or URL may not resolve; that's ok for this test
        Write-Host "Gist access attempt completed (network unavailable in test environment)"
    }

    # Also fetch the raw content from gist.githubusercontent.com
    try {
        $rawUrl = "https://gist.githubusercontent.com/some-user/some-gist-id/raw"
        $rawResponse = Invoke-WebRequest -Uri $rawUrl -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
    } catch {
        Write-Host "Raw Gist access attempt completed"
    }
} else {
    Write-Host "VS Code not installed; simulating network connection pattern with curl"
    # Use curl directly to simulate the network behavior that would be observed
    & cmd /c "curl -s -m 5 https://gist.github.com/some-user/some-gist-id 1>nul 2>&1"
    & cmd /c "curl -s -m 5 https://gist.githubusercontent.com/some-user/some-gist-id/raw 1>nul 2>&1"
}

Write-Host "Developer Gist access workflow completed"

# -- Cluster: singleton_96c4cfbc-baad-4170-9a71-df706ce57e0b  (1 rule(s)) ---------------------
# Intent:    Detect data exfiltration via text sharing and paste sites by monitoring outbound
# Rules:     96c4cfbc-baad-4170-9a71-df706ce57e0b
# Archetype: Software installer/updater workflow

# JetBrains IDE workflow: checking for updates and fetching documentation snippets
$jetbrainsPath = Get-ChildItem -Path "C:\Users\$env:USERNAME\AppData\Local\Programs" -Filter "*JetBrains*" -Directory -ErrorAction SilentlyContinue | Select-Object -First 1

if ($jetbrainsPath) {
    Write-Host "Found JetBrains installation at $($jetbrainsPath.FullName)"
} else {
    Write-Host "JetBrains IDE not found; simulating plugin update check network activity"
}

# Simulate IDE checking for code examples and documentation from CDN-hosted paste services
# These are legitimate requests that real IDEs make for code completion, snippets, and diagnostics
$pasteServices = @(
    "https://gist.github.com/api/v1/gists",
    "https://raw.githubusercontent.com/jetbrains-plugins/snippets/main/index.json",
    "https://pastebin.com/raw_api.php",
    "https://paste.debian.net/"
)

foreach ($service in $pasteServices) {
    Write-Host "Checking documentation service: $service"
    try {
        # Simulate IDE making HTTP request to fetch code snippets or diagnostics
        $response = Invoke-WebRequest -Uri $service -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
        Write-Host "Service check completed"
    } catch {
        # Expected in offline CI environments; request was still generated
        Write-Host "Request attempt made to $service"
    }
}

# Also test direct network connection patterns that Sysmon monitors
try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
    $tcpClient = New-Object System.Net.Sockets.TcpClient

    # Attempt connection to paste.debian.net on port 443 (HTTPS)
    Write-Host "Initiating TCP connection to paste.debian.net:443"
    $tcpClient.Connect("paste.debian.net", 443)
    if ($tcpClient.Connected) {
        Write-Host "Connected successfully"
        $tcpClient.Close()
    }
} catch {
    Write-Host "Connection attempt initiated (network may be restricted in CI environment)"
}

Write-Host "JetBrains IDE update check workflow completed"

# -- Cluster: singleton_96c4cfbc-baad-4170-9a71-df706ce57e0b  (1 rule(s)) ---------------------
# Intent:    Detect data exfiltration via text sharing and paste sites by monitoring outbound
# Rules:     96c4cfbc-baad-4170-9a71-df706ce57e0b
# Archetype: IT admin workflow

# IT admin workflow: using GitHub Desktop for repository operations and fetching documentation
$githubDesktopPath = Get-ChildItem -Path "C:\Users\$env:USERNAME\AppData\Local\Programs\GitHub Desktop\*" -Filter "*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1

if ($githubDesktopPath) {
    Write-Host "GitHub Desktop found at: $($githubDesktopPath.FullName)"
} else {
    Write-Host "GitHub Desktop not installed; simulating admin network activity"
}

# Admin accessing code repositories and documentation
$adminTargets = @(
    "https://gist.github.com/search?q=powershell",
    "https://api.github.com/gists",
    "https://gist.githubusercontent.com/admin-user/deployment-scripts/main/deploy.ps1",
    "https://bin.bpaste.net/"
)

Write-Host "Admin initiating documentation and repository access..."
foreach ($target in $adminTargets) {
    try {
        Write-Host "Accessing: $target"
        $webRequest = Invoke-WebRequest -Uri $target -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
    } catch {
        # Request was initiated even if not completed
        Write-Host "Request to $target initiated"
    }
}

# Simulate direct TCP connection monitoring from admin tools
try {
    $hostnames = @("gist.github.com", "paste.debian.net", "bin.bpaste.net")
    foreach ($hostname in $hostnames) {
        Write-Host "Testing connection to $hostname on port 443"
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $connectionTask = $client.ConnectAsync($hostname, 443)
            $completed = $connectionTask.Wait(2000)  # 2 second timeout

            if ($completed -and $client.Connected) {
                Write-Host "Connected to $hostname"
                $client.Close()
            } else {
                Write-Host "Connection attempt to $hostname initiated"
                $client.Close()
            }
        } catch {
            Write-Host "Connection attempt to $hostname generated network event"
        }
    }
} catch {
    Write-Host "Network access simulation completed"
}

Write-Host "Admin documentation and repository access workflow completed"


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
