# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   3  |  Feasible: 3  |  Variants: 9
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_6410bf60-1ae1-439d-9b68-ed303601110c  (1 rule(s)) ---------------------
# Intent:    Attackers use SDelete (Secure Delete) to irreversibly wipe files and cover track
# Rules:     6410bf60-1ae1-439d-9b68-ed303601110c
# Archetype: IT admin workflow

$tempDir = [System.IO.Path]::GetTempPath()
$sdeleteDir = Join-Path $tempDir 'Sysinternals'
if (-not (Test-Path $sdeleteDir)) {
  New-Item -ItemType Directory -Path $sdeleteDir -Force | Out-Null
}
$sdeleteZip = Join-Path $sdeleteDir 'SDelete.zip'
$sdeleteExe = Join-Path $sdeleteDir 'sdelete.exe'
$testFile = Join-Path $sdeleteDir 'sensitive_temp_data.txt'

try {
  if (-not (Test-Path $sdeleteExe)) {
    Add-Type -AssemblyName System.Net.Http
    $httpClient = New-Object System.Net.Http.HttpClient
    try {
      $response = $httpClient.GetAsync('https://download.sysinternals.com/files/SDelete.zip').Result
      if ($response.IsSuccessStatusCode) {
        $content = $response.Content.ReadAsByteArrayAsync().Result
        [System.IO.File]::WriteAllBytes($sdeleteZip, $content)

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($sdeleteZip, $sdeleteDir)
      }
    } finally {
      $httpClient.Dispose()
    }
  }

  if (Test-Path $sdeleteExe) {
    'Confidential audit log data to be securely deleted' | Out-File $testFile -Encoding UTF8 -Force

    $proc = Start-Process -FilePath $sdeleteExe -ArgumentList '-accepteula', '-p', '2', $testFile -NoNewWindow -PassThru -Wait

    if ($proc.ExitCode -eq 0) {
      Write-Host 'Secure deletion completed successfully'
    }
  }
} finally {
  if (Test-Path $sdeleteDir) {
    Remove-Item -Path $sdeleteDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# -- Cluster: singleton_6410bf60-1ae1-439d-9b68-ed303601110c  (1 rule(s)) ---------------------
# Intent:    Attackers use SDelete (Secure Delete) to irreversibly wipe files and cover track
# Rules:     6410bf60-1ae1-439d-9b68-ed303601110c
# Archetype: Software installer/updater workflow

$tempDir = [System.IO.Path]::GetTempPath()
$maintenanceDir = Join-Path $tempDir 'MaintenanceAgent'
if (-not (Test-Path $maintenanceDir)) {
  New-Item -ItemType Directory -Path $maintenanceDir -Force | Out-Null
}

$sdelete64Exe = Join-Path $maintenanceDir 'sdelete64.exe'
$cacheDir = Join-Path $maintenanceDir 'cache'
if (-not (Test-Path $cacheDir)) {
  New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
}

$cacheFile1 = Join-Path $cacheDir 'update_package_v3.2.1.tmp'
$cacheFile2 = Join-Path $cacheDir 'install_credentials.tmp'

try {
  if (-not (Test-Path $sdelete64Exe)) {
    Add-Type -AssemblyName System.Net.Http
    $httpClient = New-Object System.Net.Http.HttpClient
    try {
      $response = $httpClient.GetAsync('https://download.sysinternals.com/files/SDelete.zip').Result
      if ($response.IsSuccessStatusCode) {
        $content = $response.Content.ReadAsByteArrayAsync().Result
        $zipPath = Join-Path $maintenanceDir 'SDelete.zip'
        [System.IO.File]::WriteAllBytes($zipPath, $content)

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $maintenanceDir)
        Remove-Item $zipPath -Force
      }
    } finally {
      $httpClient.Dispose()
    }
  }

  if (Test-Path $sdelete64Exe) {
    'update cache data' | Out-File $cacheFile1 -Encoding UTF8 -Force
    'temporary credentials' | Out-File $cacheFile2 -Encoding UTF8 -Force

    $proc = Start-Process -FilePath $sdelete64Exe -ArgumentList '-accepteula', '-q', $cacheDir -NoNewWindow -PassThru -Wait
  }
} finally {
  if (Test-Path $maintenanceDir) {
    Remove-Item -Path $maintenanceDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# -- Cluster: singleton_6410bf60-1ae1-439d-9b68-ed303601110c  (1 rule(s)) ---------------------
# Intent:    Attackers use SDelete (Secure Delete) to irreversibly wipe files and cover track
# Rules:     6410bf60-1ae1-439d-9b68-ed303601110c
# Archetype: Document/file operation workflow

$tempDir = [System.IO.Path]::GetTempPath()
$workDir = Join-Path $tempDir 'DocumentSanitization'
if (-not (Test-Path $workDir)) {
  New-Item -ItemType Directory -Path $workDir -Force | Out-Null
}

$sdeleteExe = Join-Path $workDir 'sdelete.exe'
$docDir = Join-Path $workDir 'expired_documents'
if (-not (Test-Path $docDir)) {
  New-Item -ItemType Directory -Path $docDir -Force | Out-Null
}

$expiredDoc1 = Join-Path $docDir 'Q1_2023_Report.txt'
$expiredDoc2 = Join-Path $docDir 'Contractor_NDA_2022.txt'

try {
  if (-not (Test-Path $sdeleteExe)) {
    Add-Type -AssemblyName System.Net.Http
    $httpClient = New-Object System.Net.Http.HttpClient
    try {
      $response = $httpClient.GetAsync('https://download.sysinternals.com/files/SDelete.zip').Result
      if ($response.IsSuccessStatusCode) {
        $content = $response.Content.ReadAsByteArrayAsync().Result
        $zipPath = Join-Path $workDir 'SDelete.zip'
        [System.IO.File]::WriteAllBytes($zipPath, $content)

        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $workDir)
        Remove-Item $zipPath -Force
      }
    } finally {
      $httpClient.Dispose()
    }
  }

  if (Test-Path $sdeleteExe) {
    'Quarterly report 2023 - retention period expired' | Out-File $expiredDoc1 -Encoding UTF8 -Force
    'Contractor agreement - contract concluded in 2022' | Out-File $expiredDoc2 -Encoding UTF8 -Force

    $proc = Start-Process -FilePath $sdeleteExe -ArgumentList '-accepteula', '-p', '3', $expiredDoc1 -NoNewWindow -PassThru -Wait
    if (Test-Path $expiredDoc2) {
      $proc = Start-Process -FilePath $sdeleteExe -ArgumentList '-accepteula', '-p', '3', $expiredDoc2 -NoNewWindow -PassThru -Wait
    }
  }
} finally {
  if (Test-Path $workDir) {
    Remove-Item -Path $workDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# -- Cluster: singleton_f519892c-4d3a-48c8-ba36-b8811b3ba8e7  (1 rule(s)) ---------------------
# Intent:    Disable or suppress PowerShell command history and transcript logging to hide co
# Rules:     f519892c-4d3a-48c8-ba36-b8811b3ba8e7
# Archetype: IT admin workflow

$profilePath = $profile.CurrentUserAllHosts
if (-not (Test-Path (Split-Path $profilePath))) {
    New-Item -ItemType Directory -Path (Split-Path $profilePath) -Force | Out-Null
}

$profileContent = @'
# Enterprise PowerShell profile for standardized hardening
# Disable local command history in favor of centralized transcript logging
Set-PSReadLineOption -HistorySaveStyle SaveNothing
Set-PSReadLineOption -HistoryNoDuplicates:$true
Set-PSReadLineOption -CommandValidationHandler {
    param([System.Management.Automation.Language.CommandAst]$CommandAst)
    # Audit-grade history management
}
'@

Add-Content -Path $profilePath -Value $profileContent -ErrorAction SilentlyContinue

# Verify the setting applied
$PSReadLineOptions = Get-PSReadLineOption
Write-Host "Profile hardening applied. HistorySaveStyle: $($PSReadLineOptions.HistorySaveStyle)"

# Clean up: Remove the profile additions
if (Test-Path $profilePath) {
    Remove-Item -Path $profilePath -Force -ErrorAction SilentlyContinue
}

Start-Sleep -Milliseconds 500

# -- Cluster: singleton_f519892c-4d3a-48c8-ba36-b8811b3ba8e7  (1 rule(s)) ---------------------
# Intent:    Disable or suppress PowerShell command history and transcript logging to hide co
# Rules:     f519892c-4d3a-48c8-ba36-b8811b3ba8e7
# Archetype: User-driven workflow

# User configuring PowerShell environment for secure credential handling
$tempHistorySuppression = @{
    HistorySaveStyle = 'SaveNothing'
    HistoryNoDuplicates = $true
    MaximumHistoryCount = 32
}

foreach ($key in $tempHistorySuppression.Keys) {
    Set-PSReadLineOption -HistorySaveStyle SaveNothing -ErrorAction SilentlyContinue
}

Write-Host "Configuring secure PowerShell session"
$currentSettings = Get-PSReadLineOption | Select-Object HistorySaveStyle, HistoryNoDuplicates
Write-Host "Current HistorySaveStyle: $($currentSettings.HistorySaveStyle)"

# Simulate typical developer activity: running commands that would normally be logged
Get-ChildItem -Path $env:TEMP | Select-Object -First 5
Get-Process pwsh -ErrorAction SilentlyContinue | Select-Object Name, Id

Start-Sleep -Milliseconds 300

# -- Cluster: singleton_f519892c-4d3a-48c8-ba36-b8811b3ba8e7  (1 rule(s)) ---------------------
# Intent:    Disable or suppress PowerShell command history and transcript logging to hide co
# Rules:     f519892c-4d3a-48c8-ba36-b8811b3ba8e7
# Archetype: Software installer/updater workflow

$configPath = Join-Path -Path $env:PROGRAMDATA -ChildPath 'PowerShellConfig'
if (-not (Test-Path $configPath)) {
    New-Item -ItemType Directory -Path $configPath -Force | Out-Null
}

$configFile = Join-Path -Path $configPath -ChildPath 'bootstrap-config.ps1'
$bootstrapConfig = @'
# Automated deployment bootstrap configuration
# Centralized logging is handled by deployment agent
# Disable local PSReadLine history to prevent redundant logs

try {
    Set-PSReadLineOption -HistorySaveStyle SaveNothing -ErrorAction Stop
    Set-PSReadLineOption -HistoryNoDuplicates -ErrorAction Stop
} catch {
    Write-Warning "Failed to configure PSReadLine: $_"
}

# Enable transcript logging to centralized location instead
$transcriptPath = Join-Path -Path $env:PROGRAMDATA -ChildPath 'Logs' | Join-Path -ChildPath 'powershell_transcript.txt'
if (-not (Test-Path (Split-Path $transcriptPath))) {
    New-Item -ItemType Directory -Path (Split-Path $transcriptPath) -Force | Out-Null
}
Start-Transcript -Path $transcriptPath -Append -ErrorAction SilentlyContinue
'@

Set-Content -Path $configFile -Value $bootstrapConfig -Force

# Execute the bootstrap config
& $configFile

$readlineConfig = Get-PSReadLineOption
Write-Host "Bootstrap deployment complete. History setting: $($readlineConfig.HistorySaveStyle)"

Stop-Transcript -ErrorAction SilentlyContinue

# Clean up bootstrap artifacts
Remove-Item -Path $configFile -Force -ErrorAction SilentlyContinue
Remove-Item -Path $configPath -Force -ErrorAction SilentlyContinue

Start-Sleep -Milliseconds 300

# -- Cluster: singleton_60e31fac-1809-4dd0-8c29-7e7b1638d56d  (1 rule(s)) ---------------------
# Intent:    Detects LOLBin tools (mshta.exe, rundll32.exe) initiating outbound network conne
# Rules:     60e31fac-1809-4dd0-8c29-7e7b1638d56d
# Archetype: IT admin workflow

$htaFile = Join-Path $env:TEMP "network_diag_$(Get-Random).hta"
$htaContent = @"
<html>
<head><title>Network Diagnostics</title></head>
<body>
<script language="VBScript">
Set objShell = CreateObject("WScript.Shell")
Set objExec = objShell.Exec("cmd /c nslookup microsoft.com 8.8.8.8")
WScript.Echo "DNS lookup executed"
self.close
</script>
</body>
</html>
"@
Set-Content -Path $htaFile -Value $htaContent -Force
Start-Process -FilePath "mshta.exe" -ArgumentList $htaFile -Wait -NoNewWindow
Start-Sleep -Milliseconds 500
Remove-Item -Path $htaFile -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_60e31fac-1809-4dd0-8c29-7e7b1638d56d  (1 rule(s)) ---------------------
# Intent:    Detects LOLBin tools (mshta.exe, rundll32.exe) initiating outbound network conne
# Rules:     60e31fac-1809-4dd0-8c29-7e7b1638d56d
# Archetype: Software installer/updater workflow

$dllPath = Join-Path $env:TEMP "sysutil_$(Get-Random).dll"
[System.IO.File]::WriteAllBytes($dllPath, [byte[]](0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00))
$proxyUri = [System.Net.WebProxy]::New()
$proxyUri.IsBypassed('https://api.github.com') | Out-Null
$webClient = New-Object System.Net.ServicePointManager
$webClient.SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
Start-Process -FilePath "rundll32.exe" -ArgumentList "$dllPath,UpdateCheck" -NoNewWindow -Wait -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 300
Remove-Item -Path $dllPath -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_60e31fac-1809-4dd0-8c29-7e7b1638d56d  (1 rule(s)) ---------------------
# Intent:    Detects LOLBin tools (mshta.exe, rundll32.exe) initiating outbound network conne
# Rules:     60e31fac-1809-4dd0-8c29-7e7b1638d56d
# Archetype: User-driven workflow

$htaFile = Join-Path $env:TEMP "webutil_$(Get-Random).hta"
$htaContent = @"
<html>
<head><title>Online Help Utility</title></head>
<body>
<h1>Loading content...</h1>
<script language="VBScript">
Set objHttp = CreateObject("MSXML2.XMLHTTP.3.0")
On Error Resume Next
objHttp.Open "GET", "http://www.example.com/help", False
objHttp.Send
Set objHttp = Nothing
self.close
</script>
</body>
</html>
"@
Set-Content -Path $htaFile -Value $htaContent -Force
Start-Process -FilePath "mshta.exe" -ArgumentList $htaFile -Wait -NoNewWindow
Start-Sleep -Milliseconds 500
Remove-Item -Path $htaFile -Force -ErrorAction SilentlyContinue


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
