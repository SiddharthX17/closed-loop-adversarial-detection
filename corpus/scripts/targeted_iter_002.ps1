# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_18e283b5-d9f3-43e4-a887-df05c713a836  (1 rule(s)) ---------------------
# Intent:    Detecting mshta.exe execution with script file or URL arguments, which is a know
# Rules:     18e283b5-d9f3-43e4-a887-df05c713a836
# Archetype: IT admin workflow

# IT Admin: Execute system inventory collection HTA
$htaPath = Join-Path $env:TEMP 'inventory_collector.hta'
$htaContent = @'
<html>
<head>
<title>System Inventory</title>
<script language="VBScript">
Dim fso, shell, sysInfo
Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")
sysInfo = shell.ExpandEnvironmentStrings("%COMPUTERNAME%") & " - " & shell.ExpandEnvironmentStrings("%OS%")
MsgBox sysInfo
window.close()
</script>
</head>
<body>
<p>Collecting inventory...</p>
</body>
</html>
'@

Set-Content -Path $htaPath -Value $htaContent -Encoding UTF8

# Execute the HTA application
& mshta.exe $htaPath | Out-Null

# Clean up
Start-Sleep -Milliseconds 500
Remove-Item -Path $htaPath -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_18e283b5-d9f3-43e4-a887-df05c713a836  (1 rule(s)) ---------------------
# Intent:    Detecting mshta.exe execution with script file or URL arguments, which is a know
# Rules:     18e283b5-d9f3-43e4-a887-df05c713a836
# Archetype: Software installer/updater workflow

# Software Installer: Execute HTML-based setup configuration dialog
$htmlPath = Join-Path $env:TEMP 'setup_config.html'
$htmlContent = @'
<!DOCTYPE html>
<html>
<head>
<title>Installation Configuration</title>
<script>
window.onload = function() {
  var config = "Installation path: " + document.location;
  window.close();
};
</script>
</head>
<body>
<h1>Product Setup</h1>
<p>Configuring installation parameters...</p>
</body>
</html>
'@

Set-Content -Path $htmlPath -Value $htmlContent -Encoding UTF8

# Execute the HTML configuration interface
& mshta.exe $htmlPath | Out-Null

# Clean up installation artifacts
Start-Sleep -Milliseconds 500
Remove-Item -Path $htmlPath -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_18e283b5-d9f3-43e4-a887-df05c713a836  (1 rule(s)) ---------------------
# Intent:    Detecting mshta.exe execution with script file or URL arguments, which is a know
# Rules:     18e283b5-d9f3-43e4-a887-df05c713a836
# Archetype: User-driven workflow

# User: Open HTML-based application tool
$appPath = Join-Path $env:TEMP 'app_launcher.html'
$appContent = @'
<!DOCTYPE html>
<html>
<head>
<title>Application Launcher</title>
<hta:application id="AppLauncher" applicationName="Tool"/>
<script>
function onLoad() {
  document.body.innerHTML = '<p>Loading application...</p>';
  window.setTimeout(function() { window.close(); }, 1000);
}
</script>
</head>
<body onload="onLoad()">
<p>Application interface</p>
</body>
</html>
'@

Set-Content -Path $appPath -Value $appContent -Encoding UTF8

# Execute the application through mshta
& mshta.exe $appPath | Out-Null

# Clean up
Start-Sleep -Milliseconds 500
Remove-Item -Path $appPath -Force -ErrorAction SilentlyContinue


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
