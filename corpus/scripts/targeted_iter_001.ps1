# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_90670a15-971c-463a-9341-64e8d18bd9b0  (1 rule(s)) ---------------------
# Intent:    Detect cmd.exe executing inline scripts (.vbs, .js, .hta) with redirected output
# Rules:     90670a15-971c-463a-9341-64e8d18bd9b0
# Archetype: Software installer/updater workflow

$tempDir = [System.IO.Path]::GetTempPath()
$scriptPath = Join-Path $tempDir "postinstall_config.vbs"
$vbsContent = @"
Set objFSO = CreateObject("Scripting.FileSystemObject")
strPath = objFSO.GetSpecialFolder(2) & "\\test_config.txt"
Set objFile = objFSO.CreateTextFile(strPath, True)
objFile.WriteLine("Configuration timestamp: " & Now)
objFile.Close
WScript.Echo "Configuration completed"
"@
$vbsContent | Set-Content -Path $scriptPath -Force
try {
  # Simulate a post-install script execution pattern that would be triggered by an MSI installer
  cmd /c "cscript.exe $scriptPath > $tempDir\\install_log.txt"
  Start-Sleep -Milliseconds 500
  # Verify the inline script executed
  if (Test-Path -Path "$tempDir\\test_config.txt") {
    Write-Host "Post-install configuration completed"
  }
}
finally {
  # Cleanup generated files
  if (Test-Path -Path $scriptPath) { Remove-Item -Path $scriptPath -Force }
  if (Test-Path -Path "$tempDir\\install_log.txt") { Remove-Item -Path "$tempDir\\install_log.txt" -Force }
  if (Test-Path -Path "$tempDir\\test_config.txt") { Remove-Item -Path "$tempDir\\test_config.txt" -Force }
}

# -- Cluster: singleton_90670a15-971c-463a-9341-64e8d18bd9b0  (1 rule(s)) ---------------------
# Intent:    Detect cmd.exe executing inline scripts (.vbs, .js, .hta) with redirected output
# Rules:     90670a15-971c-463a-9341-64e8d18bd9b0
# Archetype: IT admin workflow

$tempDir = [System.IO.Path]::GetTempPath()
$htaPath = Join-Path $tempDir "system_remediation.hta"
$htaContent = @"
<html>
<head>
<title>System Remediation</title>
<hta:application applicationname="RemediationApp" version="1.0" border="thin"/>
</head>
<body>
<script language="VBScript">
Sub Window_onLoad
  MsgBox "Remediation task initiated"
  WScript.Quit(0)
End Sub
</script>
</body>
</html>
"@
$htaContent | Set-Content -Path $htaPath -Force
try {
  # Execute HTA via mshta through cmd.exe with output redirection
  $logPath = Join-Path $tempDir "remediation_results.txt"
  cmd /c "mshta.exe $htaPath > $logPath 2>&1"
  Start-Sleep -Milliseconds 1000
  Write-Host "Remediation workflow executed"
}
finally {
  # Cleanup
  if (Test-Path -Path $htaPath) { Remove-Item -Path $htaPath -Force }
  $logPath = Join-Path $tempDir "remediation_results.txt"
  if (Test-Path -Path $logPath) { Remove-Item -Path $logPath -Force }
}

# -- Cluster: singleton_90670a15-971c-463a-9341-64e8d18bd9b0  (1 rule(s)) ---------------------
# Intent:    Detect cmd.exe executing inline scripts (.vbs, .js, .hta) with redirected output
# Rules:     90670a15-971c-463a-9341-64e8d18bd9b0
# Archetype: User-driven workflow

$tempDir = [System.IO.Path]::GetTempPath()
$jsPath = Join-Path $tempDir "data_processor.js"
$jsContent = @"
var objFSO = new ActiveXObject("Scripting.FileSystemObject");
var strPath = objFSO.GetSpecialFolder(2) + "\\processed_data.txt";
var objFile = objFSO.CreateTextFile(strPath, true);
objFile.WriteLine("Processed: " + new Date().toLocaleString());
objFile.Close();
WScript.Echo("Data processing completed");
"@
$jsContent | Set-Content -Path $jsPath -Force -Encoding ASCII
try {
  # Execute JavaScript via cscript through cmd.exe
  $logPath = Join-Path $tempDir "processing_log.txt"
  cmd /c "cscript.exe $jsPath > $logPath"
  Start-Sleep -Milliseconds 500
  # Verify execution
  if (Test-Path -Path "$tempDir\\processed_data.txt") {
    Write-Host "JavaScript utility task completed successfully"
  }
}
finally {
  # Cleanup
  if (Test-Path -Path $jsPath) { Remove-Item -Path $jsPath -Force }
  $logPath = Join-Path $tempDir "processing_log.txt"
  if (Test-Path -Path $logPath) { Remove-Item -Path $logPath -Force }
  if (Test-Path -Path "$tempDir\\processed_data.txt") { Remove-Item -Path "$tempDir\\processed_data.txt" -Force }
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
