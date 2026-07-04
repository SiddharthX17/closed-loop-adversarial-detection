# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_dca366c1-0109-4973-9caf-3d39eb0d1043  (1 rule(s)) ---------------------
# Intent:    MSHTA spawning scripting interpreters (wscript.exe or cscript.exe) via inline VB
# Rules:     dca366c1-0109-4973-9caf-3d39eb0d1043
# Archetype: IT admin workflow

# Create a benign HTA application that demonstrates legitimate VBScript+WScript.Shell usage
$htaDir = Join-Path $env:TEMP 'admin_utilities'
if (-not (Test-Path $htaDir)) { New-Item -ItemType Directory -Path $htaDir | Out-Null }

$htaPath = Join-Path $htaDir 'maintenance_tool.hta'
$vbsPath = Join-Path $htaDir 'system_check.vbs'
$reportPath = Join-Path $htaDir 'system_report.txt'

# Create a simple VBScript that performs a system reporting task
$vbsContent = @'
Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

strReportPath = "' + $reportPath + '"
Set objFile = objFSO.CreateTextFile(strReportPath, True)
objFile.WriteLine "System Maintenance Report Generated: " & Now
objFile.WriteLine "This is a legitimate system administration utility."
objFile.Close
objShell.Run "cmd /c exit 0", 0
'@

$vbsContent | Out-File -FilePath $vbsPath -Encoding ASCII

# Create an HTA file that invokes the VBScript via WScript.Shell.Run
$htaContent = @'
<html>
<head>
<title>System Maintenance Utility</title>
</head>
<body>
System Maintenance in progress...
</body>
<script language="VBScript">
Set objShell = CreateObject("WScript.Shell")
objShell.Run "cscript.exe ' + $vbsPath + '", 0
</script>
</html>
'@

$htaContent | Out-File -FilePath $htaPath -Encoding ASCII

# Execute the HTA file using mshta.exe
mshta.exe $htaPath

# Wait for execution to complete
Start-Sleep -Seconds 2

# Verify the expected behavior occurred
if (Test-Path $reportPath) {
    Get-Content $reportPath | Out-Null
}

# Clean up all created files and directory
Remove-Item -Path $htaDir -Recurse -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_dca366c1-0109-4973-9caf-3d39eb0d1043  (1 rule(s)) ---------------------
# Intent:    MSHTA spawning scripting interpreters (wscript.exe or cscript.exe) via inline VB
# Rules:     dca366c1-0109-4973-9caf-3d39eb0d1043
# Archetype: Software installer/updater workflow

# Simulate a legitimate software configuration utility using HTA with VBScript execution
$configDir = Join-Path $env:TEMP 'config_utility'
if (-not (Test-Path $configDir)) { New-Item -ItemType Directory -Path $configDir | Out-Null }

$htaPath = Join-Path $configDir 'setup_wizard.hta'
$configVbs = Join-Path $configDir 'apply_settings.vbs'
$configFile = Join-Path $configDir 'app_config.ini'

# Create a VBScript that performs configuration tasks
$vbsScript = @'
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objShell = CreateObject("WScript.Shell")

strConfigPath = "' + $configFile + '"
Set objConfigFile = objFSO.CreateTextFile(strConfigPath, True)
objConfigFile.WriteLine "[Settings]"
objConfigFile.WriteLine "Version=2.0"
objConfigFile.WriteLine "LastConfigured=" & Now
objConfigFile.WriteLine "Status=Applied"
objConfigFile.Close

objShell.Run "cmd /c exit 0", 0
'@

$vbsScript | Out-File -FilePath $configVbs -Encoding ASCII

# Create HTA that calls WScript.Shell.Run with wscript.exe
$htaContent = @'
<html>
<head>
<title>Application Configuration Utility</title>
<hta:application id="ConfigApp" windowState="normal" />
</head>
<body>
<h3>Applying Configuration Settings...</h3>
</body>
<script language="VBScript">
Dim objShell
Set objShell = CreateObject("WScript.Shell")
objShell.Run "wscript.exe ' + $configVbs + '", 0
</script>
</html>
'@

$htaContent | Out-File -FilePath $htaPath -Encoding ASCII

# Execute the HTA using mshta.exe, which will spawn wscript.exe
mshta.exe $htaPath

# Allow time for subprocess completion
Start-Sleep -Seconds 2

# Verify configuration file was created
if (Test-Path $configFile) {
    Get-Content $configFile | Out-Null
}

# Clean up all created files and directory
Remove-Item -Path $configDir -Recurse -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_dca366c1-0109-4973-9caf-3d39eb0d1043  (1 rule(s)) ---------------------
# Intent:    MSHTA spawning scripting interpreters (wscript.exe or cscript.exe) via inline VB
# Rules:     dca366c1-0109-4973-9caf-3d39eb0d1043
# Archetype: User-driven workflow

# Create a realistic user-facing HTA utility (e.g., IT inventory tool)
$toolDir = Join-Path $env:TEMP 'user_tools'
if (-not (Test-Path $toolDir)) { New-Item -ItemType Directory -Path $toolDir | Out-Null }

$htaPath = Join-Path $toolDir 'inventory_tool.hta'
$processorScript = Join-Path $toolDir 'inventory_processor.vbs'
$outputFile = Join-Path $toolDir 'inventory_report.txt'

# Create VBScript that processes inventory data
$processorContent = @'
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objShell = CreateObject("WScript.Shell")

strOutputPath = "' + $outputFile + '"
Set objOutput = objFSO.CreateTextFile(strOutputPath, True)
objOutput.WriteLine "Computer Inventory Report"
objOutput.WriteLine "Timestamp: " & Now
objOutput.WriteLine "OS: Windows"
objOutput.WriteLine "Status: Processed"
objOutput.Close

objShell.Run "cmd /c tasklist /FO CSV > nul", 0
'@

$processorContent | Out-File -FilePath $processorScript -Encoding ASCII

# Create the main HTA application with UI
$htaContent = @'
<html>
<head>
<title>System Inventory Tool</title>
<hta:application id="InventoryTool" windowState="normal" width="600" height="400" />
</head>
<body>
<h2>System Inventory Analysis</h2>
<p>Gathering system information...</p>
</body>
<script language="VBScript">
Sub Window_OnLoad
    Dim objShell
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run "cscript.exe ' + $processorScript + '", 0
End Sub
</script>
</html>
'@

$htaContent | Out-File -FilePath $htaPath -Encoding ASCII

# User opens the HTA application
mshta.exe $htaPath

# Wait for processing
Start-Sleep -Seconds 2

# Verify output was generated
if (Test-Path $outputFile) {
    Get-Content $outputFile | Out-Null
}

# Clean up the tool directory
Remove-Item -Path $toolDir -Recurse -Force -ErrorAction SilentlyContinue


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
