# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   2  |  Feasible: 2  |  Variants: 5
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_8340bf12-c5eb-46d9-8b8f-513b08177301  (1 rule(s)) ---------------------
# Intent:    Detect adversaries using PowerShell to register scheduled tasks with download cr
# Rules:     8340bf12-c5eb-46d9-8b8f-513b08177301
# Archetype: IT admin workflow

$taskName = 'SystemHealthCheck'
$taskDescription = 'Weekly system diagnostic and health verification'

# Create task action that downloads health check script from internal server
$taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $uri = [System.Uri]\"http://10.0.0.50:8080/maintenance/healthcheck.ps1\"; $client = New-Object System.Net.WebClient; $scriptContent = $client.DownloadString($uri); Invoke-Expression $scriptContent"'

# Define task trigger for weekly execution
$taskTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 3am

# Set task settings for background execution
$taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable

# Create principal for SYSTEM context
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest -LogonType ServiceAccount

# Register the scheduled task
Register-ScheduledTask -TaskName $taskName -Description $taskDescription -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $principal -Force | Out-Null

# Verify task was registered
Get-ScheduledTask -TaskName $taskName | Format-List TaskName, Description, State

# Clean up
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

# SKIPPED variant 'Software installer/updater workflow': blocked pattern: payload download ('downloadfile(')

# -- Cluster: singleton_d312847c-2db1-4e03-aaa4-e33e0ae030e2  (1 rule(s)) ---------------------
# Intent:    Detects cmd.exe launching script interpreters (wscript.exe/cscript.exe) with dir
# Rules:     d312847c-2db1-4e03-aaa4-e33e0ae030e2
# Archetype: IT admin workflow

# Simulating legitimate SCCM-based script execution workflow
# An organization uses System Center Configuration Manager (SCCM) to remotely
# deploy and execute compliance audit scripts on managed systems.

$vbsScript = @'
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objShell = CreateObject("WScript.Shell")
strComputer = "."
Set objWMIService = GetObject("winmgmts:" & strComputer & "\\root\\cimv2")
Set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_OperatingSystem", , 48)
For Each objItem in colItems
    WScript.Echo "System Audit: " & objItem.Caption
Next
'

# Create a legitimate-looking audit script in a real SCCM-style staging directory
$stagingPath = [System.IO.Path]::Combine($env:ProgramData, 'Microsoft', 'SystemCenter')
if (-not (Test-Path $stagingPath)) {
    New-Item -ItemType Directory -Path $stagingPath -Force | Out-Null
}

$scriptPath = [System.IO.Path]::Combine($stagingPath, 'audit_config.vbs')
Set-Content -Path $scriptPath -Value $vbsScript -Encoding ASCII

try {
    # Simulate SCCM remote execution: launching via cmd.exe with /c flag
    # This is how ConfigMgr and similar tools invoke scripts across systems
    # The command navigates to the script directory and executes it
    cmd /c "cd /d `"$stagingPath`" && cscript.exe audit_config.vbs" | Out-Null
    Start-Sleep -Milliseconds 500
} finally {
    # Clean up the created script
    if (Test-Path $scriptPath) {
        Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
    }
    if ((Get-ChildItem $stagingPath -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0) {
        Remove-Item -Path $stagingPath -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_d312847c-2db1-4e03-aaa4-e33e0ae030e2  (1 rule(s)) ---------------------
# Intent:    Detects cmd.exe launching script interpreters (wscript.exe/cscript.exe) with dir
# Rules:     d312847c-2db1-4e03-aaa4-e33e0ae030e2
# Archetype: Software installer/updater workflow

# Simulating legitimate software installer post-install configuration workflow
# Enterprise applications often execute VBScript-based configuration/validation
# scripts from temporary directories as part of their installation or update process.

$vbsConfig = @'
' Installation verification script
Set objFSO = CreateObject("Scripting.FileSystemObject")
strLogPath = objFSO.BuildPath(objFSO.GetSpecialFolder(2), "install_verify.log")
Set objFile = objFSO.CreateTextFile(strLogPath, True)
objFile.WriteLine "Configuration verification completed at " & Now
objFile.Close
'

# Create a staging directory in user's temp location (realistic for installers)
$tempStaging = [System.IO.Path]::Combine($env:TEMP, 'AppSetup_' + (Get-Random))
New-Item -ItemType Directory -Path $tempStaging -Force | Out-Null

$vbsPath = [System.IO.Path]::Combine($tempStaging, 'verify_config.vbs')
Set-Content -Path $vbsPath -Value $vbsConfig -Encoding ASCII

try {
    # Installer executes configuration verification via cmd /c
    # This pattern is common in MSI and other enterprise installer frameworks
    cmd /c "cd \ && cd /d `"$tempStaging`" && wscript.exe verify_config.vbs" | Out-Null
    Start-Sleep -Milliseconds 300
} finally {
    # Clean up installer artifacts
    if (Test-Path $tempStaging) {
        Remove-Item -Path $tempStaging -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_d312847c-2db1-4e03-aaa4-e33e0ae030e2  (1 rule(s)) ---------------------
# Intent:    Detects cmd.exe launching script interpreters (wscript.exe/cscript.exe) with dir
# Rules:     d312847c-2db1-4e03-aaa4-e33e0ae030e2
# Archetype: User-driven workflow

# Simulating legitimate user-driven automation workflow
# Users in many organizations receive or download business process automation
# scripts (data export, file organization, backup preparation) and execute them.

$vbsProcess = @'
' File processing automation script
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objShell = CreateObject("WScript.Shell")
' Collect file list from user documents
strPath = objShell.SpecialFolders("MyDocuments")
Set objFolder = objFSO.GetFolder(strPath)
strReport = "File Inventory: " & objFolder.Files.Count & " files found"
WScript.Echo strReport
'

# Simulate user downloading a script to their Downloads folder
$downloadsPath = [System.IO.Path]::Combine($env:USERPROFILE, 'Downloads')
if (-not (Test-Path $downloadsPath)) {
    New-Item -ItemType Directory -Path $downloadsPath -Force | Out-Null
}

$scriptPath = [System.IO.Path]::Combine($downloadsPath, 'file_report.vbs')
Set-Content -Path $scriptPath -Value $vbsProcess -Encoding ASCII

try {
    # User executes downloaded script via command line
    # (common for batch operations, data processing, file utilities)
    cmd /c "cd /d `"$downloadsPath`" && cscript.exe file_report.vbs" | Out-Null
    Start-Sleep -Milliseconds 300
} finally {
    # Clean up downloaded script after execution
    if (Test-Path $scriptPath) {
        Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
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
