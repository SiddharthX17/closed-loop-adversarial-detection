# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   2  |  Feasible: 2  |  Variants: 4
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_5f8684a9-f09c-4415-820e-571ef9015c4c  (1 rule(s)) ---------------------
# Intent:    Attackers extract the NTDS.dit Active Directory database and SYSTEM registry hiv
# Rules:     5f8684a9-f09c-4415-820e-571ef9015c4c
# Archetype: IT admin workflow

# Domain controller database maintenance: query NTDS.dit database integrity and recovery information
# This reflects real IT admin work on DC systems where backup and recovery procedures must be validated

$ntdsUtilPath = 'C:\Windows\System32\ntdsutil.exe'
$logPath = "$env:TEMP\ntdsutil_diagnostic_$(Get-Random).log"

if (Test-Path $ntdsUtilPath) {
    # Run ntdsutil diagnostic query that references NTDS configuration context
    # Real admins use this to check database status before maintenance windows
    $ntdsCommands = @(
        'ifm',
        'semantic database analysis',
        'go'
    )

    $commandInput = ($ntdsCommands -join "`n") + "`nquit"

    # Execute ntdsutil with diagnostic parameters
    $commandInput | & $ntdsUtilPath 2>&1 | Out-File -FilePath $logPath -Encoding UTF8

    Start-Sleep -Milliseconds 500

    # Clean up log file
    if (Test-Path $logPath) {
        Remove-Item -Path $logPath -Force -ErrorAction SilentlyContinue
    }
}

# Query registry for SYSTEM hive backup status as part of disaster recovery audit
$systemHiveBackupKeys = @(
    'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager',
    'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS'
)

foreach ($regPath in $systemHiveBackupKeys) {
    if (Test-Path $regPath) {
        Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue | Out-Null
    }
}

# -- Cluster: singleton_8bd8748f-a0ce-49ef-8dab-dca1103351eb  (1 rule(s)) ---------------------
# Intent:    Detection of Windows Script Host interpreters (cscript.exe, wscript.exe) executi
# Rules:     8bd8748f-a0ce-49ef-8dab-dca1103351eb
# Archetype: IT admin workflow

$tempDir = $env:TEMP
$scriptName = 'hwaudit_' + (Get-Random -Maximum 10000) + '.vbs'
$scriptPath = Join-Path -Path $tempDir -ChildPath $scriptName

# Create a legitimate VBScript for system inventory
$vbsContent = @'
Dim objWMI, colItems, objItem, objFSO, logFile
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objWMI = GetObject("winmgmts:")
Set colItems = objWMI.ExecQuery("Select * from Win32_Processor")
logFile = objFSO.BuildPath(objFSO.GetSpecialFolder(2), "hw_log.txt")
Set objFile = objFSO.CreateTextFile(logFile)
For Each objItem in colItems
  objFile.WriteLine "Processor: " & objItem.Name
Next
objFile.Close
'@

$vbsContent | Out-File -FilePath $scriptPath -Encoding UTF8 -Force

# Execute the VBScript via cscript - legitimate admin task
cscript.exe $scriptPath

# Cleanup
Start-Sleep -Milliseconds 500
if (Test-Path -Path $scriptPath) {
  Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
}
$logPath = Join-Path -Path $env:TEMP -ChildPath 'hw_log.txt'
if (Test-Path -Path $logPath) {
  Remove-Item -Path $logPath -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_8bd8748f-a0ce-49ef-8dab-dca1103351eb  (1 rule(s)) ---------------------
# Intent:    Detection of Windows Script Host interpreters (cscript.exe, wscript.exe) executi
# Rules:     8bd8748f-a0ce-49ef-8dab-dca1103351eb
# Archetype: Software installer/updater workflow

$appDataPath = Join-Path -Path $env:APPDATA -ChildPath 'SoftwareSetup'
if (-not (Test-Path -Path $appDataPath)) {
  New-Item -ItemType Directory -Path $appDataPath -Force | Out-Null
}

$scriptName = 'install_config.js'
$scriptPath = Join-Path -Path $appDataPath -ChildPath $scriptName

# Create a legitimate JavaScript for application configuration
$jsContent = @'
var objFSO = new ActiveXObject("Scripting.FileSystemObject");
var strPath = objFSO.GetSpecialFolder(2);
var logFile = objFSO.BuildPath(strPath, "app_setup.log");
var objFile = objFSO.CreateTextFile(logFile);
objFile.WriteLine("Application configuration initialized");
objFile.WriteLine("Timestamp: " + new Date());
objFile.Close();
'@

$jsContent | Out-File -FilePath $scriptPath -Encoding UTF8 -Force

# Execute via wscript - installer routine
wscript.exe $scriptPath

# Cleanup - installer removes temporary files
Start-Sleep -Milliseconds 500
if (Test-Path -Path $scriptPath) {
  Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
}
if (Test-Path -Path $appDataPath) {
  Remove-Item -Path $appDataPath -Recurse -Force -ErrorAction SilentlyContinue
}
$logPath = Join-Path -Path $env:TEMP -ChildPath 'app_setup.log'
if (Test-Path -Path $logPath) {
  Remove-Item -Path $logPath -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_8bd8748f-a0ce-49ef-8dab-dca1103351eb  (1 rule(s)) ---------------------
# Intent:    Detection of Windows Script Host interpreters (cscript.exe, wscript.exe) executi
# Rules:     8bd8748f-a0ce-49ef-8dab-dca1103351eb
# Archetype: User-driven workflow

$downloadsPath = Join-Path -Path $env:USERPROFILE -ChildPath 'Downloads'
$tempExtractPath = Join-Path -Path $env:APPDATA -ChildPath 'Local\DocumentTools'

if (-not (Test-Path -Path $tempExtractPath)) {
  New-Item -ItemType Directory -Path $tempExtractPath -Force | Out-Null
}

$scriptName = 'extract_docs.vbs'
$scriptPath = Join-Path -Path $tempExtractPath -ChildPath $scriptName

# VBScript for extracting and organizing downloaded files
$vbsContent = @'
Dim objFSO, objShell, downloadsFolder, outputLog
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objShell = CreateObject("WScript.Shell")
downloadsFolder = objShell.SpecialFolders("Downloads")
outputLog = objFSO.BuildPath(objFSO.GetSpecialFolder(2), "doc_extract.log")
Set logFile = objFSO.CreateTextFile(outputLog)
logFile.WriteLine "Processing downloads from: " & downloadsFolder
logFile.WriteLine "Operation completed at: " & Now
logFile.Close
'@

$vbsContent | Out-File -FilePath $scriptPath -Encoding UTF8 -Force

# User executes the helper script
wscript.exe $scriptPath

# Cleanup
Start-Sleep -Milliseconds 500
if (Test-Path -Path $scriptPath) {
  Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
}
if (Test-Path -Path $tempExtractPath) {
  Remove-Item -Path $tempExtractPath -Recurse -Force -ErrorAction SilentlyContinue
}
$logPath = Join-Path -Path $env:TEMP -ChildPath 'doc_extract.log'
if (Test-Path -Path $logPath) {
  Remove-Item -Path $logPath -Force -ErrorAction SilentlyContinue
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
