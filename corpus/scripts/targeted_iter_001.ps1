# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_e8c37bfc-1a51-4e06-9c89-7d7175b0926b  (1 rule(s)) ---------------------
# Intent:    Detects cmd.exe invoking echo with output redirection to create and execute VBSc
# Rules:     e8c37bfc-1a51-4e06-9c89-7d7175b0926b
# Archetype: Software installer/updater workflow

$ErrorActionPreference = 'SilentlyContinue'

# Simulate msiexec context by creating a temporary MSI execution context
# This demonstrates how an installer would generate and run VBScript configuration
$tempDir = $env:TEMP
$vbsPath = Join-Path $tempDir 'setup_config.vbs'
$logPath = Join-Path $tempDir 'setup_config.log'

# Create a legitimate VBScript for application configuration
# (This would normally be embedded in the installer package)
$vbsContent = @'
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objReg = CreateObject("WScript.Shell")

' Record configuration timestamp
strLog = Now & " - Configuration executed" & vbCrLf
objFSO.CreateTextFile("{logPath}").Write strLog
objReg.LogEvent 4, "Application configuration completed"
'@

# Write VBScript using cmd.exe with echo and redirection (matches detection pattern)
# This is the actual installer workflow — cmd.exe is invoked by msiexec context
cmd /c "echo Set objFSO = CreateObject(^"Scripting.FileSystemObject^"^)  > $vbsPath"
cmd /c "echo Set objReg = CreateObject(^"WScript.Shell^"^)  >> $vbsPath"
cmd /c "echo strLog = Now ^& \" - Configuration executed\" ^& vbCrLf  >> $vbsPath"
cmd /c "echo objFSO.CreateTextFile(\"$logPath\").Write strLog  >> $vbsPath"

# Execute the generated VBScript (legitimate post-install configuration)
cscript.exe $vbsPath

# Verify execution and clean up
if (Test-Path $vbsPath) {
    Remove-Item $vbsPath -Force
}
if (Test-Path $logPath) {
    Remove-Item $logPath -Force
}

# -- Cluster: singleton_e8c37bfc-1a51-4e06-9c89-7d7175b0926b  (1 rule(s)) ---------------------
# Intent:    Detects cmd.exe invoking echo with output redirection to create and execute VBSc
# Rules:     e8c37bfc-1a51-4e06-9c89-7d7175b0926b
# Archetype: IT admin workflow

$ErrorActionPreference = 'SilentlyContinue'

# Simulate admin maintenance context (current directory is Program Files)
# Generate VBScript for system diagnostic using cmd.exe echo redirection
$workDir = Join-Path $env:ProgramFiles 'Diagnostic'
if (-not (Test-Path $workDir)) {
    New-Item -ItemType Directory -Path $workDir -Force | Out-Null
}

Set-Location $workDir

$vbsPath = Join-Path $workDir 'system_check.vbs'
$reportPath = Join-Path $workDir 'diagnostic_report.txt'

# Generate VBScript for system verification using cmd.exe echo and redirection
# This pattern matches the detection rule: cmd /c echo > .vbs with installer context
cmd /c "echo ' System diagnostic script  > $vbsPath"
cmd /c "echo Set objWMI = GetObject(^"winmgmts:^"^)  >> $vbsPath"
cmd /c "echo Set colItems = objWMI.ExecQuery(^"Select * from Win32_ComputerSystem^"^)  >> $vbsPath"
cmd /c "echo For Each objItem in colItems  >> $vbsPath"
cmd /c "echo   strOutput = objItem.Name ^& vbTab ^& objItem.SystemType  >> $vbsPath"
cmd /c "echo Next  >> $vbsPath"

# Execute the diagnostic VBScript
cscript.exe $vbsPath > $reportPath 2>&1

# Clean up generated files
if (Test-Path $vbsPath) {
    Remove-Item $vbsPath -Force
}
if (Test-Path $reportPath) {
    Remove-Item $reportPath -Force
}

# Return to previous location
Set-Location $env:TEMP
if (Test-Path $workDir) {
    Remove-Item $workDir -Force -Recurse
}

# -- Cluster: singleton_e8c37bfc-1a51-4e06-9c89-7d7175b0926b  (1 rule(s)) ---------------------
# Intent:    Detects cmd.exe invoking echo with output redirection to create and execute VBSc
# Rules:     e8c37bfc-1a51-4e06-9c89-7d7175b0926b
# Archetype: User-driven workflow

$ErrorActionPreference = 'SilentlyContinue'

# Simulate user-initiated application setup from Downloads
# Many legacy applications generate VBScript helpers during first-run initialization
$downloadsPath = [Environment]::GetFolderPath('UserProfile') + '\Downloads'
$setupWorkDir = Join-Path $downloadsPath 'AppSetup'

if (-not (Test-Path $setupWorkDir)) {
    New-Item -ItemType Directory -Path $setupWorkDir -Force | Out-Null
}

$vbsPath = Join-Path $setupWorkDir 'init_environment.vbs'

# Generate VBScript using cmd.exe echo redirection (matches detection pattern)
# This script configures application paths and environment variables
cmd /c "echo ' Initialize application environment  > $vbsPath"
cmd /c "echo Dim objShell, strAppPath, strAppData  >> $vbsPath"
cmd /c "echo Set objShell = CreateObject(^"WScript.Shell^"^)  >> $vbsPath"
cmd /c "echo strAppPath = objShell.ExpandEnvironmentStrings(^"^%APPDATA^%\\MyApplication^"^)  >> $vbsPath"
cmd /c "echo If Not objShell.FileSystemObject.FolderExists(strAppPath) Then  >> $vbsPath"
cmd /c "echo   objShell.FileSystemObject.CreateFolder strAppPath  >> $vbsPath"
cmd /c "echo End If  >> $vbsPath"

# Execute the initialization script
cscript.exe $vbsPath

# Clean up
if (Test-Path $vbsPath) {
    Remove-Item $vbsPath -Force
}
if (Test-Path $setupWorkDir) {
    Remove-Item $setupWorkDir -Force -Recurse
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
