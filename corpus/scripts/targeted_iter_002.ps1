# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   2  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_09a91ef1-5e25-4f77-ad55-38a652652c00  (1 rule(s)) ---------------------
# Intent:    Detect scheduled task engines or system loaders spawning WSH interpreters (cscri
# Rules:     09a91ef1-5e25-4f77-ad55-38a652652c00
# Archetype: IT admin workflow

$taskName = 'MaintenanceLogCleanup'
$taskPath = Join-Path $env:ProgramData 'Microsoft\Windows\maintenance_cleanup.vbs'

# Create a realistic maintenance script that processes logs
$vbscript = @'
Set objFSO = CreateObject("Scripting.FileSystemObject")
strLogsPath = "" & objFSO.GetSpecialFolder(2) & "\Windows\Temp"
Set objFolder = objFSO.GetFolder(strLogsPath)
For Each objFile In objFolder.Files
    If objFSO.GetExtensionName(objFile.Name) = "log" Then
        If DateDiff("d", objFile.DateCreated, Now) > 7 Then
            objFile.Delete
        End If
    End If
Next
'@

if (-not (Test-Path (Split-Path $taskPath))) {
    New-Item -ItemType Directory -Path (Split-Path $taskPath) -Force | Out-Null
}

Set-Content -Path $taskPath -Value $vbscript -Encoding UTF8

# Register the scheduled task using schtasks (which invokes taskeng.exe)
$action = New-ScheduledTaskAction -Execute 'cscript.exe' -Argument "`"$taskPath`""
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Force -ErrorAction SilentlyContinue

# Wait for task engine to spawn and execute the script
Start-Sleep -Seconds 3

# Cleanup
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item -Path $taskPath -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_09a91ef1-5e25-4f77-ad55-38a652652c00  (1 rule(s)) ---------------------
# Intent:    Detect scheduled task engines or system loaders spawning WSH interpreters (cscri
# Rules:     09a91ef1-5e25-4f77-ad55-38a652652c00
# Archetype: Software installer/updater workflow

$configPath = Join-Path $env:ProgramData 'ConfigMgr\agent_config.vbs'
$helperScript = Join-Path $env:ProgramData 'ConfigMgr\deploy_helper.html'

# Ensure directory exists
if (-not (Test-Path (Split-Path $configPath))) {
    New-Item -ItemType Directory -Path (Split-Path $configPath) -Force | Out-Null
}

# Create a VBScript that simulates configuration deployment
$vbscript = @'
Set objWMI = GetObject("winmgmts:")
Set colItems = objWMI.ExecQuery("Select * from Win32_OperatingSystem")
For Each objItem in colItems
    Set objReg = GetObject("winmgmts:root\\default:StdRegProv")
    objReg.SetStringValue &H80000002, "Software\\Microsoft\\ConfigMgr\\Agent", "LastUpdate", Now
Next
'@

Set-Content -Path $configPath -Value $vbscript -Encoding UTF8

# Create an HTML file that mshta will execute (common in enterprise deployment)
$htmlContent = @'
<html>
<script language="VBScript">
CreateObject("WScript.Shell").Run "cscript.exe \""" & configPath & "\"" ", 0, False
</script>
</html>
'@

Set-Content -Path $helperScript -Value $htmlContent -Encoding UTF8

# Execute via mshta (simulating enterprise deployment tooling)
& mshta.exe ("file://" + $helperScript) -ErrorAction SilentlyContinue

Start-Sleep -Seconds 2

# Cleanup
Remove-Item -Path $configPath -Force -ErrorAction SilentlyContinue
Remove-Item -Path $helperScript -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_09a91ef1-5e25-4f77-ad55-38a652652c00  (1 rule(s)) ---------------------
# Intent:    Detect scheduled task engines or system loaders spawning WSH interpreters (cscri
# Rules:     09a91ef1-5e25-4f77-ad55-38a652652c00
# Archetype: User-driven workflow

$appDataPath = Join-Path $env:APPDATA 'LocalToolkit\report_generator.vbs'
$tempLoader = Join-Path $env:TEMP 'toolkit_loader.vbs'

# Ensure AppData structure exists
if (-not (Test-Path (Split-Path $appDataPath))) {
    New-Item -ItemType Directory -Path (Split-Path $appDataPath) -Force | Out-Null
}

# Create a realistic utility script that generates a report
$utilityScript = @'
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objFile = objFSO.CreateTextFile(objFSO.GetSpecialFolder(2) & "\\runtime_report.txt", True)
objFile.WriteLine "=== System Report ==="
objFile.WriteLine "Generated: " & Now
objFile.Close
'@

Set-Content -Path $appDataPath -Value $utilityScript -Encoding UTF8

# Create a loader script in temp that rundll32 can invoke
$loaderScript = @'
CreateObject("WScript.Shell").Run "wscript.exe \"" & appDataPath & "\"" , 0, False
'@

Set-Content -Path $tempLoader -Value $loaderScript -Encoding UTF8

# Execute the loader via rundll32 (simulating application launcher behavior)
# rundll32 is used by many legitimate tools to delegate script execution
$result = & rundll32.exe ("shell32.dll,ShellExec_RunDLL") ("wscript.exe") (`"$tempLoader`") -ErrorAction SilentlyContinue

Start-Sleep -Seconds 2

# Cleanup
Remove-Item -Path $appDataPath -Force -ErrorAction SilentlyContinue
Remove-Item -Path $tempLoader -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path $env:TEMP 'runtime_report.txt') -Force -ErrorAction SilentlyContinue

# SKIPPED cluster singleton_abf62430-d14c-4519-9d75-25daec01a6a9: rdrleakdiag.exe is a Microsoft Remote Desktop Leak Diagnostic tool that is NOT installed on standard windows-latest GitHub Actions runners. The tool is part of the Remote Desktop Client suite and requires explicit installation. Additionally, the /fullmemdmp flag is specifically designed for diagnosing remote desktop memory leaks in production RDP environments, not standalone systems. Attempting to invoke a non-existent executable will fail with 'file not found' rather than generating the intended Sysmon process creation events. While the tool could theoretically be downloaded and installed, doing so would require either: (1) a pre-built binary artifact (introducing supply chain concerns in a security research pipeline), or (2) building from source (not available publicly). The legitimate use case for rdrleakdiag requires an active RDP session context and diagnostic scenario that cannot be meaningfully replicated on an ephemeral CI runner.

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
