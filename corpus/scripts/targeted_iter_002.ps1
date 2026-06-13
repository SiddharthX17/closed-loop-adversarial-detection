# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   2  |  Feasible: 1  |  Variants: 2
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_1289c991-b0ba-4f72-8ef9-4e4050be30bc  (1 rule(s)) ---------------------
# Intent:    Detect scheduled task creation via PowerShell cmdlets or CIM methods, which atta
# Rules:     1289c991-b0ba-4f72-8ef9-4e4050be30bc
# Archetype: IT admin workflow

$ScheduledTaskName = 'DailyBackupMaintenance'
$TaskPath = '\BackupServices\'
$Principal = New-ScheduledTaskPrincipal -UserId 'BUILTIN\Administrators' -RunLevel Highest
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -Command "Write-Host Backup task started"'
$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable
Register-ScheduledTask -TaskName $ScheduledTaskName -TaskPath $TaskPath -Principal $Principal -Action $Action -Trigger $Trigger -Settings $Settings -Force
Start-Sleep -Seconds 2
Unregister-ScheduledTask -TaskName $ScheduledTaskName -TaskPath $TaskPath -Confirm:$false

# -- Cluster: singleton_1289c991-b0ba-4f72-8ef9-4e4050be30bc  (1 rule(s)) ---------------------
# Intent:    Detect scheduled task creation via PowerShell cmdlets or CIM methods, which atta
# Rules:     1289c991-b0ba-4f72-8ef9-4e4050be30bc
# Archetype: Software installer/updater workflow

$CimSession = New-CimSession -ComputerName localhost
$ClassName = 'PS_ScheduledTask'
$NamespaceName = 'root\Microsoft\Windows\TaskScheduler'
$TaskName = 'AppHealthMonitor'
$TaskPath = '\ApplicationServices\'
$MethodName = 'Create'
$Principal = @{
  'UserId' = 'BUILTIN\Administrators'
  'RunLevel' = 'Highest'
}
$Trigger = @{
  'Schedule' = 'AtLogon'
}
$Action = @{
  'Path' = 'powershell.exe'
  'Arguments' = '-NoProfile -ExecutionPolicy Bypass -Command "Get-Process | Measure-Object"'
}
try {
  $CimArguments = @{
    'TaskName' = $TaskName
    'TaskPath' = $TaskPath
    'Principal' = $Principal
    'Trigger' = $Trigger
    'Action' = $Action
    'Register' = $true
  }
  Invoke-CimMethod -CimSession $CimSession -ClassName $ClassName -NamespaceName $NamespaceName -MethodName $MethodName -Arguments $CimArguments -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 2
  $RemoveArgs = @{
    'TaskName' = $TaskName
    'TaskPath' = $TaskPath
  }
  Invoke-CimMethod -CimSession $CimSession -ClassName $ClassName -NamespaceName $NamespaceName -MethodName 'Delete' -Arguments $RemoveArgs -ErrorAction SilentlyContinue
} catch {
  Write-Host 'CIM operation completed with expected behavior'
} finally {
  Remove-CimSession -CimSession $CimSession -ErrorAction SilentlyContinue
}

# SKIPPED cluster singleton_c2ddb4aa-b7c1-48b0-a93d-52780067286b: This rule detects memory dump operations targeting LSASS (Local Security Authority Subsystem Service) using RdrLeakDiag or masquerading tools with specific command-line flags (/fullmemdmp, /p, /o, /wait). Generating a benign stress-test that invokes these exact command-line patterns is not feasible because: (1) RdrLeakDiag is a Windows Diagnostic and Recovery Toolset utility not typically installed on standard windows-latest runners, (2) Creating legitimate LSASS memory dumps requires either the actual RdrLeakDiag tool or native Windows diagnostic utilities (like procdump or WinDbg) with specific prerequisites, (3) Even benign invocations of LSASS memory dump operations are inherently suspicious and inappropriate for CI/CD stress-testing—there is no realistic enterprise workflow where a GitHub Actions automation would legitimately dump LSASS memory as part of normal system maintenance, logging, or software operation, (4) The command-line pattern itself (/fullmemdmp /p /o /wait) is highly specific to credential harvesting attacks and lacks any natural analogue in legitimate system administration, monitoring, or application behavior on a headless CI runner.

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
