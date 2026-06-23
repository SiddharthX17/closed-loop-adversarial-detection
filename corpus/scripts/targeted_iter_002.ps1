# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_84c8e8c0-af53-4ec4-93e7-f6b67dd81222  (1 rule(s)) ---------------------
# Intent:    Detect unauthorized use of script hosts (VBScript, PowerShell, CMD) to register 
# Rules:     84c8e8c0-af53-4ec4-93e7-f6b67dd81222
# Archetype: IT admin workflow

$taskName = 'SystemHealthCheck_Daily'
$taskPath = '\Microsoft\Windows\System32\'
$scriptPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts_backup.ps1'

# Create a minimal placeholder script that would be invoked by the task
if (-not (Test-Path $scriptPath)) {
  New-Item -ItemType File -Path $scriptPath -Force | Out-Null
  Add-Content -Path $scriptPath -Value '# Health check log entry' -Force
}

try {
  # Register task using COM Schedule.Service interface - standard admin method
  $service = New-Object -ComObject 'Schedule.Service'
  $service.Connect()
  $rootFolder = $service.GetFolder('\Microsoft\Windows\System32')

  $taskDef = $service.NewTask(0)
  $taskDef.RegistrationInfo.Description = 'Daily system diagnostics and reporting'

  $triggers = $taskDef.Triggers
  $trigger = $triggers.Create(1)  # TASK_TRIGGER_DAILY
  $trigger.StartBoundary = (Get-Date -Year 2024 -Month 1 -Day 1 -Hour 2 -Minute 0 -Second 0 -Millisecond 0).ToString('s')

  $actions = $taskDef.Actions
  $action = $actions.Create(0)  # TASK_ACTION_EXEC
  $action.Path = 'powershell.exe'
  $action.Arguments = "-ExecutionPolicy Bypass -NoProfile -File `"$scriptPath`""

  $taskDef.Principal.RunLevel = 1  # TASK_RUNLEVEL_HIGHEST

  # This RegisterTask call is the detection signature - legitimate admin activity
  $rootFolder.RegisterTaskDefinition($taskName, $taskDef, 6, $null, $null, 0) | Out-Null

  Write-Host "Task $taskName registered successfully"
}
catch {
  Write-Host "Task registration encountered error (may already exist): $_"
}
finally {
  # Cleanup
  $service = New-Object -ComObject 'Schedule.Service'
  $service.Connect()
  try {
    $rootFolder = $service.GetFolder('\Microsoft\Windows\System32')
    $rootFolder.DeleteTask($taskName, 0)
  }
  catch { }

  if (Test-Path $scriptPath) {
    Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
  }
}

# SKIPPED variant 'Software installer/updater workflow': blocked pattern: cmd batch syntax ('echo off')

# -- Cluster: singleton_84c8e8c0-af53-4ec4-93e7-f6b67dd81222  (1 rule(s)) ---------------------
# Intent:    Detect unauthorized use of script hosts (VBScript, PowerShell, CMD) to register 
# Rules:     84c8e8c0-af53-4ec4-93e7-f6b67dd81222
# Archetype: User-driven workflow

$taskName = 'LocalBackupRotation'
$vbsPath = Join-Path $env:TEMP 'backup_config.vbs'

# Create a VBScript that registers a scheduled task - simulates behavior of
# enterprise backup/monitoring tools that are distributed to users
$vbsContent = @'
Set objScheduler = CreateObject("Schedule.Service")
objScheduler.Connect()
Set objRootFolder = objScheduler.GetFolder("\")
Set objTaskDef = objScheduler.NewTask(0)

objTaskDef.RegistrationInfo.Description = "Weekly backup maintenance"

Set objTriggers = objTaskDef.Triggers
Set objTrigger = objTriggers.Create(1)
objTrigger.StartBoundary = "2024-01-01T04:00:00"

Set objActions = objTaskDef.Actions
Set objAction = objActions.Create(0)
objAction.Path = "cmd.exe"
objAction.Arguments = "/c echo Backup rotation check"

objRootFolder.RegisterTaskDefinition "LocalBackupRotation", objTaskDef, 6, Null, Null, 0
WScript.Echo "Task registered"
'@

Set-Content -Path $vbsPath -Value $vbsContent -Encoding ASCII -Force

try {
  # End-user runs a utility script that internally uses VBScript
  # This is realistic for enterprise tools distributed via app stores
  & cscript.exe $vbsPath 2>$null | Out-Null

  Start-Sleep -Milliseconds 300
  Write-Host "Backup task configured"
}
catch {
  Write-Host "Configuration error: $_"
}
finally {
  # Cleanup
  cmd.exe /c "schtasks.exe /delete /tn $taskName /f" 2>$null

  if (Test-Path $vbsPath) {
    Remove-Item -Path $vbsPath -Force -ErrorAction SilentlyContinue
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
