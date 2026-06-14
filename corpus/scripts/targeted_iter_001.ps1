# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 2
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_60c04e77-f1ae-4795-8f15-809f59b7409e  (1 rule(s)) ---------------------
# Intent:    Detection of privilege-escalated scheduled task creation via PowerShell cmdlets,
# Rules:     60c04e77-f1ae-4795-8f15-809f59b7409e
# Archetype: IT admin workflow

$taskName = 'SystemMaintenanceDiskCleanup'
$taskPath = '\\Microsoft\\Windows\\Maintenance\\'
$taskDescription = 'Automated disk cleanup and temporary file removal for system health'

try {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -Command "Remove-Item -Path $env:TEMP\\* -Force -ErrorAction SilentlyContinue; Remove-Item -Path $env:SystemRoot\\Temp\\* -Force -ErrorAction SilentlyContinue"'

    $trigger = New-ScheduledTaskTrigger -Daily -At 2:00AM

    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\\SYSTEM' -RunLevel Highest -LogonType ServiceAccount

    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $taskDescription -Force

    Write-Output "Task $taskName registered successfully"

    Start-Sleep -Seconds 2

    Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false

    Write-Output "Task $taskName cleaned up"
}
catch {
    Write-Error "Failed to complete task operation: $_"
    try {
        Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false -ErrorAction SilentlyContinue
    } catch {}
}

# -- Cluster: singleton_60c04e77-f1ae-4795-8f15-809f59b7409e  (1 rule(s)) ---------------------
# Intent:    Detection of privilege-escalated scheduled task creation via PowerShell cmdlets,
# Rules:     60c04e77-f1ae-4795-8f15-809f59b7409e
# Archetype: Software installer/updater workflow

$taskName = 'PatchManagementAgent'
$taskPath = '\\Software\\Deployment\\'
$taskDescription = 'Automated system patching and update deployment'

try {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -Command "Write-Host 1 > $null"'

    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3:00AM

    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\\SYSTEM' -RunLevel Highest -LogonType ServiceAccount

    Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action -Trigger $trigger -Principal $principal -Description $taskDescription -Force

    Write-Output "Task $taskName created"

    Start-Sleep -Seconds 1

    $existingTask = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath

    $newAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -Command "Write-Host 2 > $null"'

    $newPrincipal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\\SYSTEM' -RunLevel Highest -LogonType ServiceAccount

    Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $newAction -Principal $newPrincipal

    Write-Output "Task $taskName updated with elevated principal"

    Start-Sleep -Seconds 2

    Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false

    Write-Output "Task $taskName cleaned up"
}
catch {
    Write-Error "Failed to complete task operation: $_"
    try {
        Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false -ErrorAction SilentlyContinue
    } catch {}
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
