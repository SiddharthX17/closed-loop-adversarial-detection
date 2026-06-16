# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   2  |  Feasible: 2  |  Variants: 4
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_6c7fdc8a-2c7b-49ea-8836-3f426cbca870  (1 rule(s)) ---------------------
# Intent:    Detect scheduled task registration via PowerShell with elevated (Administrators)
# Rules:     6c7fdc8a-2c7b-49ea-8836-3f426cbca870
# Archetype: Software installer/updater workflow

$taskName = 'SystemMaintenance_' + (Get-Random -Minimum 10000 -Maximum 99999)
$taskPath = '\Microsoft\Windows\SystemMaintenance\'
$taskAction = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c echo Maintenance check completed' -WorkingDirectory $env:WINDIR
$taskTrigger = New-ScheduledTaskTrigger -Daily -At 2:00 AM
$principal = New-ScheduledTaskPrincipal -UserId 'BUILTIN\Administrators' -RunLevel Highest

try {
  Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Principal $principal -TaskPath $taskPath -Description 'Automated system maintenance task' -Force -ErrorAction Stop
  Write-Host "Task $taskName registered successfully"
  Start-Sleep -Milliseconds 500
  Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false -ErrorAction Stop
  Write-Host "Task $taskName cleaned up"
} catch {
  Write-Host "Error during task lifecycle: $_"
}

# -- Cluster: singleton_6c7fdc8a-2c7b-49ea-8836-3f426cbca870  (1 rule(s)) ---------------------
# Intent:    Detect scheduled task registration via PowerShell with elevated (Administrators)
# Rules:     6c7fdc8a-2c7b-49ea-8836-3f426cbca870
# Archetype: IT admin workflow

$existingTaskName = 'DefragmentationEngine'
$existingTaskPath = '\Microsoft\Windows\Defrag\'

$taskAction = New-ScheduledTaskAction -Execute 'defrag.exe' -Argument 'C: /U /V' -WorkingDirectory $env:WINDIR
$taskTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3:00 AM
$principal = New-ScheduledTaskPrincipal -UserId 'BUILTIN\Administrators' -RunLevel Highest

try {
  Register-ScheduledTask -TaskName $existingTaskName -Action $taskAction -Trigger $taskTrigger -Principal $principal -TaskPath $existingTaskPath -Description 'Weekly disk defragmentation' -Force -ErrorAction Stop
  Write-Host "Base task $existingTaskName registered"
  Start-Sleep -Milliseconds 300

  Set-ScheduledTask -TaskName $existingTaskName -TaskPath $existingTaskPath -Principal $principal -Action $taskAction -ErrorAction Stop
  Write-Host "Task $existingTaskName updated with elevated principal"
  Start-Sleep -Milliseconds 300

  Unregister-ScheduledTask -TaskName $existingTaskName -TaskPath $existingTaskPath -Confirm:$false -ErrorAction Stop
  Write-Host "Task $existingTaskName removed"
} catch {
  Write-Host "Error during task modification: $_"
}

# -- Cluster: singleton_fe52fb60-d778-4c5b-b602-efbb645233f8  (1 rule(s)) ---------------------
# Intent:    Detect WScript.exe that has been renamed or disguised to execute from security v
# Rules:     fe52fb60-d778-4c5b-b602-efbb645233f8
# Archetype: Software installer/updater workflow

# Simulates a security vendor post-installation configuration task
# This represents legitimate EDR/antivirus setup automation

$vendorPath = 'C:\Program Files\Symantec\Endpoint Protection\ToolRunner'
$wscriptSource = 'C:\Windows\System32\wscript.exe'
$configScript = Join-Path $vendorPath 'config_setup.vbs'

try {
    # Create vendor tool directory structure
    if (-not (Test-Path $vendorPath)) {
        New-Item -ItemType Directory -Path $vendorPath -Force | Out-Null
    }

    # Copy legitimate wscript.exe to vendor directory
    # This preserves OriginalFileName metadata pointing to wscript.exe
    Copy-Item -Path $wscriptSource -Destination (Join-Path $vendorPath 'wscript.exe') -Force

    # Create a harmless VBScript configuration task
    $vbsContent = @'
Set objShell = CreateObject("WScript.Shell")
objShell.LogEvent 4, "Configuration initialization started"
WScript.Sleep 500
objShell.LogEvent 4, "Configuration initialization completed"
'@
    Set-Content -Path $configScript -Value $vbsContent -Encoding ASCII

    # Invoke wscript.exe from the vendor directory to execute the configuration script
    # Sysmon will record: Image = C:\Program Files\Symantec\..., OriginalFileName = wscript.exe
    & (Join-Path $vendorPath 'wscript.exe') $configScript //NoLogo
    Start-Sleep -Milliseconds 1000

    # Clean up
    Remove-Item -Path $configScript -Force -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path $vendorPath 'wscript.exe') -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $vendorPath -Force -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Configuration task encountered an issue: $_"
    # Attempt cleanup on error
    Remove-Item -Path $vendorPath -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_fe52fb60-d778-4c5b-b602-efbb645233f8  (1 rule(s)) ---------------------
# Intent:    Detect WScript.exe that has been renamed or disguised to execute from security v
# Rules:     fe52fb60-d778-4c5b-b602-efbb645233f8
# Archetype: IT admin workflow

# Simulates IT admin using vendor-supplied diagnostic tooling
# This represents legitimate compliance verification and agent health checks

$vendorPath = 'C:\Program Files\CrowdStrike\CSFalconService\Diagnostics'
$wscriptSource = 'C:\Windows\System32\wscript.exe'
$diagnosticScript = Join-Path $vendorPath 'health_check.vbs'

try {
    # Create vendor diagnostics directory
    if (-not (Test-Path $vendorPath)) {
        New-Item -ItemType Directory -Path $vendorPath -Force | Out-Null
    }

    # Copy wscript.exe for vendor diagnostics
    Copy-Item -Path $wscriptSource -Destination (Join-Path $vendorPath 'wscript.exe') -Force

    # Create health check VBScript
    $vbsContent = @'
Set objShell = CreateObject("WScript.Shell")
Set objFS = CreateObject("Scripting.FileSystemObject")
objShell.LogEvent 4, "Initiating agent health verification"
WScript.Sleep 300
objShell.LogEvent 4, "Agent services responding: ACTIVE"
WScript.Sleep 300
objShell.LogEvent 4, "License validation: CURRENT"
WScript.Sleep 300
objShell.LogEvent 4, "Health check completed successfully"
'@
    Set-Content -Path $diagnosticScript -Value $vbsContent -Encoding ASCII

    # Execute the health check from vendor path
    & (Join-Path $vendorPath 'wscript.exe') $diagnosticScript //NoLogo
    Start-Sleep -Milliseconds 500

    # Clean up diagnostic artifacts
    Remove-Item -Path $diagnosticScript -Force -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path $vendorPath 'wscript.exe') -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $vendorPath -Force -ErrorAction SilentlyContinue
} catch {
    Write-Warning "Diagnostic verification failed: $_"
    Remove-Item -Path $vendorPath -Recurse -Force -ErrorAction SilentlyContinue
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
