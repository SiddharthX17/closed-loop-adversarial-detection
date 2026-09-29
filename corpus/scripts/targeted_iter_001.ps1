# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   2  |  Feasible: 2  |  Variants: 5
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_cb757e5e-f770-4521-9880-588aef1c902d  (1 rule(s)) ---------------------
# Intent:    Detect when Service Control Manager spawns an interpreter (cmd, PowerShell, etc.
# Rules:     cb757e5e-f770-4521-9880-588aef1c902d
# Archetype: IT admin workflow

$ErrorActionPreference = 'Stop'

# Create a temporary service configuration that will spawn PowerShell
# to perform legitimate remote diagnostics collection
$serviceName = 'DiagnosticSvc'
$taskPath = 'Microsoft\Windows\Diagnostics\ScheduledMaintenance'
$taskName = 'HealthCheckTask'

# Create a benign PowerShell script that would be executed by a service
$scriptContent = @'
Param(
    [string]$RemoteHost,
    [string]$SharePath
)

if ($RemoteHost -and $SharePath) {
    # Legitimate diagnostic activity: accessing remote admin shares to collect logs
    $adminSharePath = "\\\\$RemoteHost\\admin$\\Temp"

    try {
        # Attempt to access the remote admin share (would be used for collecting diagnostics)
        Get-Item -Path $adminSharePath -ErrorAction SilentlyContinue | Out-Null

        # Access IPC share for WMI queries and remote diagnostics
        Get-Item -Path "\\\\$RemoteHost\\ipc$" -ErrorAction SilentlyContinue | Out-Null

        # Access c$ share for copying system files for analysis
        Get-Item -Path "\\\\$RemoteHost\\c$\\Windows\\System32\\drivers\\etc" -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        # Shares may not be accessible; this is expected in non-domain environments
    }
}
'@

# Write the script to a temporary location
$tempScript = Join-Path -Path $env:TEMP -ChildPath "diag_collector.ps1"
Set-Content -Path $tempScript -Value $scriptContent -Encoding UTF8

# Create a scheduled task that uses a service account (SYSTEM context)
# This naturally spawns PowerShell from services.exe or svchost.exe
try {
    $taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$tempScript`" -RemoteHost 'localhost' -SharePath 'admin$'"

    $taskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)

    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount

    $task = New-ScheduledTask -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $principal

    # Register the task
    Register-ScheduledTask -TaskName $taskName -InputObject $task -TaskPath $taskPath -Force | Out-Null

    # Wait briefly for the task to execute and generate Sysmon events
    Start-Sleep -Seconds 8

    # Clean up the scheduled task
    try {
        Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false -ErrorAction SilentlyContinue
    } catch {
        # Task cleanup may fail if it hasn't finished; this is acceptable
    }
}
catch {
    # Silently continue if task scheduling fails (expected in non-admin CI environments)
}

# Clean up the temporary script
if (Test-Path $tempScript) {
    Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
}

Write-Host 'Diagnostic collection workflow completed'

# -- Cluster: singleton_cb757e5e-f770-4521-9880-588aef1c902d  (1 rule(s)) ---------------------
# Intent:    Detect when Service Control Manager spawns an interpreter (cmd, PowerShell, etc.
# Rules:     cb757e5e-f770-4521-9880-588aef1c902d
# Archetype: Software installer/updater workflow

$ErrorActionPreference = 'SilentlyContinue'

# Enterprise deployment verification scenario
# A service spawns PowerShell to check software installation status on remote machines

# Create a deployment verification script that accesses admin shares
$deploymentScript = @'
Param(
    [string]$TargetMachine = 'localhost'
)

# Verify software is properly installed by checking remote admin shares
$installPaths = @(
    "\\\\$TargetMachine\\admin$\\Temp",
    "\\\\$TargetMachine\\c$\\Program Files\\Enterprise",
    "\\\\$TargetMachine\\ipc$"
)

foreach ($path in $installPaths) {
    try {
        $item = Get-Item -Path $path -ErrorAction SilentlyContinue
        # Log would indicate successful access for deployment verification
    }
    catch {
        # Access denied is expected in non-domain environments
    }
}
'@

# Save deployment script
$scriptPath = Join-Path -Path $env:TEMP -ChildPath "deploy_verify.ps1"
Set-Content -Path $scriptPath -Value $deploymentScript -Encoding UTF8

# Simulate service spawning PowerShell for deployment verification
# First, create a task that runs as SYSTEM (simulating svchost behavior)
try {
    $taskName = 'SoftwareDeploymentCheck'
    $taskPath = 'Microsoft\\Windows\\Software'

    $psArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -TargetMachine 'localhost'"

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $psArgs
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(3)
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount

    $task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal
    Register-ScheduledTask -TaskName $taskName -InputObject $task -TaskPath $taskPath -Force | Out-Null

    # Allow task to execute
    Start-Sleep -Seconds 6

    # Clean up
    Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false -ErrorAction SilentlyContinue
}
catch {
    # Task scheduling may fail in CI environments
}

# Clean up script file
if (Test-Path $scriptPath) {
    Remove-Item -Path $scriptPath -Force
}

Write-Host 'Deployment verification completed'

# -- Cluster: singleton_cb757e5e-f770-4521-9880-588aef1c902d  (1 rule(s)) ---------------------
# Intent:    Detect when Service Control Manager spawns an interpreter (cmd, PowerShell, etc.
# Rules:     cb757e5e-f770-4521-9880-588aef1c902d
# Archetype: User-driven workflow

$ErrorActionPreference = 'SilentlyContinue'

# Administrative troubleshooting scenario
# Administrator uses PowerShell to access network shares for diagnostics and file operations

# Direct administrative share access for legitimate troubleshooting
$adminSharePaths = @(
    '\\\\localhost\\admin$\\Temp',
    '\\\\localhost\\c$\\Windows\\Temp',
    '\\\\localhost\\ipc$'
)

# Attempt to access each share (normal admin troubleshooting would do this)
foreach ($share in $adminSharePaths) {
    try {
        Get-Item -Path $share -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        # Access may be denied; expected behavior
    }
}

# Test using cmd.exe spawned command (another legitimate scenario)
cmd /c "net use \\\\localhost\\admin$ 2>nul && net use \\\\localhost\\c$ 2>nul && net use \\\\localhost\\ipc$ 2>nul" | Out-Null

# Legitimate file access pattern via PowerShell
try {
    # A real admin might check event logs or system files via admin shares
    $null = cmd /c "dir \\\\localhost\\admin$\\Temp 2>nul"
    $null = cmd /c "dir \\\\localhost\\c$\\Windows 2>nul"
}
catch {
    # Expected failures in isolated environments
}

Write-Host 'Administrative access verification completed'

# SKIPPED variant 'IT admin workflow': blocked pattern: cmd batch syntax ('echo off')

# SKIPPED variant 'Software installer/updater workflow': blocked pattern: cmd batch syntax ('echo off')


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
