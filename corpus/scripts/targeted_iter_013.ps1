# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:   iter_003
# Clusters:    1  |  Feasible: 1  |  Variants: 3
# Runner:      corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_003'

# -- Cluster: singleton_bd89dbb7  (1 rule(s)) ---------------------------------
# Intent:    Detect scheduled task creation via PowerShell with encoded commands
# Rules:     bd89dbb7-79c4-4240-a877-60179d64d9be
# Archetype: IT admin workflow

$diagScript = @'
[CmdletBinding()]
param([string]$LogPath = 'C:\Logs\WeeklyDiag.log')
$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$osInfo    = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$diskInfo  = Get-Volume -DriveLetter C -ErrorAction SilentlyContinue
Add-Content -Path $LogPath -Value "[$timestamp] OS: $($osInfo.Caption) | Free: $([math]::Round($diskInfo.SizeRemaining/1GB,2)) GB"
'@

$scriptPath = Join-Path $env:TEMP 'WeeklyDiagnostics.ps1'
Set-Content -Path $scriptPath -Value $diagScript -Encoding UTF8

$commandStr   = "& '$scriptPath'"
$encodedBytes = [System.Text.Encoding]::Unicode.GetBytes($commandStr)
$encodedCmd   = [Convert]::ToBase64String($encodedBytes)

$action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -EncodedCommand $encodedCmd"
$trigger   = New-ScheduledTaskTrigger -Daily -At ([datetime]::Today.AddDays(1).AddHours(2))
$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest

try {
    Register-ScheduledTask -TaskName 'WeeklySystemDiagnostics' `
        -Action $action -Trigger $trigger -Principal $principal `
        -Description 'Weekly system health diagnostics for operations team' `
        -Force -ErrorAction Stop
    Start-Sleep -Milliseconds 600
    Get-ScheduledTask -TaskName 'WeeklySystemDiagnostics' -ErrorAction SilentlyContinue | Out-Null
} catch {
    Write-Host "Task registration status: $($_.Exception.Message)"
} finally {
    Unregister-ScheduledTask -TaskName 'WeeklySystemDiagnostics' -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_bd89dbb7  (1 rule(s)) ---------------------------------
# Intent:    Detect scheduled task creation via PowerShell with encoded commands
# Rules:     bd89dbb7-79c4-4240-a877-60179d64d9be
# Archetype: Software installer/updater workflow

$patchScript = @'
param([string]$ManifestPath = 'C:\ProgramData\CorpUpdates\manifest.xml')
if (Test-Path $ManifestPath) {
    [xml]$manifest = Get-Content $ManifestPath -ErrorAction SilentlyContinue
    Write-Host "Patch manifest version: $($manifest.Updates.Version)"
}
$logPath = 'C:\Logs\PatchValidation.log'
Add-Content -Path $logPath -Value "$(Get-Date -Format 'o') Validation complete"
'@

$manifestDir  = 'C:\ProgramData\CorpUpdates'
$manifestPath = Join-Path $manifestDir 'manifest.xml'
$patchPath    = Join-Path $env:TEMP 'ValidatePatches.ps1'

try {
    New-Item -ItemType Directory -Path $manifestDir -Force -ErrorAction SilentlyContinue | Out-Null
    Set-Content -Path $manifestPath -Value '<?xml version="1.0"?><Updates><Version>2024.03.01</Version></Updates>' -ErrorAction SilentlyContinue
    Set-Content -Path $patchPath -Value $patchScript -Encoding UTF8

    $patchCmd     = "& '$patchPath' -ManifestPath '$manifestPath'"
    $patchEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($patchCmd))

    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -EncodedCommand $patchEncoded"
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest

    Register-ScheduledTask -TaskName 'CorpPatchValidation' `
        -Action $action -Trigger $trigger -Principal $principal `
        -Description 'Post-deployment patch validation for configuration management' `
        -Force -ErrorAction Stop
    Start-Sleep -Milliseconds 500
} catch {
    Write-Host "Installer task status: $($_.Exception.Message)"
} finally {
    Unregister-ScheduledTask -TaskName 'CorpPatchValidation' -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Path $patchPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $manifestPath -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_bd89dbb7  (1 rule(s)) ---------------------------------
# Intent:    Detect scheduled task creation via PowerShell with encoded commands
# Rules:     bd89dbb7-79c4-4240-a877-60179d64d9be
# Archetype: User-driven workflow

$taskNames = @('AppDataBackup', 'BrowserCacheClean', 'DownloadsFolderSync')
$taskName  = $taskNames | Get-Random

$userScript   = "Get-Date | Add-Content -Path (Join-Path `$env:TEMP 'corp_activity.log')"
$userEncoded  = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($userScript))

$action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -EncodedCommand $userEncoded"
$trigger   = New-ScheduledTaskTrigger -Daily -At ([datetime]::Today.AddDays(1).AddHours(7))
$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest

try {
    Register-ScheduledTask -TaskName $taskName `
        -Action $action -Trigger $trigger -Principal $principal `
        -Description 'User-configured maintenance task' `
        -Force -ErrorAction Stop
    Start-Sleep -Milliseconds 400
} catch {
    Write-Host "User task status: $($_.Exception.Message)"
} finally {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
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