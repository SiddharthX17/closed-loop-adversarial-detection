# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   2  |  Feasible: 2  |  Variants: 5
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_bd5f77f5-9b6e-4e75-abd7-3ce69e7e2000  (1 rule(s)) ---------------------
# Intent:    Attackers register scheduled tasks via PowerShell with elevated privileges and l
# Rules:     bd5f77f5-9b6e-4e75-abd7-3ce69e7e2000
# Archetype: IT admin workflow

$taskName = 'SystemMaintenance_LogRotation'
$taskPath = '\Microsoft\Windows\Maintenance\'
$description = 'Automated log rotation and temporary file cleanup for system health monitoring'

# Create a legitimate maintenance script in Program Files
$maintenanceDir = 'C:\Program Files\SystemMaintenance'
if (-not (Test-Path $maintenanceDir)) {
    New-Item -ItemType Directory -Path $maintenanceDir -Force | Out-Null
}

$scriptPath = Join-Path -Path $maintenanceDir -ChildPath 'maintenance.ps1'
$scriptContent = @'
# Maintenance operations
$logPath = Join-Path -Path $env:TEMP -ChildPath 'syslogs'
if (Test-Path $logPath) {
    Get-ChildItem -Path $logPath -Filter '*.log' -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item -Force -ErrorAction SilentlyContinue
}

# Clean temporary files
Get-ChildItem -Path $env:TEMP -ErrorAction SilentlyContinue | Where-Object { $_.LastAccessTime -lt (Get-Date).AddDays(-7) -and $_.PSIsContainer -eq $false } | Remove-Item -Force -ErrorAction SilentlyContinue
'@

Set-Content -Path $scriptPath -Value $scriptContent -Force

# Register scheduled task with elevated RunLevel and startup trigger
try {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $scriptPath)
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -RunLevel 'Highest' -LogonType ServiceAccount
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $description -Force | Out-Null
} catch {
    # Task may already exist or registration may fail in test environment
}

# Verification and cleanup
Start-Sleep -Seconds 1

# Unregister the task to clean up
try {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
} catch {
    # Task may not exist
}

# Remove the maintenance script directory
if (Test-Path $maintenanceDir) {
    Remove-Item -Path $maintenanceDir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_bd5f77f5-9b6e-4e75-abd7-3ce69e7e2000  (1 rule(s)) ---------------------
# Intent:    Attackers register scheduled tasks via PowerShell with elevated privileges and l
# Rules:     bd5f77f5-9b6e-4e75-abd7-3ce69e7e2000
# Archetype: Software installer/updater workflow

$taskName = 'ApplicationHealthMonitor_LogonTask'
$description = 'Application health verification and recovery at user logon'

# Simulate software installation in ProgramData (common for enterprise apps)
$appDir = 'C:\ProgramData\EnterpriseApp\HealthMonitor'
if (-not (Test-Path $appDir)) {
    New-Item -ItemType Directory -Path $appDir -Force | Out-Null
}

$monitorScript = Join-Path -Path $appDir -ChildPath 'health_check.ps1'
$scriptContent = @'
# Application health monitoring
$appState = @{
    ServiceRunning = $true
    LastCheck = (Get-Date)
    ConfigValid = $true
}

# Verify critical application services are running
$criticalServices = @('EventLog', 'Winmgmt')
foreach ($svc in $criticalServices) {
    $serviceStatus = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($null -eq $serviceStatus -or $serviceStatus.Status -ne 'Running') {
        Start-Service -Name $svc -ErrorAction SilentlyContinue
    }
}
'@

Set-Content -Path $monitorScript -Value $scriptContent -Force

# Register task with AtLogon trigger and highest privilege level
try {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $monitorScript
    )
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -RunLevel 'Highest' -LogonType ServiceAccount
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $description -Force | Out-Null
} catch {
    # Task registration may fail in limited CI environments
}

Start-Sleep -Seconds 1

# Cleanup
try {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
} catch {
    # Task may not exist
}

if (Test-Path $appDir) {
    Remove-Item -Path $appDir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_4f1f8b5d-1702-4c93-bf20-eab9af3175fa  (1 rule(s)) ---------------------
# Intent:    Detect shell interpreters (cmd, PowerShell, etc.) initiating outbound connection
# Rules:     4f1f8b5d-1702-4c93-bf20-eab9af3175fa
# Archetype: IT admin workflow

$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

# Simulate infrastructure admin downloading deployment validation script from public GitHub
# This represents a realistic scenario where ops teams fetch setup utilities
$repoUrl = 'https://raw.githubusercontent.com/PowerShell/PowerShell/master/README.md'
$tempDir = [System.IO.Path]::GetTempPath()
$configFile = Join-Path $tempDir 'deployment_manifest.txt'

try {
    # Admin downloading configuration manifest from GitHub raw endpoint
    Write-Host 'Retrieving deployment manifest from repository...'
    $manifest = Invoke-WebRequest -Uri $repoUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop

    if ($manifest.StatusCode -eq 200) {
        # Validate content locally
        $contentHash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($manifest.Content))
        $hashString = ($contentHash | ForEach-Object { $_.ToString('x2') }) -join ''

        Write-Host "Manifest retrieved. Hash: $($hashString.Substring(0,16))..."

        # Save for audit trail
        Add-Content -Path $configFile -Value (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') -ErrorAction SilentlyContinue
        Add-Content -Path $configFile -Value "Source: raw.githubusercontent.com" -ErrorAction SilentlyContinue
        Add-Content -Path $configFile -Value "Status: Downloaded" -ErrorAction SilentlyContinue
    }
}
catch {
    Write-Host "Download attempt completed with status: $_"
}
finally {
    # Cleanup
    Remove-Item -Path $configFile -Force -ErrorAction SilentlyContinue
    Write-Host 'Cleanup complete.'
}

Start-Sleep -Milliseconds 500

# -- Cluster: singleton_4f1f8b5d-1702-4c93-bf20-eab9af3175fa  (1 rule(s)) ---------------------
# Intent:    Detect shell interpreters (cmd, PowerShell, etc.) initiating outbound connection
# Rules:     4f1f8b5d-1702-4c93-bf20-eab9af3175fa
# Archetype: Software installer/updater workflow

$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

# Simulate CI/CD build system verifying tool dependencies
# Represents realistic build orchestration where parent CI process spawns PowerShell
$buildWorkspace = Join-Path $env:TEMP 'build_cache_verify'
if (-not (Test-Path $buildWorkspace)) {
    New-Item -ItemType Directory -Path $buildWorkspace -Force | Out-Null
}

$versionCacheFile = Join-Path $buildWorkspace 'tool_versions.log'

try {
    # CI system downloading tool version manifest from GitHub
    Write-Host 'Build system: Retrieving dependency versions from upstream...'

    $githubUrl = 'https://raw.githubusercontent.com/dotnet/runtime/main/README.md'
    $pasteUrl = 'https://paste.rs/raw'

    # Fetch from primary source
    Write-Host 'Contacting primary repository...'
    $response1 = Invoke-WebRequest -Uri $githubUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue
    if ($response1) {
        Add-Content -Path $versionCacheFile -Value "[$(Get-Date -Format 'HH:mm:ss')] Primary source: OK" -ErrorAction SilentlyContinue
    }

    # Build system may also check alternative hosts for mirrors
    Write-Host 'Checking backup location...'
    $response2 = Invoke-WebRequest -Uri $pasteUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue
    if ($response2) {
        Add-Content -Path $versionCacheFile -Value "[$(Get-Date -Format 'HH:mm:ss')] Backup location: Checked" -ErrorAction SilentlyContinue
    }

    Write-Host 'Dependency verification complete.'
}
catch {
    Write-Host "Upstream check result: $_"
}
finally {
    # Cleanup build workspace
    Remove-Item -Path $buildWorkspace -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host 'Build workspace cleaned.'
}

Start-Sleep -Milliseconds 300

# -- Cluster: singleton_4f1f8b5d-1702-4c93-bf20-eab9af3175fa  (1 rule(s)) ---------------------
# Intent:    Detect shell interpreters (cmd, PowerShell, etc.) initiating outbound connection
# Rules:     4f1f8b5d-1702-4c93-bf20-eab9af3175fa
# Archetype: User-driven workflow

$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

# Developer bootstrapping project workspace with configuration from public sources
# Represents realistic onboarding where developers fetch project templates
$projectRoot = Join-Path $env:TEMP 'project_bootstrap'
if (-not (Test-Path $projectRoot)) {
    New-Item -ItemType Directory -Path $projectRoot -Force | Out-Null
}

$configLog = Join-Path $projectRoot 'setup_log.txt'

try {
    Write-Host 'Developer: Initializing project workspace...'

    # Fetch project configuration template from gist
    Write-Host 'Retrieving project configuration template...'
    $gistUrl = 'https://gist.githubusercontent.com/octocat/1234567/raw/config.json'
    $configResponse = Invoke-WebRequest -Uri $gistUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue

    if ($configResponse) {
        Write-Host 'Configuration template retrieved.'
        Add-Content -Path $configLog -Value "Config source: gist.githubusercontent.com" -ErrorAction SilentlyContinue
    }

    # Check build guidelines from alternative paste service
    Write-Host 'Checking build documentation...'
    $docsUrl = 'https://paste.ee/r/abc123'
    $docsResponse = Invoke-WebRequest -Uri $docsUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction SilentlyContinue

    if ($docsResponse) {
        Write-Host 'Build documentation available.'
        Add-Content -Path $configLog -Value "Docs verified from: paste.ee" -ErrorAction SilentlyContinue
    }

    # Validate workspace structure
    Write-Host 'Workspace ready for development.'
}
catch {
    Write-Host "Workspace setup status: $_"
}
finally {
    # Cleanup project bootstrap directory
    Remove-Item -Path $projectRoot -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host 'Workspace cleanup complete.'
}

Start-Sleep -Milliseconds 300


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
