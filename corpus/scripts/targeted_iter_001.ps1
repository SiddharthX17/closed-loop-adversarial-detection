# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   2  |  Feasible: 2  |  Variants: 6
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# SKIPPED variant 'IT admin workflow': blocked pattern: hidden window ('-windowstyle hidden')

# SKIPPED variant 'Software installer/updater workflow': blocked pattern: hidden window ('-windowstyle hidden')

# SKIPPED variant 'Document/file operation workflow': blocked pattern: hidden window ('-windowstyle hidden')

# -- Cluster: singleton_524a6953-b920-4eb1-b13f-8fc75e7219d3  (1 rule(s)) ---------------------
# Intent:    Detect UAC bypass attempts that hijack the mscfile (Task Scheduler) shell handle
# Rules:     524a6953-b920-4eb1-b13f-8fc75e7219d3
# Archetype: IT admin workflow

$ErrorActionPreference = 'SilentlyContinue'

# Define the mscfile handler registry path for auditing
$mscfilePath = 'HKCU:\Software\Classes\mscfile\shell\open\command'
$classesRoot = 'HKCU:\Software\Classes\mscfile'

# Backup current state for audit logging
$backupFile = Join-Path $env:TEMP 'mscfile_audit_backup.txt'

# Create Classes hive structure if needed (standard Windows setup)
if (-not (Test-Path $classesRoot)) {
  New-Item -Path $classesRoot -Force | Out-Null
}

# Read existing registry configuration for audit purposes
try {
  $currentHandler = (Get-Item $mscfilePath -ErrorAction Stop).GetValue('') 2>$null
  "Current mscfile handler: $currentHandler" | Out-File -FilePath $backupFile -Append
} catch {
  "Registry path not yet configured" | Out-File -FilePath $backupFile
}

# Legitimate operation: Restore default Task Scheduler handler
$defaultTaskSchedulerPath = 'C:\Windows\System32\mmc.exe'
$legitimateHandler = "\"$defaultTaskSchedulerPath\" /s taskschd.msc"

# Write legitimate registry value
New-Item -Path $mscfilePath -Force | Out-Null
Set-ItemProperty -Path $mscfilePath -Name '(Default)' -Value $legitimateHandler -Type String

# Verify the value was set correctly
$verifyHandler = (Get-ItemProperty -Path $mscfilePath).'(Default)'
"Verified handler set to: $verifyHandler" | Out-File -FilePath $backupFile -Append

# Cleanup: Remove the test registry entries
Remove-Item -Path $classesRoot -Recurse -Force
Remove-Item -Path $backupFile -Force

Write-Host 'Administrator audit completed successfully'

# -- Cluster: singleton_524a6953-b920-4eb1-b13f-8fc75e7219d3  (1 rule(s)) ---------------------
# Intent:    Detect UAC bypass attempts that hijack the mscfile (Task Scheduler) shell handle
# Rules:     524a6953-b920-4eb1-b13f-8fc75e7219d3
# Archetype: Software installer/updater workflow

$ErrorActionPreference = 'SilentlyContinue'

# Simulate enterprise task management tool installation setup
$installPath = Join-Path $env:ProgramFiles 'EnterpriseTaskManager'
$executableName = 'taskmanager_engine.exe'
$mockToolPath = Join-Path $env:TEMP $executableName

# Create mock installer executable (stub file for registry association)
if (-not (Test-Path $mockToolPath)) {
  Set-Content -Path $mockToolPath -Value 'MZ' -Encoding Ascii
}

# Define installation registry paths
$classesPath = 'HKCU:\Software\Classes'
$mscfileBase = Join-Path $classesPath 'mscfile'
$shellPath = Join-Path $mscfileBase 'shell\open\command'

# Installation step: Register custom mscfile handler for the enterprise tool
# This is typical during MSI or installer execution
New-Item -Path $classesPath -Force | Out-Null
New-Item -Path $mscfileBase -Force | Out-Null
New-Item -Path $shellPath -Force | Out-Null

# Set the file type description
Set-ItemProperty -Path $mscfileBase -Name '(Default)' -Value 'Windows Task Scheduler File' -Type String

# Register command handler - installer associates .msc files with its execution engine
Set-ItemProperty -Path $shellPath -Name '(Default)' -Value ('"' + $mockToolPath + '" "%1"') -Type String

# Log installation configuration
$configLog = Join-Path $env:TEMP 'installation_config.log'
Add-Content -Path $configLog -Value "Installation: EnterpriseTaskManager"
Add-Content -Path $configLog -Value "Handler registered: $mockToolPath"
Add-Content -Path $configLog -Value "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

# Uninstall cleanup: Remove registry entries created during setup
Remove-Item -Path $mscfileBase -Recurse -Force
Remove-Item -Path $mockToolPath -Force
Remove-Item -Path $configLog -Force

Write-Host 'Installation setup completed'

# -- Cluster: singleton_524a6953-b920-4eb1-b13f-8fc75e7219d3  (1 rule(s)) ---------------------
# Intent:    Detect UAC bypass attempts that hijack the mscfile (Task Scheduler) shell handle
# Rules:     524a6953-b920-4eb1-b13f-8fc75e7219d3
# Archetype: User-driven workflow

$ErrorActionPreference = 'SilentlyContinue'

# Simulate user-initiated system utility for managing file associations
# User opens Settings or a configuration utility that offers to fix .msc file handling

$classesPath = 'HKCU:\Software\Classes'
$mscfileKey = Join-Path $classesPath 'mscfile'
$openCommandPath = Join-Path $mscfileKey 'shell\open\command'

# Check current state - utility detects if handler is missing or misconfigured
if (-not (Test-Path $openCommandPath)) {
  Write-Host 'Detected missing mscfile handler, attempting repair...'
}

# Create the registry structure
New-Item -Path $classesPath -Force | Out-Null
New-Item -Path $mscfileKey -Force | Out-Null
New-Item -Path $openCommandPath -Force | Out-Null

# User accepts repair recommendation: Set standard Windows Task Scheduler handler
# This is what the Windows settings utility would normally recommend
$systemRoot = $env:SystemRoot
$taskSchedulerPath = Join-Path $systemRoot 'System32\taskschd.msc'

# User confirms the suggested action by clicking "Apply" or "OK"
Set-ItemProperty -Path $mscfileKey -Name '(Default)' -Value 'Task Scheduler Configuration File' -Type String

# Write the command handler that the utility recommends
# Standard path: use mmc.exe with taskschd.msc parameter
Set-ItemProperty -Path $openCommandPath -Name '(Default)' -Value ('"' + (Join-Path $systemRoot 'System32\mmc.exe') + '" "' + $taskSchedulerPath + '"') -Type String

# Log the repair action to user's local history
$repairLog = Join-Path $env:TEMP 'file_association_repair.log'
Add-Content -Path $repairLog -Value "File Association Repair Tool"
Add-Content -Path $repairLog -Value "File type: mscfile (Windows Task Scheduler Configuration File)"
Add-Content -Path $repairLog -Value "Action: Restored default handler"
Add-Content -Path $repairLog -Value "Timestamp: $(Get-Date)"

# User closes the utility, cleanup occurs
Remove-Item -Path $mscfileKey -Recurse -Force
Remove-Item -Path $repairLog -Force

Write-Host 'File association repair completed'


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
