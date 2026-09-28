# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   3  |  Feasible: 3  |  Variants: 9
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_ce4c8302-34d2-4a92-bb43-8964e42aa802  (1 rule(s)) ---------------------
# Intent:    Attackers stealing the NTDS.dit database (Active Directory credential store) by 
# Rules:     ce4c8302-34d2-4a92-bb43-8964e42aa802
# Archetype: IT admin workflow

$tempDir = $env:TEMP + '\dc_backup_' + [System.Guid]::NewGuid().ToString('N').Substring(0,8)
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

try {
  # Simulate legitimate IFM backup operation
  # Legitimate admin would run this on domain controller for DR purposes
  Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Initiating domain controller disaster recovery backup"

  # Create mock NTDS.dit and config\system files to simulate what would be backed up
  $mockNtdsPath = Join-Path $tempDir 'ntds.dit'
  $mockConfigPath = Join-Path $tempDir 'config'
  New-Item -ItemType Directory -Path $mockConfigPath -Force | Out-Null

  # Write minimal mock content
  Add-Content -Path $mockNtdsPath -Value 'mock ntds backup'
  Add-Content -Path (Join-Path $mockConfigPath 'system') -Value 'mock system hive'

  # Execute ntdsutil with IFM create full parameters (legitimate admin workflow)
  # This produces the command line signature the rule is looking for
  $command = @(
    'ntdsutil.exe',
    'ac i ntds',
    'ifm',
    'create full',
    $tempDir
  ) -join ' '

  Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Command: $command"

  # For lab/test purposes on non-domain-controller, catch expected errors gracefully
  try {
    & cmd /c "ntdsutil.exe 'ac i ntds' 'ifm' 'create full $tempDir' quit quit" 2>&1 | Out-Null
  }
  catch {
    # Expected to fail on non-DC, but command line is logged
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] IFM operation result: Expected failure on non-DC (normal in lab)"
  }

  Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Domain controller backup workflow complete"
}
finally {
  # Cleanup backup directory
  if (Test-Path $tempDir) {
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# -- Cluster: singleton_ce4c8302-34d2-4a92-bb43-8964e42aa802  (1 rule(s)) ---------------------
# Intent:    Attackers stealing the NTDS.dit database (Active Directory credential store) by 
# Rules:     ce4c8302-34d2-4a92-bb43-8964e42aa802
# Archetype: Software installer/updater workflow

$backupJobDir = $env:TEMP + '\backup_job_' + [System.Guid]::NewGuid().ToString('N').Substring(0,8)
New-Item -ItemType Directory -Path $backupJobDir -Force | Out-Null

try {
  Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Backup service initiating system component inventory"

  # Simulate backup software checking for NTDS and system configuration
  # Real backup tools enumerate these paths as part of backup planning
  $inventoryLog = Join-Path $backupJobDir 'backup_inventory.log'

  # Log component paths that backup software would discover
  @(
    "Component: Active Directory Database",
    "Path: config\\system hive location",
    "File: ntds.dit",
    "Backup Strategy: IFM create full consistency snapshot"
  ) | Out-File -FilePath $inventoryLog -Encoding ASCII

  Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Checking ntds.dit configuration for backup eligibility"

  # Legitimate backup agent workflow: invoke ntdsutil to prepare IFM snapshot
  # This is standard practice for backup software on domain controllers
  $backupCommand = @(
    'ntdsutil.exe',
    'ac i ntds',
    'ifm',
    'create full',
    $backupJobDir
  ) -join ' '

  Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Executing backup preparation: $backupCommand"

  try {
    & cmd /c "ntdsutil.exe 'ac i ntds' 'ifm' 'create full $backupJobDir' quit quit" 2>&1 | Out-Null
  }
  catch {
    # Expected on non-DC systems, logs indicate proper tool invocation
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Backup preparation result: Non-DC environment (skipping NTDS backup)"
  }

  Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Backup inventory phase complete"
}
finally {
  # Cleanup backup job directory
  if (Test-Path $backupJobDir) {
    Remove-Item -Path $backupJobDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# -- Cluster: singleton_ce4c8302-34d2-4a92-bb43-8964e42aa802  (1 rule(s)) ---------------------
# Intent:    Attackers stealing the NTDS.dit database (Active Directory credential store) by 
# Rules:     ce4c8302-34d2-4a92-bb43-8964e42aa802
# Archetype: User-driven workflow

$maintenanceDir = $env:TEMP + '\ad_maintenance_' + [System.Guid]::NewGuid().ToString('N').Substring(0,8)
New-Item -ItemType Directory -Path $maintenanceDir -Force | Out-Null

try {
  Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Active Directory maintenance: Starting NTDS health check"

  # Create subdirectories for NTDS backup output
  $ifmOutputDir = Join-Path $maintenanceDir 'ifm_snapshot'
  New-Item -ItemType Directory -Path $ifmOutputDir -Force | Out-Null

  # Document the maintenance action
  $maintenanceLog = Join-Path $maintenanceDir 'maintenance_log.txt'
  @(
    "[$(Get-Date)] AD Maintenance Session Started",
    "Task: NTDS.dit integrity validation and recovery snapshot creation",
    "Component: ntds.dit active directory database",
    "Config Source: config\\system registry hive",
    "Operation: IFM create full snapshot for validation"
  ) | Out-File -FilePath $maintenanceLog -Encoding ASCII

  Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Validating ntds.dit configuration parameters"

  # Execute ntdsutil to create IFM snapshot (legitimate maintenance operation)
  # Domain admin would run this to validate recovery procedures
  $ntdsutilCommand = @(
    'ntdsutil.exe',
    'ac i ntds',
    'ifm',
    'create full',
    $ifmOutputDir
  ) -join ' '

  Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Creating NTDS snapshot: $ntdsutilCommand"

  try {
    & cmd /c "ntdsutil.exe 'ac i ntds' 'ifm' 'create full $ifmOutputDir' quit quit" 2>&1 | Out-Null
  }
  catch {
    # Expected on non-DC, document the attempt
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] NTDS snapshot creation: Non-DC environment detected, operation skipped"
  }

  Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Active Directory maintenance: Health check complete"
  Write-Host "[$(Get-Date -Format 'HH:mm:ss')] All validation checks passed"
}
finally {
  # Cleanup maintenance directory
  if (Test-Path $maintenanceDir) {
    Remove-Item -Path $maintenanceDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

# -- Cluster: singleton_f1d5151e-595c-4fcb-bb1c-5464e07c9d96  (1 rule(s)) ---------------------
# Intent:    Remote code execution via PowerShell remoting cmdlets (Invoke-Command, New-PSSes
# Rules:     f1d5151e-595c-4fcb-bb1c-5464e07c9d96
# Archetype: IT admin workflow

$targetComputer = 'WORKSTATION-01'
$remoteCred = New-Object System.Management.Automation.PSCredential('DOMAIN\Administrator', (ConvertTo-SecureString 'P@ssw0rd123' -AsPlainText -Force))

try {
  $session = New-PSSession -ComputerName $targetComputer -Credential $remoteCred -ErrorAction Stop
  $osInfo = Invoke-Command -Session $session -ScriptBlock { Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber }
  Write-Output "OS Information: $osInfo"
  Remove-PSSession $session
} catch [System.UnauthorizedAccessException] {
  Write-Output "Access denied to $targetComputer (expected in isolated environment)"
}

$localComputer = 'localhost'
$softwareInfo = Invoke-Command -ComputerName $localComputer -ScriptBlock {
  Get-WmiObject Win32_Product | Select-Object Name, Version | Sort-Object Name
}
Write-Output "Inventory collection complete"

# -- Cluster: singleton_f1d5151e-595c-4fcb-bb1c-5464e07c9d96  (1 rule(s)) ---------------------
# Intent:    Remote code execution via PowerShell remoting cmdlets (Invoke-Command, New-PSSes
# Rules:     f1d5151e-595c-4fcb-bb1c-5464e07c9d96
# Archetype: User-driven workflow

$devServer = 'DEVAPP-02'

try {
  $remoteSession = New-PSSession -ComputerName $devServer -ErrorAction Stop
  $eventLogs = Invoke-Command -Session $remoteSession -ScriptBlock {
    Get-EventLog -LogName Application -Newest 50 -EntryType Error | Select-Object TimeGenerated, Source, Message
  }
  Write-Output "Retrieved $($eventLogs.Count) error events"
  Remove-PSSession $remoteSession
} catch [System.Net.Sockets.SocketException] {
  Write-Output "Cannot connect to $devServer (expected in isolated environment)"
} catch {
  Write-Output "Connection attempt to development server completed"
}

Enter-PSSession -ComputerName $devServer -ErrorAction SilentlyContinue
Exit-PSSession

# -- Cluster: singleton_f1d5151e-595c-4fcb-bb1c-5464e07c9d96  (1 rule(s)) ---------------------
# Intent:    Remote code execution via PowerShell remoting cmdlets (Invoke-Command, New-PSSes
# Rules:     f1d5151e-595c-4fcb-bb1c-5464e07c9d96
# Archetype: Software installer/updater workflow

$servers = @('SERVER-PATCH-01', 'SERVER-PATCH-02')
$patchScriptBlock = {
  $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 -ExpandProperty HotFixID
  return $hotfixes
}

foreach ($server in $servers) {
  try {
    $patchSession = New-PSSession -ComputerName $server -ErrorAction Stop
    $installedPatches = Invoke-Command -Session $patchSession -ScriptBlock $patchScriptBlock
    Write-Output "Server $server - Latest patches: $installedPatches"
    Remove-PSSession $patchSession
  } catch [System.Net.Sockets.SocketException] {
    Write-Output "Cannot reach $server (expected in isolated environment)"
  } catch {
    Write-Output "Patch inventory task executed"
  }
}

$wsManUri = 'https://SERVER-PATCH-01:5985/wsman'
Enter-PSSession -ConnectionUri $wsManUri -ErrorAction SilentlyContinue
Exit-PSSession

Write-Output "Configuration validation workflow completed"

# -- Cluster: singleton_737e86a8-49c8-40a1-a8c7-64c5b9e23e4c  (1 rule(s)) ---------------------
# Intent:    Attackers execute Windows Script Host (cscript.exe/wscript.exe) from user-writab
# Rules:     737e86a8-49c8-40a1-a8c7-64c5b9e23e4c
# Archetype: Software installer/updater workflow

$tempDir = Join-Path $env:TEMP 'AppSetup_Staging'
if (Test-Path $tempDir) { Remove-Item $tempDir -Recurse -Force }
New-Item -ItemType Directory -Path $tempDir | Out-Null

# Create a benign VBScript that would normally be part of installer configuration
$vbscriptContent = @'
Set objWshShell = CreateObject("WScript.Shell")
objWshShell.CurrentDirectory = WScript.ScriptFullName
Set objFSO = CreateObject("Scripting.FileSystemObject")
strLogFile = objFSO.GetParentFolderName(WScript.ScriptFullName) & "\\setup_log.txt"
Set objLogFile = objFSO.CreateTextFile(strLogFile, True)
objLogFile.Write "Setup initialization completed at " & Now() & vbCrLf
objLogFile.Close()
'@

$scriptPath = Join-Path $tempDir 'initialize.vbs'
Set-Content -Path $scriptPath -Value $vbscriptContent -Encoding ASCII

# Execute the VBScript from TEMP directory via cscript.exe - legitimate installer post-setup
cscript.exe $scriptPath

# Verify log was created (confirming script execution)
Start-Sleep -Milliseconds 500
$logPath = Join-Path $tempDir 'setup_log.txt'
if (Test-Path $logPath) {
    Remove-Item $logPath -Force
}

# Cleanup
Remove-Item $scriptPath -Force
Remove-Item $tempDir -Force

# -- Cluster: singleton_737e86a8-49c8-40a1-a8c7-64c5b9e23e4c  (1 rule(s)) ---------------------
# Intent:    Attackers execute Windows Script Host (cscript.exe/wscript.exe) from user-writab
# Rules:     737e86a8-49c8-40a1-a8c7-64c5b9e23e4c
# Archetype: User-driven workflow

$downloadsDir = Join-Path $env:USERPROFILE 'Downloads'
if (-not (Test-Path $downloadsDir)) {
    New-Item -ItemType Directory -Path $downloadsDir | Out-Null
}

# Create a benign configuration utility script as would come from an intranet portal
$jscriptContent = @'
var WshShell = new ActiveXObject("WScript.Shell");
var FSO = new ActiveXObject("Scripting.FileSystemObject");
var logPath = WshShell.CurrentDirectory + "\\config_applied.txt";
var logFile = FSO.CreateTextFile(logPath, true);
logFile.WriteLine("Configuration utility executed: " + new Date());
logFile.Close();
'@

$scriptPath = Join-Path $downloadsDir 'ConfigUtility.js'
Set-Content -Path $scriptPath -Value $jscriptContent -Encoding ASCII

# Execute the downloaded script via wscript.exe from Downloads - legitimate user workflow
wscript.exe $scriptPath

# Verify execution
Start-Sleep -Milliseconds 500
$logPath = Join-Path $downloadsDir 'config_applied.txt'
if (Test-Path $logPath) {
    Remove-Item $logPath -Force
}

# Cleanup
Remove-Item $scriptPath -Force

# -- Cluster: singleton_737e86a8-49c8-40a1-a8c7-64c5b9e23e4c  (1 rule(s)) ---------------------
# Intent:    Attackers execute Windows Script Host (cscript.exe/wscript.exe) from user-writab
# Rules:     737e86a8-49c8-40a1-a8c7-64c5b9e23e4c
# Archetype: IT admin workflow

$appdataDir = $env:APPDATA
$maintDir = Join-Path $appdataDir 'ITMaintenance'
if (Test-Path $maintDir) { Remove-Item $maintDir -Recurse -Force }
New-Item -ItemType Directory -Path $maintDir | Out-Null

# Create a benign maintenance script as would be deployed by IT
$vbscriptContent = @'
Set objWshShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")
strEnv = objWshShell.ExpandEnvironmentStrings("%COMPUTERNAME%")
strLogPath = objFSO.GetParentFolderName(WScript.ScriptFullName) & "\\maint_record.txt"
Set objLogFile = objFSO.CreateTextFile(strLogPath, True)
objLogFile.Write "Maintenance check run on " & strEnv & " at " & Now() & vbCrLf
objLogFile.Close()
'@

$scriptPath = Join-Path $maintDir 'compliance_check.vbs'
Set-Content -Path $scriptPath -Value $vbscriptContent -Encoding ASCII

# Execute the maintenance script from AppData via cscript.exe
cscript.exe $scriptPath

# Verify execution
Start-Sleep -Milliseconds 500
$logPath = Join-Path $maintDir 'maint_record.txt'
if (Test-Path $logPath) {
    Remove-Item $logPath -Force
}

# Cleanup
Remove-Item $scriptPath -Force
Remove-Item $maintDir -Force


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
