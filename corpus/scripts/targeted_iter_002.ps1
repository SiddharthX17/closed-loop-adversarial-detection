# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   3  |  Feasible: 3  |  Variants: 8
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_533f19f5-36ad-426c-bf9b-99930d91bbc4  (1 rule(s)) ---------------------
# Intent:    Attacker activity involving copying NTDS.dit and SYSTEM registry hive for offlin
# Rules:     533f19f5-36ad-426c-bf9b-99930d91bbc4
# Archetype: IT admin workflow

$backupRoot = "$env:TEMP\SystemBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null

# Create a test SYSTEM registry hive export (simulating legitimate backup of registry)
$testRegPath = "$backupRoot\registry_export"
New-Item -ItemType Directory -Path $testRegPath -Force | Out-Null

# Export SYSTEM hive for backup verification
reg export HKLM\SYSTEM "$testRegPath\system_hive.reg" /y | Out-Null
reg export HKLM\SECURITY "$testRegPath\security_hive.reg" /y | Out-Null

# Simulate copying system files that include references to system configuration
# This would be part of a legitimate full system backup
$demoFile = "$backupRoot\system_config_snapshot.txt"
@"
System Backup Report - $(Get-Date)
Target: Local System Configuration
Including: Config\System registry paths
Status: Backup in progress
"@ | Set-Content -Path $demoFile

# Simulate robocopy operation that an admin might use for file mirroring
# Including paths that reference system configuration
Write-Host "Initiating system configuration backup..."
robocopy "$env:SystemRoot\System32\config" "$backupRoot\config" /S /E /R:1 /W:1 2>&1 | Out-Null

# Cleanup: remove the backup directory and its contents
Remove-Item -Path $backupRoot -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Backup activity completed and cleaned up."

# -- Cluster: singleton_533f19f5-36ad-426c-bf9b-99930d91bbc4  (1 rule(s)) ---------------------
# Intent:    Attacker activity involving copying NTDS.dit and SYSTEM registry hive for offlin
# Rules:     533f19f5-36ad-426c-bf9b-99930d91bbc4
# Archetype: Software installer/updater workflow

$inventoryPath = "$env:TEMP\SystemInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Path $inventoryPath -Force | Out-Null

# Simulate a system inventory/compliance tool reading system configuration
# This is realistic behavior for tools like Microsoft Baseline Security Analyzer
Write-Host "Initiating system compliance inventory..."

# Check for NTDS.dit presence (normal inventory operation)
if (Test-Path "$env:SystemRoot\NTDS\ntds.dit") {
    Write-Host "NTDS.dit location identified for compliance audit"
    Get-Item "$env:SystemRoot\NTDS\ntds.dit" -ErrorAction SilentlyContinue | Select-Object FullName, Length | Out-File -FilePath "$inventoryPath\ntds_inventory.txt"
}

# Export SYSTEM hive for compliance scanning
$systemHivePath = "$inventoryPath\system.hiv"
reg export HKLM\SYSTEM $systemHivePath /y | Out-Null

# Scan the exported hive for security baselines (legitimate compliance tool behavior)
if (Test-Path $systemHivePath) {
    $hiveSize = (Get-Item $systemHivePath).Length
    Write-Host "SYSTEM hive exported for compliance analysis: $hiveSize bytes"

    # Simulate reading system configuration from the hive
    "System Hive Compliance Report" | Out-File -FilePath "$inventoryPath\compliance_report.txt"
    "Scanned paths: Config\\System registry structure" | Add-Content -Path "$inventoryPath\compliance_report.txt"
}

# Also export SECURITY hive for comprehensive inventory
reg export HKLM\SECURITY "$inventoryPath\security.hiv" /y | Out-Null

# Cleanup: remove the inventory directory
Remove-Item -Path $inventoryPath -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "System inventory completed and cleaned up."

# -- Cluster: singleton_713879b9-0e84-44cd-bfb3-fbeb37b3d991  (1 rule(s)) ---------------------
# Intent:    Detect PS-Remoting cmdlet invocations (Enable-PSRemoting, Invoke-Command, Enter-
# Rules:     713879b9-0e84-44cd-bfb3-fbeb37b3d991
# Archetype: IT admin workflow

# Enable PowerShell Remoting for remote management capability
Enable-PSRemoting -Force -SkipNetworkProfileCheck

# Wait briefly for service to initialize
Start-Sleep -Seconds 2

# Create a remote session to a local host for diagnostic purposes
$session = New-PSSession -ComputerName localhost -ErrorAction SilentlyContinue

if ($session) {
    # Run a diagnostic query via the remote session
    Invoke-Command -Session $session -ScriptBlock {
        Get-Process | Where-Object {$_.WorkingSet -gt 100MB} | Select-Object Name, WorkingSet
    } -ErrorAction SilentlyContinue

    # Clean up the session
    Remove-PSSession -Session $session -ErrorAction SilentlyContinue
}

# Enter the local session briefly to verify remoting is operational
$localSession = New-PSSession -ComputerName localhost -ErrorAction SilentlyContinue
if ($localSession) {
    Enter-PSSession -Session $localSession -ErrorAction SilentlyContinue | Exit-PSSession -ErrorAction SilentlyContinue
    Remove-PSSession -Session $localSession -ErrorAction SilentlyContinue
}

# Cleanup: Disable PSRemoting to return to default state
Disable-PSRemoting -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_713879b9-0e84-44cd-bfb3-fbeb37b3d991  (1 rule(s)) ---------------------
# Intent:    Detect PS-Remoting cmdlet invocations (Enable-PSRemoting, Invoke-Command, Enter-
# Rules:     713879b9-0e84-44cd-bfb3-fbeb37b3d991
# Archetype: Software installer/updater workflow

# Simulate an automated deployment framework establishing remote sessions
# This represents how enterprise configuration management tools (SCCM, Ansible, Puppet) operate

$targetHosts = @('localhost')
$deploymentLog = Join-Path $env:TEMP 'deployment_log.txt'

# Initialize deployment framework connection
New-PSSession -ComputerName localhost -Name 'DeploymentSession' -ErrorAction SilentlyContinue | Out-Null

foreach ($host in $targetHosts) {
    try {
        # Establish remote session for configuration validation
        $remoteSession = New-PSSession -ComputerName $host -ErrorAction SilentlyContinue

        if ($remoteSession) {
            # Retrieve installed software inventory via remoting
            $softwareInfo = Invoke-Command -Session $remoteSession -ScriptBlock {
                Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' |
                    Select-Object DisplayName, DisplayVersion -ErrorAction SilentlyContinue
            } -ErrorAction SilentlyContinue

            # Log results
            if ($softwareInfo) {
                Add-Content -Path $deploymentLog -Value "Host: $host - Software inventory retrieved"
            }

            # Close the session
            Remove-PSSession -Session $remoteSession -ErrorAction SilentlyContinue
        }
    }
    catch {
        Add-Content -Path $deploymentLog -Value "Warning: Could not connect to $host"
    }
}

# Clean up any remaining sessions
Get-PSSession -ErrorAction SilentlyContinue | Remove-PSSession -ErrorAction SilentlyContinue

# Clean up log file
if (Test-Path $deploymentLog) {
    Remove-Item -Path $deploymentLog -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_713879b9-0e84-44cd-bfb3-fbeb37b3d991  (1 rule(s)) ---------------------
# Intent:    Detect PS-Remoting cmdlet invocations (Enable-PSRemoting, Invoke-Command, Enter-
# Rules:     713879b9-0e84-44cd-bfb3-fbeb37b3d991
# Archetype: User-driven workflow

# Developer establishing an interactive remote session for troubleshooting
# This simulates a realistic scenario where a user needs direct shell access to a remote system

$remoteHost = 'localhost'

# Create a new PSSession for interactive use
$interactiveSession = New-PSSession -ComputerName $remoteHost -ErrorAction SilentlyContinue

if ($interactiveSession) {
    # Simulate entering the remote session for troubleshooting
    # In a real scenario, this would be interactive, but we'll execute a command block
    # that demonstrates the Enter-PSSession workflow

    # First, query remote system information
    Invoke-Command -Session $interactiveSession -ScriptBlock {
        # Get recent event logs for troubleshooting
        Get-EventLog -LogName Application -Newest 10 -ErrorAction SilentlyContinue |
            Select-Object TimeGenerated, Source, EventID, Message
    } -ErrorAction SilentlyContinue

    # Demonstrate Enter-PSSession workflow
    # Note: Enter-PSSession in script context is limited, so we use Invoke-Command
    # to simulate the same behavior and event generation
    Invoke-Command -Session $interactiveSession -ScriptBlock {
        # Check running services for the application
        Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName
    } -ErrorAction SilentlyContinue

    # Cleanup
    Remove-PSSession -Session $interactiveSession -ErrorAction SilentlyContinue
} else {
    Write-Host 'Could not establish remote session for troubleshooting'
}

# Also demonstrate the Enter-PSSession cmdlet being invoked
# (even though full interactive use is limited in non-interactive CI environments)
$testSession = New-PSSession -ComputerName localhost -ErrorAction SilentlyContinue
if ($testSession) {
    # Simulate a brief Enter-PSSession invocation
    try {
        $null = Enter-PSSession -Session $testSession -ErrorAction SilentlyContinue
    }
    catch {
        # Expected in non-interactive environment
    }
    finally {
        Remove-PSSession -Session $testSession -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_398f304f-13bb-44b6-8fb4-ccdd0985dcd4  (1 rule(s)) ---------------------
# Intent:    Detects when Windows Explorer spawns script interpreters (cscript, wscript, msht
# Rules:     398f304f-13bb-44b6-8fb4-ccdd0985dcd4
# Archetype: User-driven workflow

# Simulate a user downloading and running a legitimate maintenance VBScript from Downloads
$downloadsPath = [System.Environment]::GetFolderPath('MyDocuments') -replace 'Documents', 'Downloads'
if (-not (Test-Path $downloadsPath)) {
    New-Item -ItemType Directory -Path $downloadsPath -Force | Out-Null
}

$scriptPath = Join-Path $downloadsPath 'registry_backup_utility.vbs'

# Create a benign VBScript that performs a legitimate backup operation
$vbscriptContent = @'
Set oShell = CreateObject("WScript.Shell")
Set oFSO = CreateObject("Scripting.FileSystemObject")

backupDir = oShell.SpecialFolders("Temp") & "\\reg_backup_temp"
if not oFSO.FolderExists(backupDir) then
    oFSO.CreateFolder(backupDir)
end if

regPath = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
backupFile = backupDir & "\\explorer_settings.reg"

' @
$vbscriptContent | Out-File -FilePath $scriptPath -Encoding ASCII -Force

# Invoke the script via wscript.exe, simulating Explorer launching it
& wscript.exe $scriptPath

# Cleanup
Start-Sleep -Milliseconds 500
Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path $downloadsPath 'reg_backup_temp') -Recurse -Force -ErrorAction SilentlyContinue

# SKIPPED variant 'Software installer/updater workflow': blocked pattern: hidden window ('-windowstyle hidden')

# -- Cluster: singleton_398f304f-13bb-44b6-8fb4-ccdd0985dcd4  (1 rule(s)) ---------------------
# Intent:    Detects when Windows Explorer spawns script interpreters (cscript, wscript, msht
# Rules:     398f304f-13bb-44b6-8fb4-ccdd0985dcd4
# Archetype: IT admin workflow

$appDataPath = $env:APPDATA
$adminScriptDir = Join-Path $appDataPath 'AdminTools'
if (-not (Test-Path $adminScriptDir)) {
    New-Item -ItemType Directory -Path $adminScriptDir -Force | Out-Null
}

$maintenanceScript = Join-Path $adminScriptDir 'log_maintenance.vbs'

# Create a realistic admin maintenance script
$scriptContent = @'
Set oFSO = CreateObject("Scripting.FileSystemObject")
Set oShell = CreateObject("WScript.Shell")

logDir = oShell.ExpandEnvironmentStrings("%SystemRoot%\\Logs")
if oFSO.FolderExists(logDir) then
    Set logFolder = oFSO.GetFolder(logDir)
    Set files = logFolder.Files
    for each file in files
        if Right(file.Name, 4) = ".log" then
            if DateDiff("d", file.DateCreated, Now()) > 30 then
                oFSO.DeleteFile file.Path
            end if
        end if
    next
end if
' @

$scriptContent | Out-File -FilePath $maintenanceScript -Encoding ASCII -Force

# Invoke via cscript to simulate admin workflow through Explorer
& cscript.exe $maintenanceScript

# Cleanup
Start-Sleep -Milliseconds 500
Remove-Item -Path $maintenanceScript -Force -ErrorAction SilentlyContinue
Remove-Item -Path $adminScriptDir -Force -ErrorAction SilentlyContinue


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
