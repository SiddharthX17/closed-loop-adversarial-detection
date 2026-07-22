# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   5  |  Feasible: 5  |  Variants: 14
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_c5e15143-6ec7-48ee-afeb-890283d5c4ea  (1 rule(s)) ---------------------
# Intent:    Detects abuse of msiexec.exe to install packages from user-writable staging dire
# Rules:     c5e15143-6ec7-48ee-afeb-890283d5c4ea
# Archetype: IT admin workflow

$stagingDir = Join-Path $env:TEMP "SoftwareStaging_$(Get-Random)"
$msiPath = Join-Path $stagingDir "legitimateapp.msi"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

# Create a minimal valid MSI file (empty CAB structure for Sysmon detection purposes)
# Real MSI files are much larger, but this is sufficient to trigger event capture
Add-Content -Path $msiPath -Value 'This is a placeholder MSI content' -Force

try {
    # Install the MSI with standard deployment parameters
    # /i for install, /package for MSI source, /quiet for unattended installation
    msiexec.exe /i "$msiPath" /quiet /norestart

    # Brief delay to allow Sysmon to capture the event
    Start-Sleep -Milliseconds 500
} catch {
    # Suppress expected failures from invalid MSI format
}

# Cleanup the staging directory
if (Test-Path -Path $stagingDir) {
    Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_c5e15143-6ec7-48ee-afeb-890283d5c4ea  (1 rule(s)) ---------------------
# Intent:    Detects abuse of msiexec.exe to install packages from user-writable staging dire
# Rules:     c5e15143-6ec7-48ee-afeb-890283d5c4ea
# Archetype: Software installer/updater workflow

$downloadsDir = Join-Path $env:USERPROFILE "Downloads"
$appData = Join-Path $env:APPDATA "SoftwareUpdater"
$msiFileName = "security_update.msi"
$msiPath = Join-Path $downloadsDir $msiFileName

New-Item -ItemType Directory -Path $appData -Force | Out-Null

# Write a fake MSI manifest to the downloads directory
Add-Content -Path $msiPath -Value 'Binary installer package content' -Force

try {
    # Execute the MSI installation from Downloads with standard parameters
    # This represents legitimate user-initiated installation workflows
    msiexec.exe /i $msiPath /quiet /norestart /log (Join-Path $appData "install.log")

    Start-Sleep -Milliseconds 500
} catch {
    # Suppress expected failures
}

# Cleanup
if (Test-Path -Path $msiPath) {
    Remove-Item -Path $msiPath -Force -ErrorAction SilentlyContinue
}
if (Test-Path -Path $appData) {
    Remove-Item -Path $appData -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_c5e15143-6ec7-48ee-afeb-890283d5c4ea  (1 rule(s)) ---------------------
# Intent:    Detects abuse of msiexec.exe to install packages from user-writable staging dire
# Rules:     c5e15143-6ec7-48ee-afeb-890283d5c4ea
# Archetype: User-driven workflow

$tempDir = Join-Path $env:TEMP "AppInstaller_$(Get-Random)"
$msiPath = Join-Path $tempDir "setup.msi"

New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

# Create installer package in temp directory
Add-Content -Path $msiPath -Value 'MSI package binary data' -Force

try {
    # Install from temp location with standard msiexec parameters
    msiexec.exe /i $msiPath /quiet /norestart

    Start-Sleep -Milliseconds 500
} catch {
    # Expected error due to invalid MSI format is acceptable
}

# Cleanup temporary files
if (Test-Path -Path $tempDir) {
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_c565ac23-9aea-4c00-823a-b3e84f3572ea  (1 rule(s)) ---------------------
# Intent:    Detecting unauthorized modifications to BitLocker FVE security policy registry k
# Rules:     c565ac23-9aea-4c00-823a-b3e84f3572ea
# Archetype: Software installer/updater workflow

$registryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
$testValueName = 'EnableBDEWithoutCompatibleTPM'
$svchostPath = 'C:\Windows\System32\svchost.exe'

# Verify registry path exists for FVE policies
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Create a registry write event that mimics policy application
# This simulates legitimate BitLocker policy configuration deployment
Set-ItemProperty -Path $registryPath -Name $testValueName -Value 0 -Type DWord -Force

# Simulate another policy setting that would be applied during system configuration
Set-ItemProperty -Path $registryPath -Name 'RDVDenied' -Value 1 -Type DWord -Force

# Verify the write occurred and retrieve the values
Get-ItemProperty -Path $registryPath

# Clean up the test registry entries
Remove-ItemProperty -Path $registryPath -Name $testValueName -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $registryPath -Name 'RDVDenied' -Force -ErrorAction SilentlyContinue

# Clean up the registry key if empty
if ((Get-Item $registryPath -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0) {
    Remove-Item -Path $registryPath -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_c565ac23-9aea-4c00-823a-b3e84f3572ea  (1 rule(s)) ---------------------
# Intent:    Detecting unauthorized modifications to BitLocker FVE security policy registry k
# Rules:     c565ac23-9aea-4c00-823a-b3e84f3572ea
# Archetype: IT admin workflow

$registryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\FVE'
$configPath = $env:TEMP + '\bitlocker_policy_config.txt'

# Create a simulated policy deployment configuration file
@'
BitLocker FVE Policy Configuration
Timestamp: [$(Get-Date)]
Operation: Deploy encryption policy updates
Target: FVE registry settings
'@ | Set-Content -Path $configPath

# Ensure the FVE policy registry path exists
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Apply multiple FVE policy settings as an admin would during policy deployment
# These represent legitimate enterprise security configurations
Set-ItemProperty -Path $registryPath -Name 'EncryptionMethod' -Value 3 -Type DWord -Force
Set-ItemProperty -Path $registryPath -Name 'DisableExternalDMA' -Value 1 -Type DWord -Force
Set-ItemProperty -Path $registryPath -Name 'RDVHardwareDisabled' -Value 1 -Type DWord -Force
Set-ItemProperty -Path $registryPath -Name 'RDVDenied' -Value 1 -Type DWord -Force

# Retrieve and log the applied settings
Write-Output 'Applied FVE Policy Settings:'
Get-ItemProperty -Path $registryPath | Format-List

# Remove temporary configuration file
Remove-Item -Path $configPath -Force -ErrorAction SilentlyContinue

# Clean up all test registry values
'EncryptionMethod', 'DisableExternalDMA', 'RDVHardwareDisabled', 'RDVDenied' | ForEach-Object {
    Remove-ItemProperty -Path $registryPath -Name $_ -Force -ErrorAction SilentlyContinue
}

# Clean up the registry key if empty
if (@(Get-Item $registryPath -ErrorAction SilentlyContinue).Count -eq 0) {
    Remove-Item -Path $registryPath -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_62b19731-dcc1-4430-9f2b-c9b104d19621  (1 rule(s)) ---------------------
# Intent:    Adversaries abuse file association and event handler registration through comman
# Rules:     62b19731-dcc1-4430-9f2b-c9b104d19621
# Archetype: IT admin workflow

# File association diagnostic report generation
# Common IT maintenance task for enterprise fleet documentation

$reportPath = Join-Path $env:TEMP "FileAssociationReport_$(Get-Date -Format yyyyMMdd_HHmmss).txt"

# Verify current file associations and document them
Write-Output "File Association Diagnostic Report" | Out-File -FilePath $reportPath
Write-Output "Generated: $(Get-Date -u)" | Out-File -FilePath $reportPath -Append
Write-Output "" | Out-File -FilePath $reportPath -Append

# Query current file associations using assoc command
# IT staff use this to check if critical file types are properly registered
Write-Output "=== Current File Associations ===" | Out-File -FilePath $reportPath -Append
cmd /c "assoc .txt" | Out-File -FilePath $reportPath -Append
cmd /c "assoc .pdf" | Out-File -FilePath $reportPath -Append
cmd /c "assoc .exe" | Out-File -FilePath $reportPath -Append
cmd /c "assoc .ps1" | Out-File -FilePath $reportPath -Append

Write-Output "" | Out-File -FilePath $reportPath -Append
Write-Output "=== File Type Handler Information ===" | Out-File -FilePath $reportPath -Append

# Document file type handlers to verify proper registration
cmd /c "ftype txtfile" | Out-File -FilePath $reportPath -Append
cmd /c "ftype exefile" | Out-File -FilePath $reportPath -Append
cmd /c "ftype batfile" | Out-File -FilePath $reportPath -Append

Write-Output "" | Out-File -FilePath $reportPath -Append
Write-Output "Report saved to: $reportPath" | Out-File -FilePath $reportPath -Append

# Clean up report
Remove-Item -Path $reportPath -Force

# -- Cluster: singleton_62b19731-dcc1-4430-9f2b-c9b104d19621  (1 rule(s)) ---------------------
# Intent:    Adversaries abuse file association and event handler registration through comman
# Rules:     62b19731-dcc1-4430-9f2b-c9b104d19621
# Archetype: Software installer/updater workflow

# Application installer file type registration workflow
# Simulates legitimate software installation handler registration

$tempDir = Join-Path $env:TEMP "AppInstaller_$(Get-Random)"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

$setupScriptPath = Join-Path $tempDir "setup_handlers.vbs"

# Create a minimal VBScript for file type registration (realistic installer pattern)
$vbsContent = @'
Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")
' + "`n" + @'
objShell.Run "assoc .custom_doc=Custom.Document", 0, True
objShell.Run "ftype Custom.Document=notepad.exe %%%%1", 0, True
' + "`n" + @'
WScript.Echo "File type handlers registered"
'@

Set-Content -Path $setupScriptPath -Value $vbsContent

# Execute the VBScript installer registration using WScript
# This is realistic post-installation file handler setup
Write-Output "Registering file type handlers..."
cscript.exe $setupScriptPath | Out-Null

# Verify registration via PowerShell (post-install validation common in enterprise)
Write-Output "Validating file associations..."
$verifyOutput = cmd /c "assoc .custom_doc" 2>&1
if ($verifyOutput -match "Custom.Document") {
    Write-Output "File associations validated successfully."
}

# Clean up installer artifacts
Remove-Item -Path $tempDir -Recurse -Force

# -- Cluster: singleton_62b19731-dcc1-4430-9f2b-c9b104d19621  (1 rule(s)) ---------------------
# Intent:    Adversaries abuse file association and event handler registration through comman
# Rules:     62b19731-dcc1-4430-9f2b-c9b104d19621
# Archetype: User-driven workflow

# User-initiated batch document processing workflow
# End-users execute PowerShell scripts that include command-line variables for automation

$tempDir = Join-Path $env:TEMP "DocumentProcess_$(Get-Random)"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

$sourceFile = Join-Path $tempDir "template.txt"
Set-Content -Path $sourceFile -Value "Company Report Template - Q4 2024"

# Create a processing script that uses command-line variables
$processorScript = Join-Path $tempDir "processor.ps1"
$processorContent = @'
param(
    [string]$InputFile,
    [string]$OutputFile,
    [string]$CompanyName = "Default Corp"
)

if (Test-Path $InputFile) {
    $content = Get-Content $InputFile
    $processed = $content -replace "Company", $CompanyName
    Set-Content -Path $OutputFile -Value $processed
    Write-Output "Document processed: $OutputFile"
}
'@

Set-Content -Path $processorScript -Value $processorContent

# Execute the processor with command-line variable assignment
# This pattern is realistic for user automation workflows
$outputFile = Join-Path $tempDir "report_processed.txt"
powershell.exe -File $processorScript -InputFile $sourceFile -OutputFile $outputFile -CompanyName "Acme Corp"

# Alternative execution pattern using variable assignment in command context
$assignmentScript = Join-Path $tempDir "assignment.ps1"
$assignmentContent = @'
$reportName = "quarterly_analysis"
$fileName = "$reportName.xlsx"
Write-Output "Processing: $fileName"
Write-Output "Report: $reportName initialized"
'@

Set-Content -Path $assignmentScript -Value $assignmentContent
powershell.exe -File $assignmentScript

# Clean up
Remove-Item -Path $tempDir -Recurse -Force

# -- Cluster: singleton_e44bc2ac-7108-4733-9351-a78a1e4d57d1  (1 rule(s)) ---------------------
# Intent:    Detects execution of side-load-susceptible binaries (dotnet.exe and onedrive.exe
# Rules:     e44bc2ac-7108-4733-9351-a78a1e4d57d1
# Archetype: IT admin workflow

$dotnetPath = 'C:\Program Files\dotnet\dotnet.exe'
if (Test-Path $dotnetPath) {
    Write-Host "Verifying .NET Framework installation..."
    & $dotnetPath --version
    Start-Sleep -Seconds 2
    & $dotnetPath --list-runtimes
} else {
    Write-Host ".NET SDK not installed on this system"
}

# -- Cluster: singleton_e44bc2ac-7108-4733-9351-a78a1e4d57d1  (1 rule(s)) ---------------------
# Intent:    Detects execution of side-load-susceptible binaries (dotnet.exe and onedrive.exe
# Rules:     e44bc2ac-7108-4733-9351-a78a1e4d57d1
# Archetype: User-driven workflow

$oneDrivePath = Join-Path $env:LOCALAPPDATA 'Microsoft\OneDrive\OneDrive.exe'
if (Test-Path $oneDrivePath) {
    Write-Host "Starting OneDrive synchronization..."
    & $oneDrivePath /personal
    Start-Sleep -Seconds 3
    taskkill /IM OneDrive.exe /F 2>$null | Out-Null
} else {
    Write-Host "OneDrive not found in user profile"
}

# -- Cluster: singleton_e44bc2ac-7108-4733-9351-a78a1e4d57d1  (1 rule(s)) ---------------------
# Intent:    Detects execution of side-load-susceptible binaries (dotnet.exe and onedrive.exe
# Rules:     e44bc2ac-7108-4733-9351-a78a1e4d57d1
# Archetype: Software installer/updater workflow

$dotnetPath = 'C:\Program Files\dotnet\dotnet.exe'
if (Test-Path $dotnetPath) {
    Write-Host "Validating .NET dependencies for application deployment..."
    $tempDir = Join-Path $env:TEMP "dotnet_validation_$(Get-Random)"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    try {
        Push-Location $tempDir
        & $dotnetPath new globaljson --sdk-version 6.0.0 --force 2>$null | Out-Null
        & $dotnetPath --info | Select-Object -First 5
        Write-Host "Deployment validation complete"
    } finally {
        Pop-Location
        Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Host ".NET not available for deployment"
}

# -- Cluster: singleton_3f71f5e9-90e2-469e-943a-591d992514bb  (1 rule(s)) ---------------------
# Intent:    Attackers using sc.exe to modify system service configuration, particularly crea
# Rules:     3f71f5e9-90e2-469e-943a-591d992514bb
# Archetype: IT admin workflow

# IT admin workflow: Verify and configure Windows service state for compliance audit
# Simulates a sysadmin checking service configuration as part of routine maintenance

$Services = @('w32time', 'wuauserv', 'bits', 'schedule', 'dnscache', 'rpcss')
$LogFile = Join-Path $env:TEMP 'service_audit_$(Get-Date -Format yyyyMMdd_HHmmss).log'

foreach ($Service in $Services) {
    # Query current service configuration
    & sc.exe config $Service query 2>&1 | Out-Null

    # In a real admin scenario, verify the service is set to auto-start if it's critical
    $ServiceObj = Get-Service -Name $Service -ErrorAction SilentlyContinue
    if ($ServiceObj -and $ServiceObj.StartType -ne 'Automatic') {
        # Log the service state for audit purposes
        "Service: $Service | StartType: $($ServiceObj.StartType)" | Add-Content $LogFile
    }
}

# Simulate admin checking if a service is running and needs to be started
if ((Get-Service -Name 'bits' -ErrorAction SilentlyContinue).Status -eq 'Stopped') {
    & sc.exe start bits 2>&1 | Out-Null
}

# Configuration verification: check event log service
if ((Get-Service -Name 'eventlog' -ErrorAction SilentlyContinue).Status -eq 'Stopped') {
    & sc.exe start eventlog 2>&1 | Out-Null
}

# Verify RPC service is properly configured
& sc.exe config rpcss start= auto 2>&1 | Out-Null

# Clean up
if (Test-Path $LogFile) {
    Remove-Item $LogFile -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_3f71f5e9-90e2-469e-943a-591d992514bb  (1 rule(s)) ---------------------
# Intent:    Attackers using sc.exe to modify system service configuration, particularly crea
# Rules:     3f71f5e9-90e2-469e-943a-591d992514bb
# Archetype: Software installer/updater workflow

# Software installer/updater workflow: Configure services as part of system update
# Simulates MSI/updater script ensuring required services are available after deployment

$TempDir = Join-Path $env:TEMP 'installer_services_temp'
if (-not (Test-Path $TempDir)) {
    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
}

$InstallerLog = Join-Path $TempDir 'update_services.log'

# Real installer workflow: verify Windows Update service dependencies
try {
    # Ensure WU service and dependencies are configured for next update cycle
    & sc.exe config wuauserv start= auto 2>&1 | Out-Null
    & sc.exe config bits start= auto 2>&1 | Out-Null
    & sc.exe config rpcss start= auto 2>&1 | Out-Null
    & sc.exe config dnscache start= auto 2>&1 | Out-Null

    # Some installers verify Task Scheduler is running for scheduled tasks
    $ScheduleService = Get-Service -Name 'schedule' -ErrorAction SilentlyContinue
    if ($ScheduleService -and $ScheduleService.Status -eq 'Stopped') {
        & sc.exe start schedule 2>&1 | Out-Null
        "Schedule service started" | Add-Content $InstallerLog
    }

    # Network-related services for potential remote deployment scenarios
    & sc.exe config lanmanserver start= auto 2>&1 | Out-Null
    & sc.exe config lanmanworkstation start= auto 2>&1 | Out-Null
    & sc.exe config netlogon start= auto 2>&1 | Out-Null

    # Verify DNS cache is running for any network operations
    if ((Get-Service -Name 'dnscache' -ErrorAction SilentlyContinue).Status -eq 'Stopped') {
        & sc.exe start dnscache 2>&1 | Out-Null
    }

    "Service configuration verification completed" | Add-Content $InstallerLog
}
catch {
    "Error during service configuration: $_" | Add-Content $InstallerLog
}

# Clean up temporary artifacts
if (Test-Path $TempDir) {
    Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_3f71f5e9-90e2-469e-943a-591d992514bb  (1 rule(s)) ---------------------
# Intent:    Attackers using sc.exe to modify system service configuration, particularly crea
# Rules:     3f71f5e9-90e2-469e-943a-591d992514bb
# Archetype: User-driven workflow

# User-driven workflow: System utility ensuring dependent services are operational
# Simulates legitimate enterprise backup or monitoring utility verifying service state

$AppDataPath = Join-Path $env:APPDATA 'SystemUtility'
if (-not (Test-Path $AppDataPath)) {
    New-Item -ItemType Directory -Path $AppDataPath -Force | Out-Null
}

$MaintenanceLog = Join-Path $AppDataPath 'service_maintenance.log'

# User launches maintenance utility that checks service health
[datetime]$ExecutionTime = Get-Date
"Maintenance cycle started: $ExecutionTime" | Add-Content $MaintenanceLog

# Utility verifies critical Windows services for backup/monitoring operations
$CriticalServices = @('w32time', 'dnscache', 'rpcss', 'eventlog')

foreach ($Service in $CriticalServices) {
    $ServiceStatus = Get-Service -Name $Service -ErrorAction SilentlyContinue

    if ($ServiceStatus) {
        if ($ServiceStatus.Status -eq 'Stopped') {
            # Utility attempts to start the service for proper operation
            & sc.exe start $Service 2>&1 | Out-Null
            "$Service started by maintenance utility" | Add-Content $MaintenanceLog
        } else {
            "$Service is running" | Add-Content $MaintenanceLog
        }
    }
}

# Utility configures Windows Update service for timely patching
& sc.exe config wuauserv start= auto 2>&1 | Out-Null
& sc.exe config bits start= auto 2>&1 | Out-Null

# Ensure Task Scheduler is configured for scheduled maintenance tasks
& sc.exe config schedule start= auto 2>&1 | Out-Null

# Network services check for connectivity-dependent operations
if ((Get-Service -Name 'dhcp' -ErrorAction SilentlyContinue).Status -eq 'Stopped') {
    & sc.exe start dhcp 2>&1 | Out-Null
}

"Maintenance cycle completed: $(Get-Date)" | Add-Content $MaintenanceLog

# Clean up
if (Test-Path $AppDataPath) {
    Remove-Item $AppDataPath -Recurse -Force -ErrorAction SilentlyContinue
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
