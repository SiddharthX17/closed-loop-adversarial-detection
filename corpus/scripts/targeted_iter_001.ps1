# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   5  |  Feasible: 5  |  Variants: 15
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# SKIPPED variant 'IT admin workflow': blocked pattern: hidden window ('-windowstyle hidden')

# -- Cluster: singleton_8af420ec-3464-406e-aa32-0ff39808feab  (1 rule(s)) ---------------------
# Intent:    Adversaries creating scheduled tasks via PowerShell cmdlets or script hosts to e
# Rules:     8af420ec-3464-406e-aa32-0ff39808feab
# Archetype: Software installer/updater workflow

$ErrorActionPreference = 'SilentlyContinue'

# Software installation workflow creating scheduled task for automated updates
# This mimics how legitimate management tools set up maintenance tasks

$taskFolder = 'SoftwareUpdates'
$taskName = 'AutoUpdateCheck'
$scriptPath = Join-Path $env:ProgramData 'Updates'
$logFile = Join-Path $scriptPath 'update_check.log'

# Create the supporting directory structure
if (-not (Test-Path $scriptPath)) {
    New-Item -ItemType Directory -Path $scriptPath | Out-Null
}

# Create a temporary maintenance script
$maintenanceScript = Join-Path $scriptPath 'update_maintenance.ps1'
$scriptContent = @'
# Log file location
$logPath = '{0}'
Add-Content -Path $logPath -Value "Update check executed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
'@ -f $logFile

Set-Content -Path $maintenanceScript -Value $scriptContent -Encoding UTF8

try {
    # Use schtasks.exe to create the scheduled task (common in installer workflows)
    $action = 'powershell.exe'
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$maintenanceScript`""

    $createTaskCmd = @(
        'schtasks.exe',
        '/create',
        '/tn', "\$taskFolder\$taskName",
        '/tr', "$action $arguments",
        '/sc', 'weekly',
        '/d', 'SUN',
        '/st', '03:00:00',
        '/ru', 'NT AUTHORITY\SYSTEM',
        '/f',
        '/z'
    )

    & $createTaskCmd 2>&1 | Out-Null

    # Verify task creation
    $existingTask = schtasks.exe /query /tn "\$taskFolder\$taskName" /fo list 2>&1
    if ($existingTask -notlike '*ERROR*') {
        Write-Host "Task created via installer workflow: $taskName"
    }

    # Clean up
    schtasks.exe /delete /tn "\$taskFolder\$taskName" /f 2>&1 | Out-Null
    Remove-Item -Path $maintenanceScript -Force -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -Path $scriptPath -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
}
catch {
    Write-Host "Error during software update task setup: $_"
    Remove-Item -Path $scriptPath -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
}

Write-Host 'Software update scheduling workflow completed'

# -- Cluster: singleton_8af420ec-3464-406e-aa32-0ff39808feab  (1 rule(s)) ---------------------
# Intent:    Adversaries creating scheduled tasks via PowerShell cmdlets or script hosts to e
# Rules:     8af420ec-3464-406e-aa32-0ff39808feab
# Archetype: User-driven workflow

$ErrorActionPreference = 'SilentlyContinue'

# User workflow: creating a scheduled task for daily report generation
# This mimics how administrative users or scripts set up personal automation

$reportDir = Join-Path $env:TEMP 'daily_reports'
$taskName = 'DailyReportGeneration'

# Create report directory
if (-not (Test-Path $reportDir)) {
    New-Item -ItemType Directory -Path $reportDir | Out-Null
}

# Create report generation script in a standard location
$reportScript = Join-Path $reportDir 'generate_report.ps1'
$reportScriptContent = @'
Param([string]$OutputPath)
$timestamp = Get-Date -Format 'yyyy-MM-dd'
$reportFile = Join-Path $OutputPath "report_$timestamp.csv"
Get-WmiObject -Class Win32_LogicalDisk | Select-Object Name, Size, FreeSpace | Export-Csv -Path $reportFile -NoTypeInformation
'@

Set-Content -Path $reportScript -Value $reportScriptContent -Encoding UTF8

try {
    # Create the scheduled task using schtasks
    $pwshPath = 'powershell.exe'
    $scriptArg = "-NoProfile -ExecutionPolicy Bypass -File `"$reportScript`" -OutputPath `"$reportDir`""

    $taskCmd = @(
        'schtasks.exe',
        '/create',
        '/tn', '\\UserMaintenance\\DailyReporting',
        '/tr', "$pwshPath $scriptArg",
        '/sc', 'daily',
        '/st', '06:00:00',
        '/ru', 'NT AUTHORITY\SYSTEM',
        '/f'
    )

    & $taskCmd 2>&1 | Out-Null

    # Verify creation
    $checkTask = schtasks.exe /query /tn '\\UserMaintenance\\DailyReporting' /fo list 2>&1
    if ($checkTask -notlike '*ERROR*') {
        Write-Host "Daily report task created successfully"
    }

    # Clean up
    schtasks.exe /delete /tn '\\UserMaintenance\\DailyReporting' /f 2>&1 | Out-Null
    Remove-Item -Path $reportDir -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
}
catch {
    Write-Host "Error during report task creation: $_"
    Remove-Item -Path $reportDir -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
}

Write-Host 'User report scheduling workflow completed'

# -- Cluster: singleton_37b9adf5-1251-44bc-97fe-42cc239603b5  (1 rule(s)) ---------------------
# Intent:    Attackers using legitimate Windows tools (CertUtil and BitsAdmin) to download fi
# Rules:     37b9adf5-1251-44bc-97fe-42cc239603b5
# Archetype: IT admin workflow

# Certificate authority CRL validation for compliance audit
$tempDir = [System.IO.Path]::GetTempPath()
$crlPath = Join-Path $tempDir 'root_crl.crl'

try {
    # Retrieve CRL from internal PKI endpoint (simulated with localhost for testing)
    # This represents a real admin validating certificate chains during infrastructure maintenance
    & certutil.exe -urlcache -split -f 'http://localhost:8080/certsrv/certca.crl' $crlPath

    # Also validate with https PKI endpoint
    & certutil.exe -urlcache -f 'https://localhost:8443/pki/root.crl' $crlPath

    # Clean up
    Remove-Item -Force $crlPath -ErrorAction SilentlyContinue
}
catch {
    # Network endpoint may not be available in test environment, which is expected
    Remove-Item -Force $crlPath -ErrorAction SilentlyContinue
}

Write-Host 'Certificate authority validation complete'

# -- Cluster: singleton_37b9adf5-1251-44bc-97fe-42cc239603b5  (1 rule(s)) ---------------------
# Intent:    Attackers using legitimate Windows tools (CertUtil and BitsAdmin) to download fi
# Rules:     37b9adf5-1251-44bc-97fe-42cc239603b5
# Archetype: Software installer/updater workflow

# Enterprise patch management via BitsAdmin (SCCM distribution point)
$tempDir = [System.IO.Path]::GetTempPath()
$updateFile = Join-Path $tempDir 'patch_q4_2024.exe'
$jobName = 'EnterprisePatchJob'

try {
    # Create a BitsAdmin transfer job simulating patch distribution
    # In production, this would connect to an actual SCCM endpoint
    & bitsadmin.exe /create /download /priority normal $jobName

    # Add file transfer from enterprise SCCM server
    & bitsadmin.exe /addfile $jobName 'https://sccm.internal.corp.local/content/patch.exe' $updateFile

    # Add a second file from WSUS endpoint
    $wsusFile = Join-Path $tempDir 'wsus_manifest.xml'
    & bitsadmin.exe /addfile $jobName 'https://wsus.internal.corp.local/updates/manifest.xml' $wsusFile

    # In real deployment, /resume would start the transfer
    # & bitsadmin.exe /resume $jobName

    # Clean up the job
    & bitsadmin.exe /complete $jobName -ErrorAction SilentlyContinue
    & bitsadmin.exe /remove $jobName -ErrorAction SilentlyContinue

    # Clean up temporary files
    Remove-Item -Force $updateFile -ErrorAction SilentlyContinue
    Remove-Item -Force $wsusFile -ErrorAction SilentlyContinue
}
catch {
    & bitsadmin.exe /remove $jobName -ErrorAction SilentlyContinue
    Remove-Item -Force $updateFile -ErrorAction SilentlyContinue
    Remove-Item -Force $wsusFile -ErrorAction SilentlyContinue
}

Write-Host 'Enterprise patch transfer workflow completed'

# -- Cluster: singleton_37b9adf5-1251-44bc-97fe-42cc239603b5  (1 rule(s)) ---------------------
# Intent:    Attackers using legitimate Windows tools (CertUtil and BitsAdmin) to download fi
# Rules:     37b9adf5-1251-44bc-97fe-42cc239603b5
# Archetype: User-driven workflow

# Certificate validation troubleshooting - OCSP status checking
$tempDir = [System.IO.Path]::GetTempPath()
$certPath = Join-Path $tempDir 'server_cert.crt'
$ocspResponse = Join-Path $tempDir 'ocsp_response.bin'

try {
    # Retrieve OCSP response for certificate validation during SSL troubleshooting
    # Simulates a user or support team validating certificate chain integrity
    & certutil.exe -urlcache -split -f 'http://ocsp.digicert.com/ocsp' $ocspResponse

    # Also attempt OCSP validation via https endpoint
    & certutil.exe -urlcache -f 'https://ocsp.internal.corp.local/ocsp/check' $ocspResponse

    # Download certificate details for validation
    & certutil.exe -urlcache -split -f 'https://pki.example.corp.local/cert' $certPath

    # Verify the certificate file if it was downloaded
    if (Test-Path $certPath) {
        & certutil.exe -verify -urlfetch $certPath
    }

    # Clean up
    Remove-Item -Force $certPath -ErrorAction SilentlyContinue
    Remove-Item -Force $ocspResponse -ErrorAction SilentlyContinue
}
catch {
    Remove-Item -Force $certPath -ErrorAction SilentlyContinue
    Remove-Item -Force $ocspResponse -ErrorAction SilentlyContinue
}

Write-Host 'Certificate validation workflow completed'

# -- Cluster: singleton_e0ccd616-16f2-4203-af74-0fda2efd9835  (1 rule(s)) ---------------------
# Intent:    Attacker persistence via registry Run/RunOnce keys pointing to application updat
# Rules:     e0ccd616-16f2-4203-af74-0fda2efd9835
# Archetype: Software installer/updater workflow

$regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$appName = 'VSCodeUpdate'
$updaterPath = 'C:\Program Files\Microsoft VS Code\update.exe'

# Create a temporary directory structure to simulate VSCode installation
$tempDir = Join-Path -Path $env:TEMP -ChildPath ('vscode_' + [System.Guid]::NewGuid().ToString().Substring(0, 8))
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $tempDir -ChildPath 'bin') -Force | Out-Null

# Create a stub executable to represent the updater
$stubPath = Join-Path $tempDir -ChildPath 'bin\update.exe'
Copy-Item -Path (Get-Command cmd.exe).Path -Destination $stubPath -Force

# Simulate the updater registration in the Run key
$registryValue = $stubPath
Reg.exe add $regPath /v $appName /d $registryValue /f | Out-Null

# Wait briefly to allow Sysmon to capture the event
Start-Sleep -Milliseconds 500

# Clean up: remove the registry entry
Reg.exe delete $regPath /v $appName /f 2>$null | Out-Null

# Clean up: remove the temporary directory
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_e0ccd616-16f2-4203-af74-0fda2efd9835  (1 rule(s)) ---------------------
# Intent:    Attacker persistence via registry Run/RunOnce keys pointing to application updat
# Rules:     e0ccd616-16f2-4203-af74-0fda2efd9835
# Archetype: IT admin workflow

$regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$appName = 'GoogleUpdate'
$updaterPath = 'C:\Program Files (x86)\Google\Update\GoogleUpdate.exe'

# Create a temporary directory structure to represent Google Update installation
$tempDir = Join-Path -Path $env:TEMP -ChildPath ('googleupdate_' + [System.Guid]::NewGuid().ToString().Substring(0, 8))
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

# Create a stub executable
$stubPath = Join-Path $tempDir -ChildPath 'GoogleUpdate.exe'
Copy-Item -Path (Get-Command cmd.exe).Path -Destination $stubPath -Force

# Register the updater in the Run key using native registry API
$registryValue = $stubPath
Reg.exe add $regPath /v $appName /d $registryValue /f | Out-Null

# Wait for Sysmon to capture the event
Start-Sleep -Milliseconds 500

# Remove the registry entry (cleanup)
Reg.exe delete $regPath /v $appName /f 2>$null | Out-Null

# Clean up temporary directory
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_e0ccd616-16f2-4203-af74-0fda2efd9835  (1 rule(s)) ---------------------
# Intent:    Attacker persistence via registry Run/RunOnce keys pointing to application updat
# Rules:     e0ccd616-16f2-4203-af74-0fda2efd9835
# Archetype: User-driven workflow

$regPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$appName = 'SlackAutoUpdate'
$updaterPath = 'C:\Program Files\Slack\Slack.exe'

# Simulate Slack installation by creating a temporary directory structure
$tempDir = Join-Path -Path $env:TEMP -ChildPath ('slack_' + [System.Guid]::NewGuid().ToString().Substring(0, 8))
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

# Create a stub executable to represent Slack.exe
$stubPath = Join-Path $tempDir -ChildPath 'Slack.exe'
Copy-Item -Path (Get-Command cmd.exe).Path -Destination $stubPath -Force

# Register Slack in the Run key
$registryValue = $stubPath
Reg.exe add $regPath /v $appName /d $registryValue /f | Out-Null

# Allow time for Sysmon to record the event
Start-Sleep -Milliseconds 500

# Clean up: remove the registry entry
Reg.exe delete $regPath /v $appName /f 2>$null | Out-Null

# Clean up: remove the temporary directory
Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_dfe49bba-8f75-4a19-8464-8a87b03c4ca9  (1 rule(s)) ---------------------
# Intent:    Detect mshta.exe as a parent process executing shell commands through inline VBS
# Rules:     dfe49bba-8f75-4a19-8464-8a87b03c4ca9
# Archetype: IT admin workflow

$tempDir = [System.IO.Path]::GetTempPath()
$diagScript = Join-Path $tempDir "hw_diagnostic.hta"

# Create a legitimate HTML Application that invokes system diagnostics via VBScript
$htaContent = @'
<html>
<head>
<title>System Diagnostic Tool</title>
</head>
<body>
<h2>Running Hardware Diagnostics</h2>
<script language="VBScript">
Dim shell, osInfo, diskInfo
Set shell = CreateObject("wscript.shell")
Set osInfo = shell.Exec("cmd /c systeminfo")
Set diskInfo = shell.Exec("cmd /c wmic logicaldisk get name,size,freespace")
MsgBox "Diagnostics complete", 0, "System Health Check"
</script>
</body>
</html>
'@

Set-Content -Path $diagScript -Value $htaContent -Force

# Execute the HTA file which will spawn as an mshta.exe parent process
# The script execution will trigger Sysmon process creation events
$process = Start-Process -FilePath "mshta.exe" -ArgumentList $diagScript -PassThru -Wait -ErrorAction SilentlyContinue

# Clean up
Remove-Item -Path $diagScript -Force -ErrorAction SilentlyContinue

Write-Host "Hardware diagnostic workflow completed"

# -- Cluster: singleton_dfe49bba-8f75-4a19-8464-8a87b03c4ca9  (1 rule(s)) ---------------------
# Intent:    Detect mshta.exe as a parent process executing shell commands through inline VBS
# Rules:     dfe49bba-8f75-4a19-8464-8a87b03c4ca9
# Archetype: Software installer/updater workflow

$tempDir = [System.IO.Path]::GetTempPath()
$installerHta = Join-Path $tempDir "app_installer_check.hta"

# Create an installer pre-flight check HTA that uses VBScript to validate system
$installerContent = @'
<html>
<head>
<title>Application Pre-Install Validation</title>
</head>
<body>
<h2>Validating Installation Prerequisites</h2>
<script language="VBScript">
Dim shell, regQuery, installResult
Set shell = CreateObject("wscript.shell")

regQuery = shell.Exec("cmd /c reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion")
installResult = shell.Run("cmd /c echo Installation prerequisites validated", 0)

Dim fso
Set fso = CreateObject("Scripting.FileSystemObject")
if fso.FolderExists("C:\\Windows\\System32") then
  shell.Run "cmd /c echo System directory check passed", 0
end if
</script>
</body>
</html>
'@

Set-Content -Path $installerHta -Value $installerContent -Force

# Execute the installer pre-flight validation through mshta
$process = Start-Process -FilePath "mshta.exe" -ArgumentList $installerHta -PassThru -Wait -ErrorAction SilentlyContinue

# Clean up installer check file
Remove-Item -Path $installerHta -Force -ErrorAction SilentlyContinue

Write-Host "Application pre-install validation completed"

# -- Cluster: singleton_dfe49bba-8f75-4a19-8464-8a87b03c4ca9  (1 rule(s)) ---------------------
# Intent:    Detect mshta.exe as a parent process executing shell commands through inline VBS
# Rules:     dfe49bba-8f75-4a19-8464-8a87b03c4ca9
# Archetype: User-driven workflow

$tempDir = [System.IO.Path]::GetTempPath()
$configHta = Join-Path $tempDir "network_config_tool.hta"

# Create a legitimate user-facing HTML Application GUI tool for network configuration
$configContent = @'
<html>
<head>
<title>Network Configuration Utility</title>
<style>
body { font-family: Arial; margin: 20px; }
input { padding: 5px; margin: 5px; }
</style>
</head>
<body>
<h2>Network Settings Manager</h2>
<button onclick="CheckNetwork()">Check Network Status</button>
<script language="VBScript">
Sub CheckNetwork()
  Dim shell, netstat
  Set shell = CreateObject("wscript.shell")
  Set netstat = shell.Exec("cmd /c ipconfig /all")
  Dim gateway
  Set gateway = shell.Exec("cmd /c route print")
  MsgBox "Network check completed. Review Event Viewer for details.", 0, "Network Status"
End Sub
</script>
</body>
</html>
'@

Set-Content -Path $configHta -Value $configContent -Force

# User opens the network configuration HTA from their applications folder
# This triggers mshta.exe as parent with inline VBScript execution
$process = Start-Process -FilePath "mshta.exe" -ArgumentList $configHta -PassThru -Wait -ErrorAction SilentlyContinue

# Clean up the configuration tool
Remove-Item -Path $configHta -Force -ErrorAction SilentlyContinue

Write-Host "Network configuration tool workflow completed"

# SKIPPED variant 'IT admin workflow': blocked pattern: hidden window ('-windowstyle hidden')

# -- Cluster: singleton_5543fe68-119f-4334-8553-2c92a2d1ab1a  (1 rule(s)) ---------------------
# Intent:    Detect the use of scripting hosts (PowerShell, cmd, wscript, mshta, regsvr32) wi
# Rules:     5543fe68-119f-4334-8553-2c92a2d1ab1a
# Archetype: Software installer/updater workflow

# Software update process: common in managed enterprise environments
# Uses minimized window during dependency checking phase

$updateScript = $env:TEMP + '\update_checker.ps1'

$scriptContent = @'
# Dependency and compatibility check - runs with minimized window during updates
Write-Host "Checking application dependencies..."
$modules = @('Posh-Git', 'PSReadLine')
foreach ($module in $modules) {
    if (Get-Module -ListAvailable -Name $module) {
        Write-Host "Module $module is installed"
    } else {
        Write-Host "Module $module not found"
    }
}
Write-Host "Dependency check complete"
'@

Set-Content -Path $updateScript -Value $scriptContent

# Run with minimized window - typical for background update processes
powershell.exe -WindowStyle Minimized -File $updateScript

# Cleanup
Remove-Item -Path $updateScript -Force
Write-Host "Update check finished"

# -- Cluster: singleton_5543fe68-119f-4334-8553-2c92a2d1ab1a  (1 rule(s)) ---------------------
# Intent:    Detect the use of scripting hosts (PowerShell, cmd, wscript, mshta, regsvr32) wi
# Rules:     5543fe68-119f-4334-8553-2c92a2d1ab1a
# Archetype: User-driven workflow

# User automation: batch file organization using WScript.Shell COM interface
# Common for users automating file operations across shared drives

$wscriptFile = $env:TEMP + '\organize_files.vbs'

$vbsContent = @'
Set WshShell = CreateObject("WScript.Shell")
Set objShell = CreateObject("Shell.Application")

' Create folder for organization if needed
strPath = WshShell.ExpandEnvironmentStrings("%TEMP%") & "\organized"
Set objFolder = objShell.NameSpace(WshShell.ExpandEnvironmentStrings("%TEMP%"))

WScript.Echo "File organization utility initialized"
WScript.Echo "User home directory: " & WshShell.SpecialFolders("MyDocuments")
WScript.Echo "Organization utility ready"
'@

Set-Content -Path $wscriptFile -Value $vbsContent -Encoding ASCII

# Execute using wscript.exe - standard for user automation scripts
cscript.exe $wscriptFile

# Cleanup
Remove-Item -Path $wscriptFile -Force
Write-Host "File organization script completed"


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
