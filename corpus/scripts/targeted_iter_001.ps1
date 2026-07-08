# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   3  |  Feasible: 3  |  Variants: 8
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_35e43d3e-8ecd-407e-94d8-dd23d2d6f5a8  (1 rule(s)) ---------------------
# Intent:    Detecting nested command shell invocation via scripting interpreters (VBScript, 
# Rules:     35e43d3e-8ecd-407e-94d8-dd23d2d6f5a8
# Archetype: IT admin workflow

$scriptPath = Join-Path $env:TEMP 'deployment_config_2024.vbs'
$vbsContent = @'
Dim objShell, cmd
Set objShell = CreateObject("WScript.Shell")
' Legitimate deployment configuration
cmd = "cmd /c echo Deployment started >> " & "C:\temp\deploy.log"
objShell.Run cmd, 0, false
cmd = "cmd /c net.exe start w32time"
objShell.Run cmd, 0, false
cmd = "cmd /c reg.exe query HKLM\\Software\\Microsoft\\Windows\\ /s > " & "C:\temp\registry_audit.txt"
objShell.Run cmd, 0, false
Set objShell = Nothing
'@
Set-Content -Path $scriptPath -Value $vbsContent -Encoding ASCII
$logPath = 'C:\temp\deploy.log'
$auditPath = 'C:\temp\registry_audit.txt'
if (!(Test-Path 'C:\temp')) { New-Item -ItemType Directory -Path 'C:\temp' -Force | Out-Null }
# Execute the VBScript deployment configuration as would happen from ConfigMgr
cscript.exe $scriptPath
# Verify results were captured
if (Test-Path $logPath) {
  Get-Content $logPath
}
if (Test-Path $auditPath) {
  Remove-Item $auditPath -Force -ErrorAction SilentlyContinue
}
# Cleanup
Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
if (Test-Path $logPath) { Remove-Item $logPath -Force -ErrorAction SilentlyContinue }
if (Test-Path 'C:\temp' -PathType Container) {
  $remaining = Get-ChildItem 'C:\temp' -ErrorAction SilentlyContinue
  if ($remaining -eq $null) { Remove-Item 'C:\temp' -Force -ErrorAction SilentlyContinue }
}

# -- Cluster: singleton_35e43d3e-8ecd-407e-94d8-dd23d2d6f5a8  (1 rule(s)) ---------------------
# Intent:    Detecting nested command shell invocation via scripting interpreters (VBScript, 
# Rules:     35e43d3e-8ecd-407e-94d8-dd23d2d6f5a8
# Archetype: Software installer/updater workflow

$htaPath = Join-Path $env:TEMP 'system_config.hta'
$htaContent = @'
<HTML>
<HEAD>
  <TITLE>System Configuration</TITLE>
  <HTA:APPLICATION ID="SystemConfig" VERSION="1.0">
</HEAD>
<BODY>
  <SCRIPT LANGUAGE="VBScript">
    Dim objShell
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run "cmd /c echo Configuration started", 0, false
    objShell.Run "cmd.exe /c setx TEMP_CONFIG_VAR success", 0, false
  </SCRIPT>
</BODY>
</HTML>
'@
Set-Content -Path $htaPath -Value $htaContent -Encoding ASCII
# Execute the HTA which will internally invoke cmd.exe
mshta.exe $htaPath
Start-Sleep -Seconds 2
# Cleanup
Remove-Item $htaPath -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_35e43d3e-8ecd-407e-94d8-dd23d2d6f5a8  (1 rule(s)) ---------------------
# Intent:    Detecting nested command shell invocation via scripting interpreters (VBScript, 
# Rules:     35e43d3e-8ecd-407e-94d8-dd23d2d6f5a8
# Archetype: User-driven workflow

$scriptPath = Join-Path $env:TEMP 'system_report_generator.vbs'
$vbsContent = @'
Dim objShell, reportPath
Set objShell = CreateObject("WScript.Shell")
reportPath = "C:\temp\system_report.txt"
If Not objShell.FileSystemObject.FolderExists("C:\temp") Then
  objShell.FileSystemObject.CreateFolder("C:\temp")
End If
objShell.Run "cmd.exe /c tasklist > " & reportPath, 0, false
objShell.Run "cmd /c echo. >> " & reportPath, 0, false
objShell.Run "cmd /c systeminfo >> " & reportPath, 0, false
Set objShell = Nothing
'@
Set-Content -Path $scriptPath -Value $vbsContent -Encoding ASCII
if (!(Test-Path 'C:\temp')) { New-Item -ItemType Directory -Path 'C:\temp' -Force | Out-Null }
# User executes the VBScript utility
wscript.exe $scriptPath
Start-Sleep -Seconds 1
# Verify report was created
$reportPath = 'C:\temp\system_report.txt'
if (Test-Path $reportPath) {
  Write-Host "Report generated successfully"
  Remove-Item $reportPath -Force -ErrorAction SilentlyContinue
}
# Cleanup
Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
if (Test-Path 'C:\temp' -PathType Container) {
  $remaining = @(Get-ChildItem 'C:\temp' -ErrorAction SilentlyContinue)
  if ($remaining.Count -eq 0) { Remove-Item 'C:\temp' -Force -ErrorAction SilentlyContinue }
}

# -- Cluster: singleton_2e321480-a454-4d29-8b0d-b507d09d64a8  (1 rule(s)) ---------------------
# Intent:    Attackers abuse the BITS service and bitsadmin.exe with LOLBin post-execution no
# Rules:     2e321480-a454-4d29-8b0d-b507d09d64a8
# Archetype: IT admin workflow

$ErrorActionPreference = 'Stop'

# Create temporary working directory for BITS job staging
$stagingDir = Join-Path $env:TEMP -ChildPath ('BitsDeployment_' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

try {
    # Create a benign source file to transfer via BITS
    $sourceFile = Join-Path $stagingDir -ChildPath 'package.bin'
    [System.IO.File]::WriteAllBytes($sourceFile, [byte[]]@(0x4D, 0x5A) + (1..1000 | ForEach-Object { [byte]$_ }))

    # Create a legitimate notification script that logs completion
    $notifyScript = Join-Path $stagingDir -ChildPath 'verify_deployment.ps1'
    $notifyContent = @'
$logFile = Join-Path $env:ProgramFiles -ChildPath 'DeploymentLogs\transfer_complete.log'
if (-not (Test-Path (Split-Path $logFile))) {
    New-Item -ItemType Directory -Path (Split-Path $logFile) -Force | Out-Null
}
Add-Content -Path $logFile -Value ("[$(Get-Date)] File transfer completed successfully")
'@
    Set-Content -Path $notifyScript -Value $notifyContent -Force

    # Configure BITS job for file deployment workflow
    # Job name reflects legitimate IT operations
    $jobName = 'SoftwareUpdate_' + (Get-Date -Format 'yyyyMMdd')

    # Create BITS job with destination in Program Files (enterprise standard location)
    $destFile = Join-Path 'C:\Program Files' -ChildPath 'DeprecatedTools\downloaded_package.bin'
    $destDir = Split-Path $destFile

    if (-not (Test-Path $destDir)) {
        New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }

    # BITS job creation: standard IT admin pattern
    & bitsadmin.exe /create $jobName | Out-Null
    & bitsadmin.exe /addfile $jobName $sourceFile $destFile | Out-Null

    # Set notification command for job completion monitoring
    # Legitimate use: invoke verification/logging script on transfer completion
    & bitsadmin.exe /setnotifycmdline $jobName powershell.exe ('"' + $notifyScript + '"')

    # Resume job to trigger notification workflow
    & bitsadmin.exe /resume $jobName

    # Poll for job completion (max 30 seconds for lab environment)
    $maxWait = 30
    $elapsed = 0
    while ($elapsed -lt $maxWait) {
        $jobInfo = bitsadmin.exe /info $jobName /verbose
        if ($jobInfo -match 'Transferred') {
            Start-Sleep -Milliseconds 500
            break
        }
        Start-Sleep -Milliseconds 500
        $elapsed += 0.5
    }

    # Complete the BITS job
    & bitsadmin.exe /complete $jobName

    # Verify notification log was created (validate legitimate completion)
    Start-Sleep -Milliseconds 500

    # Cleanup BITS job
    bitsadmin.exe /resume $jobName 2>$null
    bitsadmin.exe /complete $jobName 2>$null
}
finally {
    # Cleanup all temporary artifacts
    if (Test-Path $stagingDir) {
        Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path 'C:\Program Files\DeprecatedTools') {
        Remove-Item -Path 'C:\Program Files\DeprecatedTools' -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path 'C:\Program Files\DeploymentLogs') {
        Remove-Item -Path 'C:\Program Files\DeploymentLogs' -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_2e321480-a454-4d29-8b0d-b507d09d64a8  (1 rule(s)) ---------------------
# Intent:    Attackers abuse the BITS service and bitsadmin.exe with LOLBin post-execution no
# Rules:     2e321480-a454-4d29-8b0d-b507d09d64a8
# Archetype: Software installer/updater workflow

$ErrorActionPreference = 'Stop'

# Simulate enterprise installer workflow using BITS for staged file delivery
$installerCache = Join-Path $env:TEMP -ChildPath ('InstallerStaging_' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $installerCache -Force | Out-Null

try {
    # Create mock installer package (binary stub)
    $packageSource = Join-Path $installerCache -ChildPath 'app_setup.exe'
    [System.IO.File]::WriteAllBytes($packageSource, [byte[]]@(0x4D, 0x5A) + (0..500 | ForEach-Object { [byte]($_ % 256) }))

    # Create validation script that installer framework would run post-transfer
    $validatorScript = Join-Path 'C:\Program Files' -ChildPath 'AppDeployment\verify_package_integrity.ps1'
    $validatorDir = Split-Path $validatorScript
    New-Item -ItemType Directory -Path $validatorDir -Force | Out-Null

    $validatorContent = @'
# Verify transferred package and update deployment record
$packagePath = (Get-ChildItem 'C:\Program Files\AppDeployment\*.exe' -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
if ($packagePath -and (Test-Path $packagePath)) {
    $recordFile = Join-Path 'C:\Program Files\AppDeployment' -ChildPath 'deploy_manifest.txt'
    Add-Content -Path $recordFile -Value $("Transfer complete: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
}
'@
    Set-Content -Path $validatorScript -Value $validatorContent -Force

    # Create BITS job simulating application installer delivery
    $jobName = 'ApplicationDeployment_' + (Get-Date -Format 'yyyyMMddHHmmss')
    $installDest = Join-Path 'C:\Program Files\AppDeployment' -ChildPath 'package.exe'

    # Ensure destination directory exists
    if (-not (Test-Path (Split-Path $installDest))) {
        New-Item -ItemType Directory -Path (Split-Path $installDest) -Force | Out-Null
    }

    # Create the BITS job for the installation package
    & bitsadmin.exe /create $jobName | Out-Null
    & bitsadmin.exe /addfile $jobName $packageSource $installDest | Out-Null

    # Set post-transfer verification command (common in orchestration tools)
    & bitsadmin.exe /setnotifycmdline $jobName powershell.exe ("& '" + $validatorScript + "'")

    # Start the transfer
    & bitsadmin.exe /resume $jobName

    # Wait for completion (simulate synchronous deployment)
    for ($i = 0; $i -lt 20; $i++) {
        $status = bitsadmin.exe /info $jobName /verbose | Select-String 'State'
        if ($status) { Start-Sleep -Milliseconds 500 }
        else { break }
    }

    # Mark job as complete
    & bitsadmin.exe /complete $jobName

    Start-Sleep -Milliseconds 500
}
finally {
    # Remove all staging and installation artifacts
    if (Test-Path $installerCache) {
        Remove-Item -Path $installerCache -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path 'C:\Program Files\AppDeployment') {
        Remove-Item -Path 'C:\Program Files\AppDeployment' -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_2e321480-a454-4d29-8b0d-b507d09d64a8  (1 rule(s)) ---------------------
# Intent:    Attackers abuse the BITS service and bitsadmin.exe with LOLBin post-execution no
# Rules:     2e321480-a454-4d29-8b0d-b507d09d64a8
# Archetype: Document/file operation workflow

$ErrorActionPreference = 'Stop'

# Simulate file backup/sync operation using BITS with completion notification
$tempBackupStaging = Join-Path $env:TEMP -ChildPath ('BackupSync_' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tempBackupStaging -Force | Out-Null

try {
    # Create a document file to back up (simulating user file)
    $sourceDoc = Join-Path $tempBackupStaging -ChildPath 'report.dat'
    $docContent = [System.Text.Encoding]::UTF8.GetBytes('Quarterly business review data - $(Get-Date -Format "yyyy-MM-dd")')
    [System.IO.File]::WriteAllBytes($sourceDoc, $docContent)

    # Create post-transfer notification script (file re-indexing)
    $reindexScript = Join-Path 'C:\Program Files' -ChildPath 'FileSync\postbkup_reindex.ps1'
    $reindexDir = Split-Path $reindexScript
    New-Item -ItemType Directory -Path $reindexDir -Force | Out-Null

    $reindexContent = @'
# Re-index and validate backed-up files
$bkupDir = 'C:\Program Files\FileSync\backup_store'
if (Test-Path $bkupDir) {
    $indexFile = Join-Path $bkupDir -ChildPath 'index.dat'
    $fileList = Get-ChildItem $bkupDir -File | Measure-Object
    Add-Content -Path $indexFile -Value $("Backup index updated: $(Get-Date) - Files: $($fileList.Count)")
}
'@
    Set-Content -Path $reindexScript -Value $reindexContent -Force

    # Create backup store directory
    $backupStore = Join-Path 'C:\Program Files\FileSync' -ChildPath 'backup_store'
    New-Item -ItemType Directory -Path $backupStore -Force | Out-Null

    # Set up BITS job for document backup
    $jobName = 'DocumentBackup_' + (Get-Date -Format 'yyyyMMddHHmm')
    $backupDest = Join-Path $backupStore -ChildPath 'report.dat'

    # Create BITS transfer job
    & bitsadmin.exe /create $jobName | Out-Null
    & bitsadmin.exe /addfile $jobName $sourceDoc $backupDest | Out-Null

    # Set notification to re-index after backup completes
    & bitsadmin.exe /setnotifycmdline $jobName powershell.exe ('"' + $reindexScript + '"')

    # Start backup transfer
    & bitsadmin.exe /resume $jobName

    # Wait for transfer to complete
    $waitLimit = 30
    $elapsed = 0
    while ($elapsed -lt $waitLimit) {
        $jobState = bitsadmin.exe /info $jobName /verbose
        if ($jobState -match 'Transferred') {
            Start-Sleep -Milliseconds 300
            break
        }
        Start-Sleep -Milliseconds 300
        $elapsed += 0.3
    }

    # Complete the job
    & bitsadmin.exe /complete $jobName

    Start-Sleep -Milliseconds 500
}
finally {
    # Clean up all backup and staging data
    if (Test-Path $tempBackupStaging) {
        Remove-Item -Path $tempBackupStaging -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path 'C:\Program Files\FileSync') {
        Remove-Item -Path 'C:\Program Files\FileSync' -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_059a4e48-ef54-458f-a398-c992404f0122  (1 rule(s)) ---------------------
# Intent:    Detect adversarial registration of a malicious ServiceDll parameter in svchost s
# Rules:     059a4e48-ef54-458f-a398-c992404f0122
# Archetype: IT admin workflow

$tempServiceName = 'CustomNetworkMonitor'
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$tempServiceName"
$parametersPath = "$registryPath\Parameters"

try {
    # Create service registry structure using sc.exe
    & cmd /c "sc.exe create $tempServiceName binPath= \"C:\\Windows\\System32\\svchost.exe -k LocalSystem\" type= share start= disabled"
    Start-Sleep -Milliseconds 500

    # Add ServiceDll parameter to service configuration (legitimate operation for service group initialization)
    if (-not (Test-Path $parametersPath)) {
        New-Item -Path $parametersPath -Force | Out-Null
    }
    Set-ItemProperty -Path $parametersPath -Name 'ServiceDll' -Value 'C:\Windows\System32\lsass.exe' -Type String

    # Verify registry entry
    $value = Get-ItemProperty -Path $parametersPath -Name 'ServiceDll' -ErrorAction SilentlyContinue
    if ($value) {
        # Registry write operation completed
    }

} finally {
    # Clean up service and registry entries
    Start-Sleep -Milliseconds 500
    & cmd /c "sc.exe delete $tempServiceName" 2>$null

    if (Test-Path $registryPath) {
        Remove-Item -Path $registryPath -Force -Recurse -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_059a4e48-ef54-458f-a398-c992404f0122  (1 rule(s)) ---------------------
# Intent:    Detect adversarial registration of a malicious ServiceDll parameter in svchost s
# Rules:     059a4e48-ef54-458f-a398-c992404f0122
# Archetype: Software installer/updater workflow

$serviceName = 'NetworkDiagnostics'
$registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
$parametersPath = "$registryPath\Parameters"

try {
    # Simulate installer-initiated service group creation (legitimate during Windows updates or feature installation)
    # wusa.exe or ccmexec.exe context would trigger this in real enterprise environments
    & cmd /c "sc.exe create $serviceName binPath= \"C:\\Windows\\System32\\svchost.exe -k NetworkService\" type= share start= disabled"
    Start-Sleep -Milliseconds 300

    # Configure ServiceDll for the service group (common in installer workflows)
    if (-not (Test-Path $parametersPath)) {
        New-Item -Path $parametersPath -Force | Out-Null
    }
    Set-ItemProperty -Path $parametersPath -Name 'ServiceDll' -Value 'C:\Windows\System32\netsh.exe' -Type String

    # Log configuration action
    $regValue = Get-ItemProperty -Path $parametersPath -Name 'ServiceDll' -ErrorAction SilentlyContinue
    if ($regValue) {
        # Service group configured with DLL
    }

} finally {
    # Clean up service configuration
    Start-Sleep -Milliseconds 300
    & cmd /c "sc.exe delete $serviceName" 2>$null

    if (Test-Path $registryPath) {
        Remove-Item -Path $registryPath -Force -Recurse -ErrorAction SilentlyContinue
    }
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
