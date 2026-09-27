# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   3  |  Feasible: 3  |  Variants: 9
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_71d4f063-63ac-4a68-9fe8-1390e5d6f257  (1 rule(s)) ---------------------
# Intent:    Adversaries writing command interpreter output to administrative shares (ADMIN$ 
# Rules:     71d4f063-63ac-4a68-9fe8-1390e5d6f257
# Archetype: IT admin workflow

$remoteAdminShare = '\\127.0.0.1\admin$'
$reportDir = Join-Path $env:TEMP 'sysreport_' + (Get-Date -Format 'yyyyMMdd')
New-Item -ItemType Directory -Path $reportDir -Force | Out-Null

# Collect diagnostic information locally
$diagnosticOutput = cmd /c 'systeminfo'
Set-Content -Path (Join-Path $reportDir 'systeminfo.txt') -Value $diagnosticOutput

# Collect network configuration
$networkOutput = cmd /c 'ipconfig /all'
Set-Content -Path (Join-Path $reportDir 'ipconfig.txt') -Value $networkOutput

# Create summary report and write to local share mount point using redirection
$summaryFile = Join-Path $reportDir 'summary.txt'
cmd /c "echo System Diagnostic Report - Generated $(Get-Date) >> $summaryFile"
cmd /c "echo Machine: %COMPUTERNAME% >> $summaryFile"

# Simulate writing collection output via PowerShell redirection to admin$ mount
if (Test-Path $remoteAdminShare -ErrorAction SilentlyContinue) {
  Get-Content (Join-Path $reportDir 'systeminfo.txt') | Out-File -FilePath (Join-Path $remoteAdminShare 'diag_report.txt') -Encoding ASCII
}

# Write network diagnostics via redirection operator
$logPath = Join-Path $reportDir 'network_diagnostics.log'
cmd /c "systeminfo 1> $logPath"

# Cleanup
Remove-Item -Path $reportDir -Recurse -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_71d4f063-63ac-4a68-9fe8-1390e5d6f257  (1 rule(s)) ---------------------
# Intent:    Adversaries writing command interpreter output to administrative shares (ADMIN$ 
# Rules:     71d4f063-63ac-4a68-9fe8-1390e5d6f257
# Archetype: Software installer/updater workflow

# Enterprise deployment automation writing deployment logs to central administrative store
$deploymentShare = '\\127.0.0.1\c$'
$deploymentLogPath = Join-Path $env:TEMP 'deployment_log_' + (Get-Date -Format 'yyyyMMddHHmmss') + '.txt'

# Simulate deployment script collecting output
$deployOutput = @(
  'Deployment Agent Started: ' + (Get-Date)
  'Checking prerequisites...'
  'System configuration: OK'
  'Installation proceeding...'
)

# Write deployment log via PowerShell redirection
Set-Content -Path $deploymentLogPath -Value $deployOutput

# Consolidate to administrative C$ share if accessible (simulating central log collection)
if (Test-Path $deploymentShare -ErrorAction SilentlyContinue) {
  Copy-Item -Path $deploymentLogPath -Destination (Join-Path $deploymentShare 'Windows\Temp\deploy.log') -Force -ErrorAction SilentlyContinue
}

# Simulate installation script writing status
$statusLog = Join-Path $env:TEMP 'install_status.log'
wmic os get name /format:list >> $statusLog
wmic os get totalvirtualmemory /format:list >> $statusLog

# Write installation details via copy-item cmdlet
$installDetails = Join-Path $env:TEMP 'install_details.txt'
cmd /c "echo Installation Package Information > $installDetails"
cmd /c "echo Package: Deployment_Agent_v2.1 >> $installDetails"
cmd /c "echo Timestamp: %date% %time% >> $installDetails"

# Attempt to copy installation log to administrative share
if (Test-Path $deploymentShare -ErrorAction SilentlyContinue) {
  Copy-Item -Path $installDetails -Destination (Join-Path $deploymentShare 'Windows\Temp\install_details.log') -Force -ErrorAction SilentlyContinue
}

# Cleanup temporary files
Remove-Item -Path $deploymentLogPath -Force -ErrorAction SilentlyContinue
Remove-Item -Path $statusLog -Force -ErrorAction SilentlyContinue
Remove-Item -Path $installDetails -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_71d4f063-63ac-4a68-9fe8-1390e5d6f257  (1 rule(s)) ---------------------
# Intent:    Adversaries writing command interpreter output to administrative shares (ADMIN$ 
# Rules:     71d4f063-63ac-4a68-9fe8-1390e5d6f257
# Archetype: Document/file operation workflow

# Administrative report consolidation and archival
$adminShare = '\\127.0.0.1\admin$'
$reportBase = Join-Path $env:TEMP 'monthly_reports_' + (Get-Date -Format 'yyyyMMdd')
New-Item -ItemType Directory -Path $reportBase -Force | Out-Null

# Collect server maintenance information
$maintenanceReport = Join-Path $reportBase 'maintenance_log.txt'
cmd /c "echo SERVER MAINTENANCE REPORT - $(date /t) > $maintenanceReport"
cmd /c "systeminfo >> $maintenanceReport"
cmd /c "wmic logicaldisk get name,size,freespace >> $maintenanceReport"

# Collect service status for archival
$serviceReport = Join-Path $reportBase 'service_status.txt'
cmd /c "sc query >> $serviceReport"

# Archive reports to administrative shares if accessible
if (Test-Path $adminShare -ErrorAction SilentlyContinue) {
  Copy-Item -Path (Join-Path $reportBase 'maintenance_log.txt') -Destination (Join-Path $adminShare 'maintenance_log.txt') -Force -ErrorAction SilentlyContinue
}

# Write compliance audit output via PowerShell out-file
$auditReport = Join-Path $reportBase 'audit_trail.txt'
Get-Process | Select-Object Name, Id, ProcessName | Out-File -FilePath $auditReport -Encoding ASCII

# Consolidate all reports to central location
$consolidatedPath = Join-Path $env:TEMP 'reports_consolidated.txt'
Get-Content -Path (Join-Path $reportBase '*') -ErrorAction SilentlyContinue | Out-File -FilePath $consolidatedPath

# Move consolidated report to administrative share for centralized archival
if (Test-Path $adminShare -ErrorAction SilentlyContinue) {
  Move-Item -Path $consolidatedPath -Destination (Join-Path $adminShare 'consolidated_reports.txt') -Force -ErrorAction SilentlyContinue
}

# Cleanup local copies
Remove-Item -Path $reportBase -Recurse -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_c31bab8c-ab36-40e4-841e-7c363f90b7d7  (1 rule(s)) ---------------------
# Intent:    Attackers enabling WinRM or using PowerShell Remoting to execute commands on loc
# Rules:     c31bab8c-ab36-40e4-841e-7c363f90b7d7
# Archetype: IT admin workflow

$originalExecutionPolicy = Get-ExecutionPolicy -Scope LocalMachine
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
try {
  Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Enabling WinRM for remote management infrastructure."
  Start-Service -Name WinRM -ErrorAction SilentlyContinue
  winrm quickconfig -quiet -force

  Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Validating PSRemoting on localhost."
  Enable-PSRemoting -Force -SkipNetworkProfileCheck

  Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Testing PSSession creation to localhost."
  $session = New-PSSession -ComputerName localhost -ErrorAction SilentlyContinue

  if ($session) {
    Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Executing remote command to verify connectivity."
    $result = Invoke-Command -Session $session -ScriptBlock { Get-ComputerInfo -Property CsName } -ErrorAction SilentlyContinue
    Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Remote execution result: $result"
    Remove-PSSession -Session $session
  }

  Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] WinRM and PSRemoting infrastructure validation complete."
}
finally {
  Set-ExecutionPolicy -ExecutionPolicy $originalExecutionPolicy -Scope LocalMachine -Force
}

# -- Cluster: singleton_c31bab8c-ab36-40e4-841e-7c363f90b7d7  (1 rule(s)) ---------------------
# Intent:    Attackers enabling WinRM or using PowerShell Remoting to execute commands on loc
# Rules:     c31bab8c-ab36-40e4-841e-7c363f90b7d7
# Archetype: Software installer/updater workflow

$configMgmtLog = "$env:TEMP\config_mgmt_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
try {
  Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Initializing configuration management deployment." | Tee-Object -FilePath $configMgmtLog

  $targets = @('127.0.0.1', 'localhost')
  foreach ($target in $targets) {
    Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Creating PSSession to $target for config deployment." | Tee-Object -FilePath $configMgmtLog -Append
    try {
      $session = New-PSSession -ComputerName $target -ErrorAction Continue
      if ($session) {
        Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Executing configuration validation on $target." | Tee-Object -FilePath $configMgmtLog -Append
        $config = Invoke-Command -Session $session -ScriptBlock {
          @{
            'OS' = [System.Environment]::OSVersion.VersionString
            'PowerShellVersion' = $PSVersionTable.PSVersion.ToString()
            'Timestamp' = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
          }
        } -ErrorAction Continue
        Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Config snapshot: $($config | ConvertTo-Json)" | Tee-Object -FilePath $configMgmtLog -Append
        Remove-PSSession -Session $session
      }
    }
    catch {
      Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Warning: Could not connect to $target - $_" | Tee-Object -FilePath $configMgmtLog -Append
    }
  }

  Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Configuration management deployment phase completed. Log saved to $configMgmtLog" | Tee-Object -FilePath $configMgmtLog -Append
}
finally {
  if (Test-Path -Path $configMgmtLog) {
    Remove-Item -Path $configMgmtLog -Force
  }
}

# -- Cluster: singleton_c31bab8c-ab36-40e4-841e-7c363f90b7d7  (1 rule(s)) ---------------------
# Intent:    Attackers enabling WinRM or using PowerShell Remoting to execute commands on loc
# Rules:     c31bab8c-ab36-40e4-841e-7c363f90b7d7
# Archetype: User-driven workflow

$sessionLog = "$env:TEMP\remote_session_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
try {
  Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Initiating remote diagnostics session." | Tee-Object -FilePath $sessionLog

  Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Establishing PSSession to localhost for diagnostics." | Tee-Object -FilePath $sessionLog -Append
  $diagSession = New-PSSession -ComputerName 127.0.0.1 -ErrorAction SilentlyContinue

  if ($diagSession) {
    Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Connected to remote system. Gathering diagnostics." | Tee-Object -FilePath $sessionLog -Append

    $diagnostics = Invoke-Command -Session $diagSession -ScriptBlock {
      @{
        'SystemUptime' = (Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime)
        'LogicalProcessors' = (Get-CimInstance Win32_Processor | Measure-Object -Property NumberOfLogicalProcessors -Sum | Select-Object -ExpandProperty Sum)
        'TotalMemory_GB' = [math]::Round((Get-CimInstance Win32_ComputerSystem | Select-Object -ExpandProperty TotalPhysicalMemory) / 1GB, 2)
        'ScanTime' = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
      }
    } -ErrorAction SilentlyContinue

    Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Diagnostic Results: $($diagnostics | ConvertTo-Json)" | Tee-Object -FilePath $sessionLog -Append
    Remove-PSSession -Session $diagSession
  }

  Write-Output "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Diagnostics session complete." | Tee-Object -FilePath $sessionLog -Append
}
finally {
  if (Test-Path -Path $sessionLog) {
    Remove-Item -Path $sessionLog -Force
  }
}

# -- Cluster: singleton_0cf6c3aa-6f5a-441e-9008-118d555e9956  (1 rule(s)) ---------------------
# Intent:    Detect when script engines (PowerShell, VBScript, etc.) spawn network discovery 
# Rules:     0cf6c3aa-6f5a-441e-9008-118d555e9956
# Archetype: IT admin workflow

# Network diagnostics health check executed by IT operations
$diagnosticLog = Join-Path $env:TEMP "network_diagnostic_$(Get-Date -Format yyyyMMdd_HHmmss).txt"
$testTargets = @('8.8.8.8', 'google.com', '127.0.0.1')

foreach ($target in $testTargets) {
    Add-Content -Path $diagnosticLog -Value "=== Testing connectivity to $target ==="

    # Ping for ICMP connectivity check
    $pingResult = ping.exe -n 1 -w 1000 $target 2>&1
    Add-Content -Path $diagnosticLog -Value $pingResult

    # Resolve DNS name
    $nsResult = nslookup.exe $target 2>&1
    Add-Content -Path $diagnosticLog -Value $nsResult
}

# Local ARP table enumeration for network discovery
Add-Content -Path $diagnosticLog -Value "=== Local ARP Table ==="
$arpResult = arp.exe -a
Add-Content -Path $diagnosticLog -Value $arpResult

# Network interface and routing check
Add-Content -Path $diagnosticLog -Value "=== Network Configuration ==="
$netResult = net.exe config workstation 2>&1
Add-Content -Path $diagnosticLog -Value $netResult

# Display results
Write-Host "Diagnostic report saved to $diagnosticLog"
Get-Content -Path $diagnosticLog

# Cleanup
Remove-Item -Path $diagnosticLog -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_0cf6c3aa-6f5a-441e-9008-118d555e9956  (1 rule(s)) ---------------------
# Intent:    Detect when script engines (PowerShell, VBScript, etc.) spawn network discovery 
# Rules:     0cf6c3aa-6f5a-441e-9008-118d555e9956
# Archetype: User-driven workflow

# Network troubleshooting helper script wrapped in mshta invocation
# User runs this when experiencing network connectivity problems

$tempScriptPath = Join-Path $env:TEMP "net_check_helper.vbs"
$tempLog = Join-Path $env:TEMP "connectivity_check.txt"

# Create a simple VBScript that calls network utilities
$vbsContent = @'
Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

logFile = objFSO.BuildPath(objShell.ExpandEnvironmentStrings("%TEMP%"), "connectivity_check.txt")
Set objLog = objFSO.CreateTextFile(logFile, True)

objLog.WriteLine("Network connectivity check started at " & Now())
objLog.WriteBlankLines(1)

objLog.WriteLine("Testing ping to 8.8.8.8:")
Set objExec = objShell.Exec("cmd /c ping.exe -n 1 8.8.8.8")
objLog.Write(objExec.StdOut.ReadAll())

objLog.WriteBlankLines(1)
objLog.WriteLine("Resolving google.com via nslookup:")
Set objExec = objShell.Exec("cmd /c nslookup.exe google.com")
objLog.Write(objExec.StdOut.ReadAll())

objLog.WriteBlankLines(1)
objLog.WriteLine("ARP table enumeration:")
Set objExec = objShell.Exec("cmd /c arp.exe -a")
objLog.Write(objExec.StdOut.ReadAll())

objLog.WriteBlankLines(1)
objLog.WriteLine("Network adapters status:")
Set objExec = objShell.Exec("cmd /c net.exe config workstation")
objLog.Write(objExec.StdOut.ReadAll())

objLog.WriteLine("Check completed at " & Now())
objLog.Close()
MsgBox("Network check complete. Results saved to " & logFile), vbInformation, "Connectivity Check"
'@

Set-Content -Path $tempScriptPath -Value $vbsContent -Encoding ASCII

# Invoke the VBScript via mshta (HTML Application host)
# This is a common pattern for running diagnostic tools from user scripts
mshta.exe vbscript:CreateObject("WScript.Shell").Run("cscript.exe \"" + $tempScriptPath + "\"", 0, True)

# Wait for completion
Start-Sleep -Seconds 2

# Display and then clean up
if (Test-Path $tempLog) {
    Write-Host "Connectivity check results:"
    Get-Content -Path $tempLog
    Remove-Item -Path $tempLog -Force -ErrorAction SilentlyContinue
}

Remove-Item -Path $tempScriptPath -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_0cf6c3aa-6f5a-441e-9008-118d555e9956  (1 rule(s)) ---------------------
# Intent:    Detect when script engines (PowerShell, VBScript, etc.) spawn network discovery 
# Rules:     0cf6c3aa-6f5a-441e-9008-118d555e9956
# Archetype: Software installer/updater workflow

# Software deployment pre-flight network validation
# This runs as part of an installer to verify network readiness before deployment

$validationLog = Join-Path $env:TEMP "deployment_prereq_check.txt"
$deploymentServer = "updates.example.local"

Add-Content -Path $validationLog -Value "Software Deployment Network Pre-flight Check"
Add-Content -Path $validationLog -Value ("Initiated: {0}" -f (Get-Date))
Add-Content -Path $validationLog -Value ""

# Validate DNS resolution of deployment server
Add-Content -Path $validationLog -Value "DNS Resolution Validation:"
try {
    $dnsCheck = nslookup.exe $deploymentServer 2>&1 | Out-String
    Add-Content -Path $validationLog -Value $dnsCheck
} catch {
    Add-Content -Path $validationLog -Value "DNS lookup failed: $_"
}

Add-Content -Path $validationLog -Value ""

# Ping deployment server to verify routing
Add-Content -Path $validationLog -Value "Connectivity Check to deployment infrastructure:"
$pingTests = @('8.8.8.8', '1.1.1.1')
foreach ($server in $pingTests) {
    $pingOutput = ping.exe -n 2 -w 500 $server 2>&1 | Out-String
    Add-Content -Path $validationLog -Value "Ping $server : $pingOutput"
}

Add-Content -Path $validationLog -Value ""

# Enumerate local network configuration
Add-Content -Path $validationLog -Value "Local Network Configuration:"
$arpTable = arp.exe -a | Out-String
Add-Content -Path $validationLog -Value $arpTable

Add-Content -Path $validationLog -Value ""

# Verify network share accessibility
Add-Content -Path $validationLog -Value "Network Share Enumeration:"
$netShares = net.exe view localhost 2>&1 | Out-String
Add-Content -Path $validationLog -Value $netShares

Add-Content -Path $validationLog -Value ""
Add-Content -Path $validationLog -Value ("Check completed: {0}" -f (Get-Date))

Write-Host "Pre-flight validation complete. Review results:"
Get-Content -Path $validationLog

# Cleanup
Remove-Item -Path $validationLog -Force -ErrorAction SilentlyContinue
Write-Host "Deployment validation finished."


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
