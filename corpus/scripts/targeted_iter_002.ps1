# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   2  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_c4dd5877-1471-4762-ac8e-171cc9798b01  (1 rule(s)) ---------------------
# Intent:    Detect credential dumping via LSASS process memory extraction initiated through 
# Rules:     c4dd5877-1471-4762-ac8e-171cc9798b01
# Archetype: IT admin workflow

$diagReportPath = Join-Path $env:TEMP 'system_diagnostics_20240115.log'
$processListPath = Join-Path $env:TEMP 'process_inventory.txt'

# Admin activity: Enumerate all running processes and write to report
$processes = Get-Process | Select-Object Id, Name, CommandLine, StartTime | Format-Table -AutoSize
Add-Content -Path $processListPath -Value "Process Inventory Report $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Add-Content -Path $processListPath -Value ($processes | Out-String)

# Admin uses tasklist for secondary process verification (common in troubleshooting)
Add-Content -Path $diagReportPath -Value "System Process Listing"
cmd /c "tasklist /v >> `"$diagReportPath`" 2>&1"

# Admin retrieves specific process details for memory diagnostics
$lsassProcess = Get-Process -Name lsass -ErrorAction SilentlyContinue
if ($lsassProcess) {
    Add-Content -Path $diagReportPath -Value "LSASS Process ID: $($lsassProcess.Id)"
    Add-Content -Path $diagReportPath -Value "Working Set: $($lsassProcess.WorkingSet) bytes"
}

# Admin invokes System File Checker from temp (legitimate diagnostic tool)
$diagToolPath = Join-Path $env:TEMP 'system_check.exe'
if (Test-Path -Path 'C:\Windows\System32\sfc.exe') {
    Copy-Item -Path 'C:\Windows\System32\sfc.exe' -Destination $diagToolPath -Force
    & $diagToolPath /scannow 2>&1 | Out-Null
    Remove-Item -Path $diagToolPath -Force -ErrorAction SilentlyContinue
}

# Cleanup
Remove-Item -Path $processListPath -Force -ErrorAction SilentlyContinue
Remove-Item -Path $diagReportPath -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_c4dd5877-1471-4762-ac8e-171cc9798b01  (1 rule(s)) ---------------------
# Intent:    Detect credential dumping via LSASS process memory extraction initiated through 
# Rules:     c4dd5877-1471-4762-ac8e-171cc9798b01
# Archetype: Software installer/updater workflow

$appDataTempDir = Join-Path $env:APPDATA 'Local\Temp' 'AppInstall_Staging'
$logPath = Join-Path $appDataTempDir 'install_validation.log'

# Ensure staging directory exists
if (-not (Test-Path -Path $appDataTempDir)) {
    New-Item -Path $appDataTempDir -ItemType Directory -Force | Out-Null
}

# Installer queries running processes to check for conflicts
Add-Content -Path $logPath -Value "Installation Validation Log: $(Get-Date)"

# Use Get-Process to enumerate running applications
$runningApps = Get-Process | Where-Object { $_.ProcessName -match '^(svchost|lsass|csrss|services)' } | Select-Object Name, Id
Add-Content -Path $logPath -Value "Critical System Processes: $(($runningApps | Measure-Object).Count) detected"

# Installer uses Get-WmiObject for detailed system process enumeration
$wmiProcs = Get-WmiObject -Class Win32_Process -Filter "Name='lsass.exe' OR Name='services.exe'" -ErrorAction SilentlyContinue
if ($wmiProcs) {
    Add-Content -Path $logPath -Value "WMI Process Query: System services verified"
}

# Installer stages verification utility to AppData
$verifyToolPath = Join-Path $appDataTempDir 'verify_prerequisites.exe'
if (Test-Path -Path 'C:\Windows\System32\cmd.exe') {
    Copy-Item -Path 'C:\Windows\System32\cmd.exe' -Destination $verifyToolPath -Force -ErrorAction SilentlyContinue

    # Execute verification tool from staging directory
    & $verifyToolPath /c "echo System prerequisite verification complete" 2>&1 | Out-Null
    Remove-Item -Path $verifyToolPath -Force -ErrorAction SilentlyContinue
}

# Cleanup staging directory
Remove-Item -Path $appDataTempDir -Recurse -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_c4dd5877-1471-4762-ac8e-171cc9798b01  (1 rule(s)) ---------------------
# Intent:    Detect credential dumping via LSASS process memory extraction initiated through 
# Rules:     c4dd5877-1471-4762-ac8e-171cc9798b01
# Archetype: Document/file operation workflow

$downloadsDir = [Environment]::GetFolderPath('UserProfile') + '\Downloads'
$appDataLocalDir = $env:APPDATA + '\Local'
$tempDir = $env:TEMP

# Create a maintenance script in AppData to audit system processes
$auditScriptPath = Join-Path $appDataLocalDir 'file_audit_helper.ps1'

# This script will be used to enumerate processes before cleanup
$auditScriptContent = @'
# Legacy file audit helper - enumerates processes that may lock files
Write-Host "Auditing file locks and process state"

# Query all processes
$allProcs = Get-Process -ErrorAction SilentlyContinue

# Check for system critical processes
foreach ($proc in $allProcs) {
    if ($proc.Name -match 'lsass|svchost|services') {
        Write-Host "Critical process: $($proc.Name) (PID: $($proc.Id))"
    }
}

# Use WMI for detailed process information
try {
    $wmiProcs = Get-WmiObject -Class Win32_Process -Filter "Name='svchost.exe'" -ErrorAction SilentlyContinue
    if ($wmiProcs) {
        Write-Host "System service processes verified"
    }
} catch {
    Write-Host "WMI query completed"
}
'@

Set-Content -Path $auditScriptPath -Value $auditScriptContent -Force

# Create a harmless utility file in Downloads to simulate maintenance tools
$maintenanceToolPath = Join-Path $downloadsDir 'file_integrity_checker.exe'
if (Test-Path -Path 'C:\Windows\System32\findstr.exe') {
    Copy-Item -Path 'C:\Windows\System32\findstr.exe' -Destination $maintenanceToolPath -Force -ErrorAction SilentlyContinue
}

# Execute the audit script (which enumerates processes including LSASS)
if (Test-Path -Path $auditScriptPath) {
    & powershell.exe -ExecutionPolicy Bypass -File $auditScriptPath 2>&1 | Out-Null
}

# Invoke the utility from Downloads
if (Test-Path -Path $maintenanceToolPath) {
    & $maintenanceToolPath 'dummy search pattern' 'C:\\Windows\\Temp' 2>&1 | Out-Null
    Remove-Item -Path $maintenanceToolPath -Force -ErrorAction SilentlyContinue
}

# Cleanup
Remove-Item -Path $auditScriptPath -Force -ErrorAction SilentlyContinue

# SKIPPED cluster singleton_3e718cf2-d474-43b5-81d3-7c065d7329d6: JSON parse error: Invalid \escape: line 15 column 1150 (char 2172)

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
