# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_73c5d4df-3658-4628-af50-113323422f10  (1 rule(s)) ---------------------
# Intent:    Detect masquerading of legitimate system processes by scripts or scripting hosts
# Rules:     73c5d4df-3658-4628-af50-113323422f10
# Archetype: IT admin workflow

$ErrorActionPreference = 'SilentlyContinue'
$logPath = Join-Path $env:TEMP "process_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# Query running processes and their details - legitimate admin monitoring
Get-Process | Select-Object -Property Name, Id, ProcessName, @{Name='ParentProcessId';Expression={$_.Id}} | Format-Table -AutoSize | Out-File -FilePath $logPath -Encoding UTF8

# Enumerate system processes using WMI - common admin diagnostic activity
$sysProcesses = Get-WmiObject Win32_Process | Where-Object {$_.Name -match '^(lsass|svchost|csrss|services|explorer|dwm|smss|taskhostw)\.exe$'} | Select-Object -First 5

# Query process command lines for those processes
foreach ($proc in $sysProcesses) {
  if ($null -ne $proc) {
    $cmdLine = $proc.CommandLine
    # This reference to system process names in queries is normal admin activity
  }
}

# Use cscript to enumerate system configuration - legitimate IT admin tool usage
$vbsPath = Join-Path $env:TEMP "sysinfo_query.vbs"
@"
Set objWMI = GetObject("winmgmts:")
Set colItems = objWMI.ExecQuery("Select * from Win32_Process where Name = 'powershell.exe'")
For Each objItem in colItems
  WScript.Echo objItem.CommandLine
Next
"@ | Out-File -FilePath $vbsPath -Encoding ASCII

# Execute through cscript - parent is cscript.exe, triggers parent detection
cscript.exe "$vbsPath" 2>&1 | Out-Null

# Clean up temporary files
Remove-Item -Path $vbsPath -Force -ErrorAction SilentlyContinue
Remove-Item -Path $logPath -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_73c5d4df-3658-4628-af50-113323422f10  (1 rule(s)) ---------------------
# Intent:    Detect masquerading of legitimate system processes by scripts or scripting hosts
# Rules:     73c5d4df-3658-4628-af50-113323422f10
# Archetype: Software installer/updater workflow

$ErrorActionPreference = 'SilentlyContinue'
$installerLogPath = Join-Path $env:TEMP "installer_validation.log"
$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

# Pre-installation validation - check system processes and services
Add-Content -Path $installerLogPath -Value "[$timestamp] Starting pre-installation system validation"

# Verify critical system services are running - legitimate installer pre-check
$services = @('svchost', 'lsass', 'explorer', 'dwm')
foreach ($service in $services) {
  $running = Get-Process -Name $service -ErrorAction SilentlyContinue
  if ($running) {
    Add-Content -Path $installerLogPath -Value "[$timestamp] System process $service found: $($running.Path)"
  }
}

# Use rundll32 to extract shell icon for setup wizard - legitimate installer pattern
$iconCacheDir = Join-Path $env:TEMP "installer_cache"
if (-not (Test-Path -Path $iconCacheDir)) {
  New-Item -ItemType Directory -Path $iconCacheDir -Force | Out-Null
}

# Common installer pattern: use rundll32 to extract system resources
rundll32.exe shell32.dll,ExtractIconEx "$env:SystemRoot\system32\shell32.dll" 0 "$iconCacheDir\icon.ico" 1 2>&1 | Out-Null

# Enumerate system paths that installer needs - this triggers path references in logs
$systemPaths = @(
  "$env:SystemRoot\system32",
  "$env:SystemRoot\syswow64",
  "$env:SystemRoot\winsxs"
)

foreach ($path in $systemPaths) {
  $itemCount = @(Get-ChildItem -Path $path -ErrorAction SilentlyContinue -File | Select-Object -First 1).Count
  Add-Content -Path $installerLogPath -Value "[$timestamp] Validated system path: $path"
}

# Use mshta to validate HTML installer components - legitimate setup tool usage
$htmlTest = Join-Path $env:TEMP "install_component_check.hta"
@"
<HTML>
<BODY>
Installer validation complete.
</BODY>
</HTML>
"@ | Out-File -FilePath $htmlTest -Encoding ASCII

# Execute through mshta - parent is mshta.exe
mshta.exe "$htmlTest" 2>&1 | Out-Null

# Clean up temporary files
Remove-Item -Path $iconCacheDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $htmlTest -Force -ErrorAction SilentlyContinue
Remove-Item -Path $installerLogPath -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_73c5d4df-3658-4628-af50-113323422f10  (1 rule(s)) ---------------------
# Intent:    Detect masquerading of legitimate system processes by scripts or scripting hosts
# Rules:     73c5d4df-3658-4628-af50-113323422f10
# Archetype: User-driven workflow

$ErrorActionPreference = 'SilentlyContinue'

# User runs a system diagnostics utility - common PowerShell-based admin helper
$diagnosticsPath = Join-Path $env:TEMP "diagnostics.ps1"

$diagnosticsScript = @'
# Collect system diagnostics for troubleshooting
$report = @{}
$report['Timestamp'] = Get-Date

# Check critical system processes
$processes = Get-Process -ErrorAction SilentlyContinue | Where-Object {
  $_.ProcessName -match '^(lsass|svchost|csrss|services|explorer|dwm)$'
}

$report['SystemProcesses'] = @()
foreach ($proc in $processes) {
  $report['SystemProcesses'] += @{
    Name = $proc.ProcessName
    Path = $proc.Path
    CommandLine = $proc.CommandLine
  }
}

# Verify Windows system folders integrity
$systemFolders = @(
  "$env:SystemRoot\system32",
  "$env:SystemRoot\syswow64",
  "$env:SystemRoot\winsxs"
)

$report['SystemFolders'] = @()
foreach ($folder in $systemFolders) {
  if (Test-Path -Path $folder) {
    $report['SystemFolders'] += $folder
  }
}

# Output summary
$report
'@

Set-Content -Path $diagnosticsPath -Value $diagnosticsScript

# Execute diagnostics script through PowerShell - parent is powershell.exe
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $diagnosticsPath | Out-Null

# Also run through pwsh if available (modern PowerShell)
$pwshPath = Join-Path $env:ProgramFiles "PowerShell\7\pwsh.exe"
if (Test-Path -Path $pwshPath) {
  & $pwshPath -NoProfile -File $diagnosticsPath 2>&1 | Out-Null
}

# Invoke a registry query for diagnostic purposes - user running admin helper
reg.exe query "HKLM\SYSTEM\CurrentControlSet\Services\svchost" /v ImagePath 2>&1 | Out-Null
reg.exe query "HKLM\SYSTEM\CurrentControlSet\Services\lsass" /v ImagePath 2>&1 | Out-Null

# Clean up
Remove-Item -Path $diagnosticsPath -Force -ErrorAction SilentlyContinue


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
