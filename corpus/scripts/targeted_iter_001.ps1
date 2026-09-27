# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   2  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_50a7f4f2-a1a8-4477-849d-f032c25d5441  (1 rule(s)) ---------------------
# Intent:    Detect execution of WSH scripting engines (cscript.exe, wscript.exe) launching s
# Rules:     50a7f4f2-a1a8-4477-849d-f032c25d5441
# Archetype: IT admin workflow

$deployPath = 'C:\corp-deploy\scripts'
if (-not (Test-Path $deployPath)) {
  New-Item -ItemType Directory -Path $deployPath -Force | Out-Null
}

$scriptContent = @'
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objWshShell = CreateObject("WScript.Shell")
objWshShell.LogEvent 4, "Inventory scan initiated"
objFSO.GetSpecialFolder(0)
'@

$scriptFile = Join-Path $deployPath 'system_inventory.vbs'
Set-Content -Path $scriptFile -Value $scriptContent -Force

Write-Host "Executing inventory script from deployment folder"
cscript.exe $scriptFile

Remove-Item -Path $scriptFile -Force -ErrorAction SilentlyContinue
Remove-Item -Path $deployPath -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_50a7f4f2-a1a8-4477-849d-f032c25d5441  (1 rule(s)) ---------------------
# Intent:    Detect execution of WSH scripting engines (cscript.exe, wscript.exe) launching s
# Rules:     50a7f4f2-a1a8-4477-849d-f032c25d5441
# Archetype: Software installer/updater workflow

$appDataTempPath = Join-Path $env:APPDATA 'Local\Temp'
if (-not (Test-Path $appDataTempPath)) {
  New-Item -ItemType Directory -Path $appDataTempPath -Force | Out-Null
}

$configScript = @'
Set objWshShell = CreateObject("WScript.Shell")
objWshShell.RegWrite "HKLM\Software\TestApp\Version", "2024.1.0"
WScript.Echo "Configuration complete"
'@

$scriptPath = Join-Path $appDataTempPath 'app_config_setup.vbs'
Set-Content -Path $scriptPath -Value $configScript -Force

Write-Host "Executing post-install configuration"
cscript.exe $scriptPath

Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_50a7f4f2-a1a8-4477-849d-f032c25d5441  (1 rule(s)) ---------------------
# Intent:    Detect execution of WSH scripting engines (cscript.exe, wscript.exe) launching s
# Rules:     50a7f4f2-a1a8-4477-849d-f032c25d5441
# Archetype: User-driven workflow

$downloadsPath = Join-Path $env:USERPROFILE 'Downloads'
if (-not (Test-Path $downloadsPath)) {
  New-Item -ItemType Directory -Path $downloadsPath -Force | Out-Null
}

$jscriptContent = @'
var WshShell = new ActiveXObject("WScript.Shell");
var fso = new ActiveXObject("Scripting.FileSystemObject");
var tempPath = WshShell.ExpandEnvironmentStrings("%TEMP%");
var fileName = tempPath + "\\report_export.txt";
fso.CreateTextFile(fileName).Close();
WScript.Echo("Report extracted to " + fileName);
'@

$scriptPath = Join-Path $downloadsPath 'monthly_export.js'
Set-Content -Path $scriptPath -Value $jscriptContent -Force

Write-Host "Executing downloaded automation script"
cscript.exe $scriptPath

Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path $env:TEMP 'report_export.txt') -Force -ErrorAction SilentlyContinue

# SKIPPED cluster singleton_3ba0271c-ab3d-4d46-a355-b61463e0d9fa: This rule cluster detects credential dumping via NTDS.dit and SYSTEM registry hive extraction - specifically targeting unauthorized copies to non-default locations (TEMP, USERS, PROGRAMDATA, WINDOWS\TASKS, or alternate drives). Generating benign stress-test activity that legitimately exercises this detection logic is not feasible on a GitHub Actions runner because: (1) NTDS.dit is the Active Directory database only present on Domain Controllers in a domain environment - GitHub Actions runners are not domain-joined and do not have AD services; (2) ntdsutil.exe is exclusively a Domain Controller administrative tool for managing AD database integrity and requires a functional Active Directory infrastructure with proper schema; (3) Legitimate uses of ntdsutil.exe (offline defragmentation, semantic database analysis, authoritative restore) require the AD database to be in a specific operational or maintenance state that cannot be synthetically created on a standalone runner; (4) Creating fake NTDS.dit files and copying them with ntdsutil.exe would be purely artificial scaffolding with no real operational justification - it would not reflect any genuine enterprise workflow an IT admin or tooling would naturally perform outside of actual AD maintenance on a DC; (5) The rule's detection logic (CommandLine contains both ntds.dit AND SYSTEM AND a suspicious destination) is specifically designed to catch the credential extraction pattern, and any attempt to generate "benign" activity that combines all these signals would be contrived and not representative of real AD operations.

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
