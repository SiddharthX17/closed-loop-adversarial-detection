# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   3  |  Feasible: 3  |  Variants: 9
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# SKIPPED variant 'User-driven workflow': blocked pattern: hidden window ('-windowstyle hidden')

# SKIPPED variant 'Software installer/updater workflow': blocked pattern: hidden window ('-windowstyle hidden')

# SKIPPED variant 'IT admin workflow': blocked pattern: hidden window ('-windowstyle hidden')

# -- Cluster: cluster_9c32b190a3  (2 rule(s)) ---------------------
# Intent:    Detect system binary masquerading from non-standard locations and script interpr
# Rules:     fd31f00d-be50-438a-b0bb-370680f0fb92, f508e658-cdd4-487f-a60d-98b852fae798
# Archetype: IT admin workflow

$reportDir = Join-Path $env:ProgramData 'SystemReports'
if (-not (Test-Path $reportDir)) {
    New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
}

$taskName = 'DiagnosticComplianceCheck'
$taskPath = '\\Microsoft\\Windows\\Performance'
$psScript = Join-Path $env:ProgramData 'SystemReports\\compliance_check.ps1'

$scriptContent = @'
[System.Diagnostics.Process]::GetProcesses() | Select-Object -Property Name, Id, WorkingSet | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramData)) 'SystemReports\\process_inventory.csv')
Get-WmiObject Win32_Service | Where-Object {$_.State -eq 'Running'} | Select-Object -Property Name, ProcessId, State | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramData)) 'SystemReports\\service_status.csv')
'@

Set-Content -Path $psScript -Value $scriptContent -Force

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $psScript)
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null

Start-ScheduledTask -TaskName $taskName -TaskPath $taskPath

Start-Sleep -Seconds 3

Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false -ErrorAction SilentlyContinue

Remove-Item -Path $psScript -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path $reportDir 'process_inventory.csv') -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path $reportDir 'service_status.csv') -Force -ErrorAction SilentlyContinue
Remove-Item -Path $reportDir -Force -ErrorAction SilentlyContinue

# -- Cluster: cluster_9c32b190a3  (2 rule(s)) ---------------------
# Intent:    Detect system binary masquerading from non-standard locations and script interpr
# Rules:     fd31f00d-be50-438a-b0bb-370680f0fb92, f508e658-cdd4-487f-a60d-98b852fae798
# Archetype: Software installer/updater workflow

$stagingDir = Join-Path $env:ProgramData 'SoftwareStaging\\ComponentUpdate'
if (-not (Test-Path $stagingDir)) {
    New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null
}

$regsvr32Path = Join-Path $stagingDir 'regsvr32.exe'
$rundll32Path = Join-Path $stagingDir 'rundll32.exe'
$certutilPath = Join-Path $stagingDir 'certutil.exe'

$regsvr32Src = Join-Path $env:windir 'System32\\regsvr32.exe'
$rundll32Src = Join-Path $env:windir 'System32\\rundll32.exe'
$certutilSrc = Join-Path $env:windir 'System32\\certutil.exe'

Copy-Item -Path $regsvr32Src -Destination $regsvr32Path -Force -ErrorAction SilentlyContinue
Copy-Item -Path $rundll32Src -Destination $rundll32Path -Force -ErrorAction SilentlyContinue
Copy-Item -Path $certutilSrc -Destination $certutilPath -Force -ErrorAction SilentlyContinue

$dllPath = Join-Path $stagingDir 'samplecomponent.dll'
@'
# Minimal PE header for testing
'@ | Set-Content -Path $dllPath

if (Test-Path $regsvr32Path) {
    & cmd /c "$regsvr32Path /s /c $dllPath 2>nul" -ErrorAction SilentlyContinue
}

Start-Sleep -Milliseconds 500

if (Test-Path $rundll32Path) {
    & cmd /c "$rundll32Path oleaut32.dll,GetRecordInfoFromGuids 2>nul" -ErrorAction SilentlyContinue
}

Start-Sleep -Milliseconds 500

if (Test-Path $certutilPath) {
    & cmd /c "$certutilPath -hashfile $dllPath SHA256 2>nul" -ErrorAction SilentlyContinue
}

Start-Sleep -Milliseconds 500

Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction SilentlyContinue

# -- Cluster: cluster_9c32b190a3  (2 rule(s)) ---------------------
# Intent:    Detect system binary masquerading from non-standard locations and script interpr
# Rules:     fd31f00d-be50-438a-b0bb-370680f0fb92, f508e658-cdd4-487f-a60d-98b852fae798
# Archetype: User-driven workflow

$appStagingDir = Join-Path $env:TEMP 'PortableAppBundle'
if (-not (Test-Path $appStagingDir)) {
    New-Item -ItemType Directory -Path $appStagingDir -Force | Out-Null
}

$cmdExePath = Join-Path $appStagingDir 'cmd.exe'
$psExePath = Join-Path $appStagingDir 'powershell.exe'
$psScriptPath = Join-Path $appStagingDir 'config_setup.ps1'
$batchScriptPath = Join-Path $appStagingDir 'environment_check.bat'

Copy-Item -Path (Join-Path $env:windir 'System32\\cmd.exe') -Destination $cmdExePath -Force
Copy-Item -Path (Join-Path $env:windir 'System32\\WindowsPowerShell\\v1.0\\powershell.exe') -Destination $psExePath -Force

$psScriptContent = @'
$configPath = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ApplicationData)) 'LocalAppBundle\\config.ini'
if (-not (Test-Path (Split-Path $configPath))) {
    New-Item -ItemType Directory -Path (Split-Path $configPath) -Force | Out-Null
}
@'
APP_VERSION=1.2.3
LOG_LEVEL=INFO
CACHE_DIR=.\\cache
'@ | Set-Content -Path $configPath
'@

Set-Content -Path $psScriptPath -Value $psScriptContent

$batchScriptContent = @'
echo Validating environment
directory="%APPDATA%\\LocalAppBundle"
if not exist "%directory%" mkdir "%directory%"
echo Configuration directory verified
'@

Set-Content -Path $batchScriptPath -Value $batchScriptContent

if (Test-Path $cmdExePath) {
    & $cmdExePath /c "echo Testing portable app environment && set" 2>$null | Select-Object -First 5
}

Start-Sleep -Milliseconds 300

if (Test-Path $psExePath) {
    & $psExePath -NoProfile -Command "Write-Output 'Application health check' ; Get-Item -Path (Join-Path $appStagingDir '*.exe') -ErrorAction SilentlyContinue | Measure-Object"
}

Start-Sleep -Milliseconds 300

if (Test-Path $batchScriptPath) {
    & $cmdExePath /c $batchScriptPath 2>$null
}

Start-Sleep -Milliseconds 300

Remove-Item -Path $appStagingDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path $env:APPDATA 'LocalAppBundle') -Recurse -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_9b198abe-8ae0-44ee-b877-d45653539928  (1 rule(s)) ---------------------
# Intent:    Detect exfiltration of sensitive data via text storage/pastebin services by non-
# Rules:     9b198abe-8ae0-44ee-b877-d45653539928
# Archetype: IT admin workflow

$DiagnosticData = @"
Event Type: System Diagnostic
Timestamp: $(Get-Date)
ComputerName: $env:COMPUTERNAME
OSVersion: $([System.Environment]::OSVersion.VersionString)
MemoryUsage: $(Get-Process | Measure-Object WorkingSet -Sum | ForEach-Object {$_.Sum / 1MB})
DiskSpace: $(Get-Volume | Select-Object DriveLetter, SizeRemaining | Out-String)
"@

$TempFile = Join-Path -Path $env:TEMP -ChildPath "diag_$(Get-Random).txt"
Set-Content -Path $TempFile -Value $DiagnosticData -Force

try {
    # Simulate posting diagnostic snippet to a code-sharing service
    # This is realistic admin behavior for cross-team troubleshooting
    $Uri = "https://pastebin.com/api/api_post.php"
    $Headers = @{"Content-Type" = "application/x-www-form-urlencoded"}
    $Body = "api_dev_key=test&api_option=paste&api_paste_code=$([System.Uri]::EscapeDataString($DiagnosticData))"

    $ConnectTest = Test-Connection -ComputerName pastebin.com -Count 1 -Quiet -ErrorAction SilentlyContinue
    if ($ConnectTest) {
        Invoke-WebRequest -Uri $Uri -Method POST -Headers $Headers -Body $Body -TimeoutSec 10 -ErrorAction SilentlyContinue | Out-Null
    }
}
catch {
    # Silently continue if pastebin is unreachable (expected in isolated environments)
}
finally {
    Remove-Item -Path $TempFile -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_9b198abe-8ae0-44ee-b877-d45653539928  (1 rule(s)) ---------------------
# Intent:    Detect exfiltration of sensitive data via text storage/pastebin services by non-
# Rules:     9b198abe-8ae0-44ee-b877-d45653539928
# Archetype: Software installer/updater workflow

$BuildScriptDir = Join-Path -Path $env:TEMP -ChildPath "build_artifacts_$(Get-Random)"
New-Item -ItemType Directory -Path $BuildScriptDir -Force | Out-Null

try {
    # Simulate retrieving a shared build utility or config snippet from a code-sharing service
    # Realistic for DevOps teams sharing deployment templates
    $ConfigUri = "https://paste.ee/r/SampleBuildConfig"
    $ScriptUri = "https://rentry.co/SampleDeploymentScript"

    $ConfigFile = Join-Path -Path $BuildScriptDir -ChildPath "build_config.txt"
    $ScriptFile = Join-Path -Path $BuildScriptDir -ChildPath "deploy.ps1"

    Write-Host "[BuildSystem] Retrieving shared configuration from collaborative platform..."

    try {
        Invoke-WebRequest -Uri $ConfigUri -OutFile $ConfigFile -TimeoutSec 10 -ErrorAction SilentlyContinue
    }
    catch {
        # Expected if service is unreachable; create placeholder
        Set-Content -Path $ConfigFile -Value "# Configuration placeholder" -Force
    }

    try {
        Invoke-WebRequest -Uri $ScriptUri -OutFile $ScriptFile -TimeoutSec 10 -ErrorAction SilentlyContinue
    }
    catch {
        # Expected if service is unreachable; create placeholder
        Set-Content -Path $ScriptFile -Value "Write-Host 'Deployment template placeholder'" -Force
    }

    # Simulate build system validating retrieved artifacts
    if (Test-Path -Path $ConfigFile) {
        $ConfigContent = Get-Content -Path $ConfigFile -ErrorAction SilentlyContinue
        Write-Host "[BuildSystem] Configuration retrieved: $(($ConfigContent | Measure-Object -Line).Lines) lines"
    }

    if (Test-Path -Path $ScriptFile) {
        $ScriptContent = Get-Content -Path $ScriptFile -ErrorAction SilentlyContinue
        Write-Host "[BuildSystem] Deployment script retrieved: $(($ScriptContent | Measure-Object -Line).Lines) lines"
    }
}
finally {
    Remove-Item -Path $BuildScriptDir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_9b198abe-8ae0-44ee-b877-d45653539928  (1 rule(s)) ---------------------
# Intent:    Detect exfiltration of sensitive data via text storage/pastebin services by non-
# Rules:     9b198abe-8ae0-44ee-b877-d45653539928
# Archetype: User-driven workflow

$WorkDir = Join-Path -Path $env:TEMP -ChildPath "dev_collab_$(Get-Random)"
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null

try {
    # Simulate a developer retrieving a shared code snippet for a code review or debugging session
    # Realistic for software development teams using pastebin for collaborative debugging

    $SnippetUri = "https://dpaste.com/raw/ABC123DEF456"
    $LogUri = "https://paste.sh/raw/12345"

    $SnippetFile = Join-Path -Path $WorkDir -ChildPath "code_snippet.cs"
    $LogFile = Join-Path -Path $WorkDir -ChildPath "debug_log.txt"

    Write-Host "[Developer] Retrieving shared code snippet for review..."

    try {
        Invoke-WebRequest -Uri $SnippetUri -OutFile $SnippetFile -TimeoutSec 10 -ErrorAction SilentlyContinue
    }
    catch {
        Set-Content -Path $SnippetFile -Value "// Shared code snippet placeholder" -Force
    }

    # Also retrieve a shared debug log for collaborative analysis
    try {
        Invoke-WebRequest -Uri $LogUri -OutFile $LogFile -TimeoutSec 10 -ErrorAction SilentlyContinue
    }
    catch {
        Set-Content -Path $LogFile -Value "[Debug Log Placeholder]" -Force
    }

    # Simulate developer reviewing the retrieved artifacts
    if (Test-Path -Path $SnippetFile) {
        $SnippetContent = Get-Content -Path $SnippetFile
        Write-Host "[Developer] Code snippet received: $(($SnippetContent | Measure-Object -Line).Lines) lines"
    }

    if (Test-Path -Path $LogFile) {
        $LogContent = Get-Content -Path $LogFile
        Write-Host "[Developer] Debug log received: $(($LogContent | Measure-Object -Line).Lines) lines"
    }

    # Now simulate sharing a local error or log snippet
    $LocalError = @"
Exception: System.ArgumentNullException
Message: Value cannot be null. Parameter name: source
StackTrace: at System.Diagnostics.EventLog..ctor(String source)
Timestamp: $(Get-Date)
"@

    $ErrorFile = Join-Path -Path $WorkDir -ChildPath "error_to_share.txt"
    Set-Content -Path $ErrorFile -Value $LocalError -Force

    Write-Host "[Developer] Preparing to share error details via code-sharing platform..."

    # Simulate posting the error log for team review
    $PostUri = "https://ix.io"
    try {
        Invoke-WebRequest -Uri $PostUri -Method POST -Body $LocalError -TimeoutSec 10 -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        # Expected if service is unreachable
    }
}
finally {
    Remove-Item -Path $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
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
