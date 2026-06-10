# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   3  |  Feasible: 3  |  Variants: 8
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_400acaef-ef37-498c-8d79-9757d1366c27  (1 rule(s)) ---------------------
# Intent:    Detect renamed system binaries or binaries with mismatched OriginalFileName meta
# Rules:     400acaef-ef37-498c-8d79-9757d1366c27
# Archetype: IT admin workflow

$adminWorkdir = [System.IO.Path]::GetTempPath() + 'sysadmin_audit_' + [guid]::NewGuid().ToString().Substring(0, 8)
$null = New-Item -ItemType Directory -Path $adminWorkdir -Force

try {
  # Query running services for security baseline audit
  $scPath = 'C:\Windows\System32\sc.exe'
  & $scPath query | Select-Object -First 10 | Out-File (Join-Path $adminWorkdir 'services_baseline.txt')

  # Export registry configuration for compliance validation
  $regPath = 'C:\Windows\System32\reg.exe'
  & $regPath query 'HKLM\Software\Microsoft\Windows\CurrentVersion' /s 2>$null | Out-File (Join-Path $adminWorkdir 'registry_export.txt')

  # Enumerate system processes via cmd.exe for troubleshooting
  $cmdPath = 'C:\Windows\System32\cmd.exe'
  & $cmdPath /c tasklist.exe /svc 2>$null | Out-File (Join-Path $adminWorkdir 'process_inventory.txt')

  # Inspect Windows Defender configuration using PowerShell
  $psPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
  & $psPath -NoProfile -Command { Get-MpPreference | Select-Object DisableRealtimeMonitoring, DisableBehaviorMonitoring | Out-String } | Out-File (Join-Path $adminWorkdir 'defender_config.txt')

  # Verify file integrity for critical system binaries
  $cmd = @(
    'C:\Windows\System32\cmd.exe',
    '/c',
    'certutil.exe -hashfile C:\Windows\System32\kernel32.dll SHA256'
  )
  & $cmd[0] $cmd[1] $cmd[2] 2>$null | Out-File (Join-Path $adminWorkdir 'integrity_check.txt')

  # Query WMI for hardware inventory via wmic
  $wmicPath = 'C:\Windows\System32\wbem\wmic.exe'
  & $wmicPath logicaldisk get name 2>$null | Out-File (Join-Path $adminWorkdir 'disk_inventory.txt')

  Start-Sleep -Milliseconds 500
} finally {
  Remove-Item -Path $adminWorkdir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_400acaef-ef37-498c-8d79-9757d1366c27  (1 rule(s)) ---------------------
# Intent:    Detect renamed system binaries or binaries with mismatched OriginalFileName meta
# Rules:     400acaef-ef37-498c-8d79-9757d1366c27
# Archetype: Software installer/updater workflow

$deployDir = [System.IO.Path]::GetTempPath() + 'deployment_' + [guid]::NewGuid().ToString().Substring(0, 8)
$null = New-Item -ItemType Directory -Path $deployDir -Force

try {
  # Create a benign test DLL using Windows resources
  $testDllPath = Join-Path $deployDir 'testlib.dll'
  Copy-Item 'C:\Windows\System32\shell32.dll' $testDllPath -Force

  # Simulate DLL registration process via regsvr32 (normal installer behavior)
  $regsvr32Path = 'C:\Windows\System32\regsvr32.exe'
  & $regsvr32Path /s $testDllPath 2>$null
  Start-Sleep -Milliseconds 300

  # Unregister the DLL cleanly
  & $regsvr32Path /s /u $testDllPath 2>$null
  Start-Sleep -Milliseconds 300

  # Simulate rundll32 usage for loading libraries (common in installers)
  $rundll32Path = 'C:\Windows\System32\rundll32.exe'
  # Call a safe export from shell32.dll
  & $rundll32Path shell32.dll,ShellExecute cmd.exe /c echo Installation verification complete 2>$null | Out-Null
  Start-Sleep -Milliseconds 300

  # Use msiexec for feature query (simulates installer checking Windows features)
  $msiexecPath = 'C:\Windows\System32\msiexec.exe'
  & $msiexecPath /query /listfeatures 2>$null | Out-File (Join-Path $deployDir 'features.txt')
  Start-Sleep -Milliseconds 300

  # Simulate application configuration via cmd and registry access
  $regPath = 'C:\Windows\System32\reg.exe'
  & $regPath add 'HKLM\Software\Microsoft\Windows NT\CurrentVersion' /v 'TestValueTemp' /d 'DeploymentTest' /f 2>$null
  Start-Sleep -Milliseconds 200
  & $regPath delete 'HKLM\Software\Microsoft\Windows NT\CurrentVersion' /v 'TestValueTemp' /f 2>$null

  # Service control for post-installation verification
  $scPath = 'C:\Windows\System32\sc.exe'
  & $scPath query config winlogon 2>$null | Out-File (Join-Path $deployDir 'service_config.txt')
  Start-Sleep -Milliseconds 300

} finally {
  Remove-Item -Path $deployDir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_400acaef-ef37-498c-8d79-9757d1366c27  (1 rule(s)) ---------------------
# Intent:    Detect renamed system binaries or binaries with mismatched OriginalFileName meta
# Rules:     400acaef-ef37-498c-8d79-9757d1366c27
# Archetype: User-driven workflow

$userWorkdir = [System.IO.Path]::GetTempPath() + 'user_activity_' + [guid]::NewGuid().ToString().Substring(0, 8)
$null = New-Item -ItemType Directory -Path $userWorkdir -Force

try {
  # Open file explorer to view system directories (user natural behavior)
  $explorerPath = 'C:\Windows\explorer.exe'
  $explorerProc = Start-Process -FilePath $explorerPath -ArgumentList $userWorkdir -PassThru
  Start-Sleep -Milliseconds 800
  $explorerProc | Stop-Process -Force -ErrorAction SilentlyContinue

  # Use PowerShell to check system information (users do this for troubleshooting)
  $psPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
  & $psPath -NoProfile -Command { Get-ComputerInfo -Property WindowsVersion, WindowsBuildLabEx | Out-String } | Out-File (Join-Path $userWorkdir 'sysinfo.txt')
  Start-Sleep -Milliseconds 300

  # Launch cmd to run help commands (typical user helpdesk workflow)
  $cmdPath = 'C:\Windows\System32\cmd.exe'
  & $cmdPath /c help 2>$null | Out-File (Join-Path $userWorkdir 'cmd_help.txt')
  Start-Sleep -Milliseconds 300

  # Create a temporary text file
  $notePadContent = "User Activity Log`r`nGenerated: $(Get-Date)`r`nThis is a legitimate user file."
  $notePadPath = Join-Path $userWorkdir 'notes.txt'
  $notePadContent | Out-File $notePadPath

  # Open notepad with the file (user natural behavior)
  $notepadPath = 'C:\Windows\System32\notepad.exe'
  $notepadProc = Start-Process -FilePath $notepadPath -ArgumentList $notePadPath -PassThru
  Start-Sleep -Milliseconds 800
  $notepadProc | Stop-Process -Force -ErrorAction SilentlyContinue

  # User checking network configuration
  & $cmdPath /c ipconfig /all 2>$null | Out-File (Join-Path $userWorkdir 'network_config.txt')
  Start-Sleep -Milliseconds 300

  # User listing running applications
  & $cmdPath /c tasklist.exe 2>$null | Out-File (Join-Path $userWorkdir 'running_apps.txt')
  Start-Sleep -Milliseconds 300

} finally {
  Remove-Item -Path $userWorkdir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_54e22e3e-d331-4bf5-8c34-25632c267241  (1 rule(s)) ---------------------
# Intent:    Detect exfiltration of sensitive data by scripting engines and utilities making 
# Rules:     54e22e3e-d331-4bf5-8c34-25632c267241
# Archetype: IT admin workflow

$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'SilentlyContinue'

# Simulate admin retrieving a configuration example from a public paste service
# This is realistic: admins often fetch scripts/configs from paste services during troubleshooting
$tempDir = Join-Path $env:TEMP 'admin_config_retrieve'
if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir | Out-Null }

try {
  # Use Invoke-WebRequest to fetch from a paste service
  # In real scenarios, admins retrieve actual configuration or diagnostic scripts
  Write-Host 'Retrieving configuration reference from public repository...'
  $uri = 'https://pastebin.com/raw/dummyid'
  $outFile = Join-Path $tempDir 'config_ref.txt'

  try {
    Invoke-WebRequest -Uri $uri -OutFile $outFile -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
  } catch {
    # Create a dummy file if network unavailable to continue test flow
    @'Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
Write-Host 'Reference config loaded'
'@ | Out-File -FilePath $outFile -Encoding UTF8
  }

  # Verify retrieval
  if (Test-Path $outFile) {
    Write-Host 'Configuration reference retrieved successfully'
    Get-Content $outFile | Select-Object -First 3
  }

  # Also simulate curl.exe attempting similar operation (realistic for cross-platform teams)
  Write-Host 'Attempting curl-based retrieval as fallback method...'
  $curlPath = 'C:\Program Files\Git\mingw64\bin\curl.exe'
  if (Test-Path $curlPath) {
    & $curlPath -s 'https://paste.ee/d/1234' -o (Join-Path $tempDir 'alternate_ref.txt') -m 5
  } elseif (Test-Path 'C:\Windows\System32\curl.exe') {
    & 'C:\Windows\System32\curl.exe' -s 'https://paste.ee/d/1234' -o (Join-Path $tempDir 'alternate_ref.txt') -m 5
  }

} finally {
  # Clean up all temporary files
  Write-Host 'Cleaning up temporary configuration references...'
  if (Test-Path $tempDir) {
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Write-Host 'Admin configuration retrieval workflow completed'

# -- Cluster: singleton_54e22e3e-d331-4bf5-8c34-25632c267241  (1 rule(s)) ---------------------
# Intent:    Detect exfiltration of sensitive data by scripting engines and utilities making 
# Rules:     54e22e3e-d331-4bf5-8c34-25632c267241
# Archetype: User-driven workflow

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# Simulate developer fetching a code snippet for validation
$workDir = Join-Path $env:TEMP 'dev_snippet_test'
if (-not (Test-Path $workDir)) { New-Item -ItemType Directory -Path $workDir | Out-Null }

try {
  # Create a Python script that fetches from paste service
  # This is realistic: developers fetch snippets from pastebin for testing
  $pyScript = @'
import urllib.request
import sys
import json

try:
    url = 'https://hastebin.com/raw/example123'
    with urllib.request.urlopen(url, timeout=5) as response:
        content = response.read().decode('utf-8')
        print('Snippet retrieved, length:', len(content))
        # Simulate validation
        test_data = {"status": "valid", "parsed": True}
        print(json.dumps(test_data))
except Exception as e:
    print('Fetch attempt logged:', str(e)[:50])
    # Write fallback data
    test_data = {"status": "local_fallback", "parsed": False}
    print(json.dumps(test_data))
'@

  $pyPath = Join-Path $workDir 'validate_snippet.py'
  Set-Content -Path $pyPath -Value $pyScript -Encoding UTF8

  Write-Host 'Developer validation script created, executing snippet retrieval...'

  # Execute Python to fetch snippet
  $pythonExe = 'python'
  if (Get-Command python -ErrorAction SilentlyContinue) {
    & python $pyPath
  } elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    & python3 $pyPath
  } else {
    Write-Host 'Python not available, simulating fetch with PowerShell...'
    try {
      $content = Invoke-WebRequest -Uri 'https://dpaste.org/raw/example' -UseBasicParsing -TimeoutSec 5 | Select-Object -ExpandProperty Content
      Write-Host 'Snippet validation result: success'
    } catch {
      Write-Host 'Snippet validation: local processing only'
    }
  }

  # Also test with wscript (Windows Script Host) for VBScript variant
  Write-Host 'Testing alternate script host execution...'
  $vbScript = @'
Set objHTTP = CreateObject("MSXML2.XMLHTTP")
objHTTP.Open "GET", "https://rentry.co/raw/example", False
On Error Resume Next
objHTTP.Send
If Err.Number = 0 Then
  WScript.Echo "Remote script retrieved"
End If
'@

  $vbPath = Join-Path $workDir 'fetch_snippet.vbs'
  Set-Content -Path $vbPath -Value $vbScript -Encoding UTF8

  # Execute vbscript via wscript
  if (Test-Path 'C:\Windows\System32\wscript.exe') {
    & 'C:\Windows\System32\wscript.exe' $vbPath //B 2>&1 | Out-Null
  }

} finally {
  # Clean up all development artifacts
  Write-Host 'Cleaning up development workspace...'
  if (Test-Path $workDir) {
    Remove-Item -Path $workDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Write-Host 'Developer snippet validation workflow completed'

# -- Cluster: singleton_54e22e3e-d331-4bf5-8c34-25632c267241  (1 rule(s)) ---------------------
# Intent:    Detect exfiltration of sensitive data by scripting engines and utilities making 
# Rules:     54e22e3e-d331-4bf5-8c34-25632c267241
# Archetype: Software installer/updater workflow

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# Simulate application update manager retrieving release notes
$updateDir = Join-Path $env:TEMP 'app_update_check'
if (-not (Test-Path $updateDir)) { New-Item -ItemType Directory -Path $updateDir | Out-Null }

try {
  Write-Host 'Checking for application updates and retrieving release information...'

  # Simulate wget utility checking for updates (common in enterprise tooling)
  $wgetPath = 'C:\Program Files\Git\mingw64\bin\wget.exe'
  if (-not (Test-Path $wgetPath)) {
    $wgetPath = 'C:\Program Files (x86)\Git\mingw64\bin\wget.exe'
  }

  if (Test-Path $wgetPath) {
    Write-Host 'Downloading release notes via wget...'
    & $wgetPath --quiet --timeout=5 --output-document=(Join-Path $updateDir 'changelog.txt') 'https://paste.fo/raw/example' 2>&1 | Out-Null
    if (Test-Path (Join-Path $updateDir 'changelog.txt')) {
      Write-Host 'Release information retrieved'
      (Get-Content (Join-Path $updateDir 'changelog.txt') -ErrorAction SilentlyContinue) | Select-Object -First 2
    }
  }

  # Simulate curl-based version check (also common)
  Write-Host 'Verifying version manifest from distribution endpoint...'
  $versionCheckUri = 'https://controlc.com/raw/versioninfo'
  try {
    $versionData = Invoke-WebRequest -Uri $versionCheckUri -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop | Select-Object -ExpandProperty Content
    Write-Host 'Version manifest retrieved, parsing...'
    if ($versionData -match 'version|update') {
      Write-Host 'Update available - would proceed with staged deployment'
    }
  } catch {
    Write-Host 'Using cached version information'
    @'{
  "current": "2.4.1",
  "latest": "2.4.1",
  "status": "up_to_date"
}
'@ | Out-File -FilePath (Join-Path $updateDir 'version_cache.json') -Encoding UTF8
  }

  # Simulate mshta (HTML Application host) retrieving installer manifest
  # Some updaters use this for HTML-based update dialogs
  Write-Host 'Checking installer manifest from secure distribution channel...'
  $htmlManifest = @'
<html><head><title>Update Check</title></head><body>
Application update check completed. No updates available.
</body></html>
'@

  $htmlPath = Join-Path $updateDir 'update_manifest.hta'
  Set-Content -Path $htmlPath -Value $htmlManifest -Encoding UTF8

  # mshta would normally parse this; we'll just verify creation
  if (Test-Path $htmlPath) {
    Write-Host 'Update manifest processed'
  }

  # Also simulate perl script validation (used in some deployment frameworks)
  Write-Host 'Validating update package integrity...'
  $perlScript = @'
use LWP::UserAgent;
my $ua = LWP::UserAgent->new(timeout => 5);
my $response = $ua->get('https://pastecode.io/raw/example');
if ($response->is_success) {
  print "Package integrity verified\n";
} else {
  print "Using local verification only\n";
}
'@

  $perlPath = Join-Path $updateDir 'verify_integrity.pl'
  Set-Content -Path $perlPath -Value $perlScript -Encoding UTF8

  # Try to execute if Perl is available
  if (Get-Command perl -ErrorAction SilentlyContinue) {
    & perl $perlPath 2>&1 | Out-Null
  }

} finally {
  # Clean up all update-related temporary files
  Write-Host 'Completing update check and cleaning temporary files...'
  if (Test-Path $updateDir) {
    Remove-Item -Path $updateDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Write-Host 'Application update check workflow completed'

# SKIPPED variant 'IT admin workflow': blocked pattern: hidden window ('-windowstyle hidden')

# -- Cluster: singleton_ff2e2fd1-3f99-4bb7-b3bf-4601fe6cd3fc  (1 rule(s)) ---------------------
# Intent:    Detect adversaries using PowerShell to register and immediately modify scheduled
# Rules:     ff2e2fd1-3f99-4bb7-b3bf-4601fe6cd3fc
# Archetype: Software installer/updater workflow

$taskName = 'EDRAgentHealthCheck_' + [System.Guid]::NewGuid().ToString().Substring(0, 8)
$taskPath = '\\Microsoft\\Windows\\Endpoint Protection\\'
$taskDescription = 'EDR agent system health verification and telemetry collection'

try {
  # Simulate endpoint protection installer context
  # Real EDR products (Defender for Endpoint, CrowdStrike, etc.) do this during installation

  $systemPrincipal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\\SYSTEM' -RunLevel Highest -LogonType ServiceAccount

  $agentHealthAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -Command "& {$healthCheckPath = \"$env:ProgramFiles\\EndpointProtection\\HealthCheck.ps1\"; if (Test-Path $healthCheckPath) { & $healthCheckPath } else { Write-Host \"Health check completed\" }}"'

  $dailyTrigger = New-ScheduledTaskTrigger -Daily -At 4:30AM -RandomDelay (New-TimeSpan -Minutes 15)

  $taskSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries:$false -DontStopIfGoingOnBatteries:$false -MultipleInstances IgnoreNew -Compatibility Win8

  # Register task with Administrators principal for system-level operations
  Register-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $agentHealthAction -Trigger $dailyTrigger -Principal $systemPrincipal -Settings $taskSettings -Description $taskDescription -Force

  Start-Sleep -Milliseconds 400

  # Post-registration modification: adjust settings for faster startup detection
  $fastBootTrigger = New-ScheduledTaskTrigger -AtStartup -RandomDelay (New-TimeSpan -Seconds 30)
  Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Trigger @($fastBootTrigger, $dailyTrigger) -ErrorAction SilentlyContinue

  Start-Sleep -Milliseconds 300

  # Ensure highest privilege level is confirmed via Set-ScheduledTask (installer verification pattern)
  Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Principal (New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\\SYSTEM' -RunLevel Highest -LogonType ServiceAccount) -ErrorAction SilentlyContinue

} finally {
  # Cleanup
  Start-Sleep -Milliseconds 200
  Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false -ErrorAction SilentlyContinue
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
