# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   3  |  Feasible: 3  |  Variants: 8
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_c52786d7-f8c4-4967-87b3-d7f370760c03  (1 rule(s)) ---------------------
# Intent:    Detect scheduled tasks that spawn script interpreters or LOLBins with command pa
# Rules:     c52786d7-f8c4-4967-87b3-d7f370760c03
# Archetype: IT admin workflow

$TaskName = 'ComplianceAudit_' + [guid]::NewGuid().ToString().Substring(0, 8)
$TaskPath = '\Microsoft\Windows\ComplianceTools\'
$Action = New-ScheduledTaskAction `
  -Execute 'powershell.exe' `
  -Argument '-NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Defender | Select-Object -ExpandProperty DisableRealtimeMonitoring; Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System | Select-Object -ExpandProperty DisableTaskMgr"'
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
Start-Sleep -Seconds 2
Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false

# -- Cluster: singleton_c52786d7-f8c4-4967-87b3-d7f370760c03  (1 rule(s)) ---------------------
# Intent:    Detect scheduled tasks that spawn script interpreters or LOLBins with command pa
# Rules:     c52786d7-f8c4-4967-87b3-d7f370760c03
# Archetype: Software installer/updater workflow

$TaskName = 'SoftwareMaintenanceTask_' + [guid]::NewGuid().ToString().Substring(0, 8)
$TaskPath = '\Microsoft\Windows\SoftwareUpdates\'
$ScriptPath = Join-Path $env:TEMP 'update_manifest.ps1'
$DownloadScript = @'
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
$Uri = 'https://www.microsoft.com/en-us/download'
$null = @'
Simulating legitimate manifest retrieval
'@
$ManifestContent = @'
<?xml version="1.0"?>
<configuration><version>1.0</version></configuration>
'@
$ManifestContent | Out-File -FilePath (Join-Path $env:TEMP 'manifest.xml') -Force
'@
Set-Content -Path $ScriptPath -Value $DownloadScript -Force
$Action = New-ScheduledTaskAction `
  -Execute 'cmd.exe' `
  -Argument ('/c powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + $ScriptPath + '"')
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath
Start-Sleep -Seconds 3
Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false
Remove-Item -Path $ScriptPath -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path $env:TEMP 'manifest.xml') -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_2b1333da-e2d4-4e53-a234-77b05ad0c3f2  (1 rule(s)) ---------------------
# Intent:    Detect system binaries being executed from non-standard filesystem locations, a 
# Rules:     2b1333da-e2d4-4e53-a234-77b05ad0c3f2
# Archetype: Software installer/updater workflow

$stagingDir = Join-Path $env:TEMP "AppDeploy_$(Get-Random)"
New-Item -ItemType Directory -Path $stagingDir -Force | Out-Null

try {
  # Copy system binaries to staging area (simulating bundled runtime libs in installer)
  Copy-Item -Path "C:\Windows\System32\rundll32.exe" -Destination (Join-Path $stagingDir "rundll32.exe") -Force
  Copy-Item -Path "C:\Windows\System32\regsvr32.exe" -Destination (Join-Path $stagingDir "regsvr32.exe") -Force

  # Execute from non-standard location with legitimate parameters
  # rundll32 with shell.dll is a common legitimate operation
  & (Join-Path $stagingDir "rundll32.exe") shell.dll,Control_RunDLL sysdm.cpl @0 /wait

  # Small delay to ensure Sysmon captures the event
  Start-Sleep -Milliseconds 500

  # regsvr32 with /u /s is legitimate unregistration (common in uninstallers)
  & (Join-Path $stagingDir "regsvr32.exe") /u /s scrrun.dll 2>$null

  Start-Sleep -Milliseconds 500
}
finally {
  # Cleanup staging directory
  Remove-Item -Path $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_2b1333da-e2d4-4e53-a234-77b05ad0c3f2  (1 rule(s)) ---------------------
# Intent:    Detect system binaries being executed from non-standard filesystem locations, a 
# Rules:     2b1333da-e2d4-4e53-a234-77b05ad0c3f2
# Archetype: IT admin workflow

$recoveryStaging = Join-Path $env:TEMP "SystemRecovery_$(Get-Random)"
New-Item -ItemType Directory -Path $recoveryStaging -Force | Out-Null

try {
  # Copy critical system binaries to recovery location (admin maintenance scenario)
  Copy-Item -Path "C:\Windows\System32\svchost.exe" -Destination (Join-Path $recoveryStaging "svchost.exe") -Force
  Copy-Item -Path "C:\Windows\System32\csrss.exe" -Destination (Join-Path $recoveryStaging "csrss.exe") -Force
  Copy-Item -Path "C:\Windows\System32\msiexec.exe" -Destination (Join-Path $recoveryStaging "msiexec.exe") -Force

  # Verify binary integrity via execution (legitimate diagnostic check)
  # svchost -? displays help
  & (Join-Path $recoveryStaging "svchost.exe") -? 2>$null | Out-Null

  Start-Sleep -Milliseconds 500

  # msiexec /? is a standard system information query
  & (Join-Path $recoveryStaging "msiexec.exe") /? 2>$null | Out-Null

  Start-Sleep -Milliseconds 500
}
finally {
  # Cleanup recovery staging area
  Remove-Item -Path $recoveryStaging -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_2b1333da-e2d4-4e53-a234-77b05ad0c3f2  (1 rule(s)) ---------------------
# Intent:    Detect system binaries being executed from non-standard filesystem locations, a 
# Rules:     2b1333da-e2d4-4e53-a234-77b05ad0c3f2
# Archetype: User-driven workflow

$toolkitDir = Join-Path $env:TEMP "PortableToolkit_$(Get-Random)"
New-Item -ItemType Directory -Path $toolkitDir -Force | Out-Null

try {
  # Copy system tools to portable toolkit location (USB/removable media scenario)
  Copy-Item -Path "C:\Windows\System32\explorer.exe" -Destination (Join-Path $toolkitDir "explorer.exe") -Force
  Copy-Item -Path "C:\Windows\System32\rundll32.exe" -Destination (Join-Path $toolkitDir "rundll32.exe") -Force
  Copy-Item -Path "C:\Windows\System32\conhost.exe" -Destination (Join-Path $toolkitDir "conhost.exe") -Force
  Copy-Item -Path "C:\Windows\System32\dllhost.exe" -Destination (Join-Path $toolkitDir "dllhost.exe") -Force

  # Execute explorer with a specific path (legitimate folder browsing)
  & (Join-Path $toolkitDir "explorer.exe") $env:WINDIR 2>$null &
  $explorerPid = $?
  Start-Sleep -Milliseconds 800
  Get-Process explorer -ErrorAction SilentlyContinue | Where-Object { $_.StartTime -gt (Get-Date).AddSeconds(-2) } | Stop-Process -Force -ErrorAction SilentlyContinue

  # Execute rundll32 with legitimate diagnostic DLL
  & (Join-Path $toolkitDir "rundll32.exe") kernel32.dll 2>$null

  Start-Sleep -Milliseconds 500

  # Execute conhost to verify console host functionality
  & (Join-Path $toolkitDir "conhost.exe") 2>$null &
  Start-Sleep -Milliseconds 600
  Get-Process conhost -ErrorAction SilentlyContinue | Where-Object { $_.StartTime -gt (Get-Date).AddSeconds(-3) } | Stop-Process -Force -ErrorAction SilentlyContinue

  Start-Sleep -Milliseconds 300
}
finally {
  # Cleanup toolkit directory
  Remove-Item -Path $toolkitDir -Recurse -Force -ErrorAction SilentlyContinue
  # Ensure any lingering processes are terminated
  Get-Process explorer, conhost -ErrorAction SilentlyContinue | Where-Object { $_.StartTime -gt (Get-Date).AddSeconds(-5) } | Stop-Process -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_0c94683a-a6d8-46e8-b547-a55e044e1097  (1 rule(s)) ---------------------
# Intent:    Detect exfiltration of sensitive data via paste/text sharing services using comm
# Rules:     0c94683a-a6d8-46e8-b547-a55e044e1097
# Archetype: IT admin workflow

$ErrorActionPreference = 'Stop'
$scriptBlockId = [System.Guid]::NewGuid().ToString().Substring(0, 8)
$logPath = Join-Path $env:TEMP "cert_validation_$scriptBlockId.log"

try {
  Write-Host "[*] Certificate validation audit - checking external service endpoints"

  # Simulate legitimate SSL chain validation using certutil
  # This is a real administrative task: verifying certificate chains for compliance
  Write-Host "[*] Validating certificate chain for paste service endpoint"

  # certutil naturally connects to the domain to fetch intermediate certificates
  # when processing certificate chains. This is legitimate infrastructure validation.
  $targetDomain = 'pastebin.com'

  # Create a temporary certificate file for testing (self-signed, harmless)
  $certPath = Join-Path $env:TEMP "test_cert_$scriptBlockId.cer"
  $certContent = @"
MIIDXTCCAkWgAwIBAgIJAKlHnLoTzx3+MA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjEwMTAxMDAwMDAwWhcNMjIwMTAxMDAwMDAwWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA0Z3VS5JJcds3s7L7FJpZKqM9XN8xyK5L5YZ5K5L5YZ5K5L5YZ5K5L5YZ
5K5L5YZ5K5L5YZ5K5L5YZ5K5L5YZ5K5L5YZ5K5L5YZ5K5L5YZ5K5L5YZ5K5L5YZ
5K5L5YZ5K5L5YZ5K5L5YZ5K5L5YZ5K5L5YZ5K5L5YZ5K5L5YZ5K5L5YZ5K5L5YZ
QIDAQABo1AwTjBMBgNVHQ4EFQQTbGRhcDovL2V4YW1wbGUuY29tMCsGA1UdHwQk
MCIwIKAeoByGGmh0dHA6Ly9leGFtcGxlLmNvbS9jYS5jcmwwDQYJKoZIhvcNAQEL
BQADggEBAJC1L5BxRVD7l9pNKJTxPi9pqJ9pqJ9pqJ9pqJ9pqJ9pqJ9pqJ9pqJ9p
qJ9pqJ9pqJ9pqJ9pqJ9pqJ9pqJ9pqJ9pqJ9pqJ9pqJ9pqJ9pqJ9pqJ9pqJ9pqJ9p
qJ9pqJ9pqJ9pqJ9pqJ9pqJ9pqJ9pqJ9pqJ9pqJ9pqJ9pqJ9pqJ8=
"@

  Set-Content -Path $certPath -Value $certContent -ErrorAction Continue

  # The certutil command will attempt to build and verify the certificate chain
  # When it does, it may initiate connections to validate CRL/OCSP endpoints
  # This is the legitimate source of the network event
  Write-Host "[*] Running certificate chain validation"
  & cmd /c "certutil.exe -verify -urlfetch $certPath" 2>&1 | Out-Null

  Write-Host "[+] Certificate validation completed (expected Sysmon event on network connection)"

  # Additional validation: use certutil to check a specific domain certificate
  Write-Host "[*] Checking domain certificate availability"
  & cmd /c "certutil.exe -URL https://$targetDomain" 2>&1 | Out-Null

  Write-Host "[+] Domain certificate check completed"

} catch {
  Write-Host "[-] Error during validation: $_"
} finally {
  # Cleanup
  if (Test-Path $certPath) { Remove-Item $certPath -Force -ErrorAction SilentlyContinue }
  if (Test-Path $logPath) { Remove-Item $logPath -Force -ErrorAction SilentlyContinue }
  Write-Host "[*] Cleanup completed"
}

# -- Cluster: singleton_0c94683a-a6d8-46e8-b547-a55e044e1097  (1 rule(s)) ---------------------
# Intent:    Detect exfiltration of sensitive data via paste/text sharing services using comm
# Rules:     0c94683a-a6d8-46e8-b547-a55e044e1097
# Archetype: Software installer/updater workflow

$ErrorActionPreference = 'Stop'
$scriptBlockId = [System.Guid]::NewGuid().ToString().Substring(0, 8)
$workDir = Join-Path $env:TEMP "deployment_$scriptBlockId"

try {
  New-Item -ItemType Directory -Path $workDir -Force | Out-Null

  Write-Host "[*] Configuration deployment utility - fetching remote configuration"

  # Simulate a deployment tool that fetches config from a paste service
  # This is a real pattern in CI/CD environments where configs are shared via paste services

  $pythonScript = Join-Path $workDir "deploy_config.py"
  $configPath = Join-Path $workDir "app_config.ini"

  # Create a Python script that uses curl to fetch a configuration
  # (common in deployment automation)
  $pythonCode = @"
import subprocess
import sys
import os

def fetch_config(url):
    """Fetch application configuration from remote service."""
    try:
        cmd = ['curl', '-s', '-f', '--max-time', '5', url]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout
        else:
            print(f'Failed to fetch config: {result.returncode}', file=sys.stderr)
            return None
    except Exception as e:
        print(f'Error fetching config: {e}', file=sys.stderr)
        return None

def main():
    # Simulate configuration retrieval from a paste service
    # This would be a real config URL in production
    config_url = 'https://paste.mozilla.org/api/v2/snippet/'

    config = fetch_config(config_url)
    if config:
        print('[+] Configuration retrieved successfully')
        with open(sys.argv[1], 'w') as f:
            f.write(config)
    else:
        print('[-] Configuration fetch failed')
        sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        main()
    else:
        print('Usage: deploy_config.py <output_file>')
"@

  Set-Content -Path $pythonScript -Value $pythonCode -Encoding UTF8

  Write-Host "[*] Executing configuration deployment with remote fetch"

  # Run the Python deployment script
  # This naturally generates network connections via curl to the paste domain
  & python.exe $pythonScript $configPath 2>&1 | ForEach-Object { Write-Host "[py] $_" }

  Write-Host "[*] Configuration deployment initiated (expected curl network event)"

  # Also demonstrate direct curl usage for config validation
  Write-Host "[*] Validating configuration endpoint accessibility"

  # Use curl to check paste service connectivity (real deployment validation)
  & cmd /c "curl.exe -s -I https://paste.ee --max-time 3 2>&1" | Out-Null

  Write-Host "[+] Configuration deployment completed"

} catch {
  Write-Host "[-] Deployment error: $_"
} finally {
  # Cleanup
  if (Test-Path $workDir) { Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue }
  Write-Host "[*] Deployment artifacts cleaned up"
}

# -- Cluster: singleton_0c94683a-a6d8-46e8-b547-a55e044e1097  (1 rule(s)) ---------------------
# Intent:    Detect exfiltration of sensitive data via paste/text sharing services using comm
# Rules:     0c94683a-a6d8-46e8-b547-a55e044e1097
# Archetype: User-driven workflow

$ErrorActionPreference = 'SilentlyContinue'
$scriptBlockId = [System.Guid]::NewGuid().ToString().Substring(0, 8)
$reportPath = Join-Path $env:TEMP "connectivity_report_$scriptBlockId.txt"

try {
  Write-Host "[*] Network connectivity diagnostic - testing service endpoints"

  # List of public services to test connectivity (including paste services)
  # This is a real troubleshooting scenario where admins check multiple endpoints
  $testEndpoints = @(
    'https://pastebin.com',
    'https://paste.mozilla.org',
    'https://dpaste.com',
    'https://rentry.co',
    'https://hastebin.com',
    'https://paste.ee'
  )

  $results = @()

  Write-Host "[*] Testing connectivity to service endpoints"

  foreach ($endpoint in $testEndpoints) {
    Write-Host "[*] Testing $endpoint"

    # Use Invoke-WebRequest for PowerShell-native connectivity check
    # This generates real network events
    try {
      $response = Invoke-WebRequest -Uri $endpoint -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
      $status = 'Reachable'
    } catch {
      $status = 'Unreachable (expected in restricted environment)'
    }

    $results += [PSCustomObject]@{
      Endpoint = $endpoint
      Status = $status
      Timestamp = Get-Date
    }
  }

  Write-Host "[+] Connectivity tests completed"

  # Also test using curl for redundancy
  Write-Host "[*] Validating with curl-based endpoint check"
  & cmd /c "curl.exe -s -I https://paste.mozilla.org --max-time 3 2>&1" | Out-Null
  & cmd /c "curl.exe -s -I https://pastecode.io --max-time 3 2>&1" | Out-Null

  Write-Host "[+] Endpoint validation completed"

  # Export results (diagnostic report)
  $results | Export-Csv -Path $reportPath -NoTypeInformation -ErrorAction Continue
  Write-Host "[*] Report generated: $reportPath"

} catch {
  Write-Host "[-] Diagnostic error: $_"
} finally {
  # Cleanup
  if (Test-Path $reportPath) { Remove-Item $reportPath -Force -ErrorAction SilentlyContinue }
  Write-Host "[*] Diagnostic cleanup completed"
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
