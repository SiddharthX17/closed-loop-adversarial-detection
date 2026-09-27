# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   4  |  Feasible: 4  |  Variants: 11
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_a0c34f6e-4fe7-4f74-a8e0-47dddf07a303  (1 rule(s)) ---------------------
# Intent:    Attackers attempt to extract the NTDS.dit file (Active Directory database) via c
# Rules:     a0c34f6e-4fe7-4f74-a8e0-47dddf07a303
# Archetype: IT admin workflow

$adminCheck = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($adminCheck)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Not running as administrator. Skipping ntdsutil validation."
    exit 0
}

# Legitimate AD health check workflow
$logPath = Join-Path $env:TEMP "ad_integrity_check_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

try {
    # Capture the ntdsutil help output which legitimately references ntds.dit
    & ntdsutil.exe help 2>&1 | Tee-Object -FilePath $logPath | Select-String -Pattern 'ntds\.dit|config|system' | Out-Null

    # Document the database location and expected configuration paths
    Write-Host "AD database diagnostics captured to $logPath"

    # Verify the log was created and contains expected NTDS references
    if (Test-Path $logPath) {
        $content = Get-Content $logPath -Raw
        if ($content -match 'ntds\.dit') {
            Write-Host "AD integrity check completed successfully"
        }
    }
}
finally {
    # Clean up diagnostic logs
    if (Test-Path $logPath) {
        Remove-Item -Path $logPath -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "AD maintenance workflow completed."

# -- Cluster: singleton_a0c34f6e-4fe7-4f74-a8e0-47dddf07a303  (1 rule(s)) ---------------------
# Intent:    Attackers attempt to extract the NTDS.dit file (Active Directory database) via c
# Rules:     a0c34f6e-4fe7-4f74-a8e0-47dddf07a303
# Archetype: Software installer/updater workflow

$adminCheck = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($adminCheck)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Not running as administrator. Skipping backup diagnostics."
    exit 0
}

# Legitimate system backup discovery workflow
$diagnosticLog = Join-Path $env:TEMP "backup_discovery_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

try {
    # Capture wbadmin status output which may reference system hives and NTDS context
    & wbadmin.exe get status 2>&1 | Tee-Object -FilePath $diagnosticLog | Out-Null

    # Parse backup history for any references to system state or registry backups
    if (Test-Path $diagnosticLog) {
        $status = Get-Content $diagnosticLog -Raw

        # Check if system state backups are configured (would include NTDS in domain controllers)
        if ($status -match 'system|registry|config') {
            Write-Host "System backup configuration validated"
        }
    }

    # Document backup location requirements for compliance
    $backupInventory = Join-Path $env:TEMP "backup_inventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

    # Query backup log which may contain references to system_hive and NTDS contexts
    wbadmin.exe get versions 2>&1 | Tee-Object -FilePath $backupInventory | Select-String -Pattern 'system|ntds' | Out-Null

    if (Test-Path $backupInventory) {
        Write-Host "Backup inventory documented"
    }
}
finally {
    # Clean up diagnostic files
    @($diagnosticLog, $backupInventory) | ForEach-Object {
        if (Test-Path $_) {
            Remove-Item -Path $_ -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Host "System backup diagnostic workflow completed."

# -- Cluster: singleton_85bfb341-e093-4e14-8882-68305c7ab78d  (1 rule(s)) ---------------------
# Intent:    Detect attackers using PowerShell remoting cmdlets (Invoke-Command, New-PSSessio
# Rules:     85bfb341-e093-4e14-8882-68305c7ab78d
# Archetype: IT admin workflow

$ServerList = @('localhost', 'localhost')
$Credentials = [System.Management.Automation.PSCredential]::new('LocalAdmin', (ConvertTo-SecureString -AsPlainText -Force 'TempPass123'))

foreach ($Server in $ServerList) {
  try {
    $Session = New-PSSession -ComputerName $Server -Credential $Credentials -ErrorAction SilentlyContinue
    if ($Session) {
      $Results = Invoke-Command -Session $Session -ScriptBlock {
        $env:COMPUTERNAME
        Get-Service -Name 'WinRM' | Select-Object -Property Status
      } -ErrorAction SilentlyContinue
      Remove-PSSession -Session $Session -ErrorAction SilentlyContinue
    }
  } catch {
  }
}

Enter-PSSession -ComputerName localhost -Credential $Credentials -ErrorAction SilentlyContinue | { exit }

# -- Cluster: singleton_85bfb341-e093-4e14-8882-68305c7ab78d  (1 rule(s)) ---------------------
# Intent:    Detect attackers using PowerShell remoting cmdlets (Invoke-Command, New-PSSessio
# Rules:     85bfb341-e093-4e14-8882-68305c7ab78d
# Archetype: Software installer/updater workflow

$RemoteNodes = @('localhost')
$DeploymentScriptPath = [System.IO.Path]::Combine($env:TEMP, 'deploy_update.ps1')

@'
# Configuration verification script
Write-Output 'Verifying deployment...'
if (Test-Path 'C:\\Program Files\\') {
  Get-ChildItem 'C:\\Program Files\\' -Directory -ErrorAction SilentlyContinue | Select-Object -First 3 | ForEach-Object { $_.Name }
}
'@ | Out-File -FilePath $DeploymentScriptPath -Encoding UTF8

foreach ($Node in $RemoteNodes) {
  try {
    $PSSession = New-PSSession -ComputerName $Node -ErrorAction SilentlyContinue
    if ($PSSession) {
      Invoke-Command -Session $PSSession -FilePath $DeploymentScriptPath -ErrorAction SilentlyContinue
      Remove-PSSession $PSSession -ErrorAction SilentlyContinue
    }
  } catch {
  }
}

if (Test-Path $DeploymentScriptPath) { Remove-Item $DeploymentScriptPath -Force -ErrorAction SilentlyContinue }

# -- Cluster: singleton_85bfb341-e093-4e14-8882-68305c7ab78d  (1 rule(s)) ---------------------
# Intent:    Detect attackers using PowerShell remoting cmdlets (Invoke-Command, New-PSSessio
# Rules:     85bfb341-e093-4e14-8882-68305c7ab78d
# Archetype: User-driven workflow

$RemoteHost = 'localhost'
$AdminCreds = [System.Management.Automation.PSCredential]::new('admin', (ConvertTo-SecureString -AsPlainText -Force 'P@ssw0rd'))

try {
  Enter-PSSession -ComputerName $RemoteHost -Credential $AdminCreds -ErrorAction SilentlyContinue
  Get-WindowsUpdate -ErrorAction SilentlyContinue
  Get-Process -Name 'svchost' -ErrorAction SilentlyContinue | Measure-Object
} catch {
}

$SessionCheck = New-PSSession -ComputerName $RemoteHost -ErrorAction SilentlyContinue
if ($SessionCheck) {
  Invoke-Command -Session $SessionCheck -ScriptBlock {
    Write-Output 'Remote session connected'
    Get-HotFix | Select-Object -Property InstalledOn -Last 5
  } -ErrorAction SilentlyContinue
  Remove-PSSession $SessionCheck -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_5a0f062a-9ca1-4ec6-ab97-a72c5b15daaa  (1 rule(s)) ---------------------
# Intent:    Detects when script interpreters (PowerShell, WSH, mshta, rundll32) are invoked 
# Rules:     5a0f062a-9ca1-4ec6-ab97-a72c5b15daaa
# Archetype: IT admin workflow

# Administrator performs system diagnostics via Run dialog invocation
# This simulates real Win+R usage patterns for script execution

$diagnosticsScript = @'
Write-Host "System Diagnostic Report"
Get-WindowsFeature | Where-Object {$_.Installed -eq $true} | Select-Object -First 10
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
Write-Host "OS Version: $($osInfo.Caption)"
'@

$scriptPath = Join-Path $env:TEMP "system_diagnostics.ps1"
Set-Content -Path $scriptPath -Value $diagnosticsScript -Encoding UTF8

# Simulate Run dialog execution by directly writing to RunMRU registry
# This is what explorer.exe does when a user types a command in Win+R
$runMruPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"

try {
    # Create the registry key path if needed
    if (-not (Test-Path $runMruPath)) {
        New-Item -Path $runMruPath -Force | Out-Null
    }

    # Write PowerShell invocation to RunMRU (mimics Win+R history)
    $runCommand = "powershell.exe -File `"$scriptPath`""
    Set-ItemProperty -Path $runMruPath -Name "a" -Value $runCommand -ErrorAction Stop

    # Execute the script to complete the workflow
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $scriptPath

    # Clean up registry entries
    Remove-ItemProperty -Path $runMruPath -Name "a" -ErrorAction SilentlyContinue
}
finally {
    # Clean up script file
    if (Test-Path $scriptPath) {
        Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_5a0f062a-9ca1-4ec6-ab97-a72c5b15daaa  (1 rule(s)) ---------------------
# Intent:    Detects when script interpreters (PowerShell, WSH, mshta, rundll32) are invoked 
# Rules:     5a0f062a-9ca1-4ec6-ab97-a72c5b15daaa
# Archetype: Software installer/updater workflow

# Software deployment scenario: installer uses mshta for HTML-based setup validation
# This simulates legitimate enterprise software packaging

$htmlSetup = @'
<html>
<head><title>Setup Validation</title></head>
<body>
<script>
WScript.Echo("Setup prerequisites validated");
</script>
</body>
</html>
'@

$htmlPath = Join-Path $env:TEMP "setup_validation.hta"
Set-Content -Path $htmlPath -Value $htmlSetup -Encoding UTF8

$runMruPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"

try {
    # Create registry path if needed
    if (-not (Test-Path $runMruPath)) {
        New-Item -Path $runMruPath -Force | Out-Null
    }

    # Record mshta invocation in RunMRU as would occur via Win+R
    $mshtaCommand = "mshta.exe `"$htmlPath`""
    Set-ItemProperty -Path $runMruPath -Name "b" -Value $mshtaCommand -ErrorAction Stop

    # Execute mshta to complete installer workflow
    & mshta.exe "$htmlPath" 2>$null

    # Clean up registry
    Remove-ItemProperty -Path $runMruPath -Name "b" -ErrorAction SilentlyContinue
}
finally {
    # Clean up HTML file
    if (Test-Path $htmlPath) {
        Remove-Item -Path $htmlPath -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_5a0f062a-9ca1-4ec6-ab97-a72c5b15daaa  (1 rule(s)) ---------------------
# Intent:    Detects when script interpreters (PowerShell, WSH, mshta, rundll32) are invoked 
# Rules:     5a0f062a-9ca1-4ec6-ab97-a72c5b15daaa
# Archetype: User-driven workflow

# User runs WSH script through Run dialog for local system configuration
# This simulates legitimate end-user automation task execution

$vbScript = @'
WScript.Echo "Configuration check initiated"
Set objShell = CreateObject("WScript.Shell")
objShell.Popup "System configuration validated", 2, "Status"
WScript.Quit 0
'@

$vbsPath = Join-Path $env:TEMP "config_check.vbs"
Set-Content -Path $vbsPath -Value $vbScript -Encoding UTF8

$runMruPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"

try {
    # Ensure registry path exists
    if (-not (Test-Path $runMruPath)) {
        New-Item -Path $runMruPath -Force | Out-Null
    }

    # Log cscript execution as it would appear in RunMRU from Win+R
    $cscriptCommand = "cscript.exe `"$vbsPath`""
    Set-ItemProperty -Path $runMruPath -Name "c" -Value $cscriptCommand -ErrorAction Stop

    # Execute the VBScript
    & cscript.exe "$vbsPath" //Nologo 2>$null

    # Clean up registry entry
    Remove-ItemProperty -Path $runMruPath -Name "c" -ErrorAction SilentlyContinue
}
finally {
    # Clean up script file
    if (Test-Path $vbsPath) {
        Remove-Item -Path $vbsPath -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_f509be03-df3a-419a-b5fb-7130ed238041  (1 rule(s)) ---------------------
# Intent:    Detect living-off-the-land binary (LOLBin) downloads via HTTP(S) using built-in 
# Rules:     f509be03-df3a-419a-b5fb-7130ed238041
# Archetype: IT admin workflow

# IT admin downloading and installing a legitimate software package via certutil
# Common scenario: deploying standardized tools across a fleet of machines

$msiPath = "$env:TEMP\VCRedist2022.msi"
$msiUrl = "https://download.visualstudio.microsoft.com/download/pr/1234567/vcredist.msi"

try {
    # Use certutil to cache and download the MSI package from a legitimate vendor site
    # certutil is preferred in some environments for checksums and retry logic
    Write-Host "Downloading package via certutil..."
    & certutil.exe -urlcache -split -f $msiUrl $msiPath

    # Verify the file was downloaded successfully
    if (Test-Path $msiPath) {
        Write-Host "Package downloaded successfully: $msiPath"

        # Install silently with no user interaction (/qn) and no restart (/norestart)
        # This is standard for unattended deployment in CI/CD and enterprise environments
        Write-Host "Installing package silently..."
        & msiexec /i $msiPath /qn /norestart /l*v "$env:TEMP\install_log.txt"

        # Wait for installation to complete
        Start-Sleep -Seconds 5

        Write-Host "Installation completed"
    } else {
        Write-Host "Failed to download package"
    }
}
finally {
    # Clean up the MSI file and installation log
    if (Test-Path $msiPath) {
        Remove-Item $msiPath -Force
    }
    if (Test-Path "$env:TEMP\install_log.txt") {
        Remove-Item "$env:TEMP\install_log.txt" -Force
    }
}

# -- Cluster: singleton_f509be03-df3a-419a-b5fb-7130ed238041  (1 rule(s)) ---------------------
# Intent:    Detect living-off-the-land binary (LOLBin) downloads via HTTP(S) using built-in 
# Rules:     f509be03-df3a-419a-b5fb-7130ed238041
# Archetype: Software installer/updater workflow

# Software update manager checking for patches via WinHttpRequest (rundll32 COM invocation)
# Realistic scenario: automated update client fetching and installing patches

$vbScriptPath = "$env:TEMP\check_updates.vbs"
$msiPath = "$env:TEMP\SecurityPatch.msi"

try {
    # Create a VBScript that uses WinHttpRequest through rundll32
    # This is how legacy update clients often check for new versions
    $vbScript = @'
Dim http
Set http = CreateObject("WinHttp.WinHttpRequest.5.1")
http.Open "GET", "https://updates.example.com/security/latest.msi", False
http.Send
If http.Status = 200 Then
    Set fso = CreateObject("Scripting.FileSystemObject")
    Set file = fso.CreateTextFile("' + $msiPath + '", True)
    file.Write http.ResponseBody
    file.Close
End If
'@

    $vbScript | Out-File -FilePath $vbScriptPath -Encoding ASCII

    # Execute the VBScript via cscript
    Write-Host "Checking for software updates via WinHttpRequest..."
    & cscript.exe //NoLogo $vbScriptPath

    # Simulate successful download by creating the MSI file
    # In real scenarios, the VBScript would download from the actual update server
    if (-not (Test-Path $msiPath)) {
        New-Item -Path $msiPath -ItemType File -Force | Out-Null
    }

    # If update package is available, install it silently
    if (Test-Path $msiPath) {
        Write-Host "Update package available, installing silently..."
        # Use /quiet for silent installation with progress bar (enterprise standard)
        & msiexec /i $msiPath /quiet /norestart ALLUSERS=1
        Start-Sleep -Seconds 3
    }
}
finally {
    # Clean up temporary files
    @($vbScriptPath, $msiPath) | ForEach-Object {
        if (Test-Path $_) {
            Remove-Item $_ -Force
        }
    }
}

# SKIPPED variant 'User-driven workflow': blocked pattern: hidden window ('-windowstyle hidden')


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
