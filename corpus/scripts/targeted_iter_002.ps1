# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_11b744c0-0dd8-4678-a5a8-b0d9a7ab9516  (1 rule(s)) ---------------------
# Intent:    Detect UAC bypass attempts via COM handler registry hijacking by modifying the m
# Rules:     11b744c0-0dd8-4678-a5a8-b0d9a7ab9516
# Archetype: IT admin workflow

$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

# Define paths for audit and remediation
$mscfilePath = 'HKLM:\SOFTWARE\Classes\mscfile\shell\open\command'
$backupFile = Join-Path $env:TEMP 'mscfile_backup.reg'
$auditLog = Join-Path $env:TEMP 'registry_audit.txt'

# Create audit directory structure
$auditDir = Join-Path $env:TEMP 'SecurityAudit'
if (-not (Test-Path $auditDir)) {
  New-Item -ItemType Directory -Path $auditDir -Force | Out-Null
}

# Export current mscfile handler for audit documentation
Write-Host "[*] Exporting current COM handler configuration..."
reg export 'HKEY_LOCAL_MACHINE\SOFTWARE\Classes\mscfile' $backupFile /y 2>&1 | Out-Null

if (Test-Path $backupFile) {
  Write-Host "[+] Handler configuration backed up to audit log"
  Get-Content $backupFile | Add-Content $auditLog
}

# Verify and document the default mscfile command handler
Write-Host "[*] Auditing mscfile shell handler registration..."
if (Test-Path $mscfilePath) {
  $defaultHandler = (Get-ItemProperty -Path $mscfilePath -Name '(Default)' -ErrorAction SilentlyContinue).'(Default)'
  Write-Host "[+] Default mscfile handler: $defaultHandler"
  Add-Content $auditLog "Audit Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
  Add-Content $auditLog "mscfile handler: $defaultHandler"
}

# Document all shell subkeys under mscfile
Write-Host "[*] Documenting mscfile shell subkey structure..."
$shellPath = 'HKLM:\SOFTWARE\Classes\mscfile\shell'
if (Test-Path $shellPath) {
  $subkeys = Get-ChildItem -Path $shellPath -ErrorAction SilentlyContinue
  foreach ($subkey in $subkeys) {
    Write-Host "[+] Found shell subkey: $($subkey.PSChildName)"
    Add-Content $auditLog "Shell subkey: $($subkey.PSChildName)"
  }
}

# Perform remediation: ensure mscfile command points to legitimate system binary
Write-Host "[*] Verifying legitimate mscfile handler assignment..."
$legitimateCommand = 'mmc.exe %1'
if (Test-Path $mscfilePath) {
  $currentCommand = (Get-ItemProperty -Path $mscfilePath -Name '(Default)' -ErrorAction SilentlyContinue).'(Default)'
  if ($currentCommand -ne $legitimateCommand) {
    Write-Host "[*] Remediating handler to legitimate value..."
    Set-ItemProperty -Path $mscfilePath -Name '(Default)' -Value $legitimateCommand -Force
    Write-Host "[+] Handler remediated"
    Add-Content $auditLog "Remediation: Updated mscfile handler to $legitimateCommand"
  } else {
    Write-Host "[+] Handler already points to legitimate tool"
  }
}

# Clean up backup and audit files
Write-Host "[*] Finalizing audit documentation..."
if (Test-Path $backupFile) {
  Remove-Item -Path $backupFile -Force
}

if (Test-Path $auditLog) {
  Remove-Item -Path $auditLog -Force
}

if (Test-Path $auditDir) {
  Remove-Item -Path $auditDir -Recurse -Force
}

Write-Host "[+] Registry audit and remediation completed"
Write-Host "[*] All temporary audit files cleaned up"

# -- Cluster: singleton_11b744c0-0dd8-4678-a5a8-b0d9a7ab9516  (1 rule(s)) ---------------------
# Intent:    Detect UAC bypass attempts via COM handler registry hijacking by modifying the m
# Rules:     11b744c0-0dd8-4678-a5a8-b0d9a7ab9516
# Archetype: Software installer/updater workflow

$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

# Simulate legitimate software package registration during deployment
$packageName = 'AdminConsoleTools'
$packageVersion = '2024.01'
$installRoot = Join-Path $env:ProgramFiles 'AdminTools'
$configPath = Join-Path $env:TEMP 'package_setup.ini'

# Create installation directory structure (simulating MSI deployment)
Write-Host "[*] Initializing package deployment for $packageName $packageVersion"
if (-not (Test-Path $installRoot)) {
  New-Item -ItemType Directory -Path $installRoot -Force | Out-Null
}

# Create placeholder executable for the management console tool
$toolPath = Join-Path $installRoot 'console.exe'
$toolStub = @'
REM This is a placeholder for the management console application
REM In real deployments, this would be the actual console binary
'@
$toolStub | Set-Content $toolPath -Force

# Write installation manifest
$manifest = @"
[InstallationInfo]
ProductName=$packageName
ProductVersion=$packageVersion
InstallPath=$installRoot
DeploymentDate=$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
InstallerType=MSI
"@
$manifest | Set-Content $configPath -Force

Write-Host "[+] Package deployment structure created"

# During software setup, register COM handlers for management console integration
Write-Host "[*] Registering COM handlers for management console support..."
$mscfilePath = 'HKLM:\SOFTWARE\Classes\mscfile\shell\open\command'

# Ensure parent key structure exists
$classesPath = 'HKLM:\SOFTWARE\Classes\mscfile'
if (-not (Test-Path $classesPath)) {
  New-Item -Path $classesPath -Force | Out-Null
}

if (-not (Test-Path $mscfilePath)) {
  New-Item -Path $mscfilePath -Force | Out-Null
}

# Set the legitimate mscfile handler during package deployment
$consoleCommand = '"mmc.exe" "%1"'
Write-Host "[*] Registering handler: $consoleCommand"
Set-ItemProperty -Path $mscfilePath -Name '(Default)' -Value $consoleCommand -Force

Write-Host "[+] COM handler registration completed"

# Document the deployment in package registry location
$pkgRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AdminConsoleTools_2024'
if (-not (Test-Path $pkgRegPath)) {
  New-Item -Path $pkgRegPath -Force | Out-Null
}

Set-ItemProperty -Path $pkgRegPath -Name 'DisplayName' -Value "$packageName $packageVersion" -Force
Set-ItemProperty -Path $pkgRegPath -Name 'InstallLocation' -Value $installRoot -Force
Set-ItemProperty -Path $pkgRegPath -Name 'Publisher' -Value 'IT Operations' -Force

Write-Host "[+] Deployment tracked in Windows Registry"

# Verify handler registration
Write-Host "[*] Verifying COM handler configuration..."
$verifyPath = 'HKLM:\SOFTWARE\Classes\mscfile\shell\open\command'
if (Test-Path $verifyPath) {
  $registeredHandler = (Get-ItemProperty -Path $verifyPath -Name '(Default)' -ErrorAction SilentlyContinue).'(Default)'
  Write-Host "[+] Handler verified: $registeredHandler"
}

# Clean up installation artifacts and registry entries
Write-Host "[*] Cleaning up deployment temporary files..."
if (Test-Path $configPath) {
  Remove-Item -Path $configPath -Force
}

if (Test-Path $toolPath) {
  Remove-Item -Path $toolPath -Force
}

if (Test-Path $installRoot) {
  Remove-Item -Path $installRoot -Recurse -Force
}

# Remove test registry entries
if (Test-Path $pkgRegPath) {
  Remove-Item -Path $pkgRegPath -Recurse -Force
}

Write-Host "[+] Package deployment and cleanup completed"
Write-Host "[*] Installation simulation finished"

# -- Cluster: singleton_11b744c0-0dd8-4678-a5a8-b0d9a7ab9516  (1 rule(s)) ---------------------
# Intent:    Detect UAC bypass attempts via COM handler registry hijacking by modifying the m
# Rules:     11b744c0-0dd8-4678-a5a8-b0d9a7ab9516
# Archetype: User-driven workflow

$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

# Simulate user installing an administrative utility that requires COM handler configuration
Write-Host "[*] User administrative tool installation initiated"

$toolName = 'RemoteManagementSnap'
$tempInstallDir = Join-Path $env:TEMP "${toolName}_setup"
$setupScript = Join-Path $tempInstallDir 'setup.ps1'

# Create temporary installation directory
if (-not (Test-Path $tempInstallDir)) {
  New-Item -ItemType Directory -Path $tempInstallDir -Force | Out-Null
}

Write-Host "[+] Installation workspace prepared"

# Generate setup script that registers the tool's COM components
$setupContent = @'
# Administrative tool setup - registers console snap-in
$toolPath = Join-Path $env:ProgramFiles "RemoteManagementSnap"

if (-not (Test-Path $toolPath)) {
  New-Item -ItemType Directory -Path $toolPath -Force | Out-Null
}

# Register mscfile handler for management console integration
$mscfilePath = "HKLM:\SOFTWARE\Classes\mscfile\shell\open\command"

if (-not (Test-Path $mscfilePath)) {
  New-Item -Path $mscfilePath -Force | Out-Null
}

$handlerCmd = '"mmc.exe" "%1"'
Set-ItemProperty -Path $mscfilePath -Name "(Default)" -Value $handlerCmd -Force

Write-Host "Tool registration complete"
'@

$setupContent | Set-Content $setupScript -Force
Write-Host "[+] Setup script generated"

# Execute the installation setup (requires administrative privileges)
Write-Host "[*] Executing administrative setup..."
try {
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $setupScript 2>&1 | Out-Null
  Write-Host "[+] Administrative setup executed successfully"
} catch {
  Write-Host "[-] Setup execution encountered an issue (expected in non-admin context)"
}

# Verify that COM handler was registered
Write-Host "[*] Verifying COM handler registration..."
$verifyPath = 'HKLM:\SOFTWARE\Classes\mscfile\shell\open\command'
if (Test-Path $verifyPath) {
  $handler = (Get-ItemProperty -Path $verifyPath -Name '(Default)' -ErrorAction SilentlyContinue).'(Default)'
  Write-Host "[+] COM handler is registered: $handler"
}

# Clean up installation artifacts
Write-Host "[*] Cleaning up installation files..."
if (Test-Path $setupScript) {
  Remove-Item -Path $setupScript -Force
}

if (Test-Path $tempInstallDir) {
  Remove-Item -Path $tempInstallDir -Recurse -Force
}

Write-Host "[+] Installation cleanup completed"
Write-Host "[*] Administrative tool setup process finished"


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
