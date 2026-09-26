# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   4  |  Feasible: 4  |  Variants: 10
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_492f4bf6-4c5a-4f29-8d10-23de4501622d  (1 rule(s)) ---------------------
# Intent:    Detect Windows service creation with custom binary path specifications via sc.ex
# Rules:     492f4bf6-4c5a-4f29-8d10-23de4501622d
# Archetype: IT admin workflow

$serviceName = 'MonitoringAgent'
$binPath = Join-Path $env:ProgramFiles 'MonitoringAgent\agent.exe'
$tempDir = Join-Path $env:TEMP 'ma_install_tmp'
New-Item -ItemType Directory -Path $tempDir -ErrorAction SilentlyContinue | Out-Null
try {
    # Create a mock monitoring agent executable
    $agentPath = Join-Path $tempDir 'agent.exe'
    Copy-Item -Path $env:SystemRoot\System32\notepad.exe -Destination $agentPath -Force

    # Create Program Files subdirectory structure
    $programFilesDir = Join-Path $env:ProgramFiles 'MonitoringAgent'
    New-Item -ItemType Directory -Path $programFilesDir -ErrorAction SilentlyContinue | Out-Null

    # Deploy the agent binary
    Copy-Item -Path $agentPath -Destination $binPath -Force

    # Administrator creates the service with sc.exe specifying the binary path
    $scArgs = @('create', $serviceName, "binPath=$binPath")
    & sc.exe @scArgs | Out-Null

    # Verify service was created
    Get-Service -Name $serviceName -ErrorAction SilentlyContinue | Out-Null
} finally {
    # Cleanup: remove service and binaries
    & sc.exe delete $serviceName 2>$null
    $programFilesDir = Join-Path $env:ProgramFiles 'MonitoringAgent'
    if (Test-Path $programFilesDir) { Remove-Item -Path $programFilesDir -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $tempDir) { Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue }
}

# -- Cluster: singleton_492f4bf6-4c5a-4f29-8d10-23de4501622d  (1 rule(s)) ---------------------
# Intent:    Detect Windows service creation with custom binary path specifications via sc.ex
# Rules:     492f4bf6-4c5a-4f29-8d10-23de4501622d
# Archetype: Software installer/updater workflow

$serviceName = 'EnterpriseSync'
$programFilesDir = Join-Path $env:ProgramFiles 'EnterpriseSyncSvc'
$tempMsiDir = Join-Path $env:TEMP 'msi_installer_tmp'
New-Item -ItemType Directory -Path $tempMsiDir -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType Directory -Path $programFilesDir -ErrorAction SilentlyContinue | Out-Null

try {
    # Create a dummy service binary to deploy
    $serviceBinary = Join-Path $programFilesDir 'sync.exe'
    Copy-Item -Path $env:SystemRoot\System32\svchost.exe -Destination $serviceBinary -Force

    # Simulate MSI installer custom action that calls sc.exe to register service
    # This represents actual MSI behavior during enterprise software deployment
    $installScript = Join-Path $tempMsiDir 'install_action.ps1'
    $serviceConfig = "binPath=$serviceBinary"
    Add-Content -Path $installScript -Value "& sc.exe create $serviceName $serviceConfig"

    # Execute installation script (representing custom action execution)
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $installScript

    # Verify service exists
    $svcTest = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($svcTest) { Write-Host 'Service registered' }
} finally {
    # Cleanup: remove service and installation artifacts
    & sc.exe delete $serviceName 2>$null
    if (Test-Path $programFilesDir) { Remove-Item -Path $programFilesDir -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $tempMsiDir) { Remove-Item -Path $tempMsiDir -Recurse -Force -ErrorAction SilentlyContinue }
}

# -- Cluster: singleton_6b623cb7-8185-495a-8286-fc84fe5defc4  (1 rule(s)) ---------------------
# Intent:    Attackers running ntdsutil.exe or wbadmin.exe with command lines referencing NTD
# Rules:     6b623cb7-8185-495a-8286-fc84fe5defc4
# Archetype: IT admin workflow

$ErrorActionPreference = 'SilentlyContinue'

# Simulate legitimate AD database maintenance workflow
# ntdsutil.exe is commonly invoked by sysadmins to inspect NTDS.dit metadata

$ntdsPath = 'C:\\Windows\\ntds'
$ntdsFile = Join-Path $ntdsPath 'ntds.dit'

# Check if running on a domain controller (NTDS.dit would exist)
if (Test-Path $ntdsFile) {
    Write-Host '[+] Detected NTDS.dit - performing database diagnostics'

    # Use ntdsutil.exe to invoke legitimate diagnostic modes
    # These command sequences are standard for DC maintenance
    @'
activate instance ntds
fail
quit
quit
'@ | cmd /c 'ntdsutil.exe' 2>&1 | Out-Null

    # Query NTDS properties via command line
    $queryScript = @'
activate instance ntds
db
integ
quit
quit
'@
    $queryScript | cmd /c 'ntdsutil.exe' 2>&1 | Out-Null

    Write-Host '[+] NTDS diagnostics completed'
}

# Simulate legitimate registry inspection for system hive backup verification
# Administrators periodically validate that system hive backups are accessible
$systemHivePath = 'HKLM:\\SYSTEM'

try {
    $systemHiveTest = Get-Item -Path $systemHivePath -ErrorAction Stop
    Write-Host '[+] System registry hive accessibility verified'
} catch {
    Write-Host '[!] System hive not accessible'
}

# Simulate wbadmin listing backup metadata that references both NTDS and system state
# This is normal operational querying of backup catalog
if ((cmd /c 'where.exe wbadmin' 2>$null)) {
    Write-Host '[+] Checking Windows Backup status'
    cmd /c 'wbadmin get versions' 2>&1 | Out-Null
    cmd /c 'wbadmin get items -version:01/20/2024-15:30' 2>&1 | Out-Null
}

Write-Host '[+] System maintenance diagnostics completed'

# -- Cluster: singleton_6b623cb7-8185-495a-8286-fc84fe5defc4  (1 rule(s)) ---------------------
# Intent:    Attackers running ntdsutil.exe or wbadmin.exe with command lines referencing NTD
# Rules:     6b623cb7-8185-495a-8286-fc84fe5defc4
# Archetype: Software installer/updater workflow

$ErrorActionPreference = 'SilentlyContinue'

# Pre-patch validation workflow
# Enterprise patch and compliance tools verify backup integrity before system updates

Write-Host '[*] Starting pre-patch backup validation'

# Simulate a patch deployment tool validating backup inclusion
$backupValidationScript = @'
echo Validating backup profile for critical system state...
wbadmin get versions
echo Checking NTDS database backup status...
wbadmin get items -version:01/20/2024-15:30
echo Validation complete
'@

$backupValidationScript | cmd /c 2>&1 | Out-Null

# Simulate compliance checker looking for NTDS backup inclusion
Write-Host '[*] Compliance check: NTDS database backup inclusion'

$ntdsBackupCheck = @'
activate instance ntds
db
integ
quit
quit
'@

$ntdsBackupCheck | cmd /c 'ntdsutil.exe' 2>&1 | Out-Null

# Verify system hive is backed up (required for bare-metal recovery)
Write-Host '[*] Verifying system hive backup state'

$systemHivePath = 'C:\\Windows\\System32\\config\\system'
if (Test-Path $systemHivePath) {
    Write-Host '[+] System hive present at expected location'

    # Query backup tool for system hive inclusion
    cmd /c 'wbadmin get items -version:01/20/2024-15:30' 2>&1 | Out-Null
}

# Simulate Windows Update preparation that validates recovery tools
Write-Host '[*] Pre-patch readiness: testing backup recovery availability'

$recoveryCheckScript = @'
wbadmin get versions
echo Recovery validation completed
'@

$recoveryCheckScript | cmd /c 2>&1 | Out-Null

Write-Host '[+] Pre-patch validation workflow completed'

# -- Cluster: singleton_2f12a30f-52e8-439f-8615-5fe49b15e280  (1 rule(s)) ---------------------
# Intent:    Detect execution of system utilities that have been renamed or spoofed via PE me
# Rules:     2f12a30f-52e8-439f-8615-5fe49b15e280
# Archetype: IT admin workflow

# IT admin copying system tools to a working directory for isolated diagnostics
$workDir = Join-Path $env:TEMP 'diag_20240115'
New-Item -ItemType Directory -Path $workDir -Force | Out-Null

try {
    # Copy legitimate system utilities to working directory for isolated analysis
    Copy-Item -Path 'C:\Windows\System32\cmd.exe' -Destination (Join-Path $workDir 'cmd.exe') -Force
    Copy-Item -Path 'C:\Windows\System32\powershell.exe' -Destination (Join-Path $workDir 'powershell.exe') -Force
    Copy-Item -Path 'C:\Windows\System32\certutil.exe' -Destination (Join-Path $workDir 'certutil.exe') -Force
    Copy-Item -Path 'C:\Windows\System32\rundll32.exe' -Destination (Join-Path $workDir 'rundll32.exe') -Force

    # Execute copied tools to verify they function correctly in isolated context
    # Administrator needs to verify diagnostic tools work from alternate location
    & (Join-Path $workDir 'cmd.exe') /c 'echo System diagnostic check' > $null
    & (Join-Path $workDir 'powershell.exe') -NoProfile -Command 'Write-Host "Diagnostic verification"' > $null

    # Verify certutil can list certificate store (common admin diagnostic)
    & (Join-Path $workDir 'certutil.exe') -silent -verifyctl > $null 2>&1

    # Verify rundll32 can list loaded modules (system health check)
    & (Join-Path $workDir 'rundll32.exe') shell32.dll,ShellAbout > $null 2>&1
}
finally {
    # Clean up working directory
    Remove-Item -Path $workDir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_2f12a30f-52e8-439f-8615-5fe49b15e280  (1 rule(s)) ---------------------
# Intent:    Detect execution of system utilities that have been renamed or spoofed via PE me
# Rules:     2f12a30f-52e8-439f-8615-5fe49b15e280
# Archetype: Software installer/updater workflow

# Software installer extracting and verifying system dependencies
$installTemp = Join-Path $env:TEMP 'InstallVerify_runtime'
New-Item -ItemType Directory -Path $installTemp -Force | Out-Null

try {
    # Installer extracts copies of common system utilities for dependency verification
    Copy-Item -Path 'C:\Windows\System32\powershell.exe' -Destination (Join-Path $installTemp 'powershell.exe') -Force
    Copy-Item -Path 'C:\Windows\System32\wscript.exe' -Destination (Join-Path $installTemp 'wscript.exe') -Force
    Copy-Item -Path 'C:\Windows\System32\cscript.exe' -Destination (Join-Path $installTemp 'cscript.exe') -Force
    Copy-Item -Path 'C:\Windows\System32\regsvr32.exe' -Destination (Join-Path $installTemp 'regsvr32.exe') -Force
    Copy-Item -Path 'C:\Windows\System32\mshta.exe' -Destination (Join-Path $installTemp 'mshta.exe') -Force

    # Pre-flight checks: verify PowerShell functionality
    & (Join-Path $installTemp 'powershell.exe') -NoProfile -Command '[Environment]::OSVersion.VersionString' | Out-Null

    # Verify scripting host availability
    & (Join-Path $installTemp 'wscript.exe') -version > $null 2>&1
    & (Join-Path $installTemp 'cscript.exe') -version > $null 2>&1

    # Verify COM registration tools work
    & (Join-Path $installTemp 'regsvr32.exe') /n /i /s oleaut32.dll > $null 2>&1

    # Verify HTML Application support
    & (Join-Path $installTemp 'mshta.exe') about: > $null 2>&1
}
finally {
    # Clean up installer temporary directory
    Remove-Item -Path $installTemp -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_2f12a30f-52e8-439f-8615-5fe49b15e280  (1 rule(s)) ---------------------
# Intent:    Detect execution of system utilities that have been renamed or spoofed via PE me
# Rules:     2f12a30f-52e8-439f-8615-5fe49b15e280
# Archetype: User-driven workflow

# Portable/USB-based utilities deployed from network share or removable media
$portableDir = Join-Path $env:TEMP 'PortableTools'
New-Item -ItemType Directory -Path $portableDir -Force | Out-Null

try {
    # User/administrator has deployed portable copies of utilities on network share
    Copy-Item -Path 'C:\Windows\System32\cmd.exe' -Destination (Join-Path $portableDir 'cmd.exe') -Force
    Copy-Item -Path 'C:\Windows\System32\powershell.exe' -Destination (Join-Path $portableDir 'powershell.exe') -Force
    Copy-Item -Path 'C:\Windows\System32\certutil.exe' -Destination (Join-Path $portableDir 'certutil.exe') -Force
    Copy-Item -Path 'C:\Windows\System32\rundll32.exe' -Destination (Join-Path $portableDir 'rundll32.exe') -Force

    # User runs utilities from portable location
    $cmdPath = Join-Path $portableDir 'cmd.exe'
    $psPath = Join-Path $portableDir 'powershell.exe'
    $certPath = Join-Path $portableDir 'certutil.exe'
    $rundllPath = Join-Path $portableDir 'rundll32.exe'

    # Execute portable cmd for system information gathering
    & $cmdPath /c 'systeminfo' | Out-Null

    # Execute portable PowerShell for configuration audit
    & $psPath -NoProfile -Command 'Get-ComputerInfo' | Out-Null

    # Execute portable certutil for certificate backup
    & $certPath -silent -backup -f 'C:\Windows\Temp\cert_backup.sst' > $null 2>&1

    # Execute portable rundll32 for shell operations
    & $rundllPath shell32.dll,ShellAbout > $null 2>&1

    # Clean up certificate backup
    Remove-Item -Path 'C:\Windows\Temp\cert_backup.sst' -Force -ErrorAction SilentlyContinue
}
finally {
    # Clean up portable tools directory
    Remove-Item -Path $portableDir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_36117427-aafe-4292-ba43-6b0b67e0592e  (1 rule(s)) ---------------------
# Intent:    Dumping LSA secrets and sensitive security policy data from the registry using r
# Rules:     36117427-aafe-4292-ba43-6b0b67e0592e
# Archetype: IT admin workflow

# Legitimate scenario: backup security registry hive before applying policy changes
# IT administrators routinely export registry hives for configuration management and disaster recovery

$backupDir = Join-Path -Path $env:TEMP -ChildPath "registry_backup_$(Get-Random)"
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

try {
    # Export the SECURITY hive as part of system policy backup procedure
    # This is a standard practice before major policy deployments
    $securityBackup = Join-Path -Path $backupDir -ChildPath "SECURITY.reg"
    & reg.exe save "HKLM\SECURITY" $securityBackup /y 2>&1 | Out-Null

    # Export the POLICY hive
    $policyBackup = Join-Path -Path $backupDir -ChildPath "POLICY.reg"
    & reg.exe save "HKLM\SECURITY\Policy" $policyBackup /y 2>&1 | Out-Null

    # Verify the exports completed
    if ((Test-Path $securityBackup) -and (Test-Path $policyBackup)) {
        Write-Host "Registry backup completed successfully"
    }
}
finally {
    # Clean up the backup directory
    Remove-Item -Path $backupDir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_36117427-aafe-4292-ba43-6b0b67e0592e  (1 rule(s)) ---------------------
# Intent:    Dumping LSA secrets and sensitive security policy data from the registry using r
# Rules:     36117427-aafe-4292-ba43-6b0b67e0592e
# Archetype: Software installer/updater workflow

# Legitimate scenario: compliance monitoring tool capturing security baseline
# Enterprise security and compliance tools routinely export registry hives to verify
# system state against policy baselines

$complianceDir = Join-Path -Path $env:TEMP -ChildPath "compliance_check_$(Get-Random)"
New-Item -ItemType Directory -Path $complianceDir -Force | Out-Null

try {
    # System compliance tool captures security policy configuration
    # for audit and baseline verification purposes
    $policyExport = Join-Path -Path $complianceDir -ChildPath "security_policy.reg"
    & reg.exe save "HKLM\SECURITY\Policy\Secrets" $policyExport /y 2>&1 | Out-Null

    # Capture password policy settings for compliance report
    $passwordPolicy = Join-Path -Path $complianceDir -ChildPath "password_policy.reg"
    & reg.exe save "HKLM\SECURITY\Policy\PolAdtEv" $passwordPolicy /y 2>&1 | Out-Null

    # Simulate compliance tool processing the exported data
    if ((Test-Path $policyExport) -and (Test-Path $passwordPolicy)) {
        $fileCount = @(Get-ChildItem -Path $complianceDir -File).Count
        Write-Host "Captured $fileCount policy artifacts for compliance baseline"
    }
}
finally {
    # Clean up exported data
    Remove-Item -Path $complianceDir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_36117427-aafe-4292-ba43-6b0b67e0592e  (1 rule(s)) ---------------------
# Intent:    Dumping LSA secrets and sensitive security policy data from the registry using r
# Rules:     36117427-aafe-4292-ba43-6b0b67e0592e
# Archetype: Document/file operation workflow

# Legitimate scenario: system diagnostics collection for support/troubleshooting
# IT support routinely collects registry exports as part of diagnostic bundles
# to help troubleshoot security policy or authentication issues

$diagnosticsDir = Join-Path -Path $env:TEMP -ChildPath "diag_bundle_$(Get-Random)"
New-Item -ItemType Directory -Path $diagnosticsDir -Force | Out-Null

try {
    # Create subdirectory for registry exports
    $regExportDir = Join-Path -Path $diagnosticsDir -ChildPath "registry_exports"
    New-Item -ItemType Directory -Path $regExportDir -Force | Out-Null

    # Export security hive for diagnostics troubleshooting
    $securityExport = Join-Path -Path $regExportDir -ChildPath "SECURITY.hive"
    & reg.exe save "HKLM\SECURITY" $securityExport /y 2>&1 | Out-Null

    # Export security policies for diagnosis
    $policiesExport = Join-Path -Path $regExportDir -ChildPath "POLICY.hive"
    & reg.exe save "HKLM\SECURITY\Policy" $policiesExport /y 2>&1 | Out-Null

    # Create summary of captured diagnostics
    $summaryFile = Join-Path -Path $diagnosticsDir -ChildPath "README.txt"
    @"System Diagnostics Bundle
Created: $(Get-Date)
Contents: Registry exports for security policy troubleshooting
"@ | Out-File -FilePath $summaryFile -Encoding ASCII

    Write-Host "Diagnostic bundle created with system configuration snapshots"
}
finally {
    # Remove diagnostic bundle
    Remove-Item -Path $diagnosticsDir -Recurse -Force -ErrorAction SilentlyContinue
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
