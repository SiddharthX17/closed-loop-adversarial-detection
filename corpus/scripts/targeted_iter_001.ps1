# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   4  |  Feasible: 4  |  Variants: 11
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_75bd4163-dbe1-4628-b45e-3f6e45bd427b  (1 rule(s)) ---------------------
# Intent:    Execution of Windows Installer (msiexec.exe) to install packages from user-writa
# Rules:     75bd4163-dbe1-4628-b45e-3f6e45bd427b
# Archetype: Software installer/updater workflow

$AppDataDir = Join-Path $env:APPDATA 'VendorApp'
$MsiPath = Join-Path $AppDataDir 'installer.msi'

# Create staging directory for installer
if (-not (Test-Path $AppDataDir)) {
  New-Item -ItemType Directory -Path $AppDataDir -Force | Out-Null
}

# Create a minimal valid MSI file (empty MSI structure for benign testing)
# Real installers download this; we create a small test file
$MsiBytes = @(
  0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x3E, 0x00, 0x03, 0x00, 0xFE, 0xFF, 0x09, 0x00
)
[System.IO.File]::WriteAllBytes($MsiPath, $MsiBytes)

# Invoke msiexec with /i flag to install from APPDATA (legitimate staging location)
# Using /quiet to suppress UI in automated environment
try {
  & msiexec.exe /i $MsiPath /quiet /norestart 2>&1 | Out-Null
} catch {
  # Installer may fail validation (expected with test MSI), but the Sysmon event is generated
}

# Clean up staged installer
if (Test-Path $MsiPath) {
  Remove-Item -Path $MsiPath -Force
}

# Clean up staging directory if empty
if (Test-Path $AppDataDir) {
  Remove-Item -Path $AppDataDir -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_75bd4163-dbe1-4628-b45e-3f6e45bd427b  (1 rule(s)) ---------------------
# Intent:    Execution of Windows Installer (msiexec.exe) to install packages from user-writa
# Rules:     75bd4163-dbe1-4628-b45e-3f6e45bd427b
# Archetype: IT admin workflow

$StagingDir = Join-Path $env:ProgramData 'SoftwareStaging'
$MsiPath = Join-Path $StagingDir 'deployment_package.msi'

# Create staging directory for managed deployment
if (-not (Test-Path $StagingDir)) {
  New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null
}

# Create minimal MSI file structure
$MsiBytes = @(
  0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x3E, 0x00, 0x03, 0x00, 0xFE, 0xFF, 0x09, 0x00
)
[System.IO.File]::WriteAllBytes($MsiPath, $MsiBytes)

# Execute installer from shared staging directory
try {
  & msiexec.exe /i $MsiPath /quiet /norestart 2>&1 | Out-Null
} catch {
  # Installation may fail validation (expected), but Sysmon logs the execution
}

# Clean up deployment package
if (Test-Path $MsiPath) {
  Remove-Item -Path $MsiPath -Force
}

# Remove staging directory
if (Test-Path $StagingDir) {
  Remove-Item -Path $StagingDir -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_75bd4163-dbe1-4628-b45e-3f6e45bd427b  (1 rule(s)) ---------------------
# Intent:    Execution of Windows Installer (msiexec.exe) to install packages from user-writa
# Rules:     75bd4163-dbe1-4628-b45e-3f6e45bd427b
# Archetype: User-driven workflow

$DownloadsDir = Join-Path $env:USERPROFILE 'Downloads'
$MsiPath = Join-Path $DownloadsDir 'application.msi'

# Ensure Downloads directory exists
if (-not (Test-Path $DownloadsDir)) {
  New-Item -ItemType Directory -Path $DownloadsDir -Force | Out-Null
}

# Create minimal MSI file (simulating a downloaded installer)
$MsiBytes = @(
  0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x3E, 0x00, 0x03, 0x00, 0xFE, 0xFF, 0x09, 0x00
)
[System.IO.File]::WriteAllBytes($MsiPath, $MsiBytes)

# User runs installer from Downloads folder
try {
  & msiexec.exe /i $MsiPath /quiet /norestart 2>&1 | Out-Null
} catch {
  # Installation may fail, but the process execution is logged
}

# Clean up the installer file
if (Test-Path $MsiPath) {
  Remove-Item -Path $MsiPath -Force
}

# -- Cluster: singleton_8d8502dc-5cb2-44bb-9ffe-7f85651054b5  (1 rule(s)) ---------------------
# Intent:    Attacker modifying Internet Explorer zone trust settings to add untrusted domain
# Rules:     8d8502dc-5cb2-44bb-9ffe-7f85651054b5
# Archetype: IT admin workflow

$ErrorActionPreference = 'Stop'

# Define corporate intranet domains to be added to trusted zones
$intranetDomains = @(
    'internal.corp.local',
    'intranet.corp.local',
    'apps.corp.local'
)

# Registry path for IE Zone Map configuration
$zoneMapPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains'

try {
    # Ensure ZoneMap\Domains registry path exists
    if (-not (Test-Path $zoneMapPath)) {
        New-Item -Path $zoneMapPath -Force | Out-Null
    }

    # For each corporate domain, add registry entries for both Intranet (1) and Trusted Sites (2) zones
    foreach ($domain in $intranetDomains) {
        $domainPath = Join-Path $zoneMapPath $domain

        # Create domain subkey if it doesn't exist
        if (-not (Test-Path $domainPath)) {
            New-Item -Path $domainPath -Force | Out-Null
        }

        # Set http to Intranet zone (dword value 1)
        New-ItemProperty -Path $domainPath -Name 'http' -Value 1 -PropertyType DWord -Force | Out-Null

        # Set https to Trusted Sites zone (dword value 2)
        New-ItemProperty -Path $domainPath -Name 'https' -Value 2 -PropertyType DWord -Force | Out-Null
    }

    # Verify entries were created
    Get-Item $zoneMapPath | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
} catch {
    Write-Error "Error configuring IE trusted zones: $_"
}

# Cleanup: Remove the test registry entries added during this operation
try {
    foreach ($domain in $intranetDomains) {
        $domainPath = Join-Path $zoneMapPath $domain
        if (Test-Path $domainPath) {
            Remove-Item -Path $domainPath -Force -ErrorAction SilentlyContinue
        }
    }
} catch {
    Write-Error "Error cleaning up IE zone registry entries: $_"
}

# -- Cluster: singleton_8d8502dc-5cb2-44bb-9ffe-7f85651054b5  (1 rule(s)) ---------------------
# Intent:    Attacker modifying Internet Explorer zone trust settings to add untrusted domain
# Rules:     8d8502dc-5cb2-44bb-9ffe-7f85651054b5
# Archetype: Software installer/updater workflow

$ErrorActionPreference = 'Stop'

# Simulate enterprise application installer setting up IE trusted zones
$appDomain = 'businessapp.example.com'
$zoneMapPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains'

try {
    # Ensure the ZoneMap\Domains path exists
    if (-not (Test-Path $zoneMapPath)) {
        New-Item -Path $zoneMapPath -Force | Out-Null
    }

    # Create the application domain subkey
    $appDomainPath = Join-Path $zoneMapPath $appDomain
    if (-not (Test-Path $appDomainPath)) {
        New-Item -Path $appDomainPath -Force | Out-Null
    }

    # Installer configures both http and https for the application domain
    # Setting to Intranet zone (0x00000001) for initial compatibility
    New-ItemProperty -Path $appDomainPath -Name 'http' -Value 1 -PropertyType DWord -Force | Out-Null

    # Upgrade https to Trusted Sites zone (0x00000002) for enhanced functionality
    New-ItemProperty -Path $appDomainPath -Name 'https' -Value 2 -PropertyType DWord -Force | Out-Null

    Write-Host "Application installer configured IE trusted zones for: $appDomain"
} catch {
    Write-Error "Installer configuration error: $_"
}

# Cleanup: Remove installer-added registry configuration
try {
    $appDomainPath = Join-Path $zoneMapPath $appDomain
    if (Test-Path $appDomainPath) {
        Remove-Item -Path $appDomainPath -Force -ErrorAction SilentlyContinue
    }
} catch {
    Write-Error "Error cleaning up installer configuration: $_"
}

# -- Cluster: singleton_8d8502dc-5cb2-44bb-9ffe-7f85651054b5  (1 rule(s)) ---------------------
# Intent:    Attacker modifying Internet Explorer zone trust settings to add untrusted domain
# Rules:     8d8502dc-5cb2-44bb-9ffe-7f85651054b5
# Archetype: User-driven workflow

$ErrorActionPreference = 'Stop'

# Simulate user adding a trusted domain to IE after encountering repeated security warnings
$trustedDomain = 'partner-portal.company.net'
$zoneMapPath = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains'

try {
    # Ensure ZoneMap\Domains registry path exists
    if (-not (Test-Path $zoneMapPath)) {
        New-Item -Path $zoneMapPath -Force | Out-Null
    }

    # Create domain entry
    $domainPath = Join-Path $zoneMapPath $trustedDomain
    if (-not (Test-Path $domainPath)) {
        New-Item -Path $domainPath -Force | Out-Null
    }

    # Add http protocol as Intranet zone (0x00000001)
    New-ItemProperty -Path $domainPath -Name 'http' -Value 1 -PropertyType DWord -Force | Out-Null

    # Add https protocol as Trusted Sites zone (0x00000002)
    New-ItemProperty -Path $domainPath -Name 'https' -Value 2 -PropertyType DWord -Force | Out-Null

    # Verify the registry entries exist
    $registryEntries = Get-Item $domainPath
    Write-Host "Domain $trustedDomain has been added to trusted zones"

} catch {
    Write-Error "Error adding trusted domain: $_"
}

# Cleanup: Remove the added registry entries
try {
    $domainPath = Join-Path $zoneMapPath $trustedDomain
    if (Test-Path $domainPath) {
        Remove-Item -Path $domainPath -Force -ErrorAction SilentlyContinue
    }
} catch {
    Write-Error "Error removing trusted domain configuration: $_"
}

# -- Cluster: singleton_3d2d0f2a-5835-4d3f-8ff0-47ca1f01a753  (1 rule(s)) ---------------------
# Intent:    Detecting attempts to modify file type associations and script handlers, which i
# Rules:     3d2d0f2a-5835-4d3f-8ff0-47ca1f01a753
# Archetype: IT admin workflow

# File type association remediation audit
# IT admin verifies and repairs script handler associations after security incident

$associations = @(
    @{ext = '.vbs'; expectedHandler = 'VBSFile'},
    @{ext = '.js'; expectedHandler = 'JSFile'},
    @{ext = '.bat'; expectedHandler = 'batfile'},
    @{ext = '.cmd'; expectedHandler = 'cmdfile'}
)

# Check current associations and log findings
$auditLog = "$env:TEMP\assoc_audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
Add-Content -Path $auditLog -Value "File Type Association Audit - $(Get-Date)"
Add-Content -Path $auditLog -Value "="*60"

foreach ($item in $associations) {
    # Query current association
    $result = cmd /c "assoc $($item.ext)" 2>&1
    Add-Content -Path $auditLog -Value "Query: assoc $($item.ext)"
    Add-Content -Path $auditLog -Value "Result: $result"

    # Repair association if needed (restore to expected handler)
    cmd /c "assoc $($item.ext)=$($item.expectedHandler)" 2>&1 | Out-Null
    Add-Content -Path $auditLog -Value "Repaired to: $($item.expectedHandler)"
    Add-Content -Path $auditLog -Value ""
}

# Verify script execution handler configuration
Add-Content -Path $auditLog -Value "Script Handler Verification"
Add-Content -Path $auditLog -Value "="*60"

$handlers = @('VBSFile', 'JSFile')
foreach ($handler in $handlers) {
    $cmd = "ftype $handler"
    $output = cmd /c $cmd 2>&1
    Add-Content -Path $auditLog -Value "$cmd = $output"
}

# Document completion
Add-Content -Path $auditLog -Value ""
Add-Content -Path $auditLog -Value "Audit completed: $(Get-Date)"

# Clean up audit log
Remove-Item -Path $auditLog -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_3d2d0f2a-5835-4d3f-8ff0-47ca1f01a753  (1 rule(s)) ---------------------
# Intent:    Detecting attempts to modify file type associations and script handlers, which i
# Rules:     3d2d0f2a-5835-4d3f-8ff0-47ca1f01a753
# Archetype: Software installer/updater workflow

# Software installer: document viewer setup
# Configures file type associations during installation

# Simulate application installer registration of file handlers
$installerLog = "$env:TEMP\installer_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Add-Content -Path $installerLog -Value "Application Installation Log"
Add-Content -Path $installerLog -Value "Started: $(Get-Date)"
Add-Content -Path $installerLog -Value ""

# Register document viewer for common formats
$fileTypes = @(
    @{ext = '.rtf'; handler = 'rtffile'},
    @{ext = '.xml'; handler = 'xmlfile'}
)

foreach ($ft in $fileTypes) {
    # Register the file type with the application
    Add-Content -Path $installerLog -Value "Registering handler for $($ft.ext)"

    # Set file association using ftype (standard installer pattern)
    $ftypeCmd = "ftype $($ft.handler)=notepad.exe \"%%1\""
    cmd /c $ftypeCmd 2>&1 | Out-Null

    # Associate extension with handler using assoc
    $assocCmd = "assoc $($ft.ext)=$($ft.handler)"
    cmd /c $assocCmd 2>&1 | Out-Null

    Add-Content -Path $installerLog -Value "  Handler registration complete"
}

# Verify installations
Add-Content -Path $installerLog -Value ""
Add-Content -Path $installerLog -Value "Verification:"

foreach ($ft in $fileTypes) {
    $verify = cmd /c "assoc $($ft.ext)" 2>&1
    Add-Content -Path $installerLog -Value "  $($ft.ext) -> $verify"
}

Add-Content -Path $installerLog -Value ""
Add-Content -Path $installerLog -Value "Installation completed: $(Get-Date)"

# Clean up
Remove-Item -Path $installerLog -Force -ErrorAction SilentlyContinue

# SKIPPED variant 'User-driven workflow': blocked pattern: cmd batch syntax ('goto ')

# -- Cluster: singleton_a4ffd403-3534-4421-92d0-5c95d8abbe3e  (1 rule(s)) ---------------------
# Intent:    Detect adversaries creating or modifying Windows services using sc.exe with the 
# Rules:     a4ffd403-3534-4421-92d0-5c95d8abbe3e
# Archetype: IT admin workflow

$serviceName = 'EventLogMonitor'
$tempDir = [System.IO.Path]::GetTempPath()
$serviceDesc = 'Enterprise event log monitoring service for compliance and security auditing'

try {
    # Simulate administrator creating a service wrapper for event log collection
    # This is legitimate infrastructure tooling that uses sc.exe to manage services
    $logPath = Join-Path $tempDir 'eventlog_export.txt'

    # Create a simple PowerShell wrapper script that will be the service executable
    $wrapperScript = Join-Path $tempDir 'LogMonitor.ps1'
    $wrapperContent = @'
while ($true) {
    Get-EventLog -LogName System -Newest 100 | Out-Null
    Start-Sleep -Seconds 300
}
'@
    Set-Content -Path $wrapperScript -Value $wrapperContent -Encoding ASCII

    # Use sc.exe to create a service with binPath pointing to PowerShell execution
    # This is a legitimate enterprise pattern: wrapping scripts as Windows services
    $binPath = 'cmd.exe /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + $wrapperScript + '"'
    cmd /c "sc.exe create $serviceName binPath= `"$binPath`" DisplayName= `"Event Log Monitor`" start= auto" 2>$null

    # Verify service was created
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        # Clean up: remove the service
        cmd /c "sc.exe delete $serviceName" 2>$null
    }

    # Clean up temporary files
    Remove-Item -Path $wrapperScript -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $logPath -Force -ErrorAction SilentlyContinue
}
catch {
    # Silently clean up on any error
    cmd /c "sc.exe delete $serviceName" 2>$null
    Remove-Item -Path (Join-Path $tempDir 'LogMonitor.ps1') -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_a4ffd403-3534-4421-92d0-5c95d8abbe3e  (1 rule(s)) ---------------------
# Intent:    Detect adversaries creating or modifying Windows services using sc.exe with the 
# Rules:     a4ffd403-3534-4421-92d0-5c95d8abbe3e
# Archetype: Software installer/updater workflow

$serviceName = 'BackupAgentSvc'
$tempDir = [System.IO.Path]::GetTempPath()

try {
    # Simulate a software installer registering a legitimate service
    # This pattern is common for backup agents, antivirus, and monitoring software
    $agentExePath = Join-Path $tempDir 'BackupAgent.exe'

    # Create a minimal executable stub (using certutil as a legitimate system tool)
    # In real installation scenarios, this would be the actual vendor binary
    cmd /c "copy /Y %SystemRoot%\System32\certutil.exe `"$agentExePath`"" 2>$null

    if (Test-Path $agentExePath) {
        # Use sc.exe to register the service with proper configuration
        # This mimics legitimate installer behavior
        $binPath = '"' + $agentExePath + '" --service-mode'
        cmd /c "sc.exe create $serviceName binPath= `"$binPath`" DisplayName= `"Backup Agent Service`" start= auto description= `"Automated backup and recovery service`"" 2>$null

        # Verify and clean up
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            cmd /c "sc.exe delete $serviceName" 2>$null
        }

        Remove-Item -Path $agentExePath -Force -ErrorAction SilentlyContinue
    }
}
catch {
    cmd /c "sc.exe delete $serviceName" 2>$null
    Remove-Item -Path (Join-Path $tempDir 'BackupAgent.exe') -Force -ErrorAction SilentlyContinue
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
