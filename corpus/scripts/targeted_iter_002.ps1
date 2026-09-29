# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   2  |  Feasible: 2  |  Variants: 6
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_4a268db0-5a4c-4bcd-9795-2232ec4af6e6  (1 rule(s)) ---------------------
# Intent:    Detect modifications to Windows Firewall network profile category settings in th
# Rules:     4a268db0-5a4c-4bcd-9795-2232ec4af6e6
# Archetype: IT admin workflow

$ErrorActionPreference = 'SilentlyContinue'

# Enumerate existing network profiles from registry
$profilePath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'

if (Test-Path $profilePath) {
    $profiles = Get-ChildItem -Path $profilePath

    foreach ($profile in $profiles) {
        $profileGuid = $profile.PSChildName
        $categoryPath = "$profilePath\$profileGuid\Category"

        # Check if profile exists
        if (Test-Path "$profilePath\$profileGuid") {
            # Read current category value
            $currentCategory = Get-ItemProperty -Path "$profilePath\$profileGuid" -Name 'Category' -ErrorAction SilentlyContinue

            # Update category to Public (0) as part of audit
            Set-ItemProperty -Path "$profilePath\$profileGuid" -Name 'Category' -Value 0 -Force

            Start-Sleep -Milliseconds 100

            # Verify the change
            $newCategory = Get-ItemProperty -Path "$profilePath\$profileGuid" -Name 'Category'
        }
    }
}

# Enumerate network signatures to audit network categorization
$signaturespath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures'
if (Test-Path $signaturespath) {
    $signatures = Get-ChildItem -Path $signaturespath -ErrorAction SilentlyContinue
    foreach ($sig in $signatures) {
        $profileGuid = $sig.PSChildName
        $sigPath = "$signaturespath\$profileGuid"

        # Update category to Private (1) for authenticated networks
        if (Test-Path $sigPath) {
            Set-ItemProperty -Path $sigPath -Name 'Category' -Value 1 -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 100
        }
    }
}

# Reset categories to default Public (0) to restore baseline
$profilePath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
if (Test-Path $profilePath) {
    $profiles = Get-ChildItem -Path $profilePath -ErrorAction SilentlyContinue
    foreach ($profile in $profiles) {
        $profileGuid = $profile.PSChildName
        Set-ItemProperty -Path "$profilePath\$profileGuid" -Name 'Category' -Value 0 -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_4a268db0-5a4c-4bcd-9795-2232ec4af6e6  (1 rule(s)) ---------------------
# Intent:    Detect modifications to Windows Firewall network profile category settings in th
# Rules:     4a268db0-5a4c-4bcd-9795-2232ec4af6e6
# Archetype: Software installer/updater workflow

$ErrorActionPreference = 'SilentlyContinue'

# Simulate network profile categorization during software provisioning
$baseProfilePath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList'

# Verify Profiles registry structure exists
if (-not (Test-Path "$baseProfilePath\Profiles")) {
    New-Item -Path "$baseProfilePath\Profiles" -Force | Out-Null
}

# Check for existing active network profiles
$profilesPath = "$baseProfilePath\Profiles"
if (Test-Path $profilesPath) {
    $existingProfiles = @(Get-ChildItem -Path $profilesPath -ErrorAction SilentlyContinue)

    # For each identified profile, apply default categorization
    foreach ($profileKey in $existingProfiles) {
        $profileGuid = $profileKey.PSChildName
        $fullPath = "$profilesPath\$profileGuid"

        if (Test-Path $fullPath) {
            # Apply Work category (2) for domain-joined networks
            Set-ItemProperty -Path $fullPath -Name 'Category' -Value 2 -Force
            Start-Sleep -Milliseconds 50
        }
    }
}

# Enumerate managed network signatures and apply policy
$signaturesPath = "$baseProfilePath\Signatures"
if (Test-Path $signaturesPath) {
    $signatures = @(Get-ChildItem -Path $signaturesPath -ErrorAction SilentlyContinue)

    foreach ($sig in $signatures) {
        $sigGuid = $sig.PSChildName
        $sigFullPath = "$signaturesPath\$sigGuid"

        # Apply category based on network signature properties
        Set-ItemProperty -Path $sigFullPath -Name 'Category' -Value 0 -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 50
    }
}

# Clean up: restore profiles to default state (Public category)
$profilesPath = "$baseProfilePath\Profiles"
if (Test-Path $profilesPath) {
    $profiles = @(Get-ChildItem -Path $profilesPath -ErrorAction SilentlyContinue)
    foreach ($profile in $profiles) {
        $guid = $profile.PSChildName
        Set-ItemProperty -Path "$profilesPath\$guid" -Name 'Category' -Value 0 -Force -ErrorAction SilentlyContinue
    }
}

if (Test-Path $signaturesPath) {
    $signatures = @(Get-ChildItem -Path $signaturesPath -ErrorAction SilentlyContinue)
    foreach ($sig in $signatures) {
        $guid = $sig.PSChildName
        Set-ItemProperty -Path "$signaturesPath\$guid" -Name 'Category' -Value 0 -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_4a268db0-5a4c-4bcd-9795-2232ec4af6e6  (1 rule(s)) ---------------------
# Intent:    Detect modifications to Windows Firewall network profile category settings in th
# Rules:     4a268db0-5a4c-4bcd-9795-2232ec4af6e6
# Archetype: User-driven workflow

$ErrorActionPreference = 'SilentlyContinue'

# User changes network profile categorization through system settings
# This simulates the backend registry writes triggered by Network Settings UI

$profileBasePath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'

# Get current network profiles
if (Test-Path $profileBasePath) {
    $activeProfiles = Get-ChildItem -Path $profileBasePath -ErrorAction SilentlyContinue

    # User changes first profile to Private (1)
    if ($activeProfiles.Count -gt 0) {
        $firstProfile = $activeProfiles[0]
        $firstGuid = $firstProfile.PSChildName
        $firstPath = "$profileBasePath\$firstGuid"

        # Simulate user selecting "Private" in network settings
        Set-ItemProperty -Path $firstPath -Name 'Category' -Value 1 -Force
        Start-Sleep -Milliseconds 100

        # If more profiles exist, user changes second to Public (0)
        if ($activeProfiles.Count -gt 1) {
            $secondProfile = $activeProfiles[1]
            $secondGuid = $secondProfile.PSChildName
            $secondPath = "$profileBasePath\$secondGuid"

            Set-ItemProperty -Path $secondPath -Name 'Category' -Value 0 -Force
            Start-Sleep -Milliseconds 100
        }
    }
}

# Ensure signatures are also categorized correctly
$signaturesPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures'
if (Test-Path $signaturesPath) {
    $sigs = Get-ChildItem -Path $signaturesPath -ErrorAction SilentlyContinue
    foreach ($sig in $sigs) {
        $sigGuid = $sig.PSChildName
        $sigPath = "$signaturesPath\$sigGuid"

        # Apply Public category by default for discovered networks
        Set-ItemProperty -Path $sigPath -Name 'Category' -Value 0 -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 50
    }
}

# Restore all profiles and signatures to Public (0) baseline
$profileBasePath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
if (Test-Path $profileBasePath) {
    $profiles = Get-ChildItem -Path $profileBasePath -ErrorAction SilentlyContinue
    foreach ($profile in $profiles) {
        Set-ItemProperty -Path "$profileBasePath\$($profile.PSChildName)" -Name 'Category' -Value 0 -Force -ErrorAction SilentlyContinue
    }
}

$signaturesPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures'
if (Test-Path $signaturesPath) {
    $signatures = Get-ChildItem -Path $signaturesPath -ErrorAction SilentlyContinue
    foreach ($sig in $signatures) {
        Set-ItemProperty -Path "$signaturesPath\$($sig.PSChildName)" -Name 'Category' -Value 0 -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_39273117-ab68-4959-9750-1cfd255f5a97  (1 rule(s)) ---------------------
# Intent:    Attackers modifying Windows Event Log Channel Access registry settings to disabl
# Rules:     39273117-ab68-4959-9750-1cfd255f5a97
# Archetype: IT admin workflow

$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
$ChannelAccessPath = Join-Path -Path $RegistryPath -ChildPath 'ChannelAccess'
$BackupPath = $env:TEMP + '\EventLogBackup_' + (Get-Date -Format 'yyyyMMdd_HHmmss')

# Create backup of current registry state
New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
reg export 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog' ($BackupPath + '\EventLog_backup.reg') /y

# Ensure the registry path exists
if (-not (Test-Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force | Out-Null
}

# Apply restrictive SDDL deny rules to Security channel
# D;;CICC;;;S-1-1-0 = Deny, Object, Container Inherit, Inherit Only to Everyone
# This is standard hardening to prevent non-admin access to security logs
$CurrentAcl = (Get-ItemProperty -Path $RegistryPath -Name 'ChannelAccess' -ErrorAction SilentlyContinue).ChannelAccess
$RestrictiveAcl = 'D;;CICC;;;S-1-1-0'

if ($CurrentAcl) {
    Set-ItemProperty -Path $RegistryPath -Name 'ChannelAccess' -Value $RestrictiveAcl -Type String
} else {
    New-ItemProperty -Path $RegistryPath -Name 'ChannelAccess' -Value $RestrictiveAcl -PropertyType String -Force | Out-Null
}

Start-Sleep -Seconds 1

# Verify the registry change was applied (confirm Sysmon event 13)
Get-ItemProperty -Path $RegistryPath -Name 'ChannelAccess' | Select-Object -ExpandProperty ChannelAccess

# Restore from backup
if (Test-Path ($BackupPath + '\EventLog_backup.reg')) {
    reg import ($BackupPath + '\EventLog_backup.reg')
    Remove-Item -Path $BackupPath -Recurse -Force
}

# -- Cluster: singleton_39273117-ab68-4959-9750-1cfd255f5a97  (1 rule(s)) ---------------------
# Intent:    Attackers modifying Windows Event Log Channel Access registry settings to disabl
# Rules:     39273117-ab68-4959-9750-1cfd255f5a97
# Archetype: Software installer/updater workflow

$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
$BackupPath = $env:TEMP + '\EventLogConfig_' + (Get-Date -Format 'yyyyMMdd_HHmmss')

# Create backup before modification
New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
reg export 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog' ($BackupPath + '\config_backup.reg') /y

# Ensure registry path exists (created by installer)
if (-not (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog' -Force | Out-Null
}

if (-not (Test-Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force | Out-Null
}

# Configure SDDL with deny rules for audit purposes
# This is what an enterprise audit tool installer would do
$AuditAcl = 'D;;LC;;;S-1-5-18;D;;RC;;;S-1-1-0'

Set-ItemProperty -Path $RegistryPath -Name 'ChannelAccess' -Value $AuditAcl -Type String -Force

Start-Sleep -Milliseconds 500

# Verify installation was successful
Get-ItemProperty -Path $RegistryPath -Name 'ChannelAccess' -ErrorAction SilentlyContinue | Out-Null

# Restore from backup to clean up
if (Test-Path ($BackupPath + '\config_backup.reg')) {
    reg import ($BackupPath + '\config_backup.reg')
    Remove-Item -Path $BackupPath -Recurse -Force
}

# -- Cluster: singleton_39273117-ab68-4959-9750-1cfd255f5a97  (1 rule(s)) ---------------------
# Intent:    Attackers modifying Windows Event Log Channel Access registry settings to disabl
# Rules:     39273117-ab68-4959-9750-1cfd255f5a97
# Archetype: User-driven workflow

$RegistryPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
$BackupPath = $env:TEMP + '\EventLogConfig_Backup_' + (Get-Date -Format 'yyyyMMdd_HHmmss')

# Create backup
New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
reg export 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog' ($BackupPath + '\backup.reg') /y

# Ensure path exists
if (-not (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog')) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog' -Force | Out-Null
}

if (-not (Test-Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force | Out-Null
}

# Apply SDDL deny rules for Application event log access control
# S-1-5-20 is NETWORK SERVICE, S-1-1-0 is Everyone
$SddlValue = 'D;;RC;;;S-1-1-0'

Set-ItemProperty -Path $RegistryPath -Name 'ChannelAccess' -Value $SddlValue -Type String

Start-Sleep -Milliseconds 500

# Verify the modification
Get-ItemProperty -Path $RegistryPath -Name 'ChannelAccess'

# Restore original state
if (Test-Path ($BackupPath + '\backup.reg')) {
    reg import ($BackupPath + '\backup.reg')
    Remove-Item -Path $BackupPath -Recurse -Force
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
