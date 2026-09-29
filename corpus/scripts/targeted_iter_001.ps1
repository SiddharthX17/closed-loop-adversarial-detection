# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   2  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_679f5a69-8c90-46aa-8146-031381014ef6  (1 rule(s)) ---------------------
# Intent:    Detection of registry modifications to network profile category settings, which 
# Rules:     679f5a69-8c90-46aa-8146-031381014ef6
# Archetype: IT admin workflow

# IT admin: Document and update network profile categories for compliance audit
# This simulates a real admin maintenance task checking network profile settings

$AdminAuditLog = "$env:TEMP\network_profile_audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# Query existing network profiles from registry
$profilesPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'

if (Test-Path $profilesPath) {
    Add-Content -Path $AdminAuditLog -Value "Network Profile Audit - $(Get-Date)"
    Add-Content -Path $AdminAuditLog -Value "==============================================="

    $profiles = Get-ChildItem -Path $profilesPath -ErrorAction SilentlyContinue

    foreach ($profile in $profiles) {
        $profileName = $profile.PSChildName
        $categoryValue = (Get-ItemProperty -Path "$profilesPath\$profileName" -Name Category -ErrorAction SilentlyContinue).Category

        Add-Content -Path $AdminAuditLog -Value "Profile: $profileName"
        Add-Content -Path $AdminAuditLog -Value "  Category: $categoryValue"
    }
}

# Create a test network profile entry for validation (simulating new network discovered)
$testProfileGuid = '{AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB}'
$testProfilePath = "$profilesPath\$testProfileGuid"

try {
    # Create new registry entry if it doesn't exist
    if (-not (Test-Path $testProfilePath)) {
        New-Item -Path $testProfilePath -Force | Out-Null
    }

    # Set profile name
    New-ItemProperty -Path $testProfilePath -Name "ProfileName" -Value "Test_Corporate_Network" -PropertyType String -Force | Out-Null

    # Set category to Private (1 = Private, 0 = Public, 2 = Domain Authenticated)
    # This is a legitimate network classification admin task
    New-ItemProperty -Path $testProfilePath -Name "Category" -Value 1 -PropertyType DWord -Force | Out-Null

    Add-Content -Path $AdminAuditLog -Value "Created test profile: $testProfileGuid with Category=1 (Private)"

    # Verify the write succeeded
    $verifyCategory = (Get-ItemProperty -Path $testProfilePath -Name Category -ErrorAction SilentlyContinue).Category
    Add-Content -Path $AdminAuditLog -Value "Verification: Category value = $verifyCategory"

} catch {
    Add-Content -Path $AdminAuditLog -Value "Error: $_"
}

# Cleanup: Remove test profile
try {
    if (Test-Path $testProfilePath) {
        Remove-Item -Path $testProfilePath -Force -ErrorAction SilentlyContinue
        Add-Content -Path $AdminAuditLog -Value "Cleanup: Removed test profile"
    }
} catch {
    Add-Content -Path $AdminAuditLog -Value "Cleanup error: $_"
}

# Output audit completion
Add-Content -Path $AdminAuditLog -Value "Audit completed at $(Get-Date)"

# Display audit results
Get-Content -Path $AdminAuditLog

# Cleanup audit log
Remove-Item -Path $AdminAuditLog -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_679f5a69-8c90-46aa-8146-031381014ef6  (1 rule(s)) ---------------------
# Intent:    Detection of registry modifications to network profile category settings, which 
# Rules:     679f5a69-8c90-46aa-8146-031381014ef6
# Archetype: Software installer/updater workflow

# Installer/Configuration workflow: Network connectivity tool post-install setup
# This simulates a legitimate enterprise network optimization tool configuring profiles

$InstallLog = "$env:TEMP\netconfig_setup_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

Add-Content -Path $InstallLog -Value "Network Connectivity Configuration Tool - Setup"
Add-Content -Path $InstallLog -Value "Install time: $(Get-Date)"
Add-Content -Path $InstallLog -Value "=========================================================="

$profilesPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'

# Simulate installer discovering existing profiles and configuring them
if (Test-Path $profilesPath) {
    $profiles = Get-ChildItem -Path $profilesPath -ErrorAction SilentlyContinue

    foreach ($profile in $profiles) {
        $profileGuid = $profile.PSChildName
        $profilePath = "$profilesPath\$profileGuid"

        try {
            # Verify profile exists and read current category
            $currentCategory = (Get-ItemProperty -Path $profilePath -Name Category -ErrorAction SilentlyContinue).Category

            if ($null -ne $currentCategory) {
                Add-Content -Path $InstallLog -Value "Configuring profile $profileGuid"
                Add-Content -Path $InstallLog -Value "  Current category: $currentCategory"

                # Installer applies security policy: ensure all discovered networks are at least Private
                # This is a realistic post-install configuration step
                if ($currentCategory -ne 1) {
                    New-ItemProperty -Path $profilePath -Name "Category" -Value 1 -PropertyType DWord -Force | Out-Null
                    Add-Content -Path $InstallLog -Value "  Updated category to 1 (Private) for security"
                }
            }
        } catch {
            Add-Content -Path $InstallLog -Value "  Warning: Could not update profile - $_"
        }
    }
}

# Create installer-managed profile entries
Add-Content -Path $InstallLog -Value ""
Add-Content -Path $InstallLog -Value "Creating managed network profile entries..."

for ($i = 1; $i -le 2; $i++) {
    $managedGuid = "{CCCCCCCC-$('{0:D4}' -f $i)-5555-6666-DDDDDDDDDDDD}"
    $managedProfilePath = "$profilesPath\$managedGuid"

    try {
        if (-not (Test-Path $managedProfilePath)) {
            New-Item -Path $managedProfilePath -Force | Out-Null
        }

        # Set managed profile attributes
        New-ItemProperty -Path $managedProfilePath -Name "ProfileName" -Value "ManagedNetwork_$i" -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $managedProfilePath -Name "Category" -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $managedProfilePath -Name "Description" -Value "Managed by NetOptimizer" -PropertyType String -Force | Out-Null

        Add-Content -Path $InstallLog -Value "Created managed profile: $managedGuid"
    } catch {
        Add-Content -Path $InstallLog -Value "Error creating managed profile: $_"
    }
}

# Cleanup managed profiles
Add-Content -Path $InstallLog -Value ""
Add-Content -Path $InstallLog -Value "Cleaning up installation artifacts..."

for ($i = 1; $i -le 2; $i++) {
    $managedGuid = "{CCCCCCCC-$('{0:D4}' -f $i)-5555-6666-DDDDDDDDDDDD}"
    $managedProfilePath = "$profilesPath\$managedGuid"

    try {
        if (Test-Path $managedProfilePath) {
            Remove-Item -Path $managedProfilePath -Force -ErrorAction SilentlyContinue
            Add-Content -Path $InstallLog -Value "Removed temporary profile: $managedGuid"
        }
    } catch {
        Add-Content -Path $InstallLog -Value "Cleanup error: $_"
    }
}

Add-Content -Path $InstallLog -Value ""
Add-Content -Path $InstallLog -Value "Setup completed at $(Get-Date)"

# Output log
Get-Content -Path $InstallLog

# Cleanup
Remove-Item -Path $InstallLog -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_679f5a69-8c90-46aa-8146-031381014ef6  (1 rule(s)) ---------------------
# Intent:    Detection of registry modifications to network profile category settings, which 
# Rules:     679f5a69-8c90-46aa-8146-031381014ef6
# Archetype: User-driven workflow

# User-driven workflow: Enterprise network configuration utility
# Simulates a user running network settings configuration tool that manages profiles

$ConfigLog = "$env:TEMP\network_config_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

Add-Content -Path $ConfigLog -Value "Network Configuration Tool - User Session"
Add-Content -Path $ConfigLog -Value "Started: $(Get-Date)"
Add-Content -Path $ConfigLog -Value "========================================================"

$profilesPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'

# First, enumerate all current profiles like a UI would show them
Add-Content -Path $ConfigLog -Value "Discovered Network Profiles:"
Add-Content -Path $ConfigLog -Value ""

if (Test-Path $profilesPath) {
    $allProfiles = Get-ChildItem -Path $profilesPath -ErrorAction SilentlyContinue
    $profileCount = 0

    foreach ($profile in $allProfiles) {
        $profileGuid = $profile.PSChildName
        $props = Get-ItemProperty -Path "$profilesPath\$profileGuid" -ErrorAction SilentlyContinue
        $profileName = $props.ProfileName
        $category = $props.Category

        $categoryLabel = switch ($category) {
            0 { "Public" }
            1 { "Private" }
            2 { "Domain" }
            default { "Unknown" }
        }

        Add-Content -Path $ConfigLog -Value "[$profileCount] $profileName (GUID: $profileGuid)"
        Add-Content -Path $ConfigLog -Value "     Current category: $categoryLabel"
        $profileCount++
    }
}

Add-Content -Path $ConfigLog -Value ""
Add-Content -Path $ConfigLog -Value "User selects network to reclassify and applies new configuration..."
Add-Content -Path $ConfigLog -Value ""

# Simulate user selection and configuration change
# Create a temporary test profile to simulate a discovered/new network
$testGuid = '{EEEEEEEE-7777-8888-9999-FFFFFFFFFFFF}'
$testPath = "$profilesPath\$testGuid"

try {
    # Create test profile
    if (-not (Test-Path $testPath)) {
        New-Item -Path $testPath -Force | Out-Null
    }

    New-ItemProperty -Path $testPath -Name "ProfileName" -Value "Guest_WiFi_Network" -PropertyType String -Force | Out-Null

    # Initial category (Public)
    New-ItemProperty -Path $testPath -Name "Category" -Value 0 -PropertyType DWord -Force | Out-Null

    Add-Content -Path $ConfigLog -Value "Selected network: Guest_WiFi_Network"
    Add-Content -Path $ConfigLog -Value "Current setting: Public (0)"
    Add-Content -Path $ConfigLog -Value "User action: Change to Private for better security"

    # User reclassifies the network (realistic scenario)
    New-ItemProperty -Path $testPath -Name "Category" -Value 1 -PropertyType DWord -Force | Out-Null

    $verifyNew = (Get-ItemProperty -Path $testPath -Name Category -ErrorAction SilentlyContinue).Category
    Add-Content -Path $ConfigLog -Value "Applied change: Category = $verifyNew (Private)"

} catch {
    Add-Content -Path $ConfigLog -Value "Configuration error: $_"
}

# Cleanup
Add-Content -Path $ConfigLog -Value ""
Add-Content -Path $ConfigLog -Value "Cleaning up temporary configuration entries..."

try {
    if (Test-Path $testPath) {
        Remove-Item -Path $testPath -Force -ErrorAction SilentlyContinue
        Add-Content -Path $ConfigLog -Value "Removed temporary profile entry"
    }
} catch {
    Add-Content -Path $ConfigLog -Value "Cleanup error: $_"
}

Add-Content -Path $ConfigLog -Value ""
Add-Content -Path $ConfigLog -Value "Session ended: $(Get-Date)"

# Display log
Get-Content -Path $ConfigLog

# Cleanup log file
Remove-Item -Path $ConfigLog -Force -ErrorAction SilentlyContinue

# SKIPPED cluster singleton_8ea72355-9c48-4b99-8f31-4026fcad0f19: LLM response truncated at max_tokens (4096)

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
