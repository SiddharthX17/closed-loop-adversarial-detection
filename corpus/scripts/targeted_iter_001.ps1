# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 2
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_f3b6610c-0a01-4c1f-823e-e4a6d6ba8b0d  (1 rule(s)) ---------------------
# Intent:    Attackers disable or modify Windows Firewall rules to evade detection or allow m
# Rules:     f3b6610c-0a01-4c1f-823e-e4a6d6ba8b0d
# Archetype: IT admin workflow

$ProgressPreference = 'SilentlyContinue'
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Initiating firewall policy audit and baseline hardening."

# Query current firewall profile state to establish baseline
Write-Host "Retrieving current firewall profiles..."
$currentProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
foreach ($profile in $currentProfiles) {
    Write-Host "  Profile: $($profile.Name) - Enabled: $($profile.Enabled)"
}

# Create a temporary inbound rule for network monitoring purposes (legitimate admin task)
Write-Host "Creating temporary test rule for monitoring baseline..."
$ruleName = "IT-Ops-Monitoring-Rule-$(Get-Random -Minimum 1000 -Maximum 9999)"
New-NetFirewallRule -DisplayName $ruleName `
  -Direction Inbound `
  -Action Allow `
  -Protocol TCP `
  -LocalPort 8888 `
  -RemoteAddress 127.0.0.1 `
  -Enabled $true `
  -ErrorAction SilentlyContinue | Out-Null

# Set profile configurations as part of baseline deployment
Write-Host "Applying firewall profile hardening baseline..."
Set-NetFirewallProfile -Profile Domain -Enabled $true -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction SilentlyContinue | Out-Null
Set-NetFirewallProfile -Profile Private -Enabled $true -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction SilentlyContinue | Out-Null

# Query and log all current rules for audit trail
Write-Host "Auditing active firewall rules..."
$allRules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Select-Object -First 5
foreach ($rule in $allRules) {
    Write-Host "  Rule: $($rule.DisplayName) - Enabled: $($rule.Enabled)"
}

# Enable a firewall rule group (e.g., Windows Defender)
Write-Host "Enabling Windows Defender firewall rule group..."
Enable-NetFirewallRule -DisplayGroup "Windows Defender" -ErrorAction SilentlyContinue | Out-Null

# Query firewall profile again post-hardening
Write-Host "Verifying firewall profile state post-hardening..."
$postProfiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
foreach ($profile in $postProfiles) {
    Write-Host "  Profile: $($profile.Name) - Enabled: $($profile.Enabled)"
}

# Clean up temporary test rule
Write-Host "Removing temporary test rule..."
Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Out-Null

Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Firewall policy audit and hardening completed."

# -- Cluster: singleton_f3b6610c-0a01-4c1f-823e-e4a6d6ba8b0d  (1 rule(s)) ---------------------
# Intent:    Attackers disable or modify Windows Firewall rules to evade detection or allow m
# Rules:     f3b6610c-0a01-4c1f-823e-e4a6d6ba8b0d
# Archetype: Software installer/updater workflow

$ProgressPreference = 'SilentlyContinue'
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Starting Enterprise Security Software installation workflow."

# Installer pre-flight check: query current firewall state
Write-Host "Performing pre-installation firewall compatibility check..."
$firewallStatus = Get-NetFirewallProfile -Profile Domain -ErrorAction SilentlyContinue
if ($firewallStatus) {
    Write-Host "  Firewall status: $($firewallStatus.Enabled)"
}

# Create installer-specific temporary rules required for setup
Write-Host "Configuring firewall rules for software installation..."
$installerPort = 9876
$installerRuleName = "SecuritySoftware-Setup-$(Get-Random -Minimum 10000 -Maximum 99999)"

New-NetFirewallRule -DisplayName $installerRuleName `
  -Direction Outbound `
  -Action Allow `
  -Protocol TCP `
  -RemotePort $installerPort `
  -RemoteAddress 127.0.0.1 `
  -Enabled $true `
  -ErrorAction SilentlyContinue | Out-Null

# Apply temporary profile relaxation during installation (common during setup)
Write-Host "Temporarily adjusting firewall profile for installation..."
Set-NetFirewallProfile -Profile Public -Enabled $true -NotifyOnListen $true -ErrorAction SilentlyContinue | Out-Null

# Create additional rule group for application functionality
Write-Host "Enabling application-specific firewall rule groups..."
Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing" -ErrorAction SilentlyContinue | Out-Null
Enable-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" -ErrorAction SilentlyContinue | Out-Null

# Validate installed rules
Write-Host "Validating installed firewall configuration..."
$installedRules = Get-NetFirewallRule -DisplayName $installerRuleName -ErrorAction SilentlyContinue
if ($installedRules) {
    Write-Host "  Successfully configured rule: $installerRuleName"
}

# Post-installation cleanup: remove temporary setup rules
Write-Host "Performing post-installation firewall cleanup..."
Remove-NetFirewallRule -DisplayName $installerRuleName -ErrorAction SilentlyContinue | Out-Null

# Restore default inbound action for all profiles
Write-Host "Restoring default firewall policy..."
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -ErrorAction SilentlyContinue | Out-Null

Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Installation workflow and firewall configuration completed."


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
