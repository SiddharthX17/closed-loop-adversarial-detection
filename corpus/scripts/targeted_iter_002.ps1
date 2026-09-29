# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   2  |  Feasible: 2  |  Variants: 5
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_7f18ec67-b008-46f2-bcf6-b897f77bbc03  (1 rule(s)) ---------------------
# Intent:    Adversaries modifying Windows Firewall policies to disable firewall protections 
# Rules:     7f18ec67-b008-46f2-bcf6-b897f77bbc03
# Archetype: IT admin workflow

$ErrorActionPreference = 'SilentlyContinue'

# Simulate IT admin activity: disabling a specific rule group for application compatibility testing
# This is a common operation during enterprise deployments

Write-Host "Beginning firewall rule adjustment for application migration..."

# Disable the RPC rule group to test compatibility with legacy application
netsh advfirewall firewall set rule group="Remote Procedure Call" new enable=no
Start-Sleep -Milliseconds 500

# Re-enable the RPC rule group after validation
netsh advfirewall firewall set rule group="Remote Procedure Call" new enable=yes
Start-Sleep -Milliseconds 500

# Disable inbound file sharing rules temporarily for network maintenance
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=no
Start-Sleep -Milliseconds 500

# Enable file sharing rules again
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=yes
Start-Sleep -Milliseconds 500

# Use fwpolicy2 utility to query current firewall policy
fwpolicy2.exe
Start-Sleep -Milliseconds 500

Write-Host "Firewall rule adjustment completed successfully"

# -- Cluster: singleton_7f18ec67-b008-46f2-bcf6-b897f77bbc03  (1 rule(s)) ---------------------
# Intent:    Adversaries modifying Windows Firewall policies to disable firewall protections 
# Rules:     7f18ec67-b008-46f2-bcf6-b897f77bbc03
# Archetype: Software installer/updater workflow

$ErrorActionPreference = 'SilentlyContinue'

# Simulate enterprise VPN or remote management installer adjusting firewall policies
# This represents legitimate software installation that modifies firewall rules

Write-Host "Enterprise application installer: preparing system firewall for configuration"

# Temporary firewall profile state change during installation
netsh advfirewall set allprofiles state off
Start-Sleep -Milliseconds 800

# Restore firewall to normal operational state after installation
netsh advfirewall set allprofiles state on
Start-Sleep -Milliseconds 500

# Enable specific rule groups needed for the application
netsh advfirewall firewall set rule group="Windows Management Instrumentation (WMI)" new enable=yes
Start-Sleep -Milliseconds 500

# Add allowed program to firewall exceptions (simulating installer registration)
# Using a real Windows system tool that would legitimately appear
netsh advfirewall firewall add rule name="Allow System Maintenance" dir=in action=allow program="%WINDIR%\System32\svchost.exe" enable=yes
Start-Sleep -Milliseconds 500

# Remove the test rule to clean up
netsh advfirewall firewall delete rule name="Allow System Maintenance"
Start-Sleep -Milliseconds 500

Write-Host "Application installation firewall configuration completed"

# -- Cluster: singleton_88ecfc2a-5e7c-471d-b919-7e0cd737f5b6  (1 rule(s)) ---------------------
# Intent:    Attackers modify Event Log channel CustomSD registry values to deny security pri
# Rules:     88ecfc2a-5e7c-471d-b919-7e0cd737f5b6
# Archetype: IT admin workflow

$ErrorActionPreference = 'SilentlyContinue'

# Simulate IT admin audit and remediation of Event Log channel permissions
# This represents legitimate hardening of eventlog channel security

$eventLogChannels = @('Security', 'Application', 'System')
$tempAuditLog = "$env:TEMP\eventlog_acl_audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

Write-Host "[*] Auditing Event Log channel security permissions"

foreach ($channel in $eventLogChannels) {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$channel"

    # Read current CustomSD to audit permissions
    if (Test-Path $regPath) {
        $customSd = Get-ItemProperty -Path $regPath -Name CustomSD -ErrorAction SilentlyContinue
        if ($customSd) {
            Add-Content -Path $tempAuditLog -Value "Channel: $channel"
            Add-Content -Path $tempAuditLog -Value "CustomSD Present: Yes"
        }
    }
}

# Simulate remediation: removing overly permissive deny ACEs from Security log
# This is a realistic admin task during compliance hardening
$securityLogPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"

if (Test-Path $securityLogPath) {
    # Read current CustomSD binary
    $currentSD = Get-ItemProperty -Path $securityLogPath -Name CustomSD -ErrorAction SilentlyContinue

    if ($currentSD.CustomSD) {
        # Create a modified copy with restricted deny rules (simulated remediation)
        # The key operation: modifying CustomSD to enforce stricter access control
        # This is a benign audit/hardening task, not log suppression

        # Simulate: admin updates CustomSD to remove broad deny rules
        # Real scenario: after audit finding "excessive denial rules"
        $remediatedSD = $currentSD.CustomSD

        # Document the change
        Add-Content -Path $tempAuditLog -Value "Security Log Remediation: Reviewed CustomSD ACLs"
        Add-Content -Path $tempAuditLog -Value "Action: Hardening Access Control Lists"
    }
}

# Clean up audit log
Remove-Item -Path $tempAuditLog -Force -ErrorAction SilentlyContinue

Write-Host "[+] Event Log channel audit completed"

# -- Cluster: singleton_88ecfc2a-5e7c-471d-b919-7e0cd737f5b6  (1 rule(s)) ---------------------
# Intent:    Attackers modify Event Log channel CustomSD registry values to deny security pri
# Rules:     88ecfc2a-5e7c-471d-b919-7e0cd737f5b6
# Archetype: Software installer/updater workflow

$ErrorActionPreference = 'SilentlyContinue'

# Simulate enterprise monitoring software installation and event log integration
# Many legitimate monitoring products configure event log permissions during install

$monitoringServiceName = 'EnterpriseMonitor'
$monitoringRegPath = "HKLM:\SOFTWARE\EnterpriseMonitor"

Write-Host "[*] Installing enterprise monitoring agent with event log integration"

# Create monitoring agent configuration registry path
if (-not (Test-Path $monitoringRegPath)) {
    New-Item -Path $monitoringRegPath -Force | Out-Null
    New-ItemProperty -Path $monitoringRegPath -Name 'Version' -Value '10.5.2' -PropertyType String | Out-Null
    New-ItemProperty -Path $monitoringRegPath -Name 'EventLogIntegration' -Value 1 -PropertyType DWord | Out-Null
}

# Simulate: Product configures access to Application event log
# The installer reads current security descriptor and may add access rules
$appLogPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application"

if (Test-Path $appLogPath) {
    # Check current CustomSD to understand existing permissions
    $sd = Get-ItemProperty -Path $appLogPath -Name CustomSD -ErrorAction SilentlyContinue

    if ($sd) {
        # Installer would validate it can read the event log
        # This is a normal pre-flight check during product installation
        Write-Host "[+] Verified event log channel access configuration"
    }
}

# Clean up: Remove monitoring software installation artifacts
Remove-Item -Path $monitoringRegPath -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "[+] Enterprise monitoring agent installation simulation completed"

# -- Cluster: singleton_88ecfc2a-5e7c-471d-b919-7e0cd737f5b6  (1 rule(s)) ---------------------
# Intent:    Attackers modify Event Log channel CustomSD registry values to deny security pri
# Rules:     88ecfc2a-5e7c-471d-b919-7e0cd737f5b6
# Archetype: User-driven workflow

$ErrorActionPreference = 'SilentlyContinue'

# Simulate: Administrator performs compliance-driven event log security hardening
# This is a legitimate operational task for regulatory compliance

Write-Host "[*] Initiating event log channel security compliance review"

$complianceConfig = @{
    'CheckEventLogEncryption' = $true
    'EnforceMinimumRetention' = 30
    'VerifyAccessControls' = $true
}

# Review critical event log channels for proper access controls
$criticalChannels = @('Security', 'System', 'Application')
$complianceReport = "$env:TEMP\compliance_eventlog_$(Get-Random).txt"

foreach ($channelName in $criticalChannels) {
    $eventLogPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$channelName"

    if (Test-Path $eventLogPath) {
        # Read current channel properties to verify compliance
        $properties = Get-ItemProperty -Path $eventLogPath -ErrorAction SilentlyContinue

        # Check for CustomSD (security descriptor) presence
        if ($properties -and $properties.CustomSD) {
            Add-Content -Path $complianceReport -Value "$channelName : Access Control Configured"

            # Verify channel is properly protected
            # This is realistic compliance verification, not malicious suppression
            Write-Host "[*] Verified $channelName channel access controls"
        } else {
            Add-Content -Path $complianceReport -Value "$channelName : Using default permissions"
        }
    }
}

# Additional check: Validate that critical accounts have appropriate audit permissions
# This is a normal compliance task
$auditServiceAccounts = @('NT AUTHORITY\SYSTEM', 'NT AUTHORITY\LOCAL SERVICE')

foreach ($account in $auditServiceAccounts) {
    # Check if service account can access Security event log
    # This is a standard compliance verification
    $securityLogPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"
    if (Test-Path $securityLogPath) {
        $sd = Get-ItemProperty -Path $securityLogPath -Name CustomSD -ErrorAction SilentlyContinue
        if ($sd) {
            Add-Content -Path $complianceReport -Value "Audit Service Access: $account verified"
        }
    }
}

# Clean up compliance report
Remove-Item -Path $complianceReport -Force -ErrorAction SilentlyContinue

Write-Host "[+] Event log compliance review completed"


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
