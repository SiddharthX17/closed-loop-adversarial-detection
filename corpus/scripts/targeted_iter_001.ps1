# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_d65b10d0-e42b-42a1-bd28-892ae4d5c423  (1 rule(s)) ---------------------
# Intent:    Attackers modifying Windows Firewall policies via CLI or COM interfaces to disab
# Rules:     d65b10d0-e42b-42a1-bd28-892ae4d5c423
# Archetype: IT admin workflow

$ErrorActionPreference = 'SilentlyContinue'

# Simulate IT admin firewall maintenance and audit activity
# Creating temporary test rules for verification before production deployment

# 1. Query current firewall state using netsh (common admin verification)
Write-Host "[INFO] Auditing current firewall profile state..."
netsh advfirewall show allprofiles

# 2. Create a temporary test inbound rule via netsh
Write-Host "[INFO] Creating test inbound rule for deployment verification..."
netsh advfirewall firewall add rule name="TestInboundRuleAudit" dir=in action=allow protocol=tcp localport=8888 description="Temporary test rule for firewall audit"

# 3. Query the newly created rule
netsh advfirewall firewall show rule name="TestInboundRuleAudit"

# 4. Disable the test rule (simulating rule modification during policy review)
Write-Host "[INFO] Disabling test rule as part of audit..."
netsh advfirewall firewall set rule name="TestInboundRuleAudit" new enable=no

# 5. Use PowerShell NetFirewall cmdlets for advanced rule management
Write-Host "[INFO] Modifying firewall rules via PowerShell cmdlets..."
Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled $false
Start-Sleep -Milliseconds 500

# 6. Re-enable firewall profiles
Write-Host "[INFO] Re-enabling firewall profiles for normal operations..."
Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled $true

# 7. Query current rule state using PowerShell
Write-Host "[INFO] Verifying test rule state via PowerShell..."
Get-NetFirewallRule -DisplayName "TestInboundRuleAudit" | Select-Object DisplayName, Enabled, Direction, Action

# 8. Create another test rule to verify enable functionality
Write-Host "[INFO] Creating secondary test rule to verify enable functionality..."
New-NetFirewallRule -DisplayName "TestManagementRule" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 9999 -Enabled $true

# 9. Query and then disable via PowerShell
Write-Host "[INFO] Disabling secondary rule via PowerShell..."
Disable-NetFirewallRule -DisplayName "TestManagementRule"

# 10. Re-enable via PowerShell (simulating rule state changes during maintenance)
Enable-NetFirewallRule -DisplayName "TestManagementRule"

# 11. Cleanup: Remove test rules
Write-Host "[INFO] Cleaning up temporary test rules..."
netsh advfirewall firewall delete rule name="TestInboundRuleAudit"
Remove-NetFirewallRule -DisplayName "TestManagementRule" -Confirm:$false -ErrorAction SilentlyContinue

Write-Host "[INFO] Firewall audit and maintenance completed."

# -- Cluster: singleton_d65b10d0-e42b-42a1-bd28-892ae4d5c423  (1 rule(s)) ---------------------
# Intent:    Attackers modifying Windows Firewall policies via CLI or COM interfaces to disab
# Rules:     d65b10d0-e42b-42a1-bd28-892ae4d5c423
# Archetype: Software installer/updater workflow

$ErrorActionPreference = 'SilentlyContinue'

# Simulate security software installation firewall integration workflow
# This represents how legitimate security tools like Windows Defender or endpoint protection
# solutions modify firewall policies during installation/update

$securityToolPath = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
$logPath = "$env:TEMP\security_install_log.txt"

# 1. Security software checks current firewall state during installation
Write-Host "[INFO] Security software installer: Checking firewall compatibility..."
netsh advfirewall show currentprofile >> $logPath

# 2. Verify firewall profiles are properly configured
Write-Host "[INFO] Verifying firewall profiles for security agent compatibility..."
netsh advfirewall show allprofiles | Out-File -Append $logPath

# 3. Create allowlist rules for security tool network operations
Write-Host "[INFO] Adding firewall rules for security service network access..."
netsh advfirewall firewall add rule name="SecurityAgentOutbound" dir=out action=allow protocol=tcp remoteport=443 description="Allow security agent updates and telemetry"

# 4. Create additional rule for callback traffic
netsh advfirewall firewall add rule name="SecurityAgentCallback" dir=in action=allow protocol=tcp localport=5985 description="Allow security agent management callback"

# 5. Use PowerShell to verify rule creation
Write-Host "[INFO] Verifying rules via PowerShell..."
Get-NetFirewallRule -DisplayName "SecurityAgent*" | Format-Table DisplayName, Direction, Action

# 6. Temporarily disable firewall profiles during installation (common pattern)
Write-Host "[INFO] Temporarily adjusting firewall for installation process..."
Get-NetFirewallProfile -Name Private | Set-NetFirewallProfile -DefaultInboundAction Block

# 7. Re-enable critical protections
Write-Host "[INFO] Re-enabling firewall protections post-installation..."
Get-NetFirewallProfile | Set-NetFirewallProfile -DefaultInboundAction Block -Enabled $true

# 8. Enable specific allowlist rules
Write-Host "[INFO] Enabling security tool firewall rules..."
Enable-NetFirewallRule -DisplayName "SecurityAgentOutbound"
Enable-NetFirewallRule -DisplayName "SecurityAgentCallback"

# 9. Final state verification
Write-Host "[INFO] Final firewall state verification..."
Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table

# 10. Cleanup temporary rules
Write-Host "[INFO] Cleaning up temporary installation rules..."
netsh advfirewall firewall delete rule name="SecurityAgentOutbound"
netsh advfirewall firewall delete rule name="SecurityAgentCallback"

if (Test-Path $logPath) {
    Remove-Item $logPath -Force
}

Write-Host "[INFO] Security software installation firewall integration completed."

# -- Cluster: singleton_d65b10d0-e42b-42a1-bd28-892ae4d5c423  (1 rule(s)) ---------------------
# Intent:    Attackers modifying Windows Firewall policies via CLI or COM interfaces to disab
# Rules:     d65b10d0-e42b-42a1-bd28-892ae4d5c423
# Archetype: User-driven workflow

$ErrorActionPreference = 'SilentlyContinue'

# Simulate user-initiated network connectivity troubleshooting workflow
# Real users run diagnostics when experiencing network issues, and system
# troubleshooting tools interact with firewall state

# 1. User checks current firewall status during network troubleshooting
Write-Host "[INFO] Checking firewall status for network troubleshooting..."
Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table

# 2. User enables detailed firewall logging for diagnostics
Write-Host "[INFO] Enabling firewall logging for network diagnosis..."
Set-NetFirewallProfile -LogFileName "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" -LogMaxSizeKilobytes 4096

# 3. User verifies Remote Desktop connectivity by checking firewall rules
Write-Host "[INFO] Checking Remote Desktop firewall rules..."
Get-NetFirewallRule -DisplayName "*Remote Desktop*" | Format-Table DisplayName, Enabled, Direction

# 4. User attempts to enable RDP firewall exception if disabled
Write-Host "[INFO] Verifying RDP is allowed through firewall..."
Enable-NetFirewallRule -DisplayName "Remote Desktop - User Mode (TCP-In)" -ErrorAction SilentlyContinue

# 5. User creates temporary diagnostic rule
Write-Host "[INFO] Creating temporary diagnostics rule..."
New-NetFirewallRule -DisplayName "DiagnosticsPing" -Direction Inbound -Action Allow -Protocol ICMP -ErrorAction SilentlyContinue

# 6. User checks firewall state using both PowerShell and legacy netsh
Write-Host "[INFO] Detailed firewall state check..."
netsh advfirewall show allprofiles | Out-Null

# 7. User disables the diagnostic rule after testing
Write-Host "[INFO] Disabling diagnostic rule..."
Disable-NetFirewallRule -DisplayName "DiagnosticsPing" -ErrorAction SilentlyContinue

# 8. User queries current inbound firewall action for troubleshooting documentation
Write-Host "[INFO] Recording firewall policy state..."
Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, DefaultInboundAction, DefaultOutboundAction | Format-Table

# 9. User cleans up diagnostic rule
Write-Host "[INFO] Removing diagnostic rule..."
Remove-NetFirewallRule -DisplayName "DiagnosticsPing" -Confirm:$false -ErrorAction SilentlyContinue

Write-Host "[INFO] Network troubleshooting diagnostics completed."


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
