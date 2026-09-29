# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   2  |  Feasible: 2  |  Variants: 5
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_834e59e9-f73b-4e11-8173-bbe1dc5321e8  (1 rule(s)) ---------------------
# Intent:    Attackers programmatically disable or modify Windows Firewall rules to permit ma
# Rules:     834e59e9-f73b-4e11-8173-bbe1dc5321e8
# Archetype: IT admin workflow

# Scenario: Network security team audits and updates firewall rules for compliance
# This represents a legitimate admin maintaining Windows Firewall configuration

$ErrorActionPreference = 'SilentlyContinue'
$testRuleName = 'TestWebServerRule_' + (Get-Random -Minimum 10000 -Maximum 99999)
$testRuleName2 = 'TestDatabaseRule_' + (Get-Random -Minimum 10000 -Maximum 99999)

try {
    # Legitimate scenario: Admin creates a new inbound rule for a web server service
    # This generates the 'new-netfirewallrule' command-line artifact
    New-NetFirewallRule -DisplayName $testRuleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8080 -ErrorAction SilentlyContinue | Out-Null

    # Admin enables a specific rule group to allow corporate software communication
    # This generates the 'enablerulegroup' artifact
    Enable-NetFirewallRule -DisplayGroup "Windows Defender Firewall" -ErrorAction SilentlyContinue

    # Legitimate scenario: Configure firewall profile for domain-joined machines
    # Admin sets the domain profile to enforce specific policy
    Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction SilentlyContinue

    # Create another rule and enable it - part of routine compliance audit
    New-NetFirewallRule -DisplayName $testRuleName2 -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3306 -ErrorAction SilentlyContinue | Out-Null

    # Admin enables the newly created database rule
    Enable-NetFirewallRule -DisplayName $testRuleName2 -ErrorAction SilentlyContinue

    # Reset profile to default after audit
    Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction SilentlyContinue

    # Cleanup: Remove the test rules created during this maintenance cycle
    Remove-NetFirewallRule -DisplayName $testRuleName -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName $testRuleName2 -ErrorAction SilentlyContinue

} catch {
    # Continue on error to ensure cleanup runs
    Write-Host "Operation completed"
}

Write-Host "Firewall maintenance cycle completed"

# -- Cluster: singleton_834e59e9-f73b-4e11-8173-bbe1dc5321e8  (1 rule(s)) ---------------------
# Intent:    Attackers programmatically disable or modify Windows Firewall rules to permit ma
# Rules:     834e59e9-f73b-4e11-8173-bbe1dc5321e8
# Archetype: Software installer/updater workflow

# Scenario: Windows Defender or security software post-installation configuration
# Security tools legitimately modify firewall rules during setup/update as part of normal operation

$ErrorActionPreference = 'SilentlyContinue'
$defenderRuleName = 'Defender_Update_Service_' + (Get-Random -Minimum 10000 -Maximum 99999)
$scanRuleName = 'Defender_Scan_Service_' + (Get-Random -Minimum 10000 -Maximum 99999)

try {
    # Simulate security software creating firewall rules for its update mechanisms
    # This is typical of Windows Defender, Trend Micro, CrowdStrike, etc. during deployment

    # Create rule for Defender update service communication
    New-NetFirewallRule -DisplayName $defenderRuleName -Direction Outbound -Action Allow -Program "C:\Program Files\Windows Defender\MsMpEng.exe" -ErrorAction SilentlyContinue | Out-Null

    # Enable built-in Windows Defender firewall rules
    Enable-NetFirewallRule -DisplayGroup "Windows Defender Firewall" -ErrorAction SilentlyContinue

    # Create rule for real-time scanning engine
    New-NetFirewallRule -DisplayName $scanRuleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985 -ErrorAction SilentlyContinue | Out-Null

    # Set firewall profile to ensure Defender functions in all scenarios
    Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block -ErrorAction SilentlyContinue

    # Enable the scan service rule
    Enable-NetFirewallRule -DisplayName $scanRuleName -ErrorAction SilentlyContinue

    # Configure advanced security settings via netsh (as some installers do)
    # This generates the 'advfirewall' command-line artifacts
    cmd /c "netsh advfirewall firewall show allprofiles" | Out-Null

    # Cleanup: Remove test rules
    Remove-NetFirewallRule -DisplayName $defenderRuleName -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName $scanRuleName -ErrorAction SilentlyContinue

} catch {
    Write-Host "Security software firewall configuration completed"
}

Write-Host "Security software firewall rules configured"

# -- Cluster: singleton_56d235eb-8663-4eb8-b271-5f6801bb90e9  (1 rule(s)) ---------------------
# Intent:    Disabling IIS HTTP request logging to evade detection of web-based attack activi
# Rules:     56d235eb-8663-4eb8-b271-5f6801bb90e9
# Archetype: IT admin workflow

$iisPath = "C:\Windows\System32\inetsrv"
$appcmdExe = Join-Path $iisPath "appcmd.exe"

# Check if IIS is installed
if (-not (Test-Path $appcmdExe)) {
    Write-Host "IIS appcmd not found; IIS may not be installed on this system"
    exit 0
}

# Query current HTTP logging status for audit purposes
Write-Host "[Compliance Review] Auditing HTTP logging configuration..."
& $appcmdExe list apppool /text:name | ForEach-Object {
    Write-Host "Checking app pool: $_"
}

# Temporarily disable HTTP logging on the Default Web Site for a maintenance window
Write-Host "[Maintenance] Disabling HTTP logging on Default Web Site during scheduled maintenance..."
& $appcmdExe set site "Default Web Site" /httplogging.dontlog:true

# Verify the change
Write-Host "[Verification] Current logging status:"
& $appcmdExe list site "Default Web Site" /text:httplogging.dontlog

# Restore HTTP logging after maintenance
Start-Sleep -Seconds 2
Write-Host "[Compliance] Re-enabling HTTP logging..."
& $appcmdExe set site "Default Web Site" /httplogging.dontlog:false

# Final verification
Write-Host "[Verification] Final logging status:"
& $appcmdExe list site "Default Web Site" /text:httplogging.dontlog

Write-Host "Compliance review and maintenance completed."

# -- Cluster: singleton_56d235eb-8663-4eb8-b271-5f6801bb90e9  (1 rule(s)) ---------------------
# Intent:    Disabling IIS HTTP request logging to evade detection of web-based attack activi
# Rules:     56d235eb-8663-4eb8-b271-5f6801bb90e9
# Archetype: Software installer/updater workflow

$iisPath = "C:\Windows\System32\inetsrv"
$appcmdExe = Join-Path $iisPath "appcmd.exe"

# Check if IIS is installed
if (-not (Test-Path $appcmdExe)) {
    Write-Host "IIS appcmd not found; IIS may not be installed on this system"
    exit 0
}

# Simulate deployment automation adjusting IIS settings
Write-Host "[Deployment] Configuring IIS for application initialization..."

# Disable logging during setup phase for performance
Write-Host "[Setup Phase] Temporarily reducing I/O overhead by disabling HTTP logging..."
& $appcmdExe set apppool "DefaultAppPool" /processModel.idleTimeout:00:20:00

# Apply HTTP logging configuration update
& $appcmdExe set site "Default Web Site" /httplogging.enabled:true
& $appcmdExe set site "Default Web Site" /httplogging.dontlog:true

Start-Sleep -Seconds 3

# Re-enable logging as part of post-deployment verification
Write-Host "[Post-Deployment] Re-enabling HTTP logging for production..."
& $appcmdExe set site "Default Web Site" /httplogging.dontlog:false

Write-Host "Application initialization completed."

# -- Cluster: singleton_56d235eb-8663-4eb8-b271-5f6801bb90e9  (1 rule(s)) ---------------------
# Intent:    Disabling IIS HTTP request logging to evade detection of web-based attack activi
# Rules:     56d235eb-8663-4eb8-b271-5f6801bb90e9
# Archetype: User-driven workflow

$iisPath = "C:\Windows\System32\inetsrv"
$appcmdExe = Join-Path $iisPath "appcmd.exe"

# Check if IIS is installed
if (-not (Test-Path $appcmdExe)) {
    Write-Host "IIS appcmd not found; IIS may not be installed on this system"
    exit 0
}

# Developer debugging workflow
Write-Host "[Development] Troubleshooting IIS application performance..."

# List current app pools for context
Write-Host "[Info] Current application pools:"
& $appcmdExe list apppool /text:name

# Disable HTTP logging on staging site to reduce I/O during debugging
Write-Host "[Debugging] Disabling HTTP logging on staging site for cleaner diagnostic output..."
& $appcmdExe set site "Default Web Site" /httplogging.dontlog:true

Write-Host "[Test] Executing diagnostic queries..."
Start-Sleep -Seconds 2

# Query IIS configuration
& $appcmdExe list config "Default Web Site" /section:httplogging

Start-Sleep -Seconds 1

# Re-enable logging for production readiness
Write-Host "[Cleanup] Re-enabling HTTP logging for production deployment..."
& $appcmdExe set site "Default Web Site" /httplogging.dontlog:false

Write-Host "Debugging session completed."


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
