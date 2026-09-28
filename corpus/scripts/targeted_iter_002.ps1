# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   1  |  Feasible: 1  |  Variants: 2
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_5cb3c5ba-b5cf-47eb-be4b-769a7a8a94fc  (1 rule(s)) ---------------------
# Intent:    Attackers create malicious Windows services that masquerade as legitimate svchos
# Rules:     5cb3c5ba-b5cf-47eb-be4b-769a7a8a94fc
# Archetype: IT admin workflow

# Create a temporary service configuration for enterprise monitoring infrastructure
$serviceFile = Join-Path $env:TEMP "svc_monitor.vbs"

# Write a harmless WMI monitoring script
$monitorScript = @'
Set objWMIService = GetObject("winmgmts:")
Set colItems = objWMIService.ExecQuery("Select * from Win32_Processor")
For Each objItem in colItems
    WScript.Echo "CPU Count: " & objItem.NumberOfCores
Next
'@

$monitorScript | Out-File -FilePath $serviceFile -Encoding ASCII -Force

# Create the service with sc.exe pointing to a legitimate system path
# This represents an admin deploying a managed service for system monitoring
sc.exe create "MonitoringService" binpath= "$env:SystemRoot\System32\svchost.exe -k netsvcs" | Out-Null

# Verify the service was created in registry
Start-Sleep -Milliseconds 500
$servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\MonitoringService"
if (Test-Path $servicePath) {
    # Service creation succeeded, verify binpath in registry
    $binPathValue = (Get-ItemProperty -Path $servicePath -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
    Write-Host "Service created with binpath: $binPathValue"
}

# Clean up: remove the service and temporary file
sc.exe delete "MonitoringService" 2>$null | Out-Null
Start-Sleep -Milliseconds 500
Remove-Item -Path $serviceFile -Force -ErrorAction SilentlyContinue
Remove-Item -Path $servicePath -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_5cb3c5ba-b5cf-47eb-be4b-769a7a8a94fc  (1 rule(s)) ---------------------
# Intent:    Attackers create malicious Windows services that masquerade as legitimate svchos
# Rules:     5cb3c5ba-b5cf-47eb-be4b-769a7a8a94fc
# Archetype: Software installer/updater workflow

# Simulating an enterprise update mechanism registering a service
# This mirrors behavior of Windows Update, Defender, or similar agents

# Create a temporary PowerShell script that will be hosted as a service
$serviceScript = Join-Path $env:TEMP "health_check.ps1"
@'
# Health check monitoring script
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
$lastCheck = Get-Date
Write-EventLog -LogName "System" -Source "System" -EventId 1000 -Message "Health check initiated" -ErrorAction SilentlyContinue
'@ | Out-File -FilePath $serviceScript -Encoding UTF8 -Force

# Register a service with sc.exe using the standard svchost architecture
# The binpath references the standard svchost.exe with netsvcs group
sc.exe create "SystemHealthService" binpath= "$env:SystemRoot\System32\svchost.exe -k netsvcs" | Out-Null

# Wait for registry to catch up
Start-Sleep -Milliseconds 300

# Verify service was created
$servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\SystemHealthService"
if (Test-Path $servicePath) {
    $displayName = (Get-ItemProperty -Path $servicePath -Name DisplayName -ErrorAction SilentlyContinue).DisplayName
    Write-Host "Service registration completed."
}

# Cleanup
sc.exe delete "SystemHealthService" 2>$null | Out-Null
Start-Sleep -Milliseconds 300
Remove-Item -Path $serviceScript -Force -ErrorAction SilentlyContinue


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
