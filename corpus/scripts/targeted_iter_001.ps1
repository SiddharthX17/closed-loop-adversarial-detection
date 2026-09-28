# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 2
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_c380a957-a8b3-4845-9aac-337cc41868f5  (1 rule(s)) ---------------------
# Intent:    Attackers hijacking Windows service ImagePath registry values to point to script
# Rules:     c380a957-a8b3-4845-9aac-337cc41868f5
# Archetype: IT admin workflow

# Admin task: Configure custom service for log aggregation
$ServiceName = 'CustomLogAggregator'
$ServicePath = "C:\Windows\System32\svchost.exe"
$TestScriptPath = Join-Path $env:TEMP 'aggregator_service.ps1'

# Create a benign PowerShell script that the service would execute
$ScriptContent = @'
# Log aggregation script
Write-Host "Service started"
$LogPath = Join-Path $env:TEMP "service_logs.txt"
Add-Content -Path $LogPath -Value "$(Get-Date): Service activity logged"
'@

$ScriptContent | Out-File -FilePath $TestScriptPath -Encoding UTF8 -Force

try {
    # Simulate registry operation: Set service ImagePath (demonstrates detection pattern)
    # Real services use this structure: ImagePath = "C:\path\to\service.exe -parameters"
    # In this case, we're configuring a service that uses PowerShell for administrative tasks
    $ServiceRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\CustomLogAggregator'

    # Only proceed if we have admin rights and registry path is accessible
    if (-not (Test-Path $ServiceRegPath)) {
        New-Item -Path $ServiceRegPath -Force -ErrorAction SilentlyContinue | Out-Null
    }

    # Set ImagePath that triggers detection: PowerShell with script invocation
    $ImagePathValue = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"$TestScriptPath\""

    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\CustomLogAggregator" /v "ImagePath" /t REG_SZ /d "$ImagePathValue" /f 2>$null

    # Alternative: use -enc parameter (base64 encoded command) - another detection pattern
    $CommandString = "Get-EventLog -LogName System -Newest 10 | ConvertTo-Json"
    $EncodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($CommandString))
    $ImagePathEncoded = "powershell.exe -enc $EncodedCommand"

    reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\CustomLogAggregator" /v "ImagePath" /t REG_SZ /d "$ImagePathEncoded" /f 2>$null

    # Verify the registry modification was recorded
    Start-Sleep -Milliseconds 100

    # Registry cleanup
    reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\CustomLogAggregator" /f 2>$null

} finally {
    # Clean up test script
    if (Test-Path $TestScriptPath) {
        Remove-Item -Path $TestScriptPath -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_c380a957-a8b3-4845-9aac-337cc41868f5  (1 rule(s)) ---------------------
# Intent:    Attackers hijacking Windows service ImagePath registry values to point to script
# Rules:     c380a957-a8b3-4845-9aac-337cc41868f5
# Archetype: Software installer/updater workflow

# Software deployment automation: Register helper services via registry
# Simulates enterprise configuration management or deployment tool behavior

$HelperServices = @(
    @{
        ServiceName = 'DeprecatedHelper1'
        ScriptType = 'cmd.exe'
    },
    @{
        ServiceName = 'LegacyConfigService'
        ScriptType = 'wscript.exe'
    }
)

try {
    foreach ($Service in $HelperServices) {
        $RegPath = "HKLM\SYSTEM\CurrentControlSet\Services\$($Service.ServiceName)"

        # Create service registry entry if it does not exist
        if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($Service.ServiceName)")) {
            New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($Service.ServiceName)" -Force -ErrorAction SilentlyContinue | Out-Null
        }

        # Set ImagePath using reg.exe - typical installer behavior
        # This represents the detection pattern: reg.exe + binpath + scripting interpreter
        $ImagePath = "$($Service.ScriptType) /c echo Configuration applied"
        reg.exe add $RegPath /v "ImagePath" /t REG_SZ /d "$ImagePath" /f 2>$null

        # Add service parameters
        reg.exe add $RegPath /v "Type" /t REG_DWORD /d "16" /f 2>$null
        reg.exe add $RegPath /v "Start" /t REG_DWORD /d "3" /f 2>$null

        Start-Sleep -Milliseconds 50
    }

    # Also demonstrate cscript.exe in ImagePath (another detection variant)
    $CSCriptServicePath = "HKLM\SYSTEM\CurrentControlSet\Services\ConfigurationHelper"
    if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\ConfigurationHelper")) {
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ConfigurationHelper" -Force -ErrorAction SilentlyContinue | Out-Null
    }

    $CScriptImagePath = "cscript.exe //E:vbscript //Nologo \"C:\Windows\System32\config.vbs\""
    reg.exe add $CSCriptServicePath /v "ImagePath" /t REG_SZ /d "$CScriptImagePath" /f 2>$null

    # Demonstrate mshta.exe and rundll32.exe patterns
    $MshtaServicePath = "HKLM\SYSTEM\CurrentControlSet\Services\MHTAHelper"
    if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\MHTAHelper")) {
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MHTAHelper" -Force -ErrorAction SilentlyContinue | Out-Null
    }

    $MshtaImagePath = "mshta.exe \"javascript:void(0)\""
    reg.exe add $MshtaServicePath /v "ImagePath" /t REG_SZ /d "$MshtaImagePath" /f 2>$null

    $RundllServicePath = "HKLM\SYSTEM\CurrentControlSet\Services\RundllHelper"
    if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\RundllHelper")) {
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RundllHelper" -Force -ErrorAction SilentlyContinue | Out-Null
    }

    $RundllImagePath = "rundll32.exe shell32.dll,ShellAbout"
    reg.exe add $RundllServicePath /v "ImagePath" /t REG_SZ /d "$RundllImagePath" /f 2>$null

    Start-Sleep -Milliseconds 100

} finally {
    # Clean up all created service registry entries
    foreach ($Service in $HelperServices) {
        reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\$($Service.ServiceName)" /f 2>$null
    }

    reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\ConfigurationHelper" /f 2>$null
    reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\MHTAHelper" /f 2>$null
    reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\RundllHelper" /f 2>$null
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
