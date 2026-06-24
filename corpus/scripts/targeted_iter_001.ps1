# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 2
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_f4f5f1f2-c7c7-4290-850a-54464de8bade  (1 rule(s)) ---------------------
# Intent:    Credential Access via VSS Shadow Copy SAM Hive Extraction - detecting attempts t
# Rules:     f4f5f1f2-c7c7-4290-850a-54464de8bade
# Archetype: IT admin workflow

# Legitimate VSS snapshot inventory and registry file validation for DR planning
# This is standard pre-recovery verification performed by IT administrators

$VssAdminPath = 'C:\Windows\System32\vssadmin.exe'

if (-not (Test-Path $VssAdminPath)) {
    Write-Host 'VSS Admin not available on this system'
    exit 0
}

# Query available shadow copies (common DR validation task)
$shadowCopies = & vssadmin list shadows 2>&1

if ($shadowCopies -match 'Shadow Copy ID') {
    # Extract the first shadow copy from results for analysis
    $shadowId = ($shadowCopies | Where-Object { $_ -match 'Shadow Copy ID' } | Select-Object -First 1) -replace '.*\{(.+?)\}.*', '{$1}'

    if ($shadowId -match '^\{[a-f0-9\-]+\}$') {
        # Create temporary mount point for validation
        $mountPath = Join-Path $env:TEMP ('vss_validate_{0}' -f [System.Guid]::NewGuid().ToString('n').Substring(0,8))

        # Mount shadow copy for disaster recovery file verification
        # This is standard practice to verify backup contents before recovery
        $mountCmd = "cmd /c mklink /d `"$mountPath`" `"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\`" 2>nul"
        Invoke-Expression $mountCmd | Out-Null

        Start-Sleep -Milliseconds 500

        # Verify critical system files are present in shadow copy (legitimate validation)
        if (Test-Path $mountPath) {
            # Check for SAM file presence in shadow copy
            if (Test-Path (Join-Path $mountPath 'sam')) {
                Write-Host 'SAM hive present in shadow copy backup'
            }

            # Verify SYSTEM hive is in backup
            if (Test-Path (Join-Path $mountPath 'system')) {
                Write-Host 'SYSTEM hive present in shadow copy backup'
            }

            # Verify SECURITY hive is in backup
            if (Test-Path (Join-Path $mountPath 'security')) {
                Write-Host 'SECURITY hive present in shadow copy backup'
            }

            # Clean up mount point
            cmd /c rmdir /s /q "$mountPath" 2>nul
            Start-Sleep -Milliseconds 200
        }
    }
}

Write-Host 'VSS backup validation complete'

# SKIPPED variant 'Software installer/updater workflow': blocked pattern: cmd batch syntax ('if exist ')


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
