# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 2
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_82c9d4ca-e5a4-4325-9c2e-9a51dc3c24a0  (1 rule(s)) ---------------------
# Intent:    Attackers accessing credential hives (SAM, SYSTEM, SECURITY, NTDS.dit) through V
# Rules:     82c9d4ca-e5a4-4325-9c2e-9a51dc3c24a0
# Archetype: IT admin workflow

$vssPath = '\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1'
$registryFiles = @('config\sam', 'config\system', 'config\security')

# Create a temporary directory for this backup verification task
$tempBackupDir = Join-Path $env:TEMP "backup_verification_$(Get-Random)"
[void](New-Item -ItemType Directory -Path $tempBackupDir -ErrorAction SilentlyContinue)

try {
    # Verify backup accessibility by checking file existence through VSS path
    # This is a legitimate disaster recovery procedure
    foreach ($file in $registryFiles) {
        $vssFullPath = Join-Path $vssPath $file
        # Attempt to read file metadata without extracting credentials
        $testPath = Test-Path -LiteralPath $vssFullPath -ErrorAction SilentlyContinue

        # Use certutil to validate backup integrity (legitimate admin tool)
        if ($testPath) {
            Write-Output "Backup file accessible: $vssFullPath"
        }
    }

    # Also verify NTDS.dit accessibility for domain controller recovery scenarios
    $ntdsVssPath = Join-Path $vssPath 'ntds.dit'
    $ntdsExists = Test-Path -LiteralPath $ntdsVssPath -ErrorAction SilentlyContinue
    if ($ntdsExists) {
        Write-Output "NTDS backup found: $ntdsVssPath"
    }

    # Document the backup verification in a local report
    $reportPath = Join-Path $tempBackupDir 'vss_verification.txt'
    "Backup Verification Report\nTimestamp: $(Get-Date)\nPath checked: $vssPath\nFiles verified: $($registryFiles -join ', ')" | Out-File -FilePath $reportPath

} finally {
    # Cleanup
    Remove-Item -Path $tempBackupDir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_82c9d4ca-e5a4-4325-9c2e-9a51dc3c24a0  (1 rule(s)) ---------------------
# Intent:    Attackers accessing credential hives (SAM, SYSTEM, SECURITY, NTDS.dit) through V
# Rules:     82c9d4ca-e5a4-4325-9c2e-9a51dc3c24a0
# Archetype: Software installer/updater workflow

# Enterprise backup software performing pre-restore validation
# This legitimately checks VSS snapshots contain required system files

$backupToolDir = Join-Path $env:TEMP "enterprise_backup_tool_$(Get-Random)"
[void](New-Item -ItemType Directory -Path $backupToolDir -ErrorAction SilentlyContinue)

try {
    # Query available shadow copies for recovery planning
    $shadowCopies = @(1..3)  # Simulate checking multiple VSS snapshots

    foreach ($copyIndex in $shadowCopies) {
        $vssDevicePath = "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy$copyIndex"

        # Validate presence of critical registry hives in each snapshot
        $criticalHives = @(
            'config\sam',
            'config\system',
            'config\security'
        )

        foreach ($hive in $criticalHives) {
            $fullPath = Join-Path $vssDevicePath $hive
            # Check if hive exists in this shadow copy
            $exists = Test-Path -LiteralPath $fullPath -ErrorAction SilentlyContinue
            if ($exists) {
                # Log the finding for recovery validation
                Add-Content -Path (Join-Path $backupToolDir 'recovery_plan.log') -Value "[$(Get-Date)] Found $hive in shadow copy $copyIndex"
            }
        }

        # Also check for NTDS for domain-joined systems
        $ntdsPath = Join-Path $vssDevicePath 'ntds.dit'
        $ntdsExists = Test-Path -LiteralPath $ntdsPath -ErrorAction SilentlyContinue
        if ($ntdsExists) {
            Add-Content -Path (Join-Path $backupToolDir 'recovery_plan.log') -Value "[$(Get-Date)] Domain services data found in shadow copy $copyIndex"
        }
    }

    # Simulate backup tool creating a recovery manifest
    if (Test-Path (Join-Path $backupToolDir 'recovery_plan.log')) {
        $manifest = Get-Content (Join-Path $backupToolDir 'recovery_plan.log') | Measure-Object -Line
        Write-Output "Recovery manifest ready: $($manifest.Lines) items catalogued"
    }

} finally {
    # Cleanup all temporary files
    Remove-Item -Path $backupToolDir -Recurse -Force -ErrorAction SilentlyContinue
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
