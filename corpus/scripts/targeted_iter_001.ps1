# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   2  |  Feasible: 2  |  Variants: 6
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_c646b758-dfb0-4315-9d43-4d28db791bc3  (1 rule(s)) ---------------------
# Intent:    Detect execution of critical Windows system processes (e.g., lsass.exe, svchost.
# Rules:     c646b758-dfb0-4315-9d43-4d28db791bc3
# Archetype: Software installer/updater workflow

$tempDir = Join-Path $env:TEMP "installer_$(Get-Random)"
[void](New-Item -ItemType Directory -Path $tempDir -Force)

try {
    # Simulate installer verification: extract svchost.exe to temp for hash validation
    $sourceFile = 'C:\Windows\System32\svchost.exe'
    $tempCopy = Join-Path $tempDir 'svchost.exe'
    Copy-Item -Path $sourceFile -Destination $tempCopy -Force

    # Verify the binary signature
    $signature = Get-AuthenticodeSignature -FilePath $tempCopy
    if ($signature.Status -ne 'Valid') {
        Write-Host 'Binary validation failed'
    }

    # Compare version info with canonical location
    $tempVersion = (Get-Item $tempCopy).VersionInfo.FileVersion
    $sysVersion = (Get-Item $sourceFile).VersionInfo.FileVersion

    if ($tempVersion -eq $sysVersion) {
        Write-Host 'Version match confirmed'
    }

    # Simulate extraction workflow for csrss.exe as well
    $csrssSource = 'C:\Windows\System32\csrss.exe'
    $csrssCopy = Join-Path $tempDir 'csrss.exe'
    Copy-Item -Path $csrssSource -Destination $csrssCopy -Force

    # Quick metadata inspection
    $metadata = Get-Item $csrssCopy | Select-Object Name, Length, CreationTime

    # Simulate smss.exe copy for staged deployment verification
    $smssSource = 'C:\Windows\System32\smss.exe'
    $smssCopy = Join-Path $tempDir 'smss.exe'
    Copy-Item -Path $smssSource -Destination $smssCopy -Force

    # Validate all extracted binaries are present
    $extractedFiles = Get-ChildItem -Path $tempDir -Filter '*.exe'
    Write-Host "Extracted $($extractedFiles.Count) system binaries for validation"

} finally {
    # Clean up temporary files
    if (Test-Path -Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force
    }
}

# -- Cluster: singleton_c646b758-dfb0-4315-9d43-4d28db791bc3  (1 rule(s)) ---------------------
# Intent:    Detect execution of critical Windows system processes (e.g., lsass.exe, svchost.
# Rules:     c646b758-dfb0-4315-9d43-4d28db791bc3
# Archetype: IT admin workflow

$recoveryDir = Join-Path $env:TEMP "recovery_media_$(Get-Random)"
[void](New-Item -ItemType Directory -Path $recoveryDir -Force)

try {
    Write-Host "Preparing recovery media staging directory: $recoveryDir"

    # Administrator prepares offline recovery toolkit
    # Copy critical system processes needed for recovery boot
    $systemProcs = @('lsass.exe', 'winlogon.exe', 'services.exe', 'svchost.exe', 'dwm.exe', 'explorer.exe')

    foreach ($proc in $systemProcs) {
        $srcPath = Join-Path 'C:\Windows\System32' $proc
        if (Test-Path -Path $srcPath) {
            $destPath = Join-Path $recoveryDir $proc
            Copy-Item -Path $srcPath -Destination $destPath -Force
            Write-Host "Staged $proc for recovery"
        }
    }

    # Create inventory manifest of staged binaries
    $manifest = New-Object System.Collections.ArrayList
    Get-ChildItem -Path $recoveryDir -Filter '*.exe' | ForEach-Object {
        $manifestEntry = @{
            Name = $_.Name
            Size = $_.Length
            Hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
        }
        [void]$manifest.Add($manifestEntry)
    }

    Write-Host "Recovery toolkit prepared with $($manifest.Count) binaries"

    # Verify all expected binaries are present
    $stagedCount = (Get-ChildItem -Path $recoveryDir -Filter '*.exe').Count
    if ($stagedCount -ge 3) {
        Write-Host "Recovery media validation passed"
    }

} finally {
    # Clean up recovery staging directory
    if (Test-Path -Path $recoveryDir) {
        Remove-Item -Path $recoveryDir -Recurse -Force
        Write-Host "Recovery staging directory cleaned"
    }
}

# -- Cluster: singleton_c646b758-dfb0-4315-9d43-4d28db791bc3  (1 rule(s)) ---------------------
# Intent:    Detect execution of critical Windows system processes (e.g., lsass.exe, svchost.
# Rules:     c646b758-dfb0-4315-9d43-4d28db791bc3
# Archetype: Document/file operation workflow

$scanDir = Join-Path $env:TEMP "integrity_scan_$(Get-Random)"
[void](New-Item -ItemType Directory -Path $scanDir -Force)

try {
    Write-Host "Initiating system file integrity scan"

    # Security utility extracts binaries for signature and dependency analysis
    $criticalProcs = @(
        'lsm.exe', 'msdtc.exe', 'searchindexer.exe',
        'wmiprvse.exe', 'audiodg.exe', 'runtimebroker.exe',
        'fontdrvhost.exe', 'spoolsv.exe'
    )

    $scanResults = @{}

    foreach ($proc in $criticalProcs) {
        $srcPath = Join-Path 'C:\Windows\System32' $proc
        if (Test-Path -Path $srcPath) {
            $copyPath = Join-Path $scanDir $proc
            Copy-Item -Path $srcPath -Destination $copyPath -Force

            # Analyze extracted binary
            $fileInfo = Get-Item -Path $copyPath
            $sigInfo = Get-AuthenticodeSignature -FilePath $copyPath

            $scanResults[$proc] = @{
                Size = $fileInfo.Length
                SignatureValid = ($sigInfo.Status -eq 'Valid')
                Issuer = $sigInfo.SignerCertificate.Issuer
            }
        }
    }

    # Generate scan report
    $reportPath = Join-Path $scanDir 'scan_report.txt'
    $reportContent = "System File Integrity Scan Report`n"
    $reportContent += "Timestamp: $(Get-Date)`n"
    $reportContent += "Files Scanned: $($scanResults.Count)`n"
    $reportContent += "Signed Files: $(($scanResults.Values | Where-Object { $_.SignatureValid }).Count)`n"

    Set-Content -Path $reportPath -Value $reportContent

    Write-Host "Scan complete: Analyzed $($scanResults.Count) system binaries"

    # Verify integrity report was created
    if (Test-Path -Path $reportPath) {
        $reportSize = (Get-Item -Path $reportPath).Length
        Write-Host "Integrity report generated: $reportSize bytes"
    }

} finally {
    # Clean up scan working directory
    if (Test-Path -Path $scanDir) {
        Remove-Item -Path $scanDir -Recurse -Force
        Write-Host "Scan directory cleaned"
    }
}

# -- Cluster: singleton_1dee9b81-389f-4a47-9112-702c7c89ec01  (1 rule(s)) ---------------------
# Intent:    Theft of SAM hive credentials by accessing the hive through Volume Shadow Copy d
# Rules:     1dee9b81-389f-4a47-9112-702c7c89ec01
# Archetype: IT admin workflow

$VSSShadows = Get-WmiObject Win32_ShadowCopy | Select-Object -First 3
foreach ($Shadow in $VSSShadows) {
    $Device = $Shadow.DeviceName
    Write-Host "Verifying SAM hive in shadow copy: $Device"
    $SAMPath = Join-Path -Path $Device -ChildPath "\Windows\System32\config\sam"
    if (Test-Path $SAMPath) {
        Write-Host "SAM hive found at $SAMPath - backup integrity confirmed"
    }
}
Write-Host "Backup verification completed"

# -- Cluster: singleton_1dee9b81-389f-4a47-9112-702c7c89ec01  (1 rule(s)) ---------------------
# Intent:    Theft of SAM hive credentials by accessing the hive through Volume Shadow Copy d
# Rules:     1dee9b81-389f-4a47-9112-702c7c89ec01
# Archetype: Software installer/updater workflow

$BackupLog = "$env:TEMP\shadow_inventory_$(Get-Random).log"
$Shadows = Get-WmiObject Win32_ShadowCopy
if ($Shadows) {
    foreach ($Shadow in $Shadows) {
        $DevName = $Shadow.DeviceName
        $SAMPath = $DevName + "\Windows\System32\config\sam"
        Add-Content -Path $BackupLog -Value "Device: $DevName - SAM Path: $SAMPath"
    }
    Write-Host "Inventory logged to $BackupLog"
    Remove-Item -Path $BackupLog -Force
} else {
    Write-Host "No shadow copies available"
}

# -- Cluster: singleton_1dee9b81-389f-4a47-9112-702c7c89ec01  (1 rule(s)) ---------------------
# Intent:    Theft of SAM hive credentials by accessing the hive through Volume Shadow Copy d
# Rules:     1dee9b81-389f-4a47-9112-702c7c89ec01
# Archetype: Document/file operation workflow

$ReportFile = "$env:TEMP\compliance_report_$(Get-Date -Format yyyyMMdd).txt"
Set-Content -Path $ReportFile -Value "Shadow Copy System File Coverage Report`n"
Add-Content -Path $ReportFile -Value "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n`n"
$ShadowCopies = Get-WmiObject Win32_ShadowCopy
if ($ShadowCopies) {
    foreach ($Copy in $ShadowCopies) {
        $Device = $Copy.DeviceName
        $SystemFilePath = "$Device\Windows\System32\config\sam"
        $Status = "Present"
        Add-Content -Path $ReportFile -Value "Shadow: $Device`nSAM Location: $SystemFilePath`nStatus: $Status`n"
    }
}
Write-Host "Report saved to $ReportFile"
Start-Sleep -Seconds 1
Remove-Item -Path $ReportFile -Force


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
