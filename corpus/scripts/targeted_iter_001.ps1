# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 2
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_26ad0693-16f9-4de2-8086-16e93b214f49  (1 rule(s)) ---------------------
# Intent:    Attackers use secure deletion utilities (SDelete, Cipher) to irreversibly wipe f
# Rules:     26ad0693-16f9-4de2-8086-16e93b214f49
# Archetype: IT admin workflow

$ErrorActionPreference = 'SilentlyContinue'
$workDir = Join-Path $env:TEMP 'sysadmin_cleanup'
if (Test-Path $workDir) { Remove-Item $workDir -Recurse -Force }
$null = New-Item -ItemType Directory -Path $workDir -Force

# IT workflow: Secure cleanup of a workstation scheduled for refresh
# This simulates downloading and executing SDelete for NIST-compliant data sanitization
cd $workDir

# Download SDelete from official Microsoft Sysinternals source
$sdelUrl = 'https://download.sysinternals.com/files/SDelete.zip'
$zipFile = Join-Path $workDir 'SDelete.zip'
$extractDir = Join-Path $workDir 'sdelete_tools'

Write-Host 'Downloading SDelete from Sysinternals...'
Invoke-WebRequest -Uri $sdelUrl -OutFile $zipFile -ErrorAction SilentlyContinue | Out-Null

if (Test-Path $zipFile) {
    Expand-Archive -Path $zipFile -DestinationPath $extractDir -Force

    # Create a test file to securely delete (simulating residual data)
    $testData = Join-Path $workDir 'tempfile.txt'
    'sensitive data to be securely deleted' | Out-File -FilePath $testData -Encoding ASCII

    # Execute SDelete with -accepteula flag for non-interactive operation
    # This is standard for automated/scheduled sanitization workflows
    $sdelExe = Get-ChildItem -Path $extractDir -Filter 'sdelete*.exe' -Recurse | Select-Object -First 1

    if ($sdelExe) {
        Write-Host "Executing secure deletion: $($sdelExe.FullName) -accepteula -p 3 $testData"
        & $sdelExe.FullName -accepteula -p 3 $testData
    }
}

# Clean up working directory
Write-Host 'Cleanup complete.'
Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_26ad0693-16f9-4de2-8086-16e93b214f49  (1 rule(s)) ---------------------
# Intent:    Attackers use secure deletion utilities (SDelete, Cipher) to irreversibly wipe f
# Rules:     26ad0693-16f9-4de2-8086-16e93b214f49
# Archetype: Software installer/updater workflow

$ErrorActionPreference = 'SilentlyContinue'
$workDir = Join-Path $env:TEMP 'disk_maintenance'
if (Test-Path $workDir) { Remove-Item $workDir -Recurse -Force }
$null = New-Item -ItemType Directory -Path $workDir -Force

cd $workDir

# Software deployment workflow: Post-install disk sanitization
# This simulates a deployment tool hardening step that securely wipes free space
# after installing sensitive enterprise software

Write-Host 'Beginning post-deployment disk sanitization...'

# Create some temporary installer artifacts to simulate real deployment scenario
$tempInstaller = Join-Path $workDir 'setup_temp.bin'
$null = New-Item -ItemType File -Path $tempInstaller -Force

# Write some mock installer data
1..1000 | ForEach-Object {
    Add-Content -Path $tempInstaller -Value "Binary payload chunk $_" -ErrorAction SilentlyContinue
}

# Execute Cipher to wipe free space on C: drive
# /w parameter securely erases free space - legitimate hardening step
# Using the system drive (C:) is standard for deployment sanitization
Write-Host 'Executing Cipher.exe /w:C: to sanitize free space...'
try {
    cipher /w:C: | Out-Null
} catch {
    # Cipher may fail in container environments; that's expected
    Write-Host 'Note: Cipher.exe may not fully execute in container/CI environments'
}

# Clean up local working directory
Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'Disk maintenance completed.'


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
