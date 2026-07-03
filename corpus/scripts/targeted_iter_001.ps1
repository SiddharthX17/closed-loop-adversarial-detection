# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_fe254b53-1878-4972-98fe-8576cccf15f3  (1 rule(s)) ---------------------
# Intent:    Detect execution of masqueraded Windows system binaries (svchost, lsass, explore
# Rules:     fe254b53-1878-4972-98fe-8576cccf15f3
# Archetype: IT admin workflow

# Create temporary working directory for maintenance staging
$tempDir = Join-Path $env:TEMP "sysadmin_staging_$(Get-Random)"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

try {
    # Copy system binaries to staging directory for offline diagnostic verification
    # This is a realistic admin maintenance pattern - staging tools before deployment
    Copy-Item -Path "C:\Windows\System32\svchost.exe" -Destination $tempDir -Force
    Copy-Item -Path "C:\Windows\System32\lsass.exe" -Destination $tempDir -Force
    Copy-Item -Path "C:\Windows\System32\services.exe" -Destination $tempDir -Force
    Copy-Item -Path "C:\Windows\System32\explorer.exe" -Destination $tempDir -Force

    # Validate each binary signature and version (realistic admin verification step)
    Write-Host "Verifying diagnostic tools in staging environment..."

    # Execute staged svchost for service enumeration
    & (Join-Path $tempDir "svchost.exe") -?

    # Execute staged lsass for diagnostic purposes (non-interactive)
    Start-Process -FilePath (Join-Path $tempDir "lsass.exe") -ArgumentList "-?" -NoNewWindow -Wait -ErrorAction SilentlyContinue

    # Execute staged services for service check
    & (Join-Path $tempDir "services.exe") -?

    # Execute staged explorer for file system verification
    Start-Process -FilePath (Join-Path $tempDir "explorer.exe") -ArgumentList "/?" -NoNewWindow -Wait -ErrorAction SilentlyContinue

    Write-Host "Diagnostic verification completed successfully"
} finally {
    # Clean up temporary staging directory
    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_fe254b53-1878-4972-98fe-8576cccf15f3  (1 rule(s)) ---------------------
# Intent:    Detect execution of masqueraded Windows system binaries (svchost, lsass, explore
# Rules:     fe254b53-1878-4972-98fe-8576cccf15f3
# Archetype: Software installer/updater workflow

# Software installer creates temporary extraction directory
$installStaging = Join-Path $env:TEMP "installer_temp_$(Get-Random)"
New-Item -ItemType Directory -Path $installStaging -Force | Out-Null

try {
    Write-Host "Beginning application installation..."

    # Simulate installer extraction of system utilities
    # Many legitimate installers include regsvr32, rundll32, or msiexec for component registration
    Copy-Item -Path "C:\Windows\System32\regsvr32.exe" -Destination $installStaging -Force
    Copy-Item -Path "C:\Windows\System32\rundll32.exe" -Destination $installStaging -Force
    Copy-Item -Path "C:\Windows\System32\msiexec.exe" -Destination $installStaging -Force
    Copy-Item -Path "C:\Windows\System32\dllhost.exe" -Destination $installStaging -Force

    # Installer executes regsvr32 from staging to register COM components
    Write-Host "Registering application components..."
    & (Join-Path $installStaging "regsvr32.exe") "/? " 2>$null | Out-Null

    # Installer uses rundll32 from staging for component initialization
    & (Join-Path $installStaging "rundll32.exe") "/? " 2>$null | Out-Null

    # Installer executes dllhost from staging for COM hosting
    Start-Process -FilePath (Join-Path $installStaging "dllhost.exe") -ArgumentList "-?" -NoNewWindow -Wait -ErrorAction SilentlyContinue

    # Installer queries MSI database using msiexec from staging
    & (Join-Path $installStaging "msiexec.exe") "/?" 2>$null | Out-Null

    Write-Host "Application installation completed"
} finally {
    # Clean up staging directory
    Remove-Item -Path $installStaging -Recurse -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_fe254b53-1878-4972-98fe-8576cccf15f3  (1 rule(s)) ---------------------
# Intent:    Detect execution of masqueraded Windows system binaries (svchost, lsass, explore
# Rules:     fe254b53-1878-4972-98fe-8576cccf15f3
# Archetype: Document/file operation workflow

# User application creates working directory for document processing
$appWorkDir = Join-Path $env:APPDATA "AppTempWork_$(Get-Random)"
New-Item -ItemType Directory -Path $appWorkDir -Force | Out-Null

try {
    Write-Host "Initializing document processing application..."

    # Application extracts system utilities for file handling and shell operations
    Copy-Item -Path "C:\Windows\System32\notepad.exe" -Destination $appWorkDir -Force
    Copy-Item -Path "C:\Windows\System32\calc.exe" -Destination $appWorkDir -Force
    Copy-Item -Path "C:\Windows\System32\conhost.exe" -Destination $appWorkDir -Force
    Copy-Item -Path "C:\Windows\System32\taskhostw.exe" -Destination $appWorkDir -Force

    # Application verifies shell utilities are functional
    Write-Host "Validating system integration tools..."

    # Run notepad for document verification
    Start-Process -FilePath (Join-Path $appWorkDir "notepad.exe") -ArgumentList "/?" -NoNewWindow -Wait -ErrorAction SilentlyContinue

    # Run calc for validation check
    Start-Process -FilePath (Join-Path $appWorkDir "calc.exe") -ArgumentList "/?" -NoNewWindow -Wait -ErrorAction SilentlyContinue

    # Run conhost for console operations verification
    & (Join-Path $appWorkDir "conhost.exe") 2>$null | Out-Null

    # Run taskhostw for task scheduling operations
    Start-Process -FilePath (Join-Path $appWorkDir "taskhostw.exe") -ArgumentList "-?" -NoNewWindow -Wait -ErrorAction SilentlyContinue

    Write-Host "Document processing application ready"
} finally {
    # Clean up working directory
    Remove-Item -Path $appWorkDir -Recurse -Force -ErrorAction SilentlyContinue
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
