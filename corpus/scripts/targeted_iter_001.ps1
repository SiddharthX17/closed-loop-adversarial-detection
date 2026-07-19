# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_5d770769-75c9-4b62-af7f-825351746d5d  (1 rule(s)) ---------------------
# Intent:    BITS abuse via desktopimgdownldr.exe with malicious /lockscreenurl parameter poi
# Rules:     5d770769-75c9-4b62-af7f-825351746d5d
# Archetype: IT admin workflow

# Lock screen branding configuration by IT admin
# This script deploys a corporate lock screen image URL to standardize desktop appearance
$imageUrl = "https://corp-cdn.internal/branding/lockscreen.jpg"
$tempDir = Join-Path $env:TEMP ("lockscreen_$(Get-Random)")
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

try {
    # Simulate legitimate IT admin invoking desktopimgdownldr.exe with corporate branding image
    # This is realistic as IT departments do standardize lock screens via this binary
    $desktopImgPath = "C:\Windows\System32\desktopimgdownldr.exe"
    if (Test-Path $desktopImgPath) {
        # Call with legitimate image file parameter
        & $desktopImgPath /lockscreenurl:"C:\Windows\Branding\lockscreen.png"
    }
}
finally {
    if (Test-Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_5d770769-75c9-4b62-af7f-825351746d5d  (1 rule(s)) ---------------------
# Intent:    BITS abuse via desktopimgdownldr.exe with malicious /lockscreenurl parameter poi
# Rules:     5d770769-75c9-4b62-af7f-825351746d5d
# Archetype: Software installer/updater workflow

# Desktop image deployment during enterprise OS imaging
# Software deployment system configures lock screen during baseline build
$configDir = Join-Path $env:TEMP ("deploy_$(Get-Random)")
New-Item -ItemType Directory -Path $configDir -Force | Out-Null
$logFile = Join-Path $configDir "deployment.log"

try {
    # Log the deployment action
    Add-Content -Path $logFile -Value "[$(Get-Date)] Starting lock screen deployment"

    # Enterprise imaging tool invokes desktopimgdownldr.exe with image URL
    # This is legitimate as many enterprise deployment solutions do this
    $desktopImgPath = "C:\Windows\System32\desktopimgdownldr.exe"
    if (Test-Path $desktopImgPath) {
        # Deployment with legitimate image format
        & $desktopImgPath /lockscreenurl:"https://intranet.company.net/media/corporate_lockscreen.bmp" 2>&1 | Add-Content -Path $logFile
    }

    Add-Content -Path $logFile -Value "[$(Get-Date)] Lock screen deployment completed"
}
finally {
    if (Test-Path $configDir) {
        Remove-Item -Path $configDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_5d770769-75c9-4b62-af7f-825351746d5d  (1 rule(s)) ---------------------
# Intent:    BITS abuse via desktopimgdownldr.exe with malicious /lockscreenurl parameter poi
# Rules:     5d770769-75c9-4b62-af7f-825351746d5d
# Archetype: User-driven workflow

# User or support tech applies custom lock screen branding
# Represents legitimate manual configuration of desktop personalization
$workDir = Join-Path $env:TEMP ("personalization_$(Get-Random)")
New-Item -ItemType Directory -Path $workDir -Force | Out-Null

try {
    # Simulate user or support technician invoking desktopimgdownldr.exe
    # with custom lock screen image
    $desktopImgPath = "C:\Windows\System32\desktopimgdownldr.exe"
    if (Test-Path $desktopImgPath) {
        # User-provided or support-supplied image reference
        & $desktopImgPath /lockscreenurl:"C:\Users\Public\Pictures\custom_lockscreen.gif"
    }
}
finally {
    if (Test-Path $workDir) {
        Remove-Item -Path $workDir -Recurse -Force -ErrorAction SilentlyContinue
    }
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
