# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_86404854-1773-4a92-87b4-ac08c7a9c07d  (1 rule(s)) ---------------------
# Intent:    Detects shell interpreters (cmd.exe, powershell.exe, etc.) initiating outbound H
# Rules:     86404854-1773-4a92-87b4-ac08c7a9c07d
# Archetype: Software installer/updater workflow

# Simulate package manager downloading installer manifest from GitHub
# This is legitimate behavior for Chocolatey updating its package cache

$ChocoPath = 'C:\ProgramData\chocolatey'
if (-not (Test-Path $ChocoPath)) {
    New-Item -ItemType Directory -Path $ChocoPath -Force | Out-Null
}

# Simulate Chocolatey invoking PowerShell to fetch package metadata from GitHub
# Real Chocolatey installations do this during package resolution
$manifestUrl = 'https://raw.githubusercontent.com/chocolatey/chocolatey-coreteam-packages/master/packages'
$tempManifest = Join-Path $env:TEMP 'choco_manifest.xml'

try {
    # Use PowerShell to invoke web request, simulating package manager behavior
    # This triggers Sysmon NetworkConnect event: powershell.exe -> HTTPS -> raw.githubusercontent.com:443
    $result = Invoke-WebRequest -Uri "$manifestUrl" -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
    if ($result) {
        $result.Content | Out-File -FilePath $tempManifest -Force
    }
} catch {
    # Silently continue if GitHub is unreachable; the event is what matters
}

# Cleanup
if (Test-Path $tempManifest) {
    Remove-Item -Path $tempManifest -Force
}

Write-Output 'Package manager manifest check completed.'

# SKIPPED variant 'IT admin workflow': blocked pattern: payload download ('downloadfile(')

# -- Cluster: singleton_86404854-1773-4a92-87b4-ac08c7a9c07d  (1 rule(s)) ---------------------
# Intent:    Detects shell interpreters (cmd.exe, powershell.exe, etc.) initiating outbound H
# Rules:     86404854-1773-4a92-87b4-ac08c7a9c07d
# Archetype: User-driven workflow

# Simulate user or automation fetching a file via command shell from transfer service
# This is realistic for temporary file sharing and log collection workflows

$transferUrl = 'https://transfer.sh/test.txt'
$downloadPath = Join-Path $env:TEMP 'downloaded_data.txt'

try {
    # Invoke cmd.exe with curl to fetch file from transfer.sh
    # Triggers: cmd.exe -> HTTPS -> transfer.sh:443 (or powershell making the connection)
    # Use PowerShell to simulate the download since curl requires additional setup
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $transferUrl -OutFile $downloadPath -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
} catch {
    # Expected to fail; URL is not real
    # The important part is the NetworkConnect event is triggered
}

# Cleanup
if (Test-Path $downloadPath) {
    Remove-Item -Path $downloadPath -Force
}

Write-Output 'File transfer operation completed.'


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
