# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_7cb52374-6b8d-4faf-a3b5-f8079a9c96d6  (1 rule(s)) ---------------------
# Intent:    Detect use of the SDelete secure-deletion tool with the -accepteula flag, a tech
# Rules:     7cb52374-6b8d-4faf-a3b5-f8079a9c96d6
# Archetype: IT admin workflow

$TempPath = [System.IO.Path]::GetTempPath()
$TestFile = Join-Path $TempPath "legacy_data_$([System.IO.Path]::GetRandomFileName())"

# Create a temporary file containing non-sensitive test content to be securely deleted
New-Item -ItemType File -Path $TestFile -Force | Out-Null
Set-Content -Path $TestFile -Value "Temporary test data for secure deletion audit" | Out-Null

# Download SDelete from Sysinternals if not already present
$SDeletePath = "$env:ProgramFiles\Sysinternals\sdelete64.exe"
if (-not (Test-Path $SDeletePath)) {
    $SDeleteDir = "$env:ProgramFiles\Sysinternals"
    if (-not (Test-Path $SDeleteDir)) {
        New-Item -ItemType Directory -Path $SDeleteDir -Force | Out-Null
    }
    # Download sdelete64.exe from Microsoft Sysinternals
    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SDelete.zip" -OutFile "$env:TEMP\sdelete.zip" -TimeoutSec 30
        Expand-Archive -Path "$env:TEMP\sdelete.zip" -DestinationPath $SDeleteDir -Force
        Remove-Item "$env:TEMP\sdelete.zip" -Force
    } catch {
        # If download fails, skip the test
        Write-Host "SDelete not available"
        exit 0
    }
}

# Execute SDelete with -accepteula flag for secure deletion (legitimate administrative use)
if (Test-Path $SDeletePath) {
    & $SDeletePath -accepteula -p 2 $TestFile | Out-Null
}

# Clean up temporary test file if it still exists
if (Test-Path $TestFile) {
    Remove-Item $TestFile -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_7cb52374-6b8d-4faf-a3b5-f8079a9c96d6  (1 rule(s)) ---------------------
# Intent:    Detect use of the SDelete secure-deletion tool with the -accepteula flag, a tech
# Rules:     7cb52374-6b8d-4faf-a3b5-f8079a9c96d6
# Archetype: Software installer/updater workflow

$SysinternalsPath = "$env:ProgramFiles\Sysinternals"

# Ensure Sysinternals directory exists for tool inventory
if (-not (Test-Path $SysinternalsPath)) {
    New-Item -ItemType Directory -Path $SysinternalsPath -Force | Out-Null
}

# Check for 32-bit sdelete variant
$SDelete32Path = Join-Path $SysinternalsPath "sdelete.exe"
$SDelete64Path = Join-Path $SysinternalsPath "sdelete64.exe"

# Attempt to download and install sdelete tools for secure-deletion capability
if (-not (Test-Path $SDelete64Path) -and -not (Test-Path $SDelete32Path)) {
    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SDelete.zip" -OutFile "$env:TEMP\sdelete_pkg.zip" -TimeoutSec 30
        Expand-Archive -Path "$env:TEMP\sdelete_pkg.zip" -DestinationPath $SysinternalsPath -Force
        Remove-Item "$env:TEMP\sdelete_pkg.zip" -Force
    } catch {
        exit 0
    }
}

# Create a test file in a temporary location to verify the tool
$TestFilePath = Join-Path $env:TEMP "maintenance_cache_$([guid]::NewGuid().ToString().Substring(0,8)).tmp"
New-Item -ItemType File -Path $TestFilePath -Force | Out-Null
Set-Content -Path $TestFilePath -Value "Cache for maintenance verification"

# Execute with -accepteula for automated deployment scenarios where user interaction is not possible
if (Test-Path $SDelete64Path) {
    & $SDelete64Path -accepteula -p 1 $TestFilePath | Out-Null
} elseif (Test-Path $SDelete32Path) {
    & $SDelete32Path -accepteula -p 1 $TestFilePath | Out-Null
}

# Ensure test file is removed
if (Test-Path $TestFilePath) {
    Remove-Item $TestFilePath -Force -ErrorAction SilentlyContinue
}

# -- Cluster: singleton_7cb52374-6b8d-4faf-a3b5-f8079a9c96d6  (1 rule(s)) ---------------------
# Intent:    Detect use of the SDelete secure-deletion tool with the -accepteula flag, a tech
# Rules:     7cb52374-6b8d-4faf-a3b5-f8079a9c96d6
# Archetype: User-driven workflow

# User-initiated secure cleanup of temporary sensitive files
$SysinternalsPath = "$env:ProgramFiles\Sysinternals"

# Verify Sysinternals directory structure
if (-not (Test-Path $SysinternalsPath)) {
    New-Item -ItemType Directory -Path $SysinternalsPath -Force | Out-Null
}

# Define paths for 64-bit variant (modern systems)
$SDelete64Path = Join-Path $SysinternalsPath "sdelete64.exe"

# Download SDelete if not present
if (-not (Test-Path $SDelete64Path)) {
    try {
        $ProgressPreference = 'SilentlyContinue'
        $SDeleteZip = "$env:TEMP\sdelete_download.zip"
        Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SDelete.zip" -OutFile $SDeleteZip -TimeoutSec 30
        Expand-Archive -Path $SDeleteZip -DestinationPath $SysinternalsPath -Force
        Remove-Item $SDeleteZip -Force
    } catch {
        exit 0
    }
}

# Create a file to be securely deleted (simulating user cleanup of sensitive documents)
$UserTempFile = Join-Path $env:TEMP "budget_draft_$([guid]::NewGuid().ToString().Substring(0,8)).txt"
New-Item -ItemType File -Path $UserTempFile -Force | Out-Null
Set-Content -Path $UserTempFile -Value "Preliminary budget figures"

# Execute SDelete with -accepteula flag for secure, permanent deletion
if (Test-Path $SDelete64Path) {
    & $SDelete64Path -accepteula -p 3 $UserTempFile | Out-Null
}

# Verify cleanup
if (Test-Path $UserTempFile) {
    Remove-Item $UserTempFile -Force -ErrorAction SilentlyContinue
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
