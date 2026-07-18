# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_f9fc4f1e-0b30-4f71-88c9-30a33eb47ed7  (1 rule(s)) ---------------------
# Intent:    Detect Background Intelligent Transfer Service (BITS) job creation and managemen
# Rules:     f9fc4f1e-0b30-4f71-88c9-30a33eb47ed7
# Archetype: IT admin workflow

$bits_temp = Join-Path $env:TEMP "bits_admin_staging"
New-Item -ItemType Directory -Path $bits_temp -Force | Out-Null
Set-Location $bits_temp

# Create a BITS job for legitimate patch transfer
$job_name = "PatchDistribution_$(Get-Random)"
bitsadmin.exe /create /name $job_name

# Add a file from internal repository (simulated with localhost)
bitsadmin.exe /addfile $job_name "http://127.0.0.1/patches/kb5000000.msu" "$bits_temp\kb5000000.msu"

# Resume the job to begin transfer
bitsadmin.exe /resume $job_name

# Wait briefly for job state to update
Start-Sleep -Seconds 2

# Complete the job
bitsadmin.exe /complete $job_name

# Cleanup: Remove the temporary directory and its contents
Set-Location $env:TEMP
Remove-Item -Path $bits_temp -Recurse -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_f9fc4f1e-0b30-4f71-88c9-30a33eb47ed7  (1 rule(s)) ---------------------
# Intent:    Detect Background Intelligent Transfer Service (BITS) job creation and managemen
# Rules:     f9fc4f1e-0b30-4f71-88c9-30a33eb47ed7
# Archetype: Software installer/updater workflow

$staging_dir = Join-Path $env:ProgramData "SoftwareDeployment_$(Get-Random)"
New-Item -ItemType Directory -Path $staging_dir -Force | Out-Null
Set-Location $staging_dir

# Simulate software distribution framework using BITS
# This would be a legitimate deployment automation scenario
$job_name = "AppInstall_$(Get-Random)"
bitsadmin.exe /create /name $job_name

# Add application binary from distribution server
bitsadmin.exe /addfile $job_name "http://127.0.0.1/apps/enterprise-tool.exe" "$staging_dir\enterprise-tool.exe"

# Begin transfer
bitsadmin.exe /resume $job_name
Start-Sleep -Seconds 1

# Complete transfer
bitsadmin.exe /complete $job_name

# Cleanup
Set-Location $env:TEMP
Remove-Item -Path $staging_dir -Recurse -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_f9fc4f1e-0b30-4f71-88c9-30a33eb47ed7  (1 rule(s)) ---------------------
# Intent:    Detect Background Intelligent Transfer Service (BITS) job creation and managemen
# Rules:     f9fc4f1e-0b30-4f71-88c9-30a33eb47ed7
# Archetype: User-driven workflow

$user_appdata = Join-Path $env:APPDATA "DownloadManager"
New-Item -ItemType Directory -Path $user_appdata -Force | Out-Null
Set-Location $user_appdata

# User-initiated download via BITS-backed utility
$job_name = "UserDownload_$(Get-Random)"
bitsadmin.exe /create /name $job_name

# Add file for user download
bitsadmin.exe /addfile $job_name "http://127.0.0.1/files/document.pdf" "$user_appdata\document.pdf"

# Resume download
bitsadmin.exe /resume $job_name
Start-Sleep -Seconds 1

# Complete download
bitsadmin.exe /complete $job_name

# Cleanup
Set-Location $env:TEMP
Remove-Item -Path $user_appdata -Recurse -Force -ErrorAction SilentlyContinue


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
