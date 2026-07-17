# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   1  |  Feasible: 1  |  Variants: 2
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_34f0481c-d3ef-4b1c-ad9d-fc6f46385a19  (1 rule(s)) ---------------------
# Intent:    Attackers using BITS (Background Intelligent Transfer Service) via bitsadmin.exe
# Rules:     34f0481c-d3ef-4b1c-ad9d-fc6f46385a19
# Archetype: IT admin workflow

$BitsJobName = 'WindowsUpdate_Q4_2024'
$InternalServer = 'internal.corp.local'
$SourcePath = "http://$InternalServer/updates/KB5000000_x64.msu"
$DestPath = "$env:TEMP\KB5000000_x64.msu"

Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Starting BITS job for update distribution..."

try {
    # Create BITS job for update transfer
    bitsadmin.exe /create /name $BitsJobName /resume 2>&1 | Out-Null
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] BITS job created: $BitsJobName"

    # Add file to job
    bitsadmin.exe /addfile $BitsJobName $SourcePath $DestPath 2>&1 | Out-Null
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] File added to job from $SourcePath"

    # Resume job to start transfer
    bitsadmin.exe /resume $BitsJobName 2>&1 | Out-Null
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] BITS job resumed"

    # Poll job status with timeout
    $maxAttempts = 10
    $attempt = 0
    while ($attempt -lt $maxAttempts) {
        Start-Sleep -Seconds 1
        $jobInfo = bitsadmin.exe /info $BitsJobName /verbose 2>&1
        if ($jobInfo -match 'State: Transferred|State: Error') {
            break
        }
        $attempt++
    }

    # Complete job to finalize transfer
    bitsadmin.exe /complete $BitsJobName 2>&1 | Out-Null
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] BITS job completed: $BitsJobName"

    # Verify and cleanup
    if (Test-Path $DestPath) {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Update file transferred successfully"
        Remove-Item -Path $DestPath -Force -ErrorAction SilentlyContinue
    }
}
finally {
    # Clean up BITS job
    bitsadmin.exe /complete $BitsJobName 2>&1 | Out-Null
    Start-Sleep -Milliseconds 500
}

# -- Cluster: singleton_34f0481c-d3ef-4b1c-ad9d-fc6f46385a19  (1 rule(s)) ---------------------
# Intent:    Attackers using BITS (Background Intelligent Transfer Service) via bitsadmin.exe
# Rules:     34f0481c-d3ef-4b1c-ad9d-fc6f46385a19
# Archetype: Software installer/updater workflow

$DeploymentId = 'CONFIG_PKG_2024_v2'
$PackageServer = 'internal.corp.local'
$PackageUrl = "http://$PackageServer/updates/appconfig.zip"
$LocalPath = "$env:TEMP\appconfig.zip"

Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Initiating enterprise application deployment..."

try {
    # Create new BITS job for package deployment
    & cmd /c "bitsadmin /create /name $DeploymentId /resume 2>nul"
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Deployment job initialized: $DeploymentId"

    # Attach application package to job
    & cmd /c "bitsadmin /addfile $DeploymentId $PackageUrl $LocalPath 2>nul"
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Package attached from internal.corp.local/updates/"

    # Resume the deployment transfer
    & cmd /c "bitsadmin /resume $DeploymentId 2>nul"
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Transfer initiated"

    # Monitor deployment progress
    for ($i = 0; $i -lt 8; $i++) {
        Start-Sleep -Seconds 1
        $status = & cmd /c "bitsadmin /info $DeploymentId 2>nul" | Select-String -Pattern 'State:'
        if ($status -match 'Transferred|Error') {
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Transfer status: $status"
            break
        }
    }

    # Finalize and commit the deployment
    & cmd /c "bitsadmin /complete $DeploymentId 2>nul"
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Deployment package finalized"

    if (Test-Path $LocalPath) {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Package delivery confirmed"
        Remove-Item -Path $LocalPath -Force -ErrorAction SilentlyContinue
    }
}
finally {
    # Ensure job cleanup
    & cmd /c "bitsadmin /complete $DeploymentId 2>nul" | Out-Null
    Start-Sleep -Milliseconds 300
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
