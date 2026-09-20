# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_12d7ac2e-e9b8-40d1-af56-b3e42f700ddb  (1 rule(s)) ---------------------
# Intent:    Detect ransomware or data exfiltration attacks using GPG command-line encryption
# Rules:     12d7ac2e-e9b8-40d1-af56-b3e42f700ddb
# Archetype: IT admin workflow

# Administrator backing up encrypted audit logs for compliance archival
$logSource = $env:TEMP + '\audit_logs_2024.txt'
$encryptedBackup = $env:TEMP + '\audit_logs_2024.gpg'

# Create sample audit log content (simulating real IT operations logs)
@'
Event: User logon from 192.168.1.100
Event: File access on HKLM registry
Event: Service started: BackupService
Event: Network connection to internal backup server
'@ | Out-File -FilePath $logSource -Encoding ASCII

# Verify GPG is available on the system
$gpgPath = 'gpg'
try {
    & $gpgPath --version | Out-Null
} catch {
    Write-Host "GPG not installed, installing from Chocolatey"
    # Install GPG if not present
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force | Out-Null
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) -ErrorAction SilentlyContinue | Out-Null
    choco install gnupg -y --no-progress 2>$null | Out-Null
    $gpgPath = 'gpg'
}

# Encrypt the audit log using GPG batch mode with symmetric encryption
# This is a typical administrative backup encryption workflow
$encryptionPassword = 'ComplexAdminPassword2024'
& $gpgPath --batch --yes -c --symmetric --passphrase='ComplexAdminPassword2024' --output $encryptedBackup $logSource

if (Test-Path $encryptedBackup) {
    Write-Host "Audit logs successfully encrypted for secure backup"
}

# Cleanup: Remove unencrypted source and encrypted backup
Remove-Item -Path $logSource -Force -ErrorAction SilentlyContinue
Remove-Item -Path $encryptedBackup -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_12d7ac2e-e9b8-40d1-af56-b3e42f700ddb  (1 rule(s)) ---------------------
# Intent:    Detect ransomware or data exfiltration attacks using GPG command-line encryption
# Rules:     12d7ac2e-e9b8-40d1-af56-b3e42f700ddb
# Archetype: Software installer/updater workflow

# Automated deployment encryption: securing application configuration packages
$configDir = $env:TEMP + '\app_deployment'
$configFile = $configDir + '\database_config.ini'
$encryptedConfig = $configDir + '\database_config.ini.gpg'

New-Item -ItemType Directory -Path $configDir -Force | Out-Null

# Create sample application configuration (simulating real deployment config)
@'
[database]
host=db-prod-01.internal.local
port=5432
db_name=productiondb
[api]
endpoint=https://api.internal.local/v1
'@ | Out-File -FilePath $configFile -Encoding ASCII

# Verify GPG availability
$gpgPath = 'gpg'
try {
    & $gpgPath --version | Out-Null
} catch {
    Write-Host "GPG not installed, installing from Chocolatey"
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force | Out-Null
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) -ErrorAction SilentlyContinue | Out-Null
    choco install gnupg -y --no-progress 2>$null | Out-Null
    $gpgPath = 'gpg'
}

# Encrypt configuration using GPG in batch mode (typical CI/CD pipeline pattern)
# The --batch flag ensures non-interactive operation, required for automated deployment
& $gpgPath --batch --yes -c --symmetric --passphrase='DeploymentSecret2024' --output $encryptedConfig $configFile

if (Test-Path $encryptedConfig) {
    Write-Host "Configuration package encrypted successfully"
}

# Cleanup encrypted artifacts
Remove-Item -Path $configFile -Force -ErrorAction SilentlyContinue
Remove-Item -Path $encryptedConfig -Force -ErrorAction SilentlyContinue
Remove-Item -Path $configDir -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_12d7ac2e-e9b8-40d1-af56-b3e42f700ddb  (1 rule(s)) ---------------------
# Intent:    Detect ransomware or data exfiltration attacks using GPG command-line encryption
# Rules:     12d7ac2e-e9b8-40d1-af56-b3e42f700ddb
# Archetype: Document/file operation workflow

# User encrypting sensitive financial documents for secure storage
$documentsDir = $env:TEMP + '\financial_docs'
$sourceDocument = $documentsDir + '\Q4_expense_report.txt'
$encryptedDoc = $documentsDir + '\Q4_expense_report.txt.gpg'

New-Item -ItemType Directory -Path $documentsDir -Force | Out-Null

# Create sample sensitive document (simulating real confidential business document)
@'
Q4 EXPENSE REPORT - CONFIDENTIAL

Travel expenses: $4,500
Client entertainment: $1,200
Equipment purchases: $3,800
Conference registration: $2,100
Total: $11,600

Department Manager: John Smith
Cost Center: MKTG-401
'@ | Out-File -FilePath $sourceDocument -Encoding ASCII

# Verify GPG availability
$gpgPath = 'gpg'
try {
    & $gpgPath --version | Out-Null
} catch {
    Write-Host "GPG not installed, installing from Chocolatey"
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force | Out-Null
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1')) -ErrorAction SilentlyContinue | Out-Null
    choco install gnupg -y --no-progress 2>$null | Out-Null
    $gpgPath = 'gpg'
}

# Encrypt the sensitive document using GPG symmetric encryption
# User provides passphrase inline in batch mode for automated document protection workflow
& $gpgPath --batch --yes -c --symmetric --passphrase='SecureDocumentPassword' --output $encryptedDoc $sourceDocument

if (Test-Path $encryptedDoc) {
    Write-Host "Sensitive document encrypted and ready for secure storage"
}

# Cleanup: remove original unencrypted document and temporary encryption
Remove-Item -Path $sourceDocument -Force -ErrorAction SilentlyContinue
Remove-Item -Path $encryptedDoc -Force -ErrorAction SilentlyContinue
Remove-Item -Path $documentsDir -Force -ErrorAction SilentlyContinue


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
