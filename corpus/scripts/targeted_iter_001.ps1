# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   3  |  Feasible: 2  |  Variants: 6
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_832dd777-3c30-4992-88fc-bfb5f7ceea83  (1 rule(s)) ---------------------
# Intent:    Detect WMI/WMIC invocation spawned from script interpreters (PowerShell, VBScrip
# Rules:     832dd777-3c30-4992-88fc-bfb5f7ceea83
# Archetype: IT admin workflow

$inventoryPath = Join-Path -Path $env:TEMP -ChildPath ('hwinfo_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.csv')
Write-Host "[*] Collecting hardware inventory to $inventoryPath"

$biosInfo = @()
$biosInfo += Get-WmiObject -Class Win32_BIOS | Select-Object Manufacturer, Version, ReleaseDate

$diskInfo = @()
$diskInfo += Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID, Size, FreeSpace

$nicInfo = @()
$nicInfo += Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" | Select-Object Description, IPAddress, DefaultIPGateway

$procInfo = @()
$procInfo += Get-WmiObject -Class Win32_Process | Select-Object Name, ProcessId, CommandLine | Select-Object -First 20

Write-Host "[*] BIOS: $(($biosInfo | Measure-Object).Count) records"
Write-Host "[*] Disks: $(($diskInfo | Measure-Object).Count) records"
Write-Host "[*] NICs: $(($nicInfo | Measure-Object).Count) records"
Write-Host "[*] Processes: $(($procInfo | Measure-Object).Count) records"

$inventoryData = @{
    'BIOS' = $biosInfo
    'Disks' = $diskInfo
    'NICs' = $nicInfo
    'Processes' = $procInfo
}

$inventoryData | ConvertTo-Json | Out-File -FilePath $inventoryPath -Force
Write-Host "[+] Inventory export complete: $inventoryPath"

if (Test-Path -Path $inventoryPath) {
    Remove-Item -Path $inventoryPath -Force -ErrorAction SilentlyContinue
    Write-Host "[*] Cleaned up temporary inventory file"
}

# -- Cluster: singleton_832dd777-3c30-4992-88fc-bfb5f7ceea83  (1 rule(s)) ---------------------
# Intent:    Detect WMI/WMIC invocation spawned from script interpreters (PowerShell, VBScrip
# Rules:     832dd777-3c30-4992-88fc-bfb5f7ceea83
# Archetype: Software installer/updater workflow

$logonScriptDir = 'C:\Windows\System32\GroupPolicy\User\Scripts\Logon'
$configPath = Join-Path -Path $env:TEMP -ChildPath 'deploy_config.txt'

Write-Host "[*] Software deployment validation initiated"

# Create a temporary deployment config file
@'
APP_NAME=SecurityAgent
MIN_RAM=2048
MIN_DISKSPACE=1024
'@ | Out-File -FilePath $configPath -Force

Write-Host "[*] Checking system prerequisites using WMI"

$ramMB = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty TotalPhysicalMemory) / 1MB
Write-Host "[*] System RAM: $([Math]::Round($ramMB, 2)) MB"

$diskInfo = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object -ExpandProperty FreeSpace
Write-Host "[*] C: drive free space: $([Math]::Round($diskInfo / 1GB, 2)) GB"

$osInfo = Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Caption
Write-Host "[*] Operating System: $osInfo"

$osVersion = Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Version
Write-Host "[*] OS Version: $osVersion"

Write-Host "[+] Prerequisite validation complete"

if (Test-Path -Path $configPath) {
    Remove-Item -Path $configPath -Force -ErrorAction SilentlyContinue
    Write-Host "[*] Cleaned up deployment config file"
}

# -- Cluster: singleton_832dd777-3c30-4992-88fc-bfb5f7ceea83  (1 rule(s)) ---------------------
# Intent:    Detect WMI/WMIC invocation spawned from script interpreters (PowerShell, VBScrip
# Rules:     832dd777-3c30-4992-88fc-bfb5f7ceea83
# Archetype: User-driven workflow

$vbsScriptPath = Join-Path -Path $env:TEMP -ChildPath 'diag_tool.vbs'
$reportPath = Join-Path -Path $env:TEMP -ChildPath ('diag_report_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.txt')

Write-Host "[*] Creating diagnostic VBScript"

$vbsContent = @'
Set objWMI = GetObject("winmgmts:")
Set colItems = objWMI.ExecQuery("Select * from Win32_ComputerSystem")
For Each objItem in colItems
    WScript.Echo "Computer: " & objItem.Name
Next
Set colServices = objWMI.ExecQuery("Select * from Win32_Service WHERE State='Running'")
WScript.Echo "Running Services: " & colServices.Count
For Each objSvc in colServices
    WScript.Echo "  - " & objSvc.Name
Next
'@

$vbsContent | Out-File -FilePath $vbsScriptPath -Force
Write-Host "[*] VBScript created at $vbsScriptPath"

Write-Host "[*] Executing diagnostic VBScript"
cscript.exe $vbsScriptPath | Out-File -FilePath $reportPath -Force

Write-Host "[*] Diagnostic report saved to $reportPath"
Write-Host (Get-Content -Path $reportPath | Select-Object -First 10)

if (Test-Path -Path $vbsScriptPath) {
    Remove-Item -Path $vbsScriptPath -Force -ErrorAction SilentlyContinue
    Write-Host "[*] Cleaned up VBScript"
}

if (Test-Path -Path $reportPath) {
    Remove-Item -Path $reportPath -Force -ErrorAction SilentlyContinue
    Write-Host "[*] Cleaned up diagnostic report"
}

# -- Cluster: singleton_633cdbb8-8fac-4949-ab03-893b244c96c0  (1 rule(s)) ---------------------
# Intent:    Attackers using PowerShell to generate random bytes and write them to files in a
# Rules:     633cdbb8-8fac-4949-ab03-893b244c96c0
# Archetype: IT admin workflow

$outputDir = [System.IO.Path]::Combine($env:TEMP, 'crypto_seeds_' + [System.Guid]::NewGuid().ToString().Substring(0, 8))
New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
try {
  # Generate random seed files for backup integrity validation
  $seedCount = 5
  $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
  1..$seedCount | ForEach-Object {
    $filename = Join-Path $outputDir ("backup_seed_{0:D2}.dat" -f $_)
    $buffer = New-Object byte[] 256
    $rng.GetBytes($buffer)
    [System.IO.File]::WriteAllBytes($filename, $buffer)
    Write-Host "Created seed file: $(Split-Path $filename -Leaf)"
  }
  Write-Host "Seed generation complete. Files stored in: $outputDir"
} finally {
  if ($rng) { $rng.Dispose() }
  if (Test-Path $outputDir) { Remove-Item $outputDir -Recurse -Force }
}

# -- Cluster: singleton_633cdbb8-8fac-4949-ab03-893b244c96c0  (1 rule(s)) ---------------------
# Intent:    Attackers using PowerShell to generate random bytes and write them to files in a
# Rules:     633cdbb8-8fac-4949-ab03-893b244c96c0
# Archetype: Software installer/updater workflow

$installDir = [System.IO.Path]::Combine($env:TEMP, 'pkg_install_' + [System.Guid]::NewGuid().ToString().Substring(0, 8))
New-Item -Path $installDir -ItemType Directory -Force | Out-Null
try {
  # Package installer entropy validation: creating random validation markers
  $validationDir = Join-Path $installDir 'validation'
  New-Item -Path $validationDir -ItemType Directory -Force | Out-Null

  $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
  $packageIds = @('pkg_app_core', 'pkg_app_plugins', 'pkg_app_config')

  $packageIds | ForEach-Object {
    $validationMarker = Join-Path $validationDir ("$_.entropy")
    $randomBuffer = New-Object byte[] 128
    $rng.GetBytes($randomBuffer)
    [System.IO.File]::WriteAllBytes($validationMarker, $randomBuffer)
  }

  if ($rng) { $rng.Dispose() }
  Write-Host "Package validation entropy markers created successfully"
} finally {
  if (Test-Path $installDir) { Remove-Item $installDir -Recurse -Force }
}

# -- Cluster: singleton_633cdbb8-8fac-4949-ab03-893b244c96c0  (1 rule(s)) ---------------------
# Intent:    Attackers using PowerShell to generate random bytes and write them to files in a
# Rules:     633cdbb8-8fac-4949-ab03-893b244c96c0
# Archetype: Document/file operation workflow

$docDir = [System.IO.Path]::Combine($env:TEMP, 'document_protect_' + [System.Guid]::NewGuid().ToString().Substring(0, 8))
New-Item -Path $docDir -ItemType Directory -Force | Out-Null
try {
  # Create document fingerprint/watermark files for DLP tracking
  $documents = @('financial_report_q3.txt', 'employee_roster.txt', 'project_plan.txt')
  $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

  $documents | ForEach-Object {
    $docPath = Join-Path $docDir $_
    'Confidential document content' | Out-File -FilePath $docPath -Encoding UTF8

    # Append random fingerprint for tracking
    $fingerprint = New-Object byte[] 64
    $rng.GetBytes($fingerprint)
    [System.IO.File]::WriteAllBytes((Join-Path $docDir ("$_.fingerprint")), $fingerprint)
  }

  if ($rng) { $rng.Dispose() }
  Write-Host "Document protection fingerprints created"
} finally {
  if (Test-Path $docDir) { Remove-Item $docDir -Recurse -Force }
}

# SKIPPED cluster singleton_a0d8fe1d-6850-4576-8cee-bc43028b6cee: This rule cluster targets ESXi hypervisor management via vim-cmd, which is specific to VMware ESXi environments. GitHub Actions windows-latest runners are standard Windows VMs without ESXi hypervisor management tools or VMware vSphere infrastructure. The vim-cmd executable does not exist on Windows systems—it is an ESXi-only command-line tool. Even if vim-cmd could be installed, it requires an active ESXi infrastructure to enumerate VMs and manage snapshots. There is no legitimate way to generate these detection events on a Windows runner without the underlying VMware hypervisor environment.

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
