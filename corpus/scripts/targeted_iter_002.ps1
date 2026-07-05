# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   3  |  Feasible: 3  |  Variants: 8
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_4cb0515f-9798-4245-8051-aa0501bd4056  (1 rule(s)) ---------------------
# Intent:    Detection of script host interpreters (wscript, cscript, mshta) being spawned fr
# Rules:     4cb0515f-9798-4245-8051-aa0501bd4056
# Archetype: IT admin workflow

$tempDir = [System.IO.Path]::GetTempPath()
$wmiQuery = @"
Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor | Export-Csv -Path "$tempDir\software_inventory.csv" -NoTypeInformation
"@

Add-Type -AssemblyName System.Management

$scope = New-Object System.Management.ManagementScope("\\\\localhost\\root\\cimv2")
$scope.Connect()

$query = New-Object System.Management.ObjectQuery("SELECT Name, Version FROM Win32_Product")
$searcher = New-Object System.Management.ManagementObjectSearcher($scope, $query)
$results = $searcher.Get()

$inventoryPath = Join-Path $tempDir "software_audit_$(Get-Date -Format yyyyMMdd_HHmmss).txt"
foreach ($item in $results) {
    "$($item['Name']) - $($item['Version'])" | Add-Content -Path $inventoryPath
}

# Execute a harmless VBScript asset that might be invoked during system administration
$vbsPath = Join-Path $env:TEMP "system_check.vbs"
$vbsContent = @'
Set objWshShell = CreateObject("WScript.Shell")
Set objEnv = objWshShell.Environment("SYSTEM")
objEnv("TEMP_ASSET_CHECK") = "complete"
'@

$vbsContent | Set-Content -Path $vbsPath -Encoding ASCII

# Invoke through cscript to simulate legitimate administrative scripting
& cscript.exe $vbsPath //NoLogo | Out-Null

# Clean up
Remove-Item -Path $vbsPath -Force -ErrorAction SilentlyContinue
Remove-Item -Path $inventoryPath -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path $tempDir "software_inventory.csv") -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_4cb0515f-9798-4245-8051-aa0501bd4056  (1 rule(s)) ---------------------
# Intent:    Detection of script host interpreters (wscript, cscript, mshta) being spawned fr
# Rules:     4cb0515f-9798-4245-8051-aa0501bd4056
# Archetype: Software installer/updater workflow

$tempDir = [System.IO.Path]::GetTempPath()

# Simulate Configuration Manager or system remediation script deployment
$scriptPath = Join-Path $env:TEMP "compliance_check_$(Get-Random).vbs"
$scriptContent = @'
Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

' Compliance audit activity
strComputer = "."
Set objWMI = GetObject("winmgmts:\\\\" & strComputer & "\\root\\cimv2")
Set colItems = objWMI.ExecQuery("Select * from Win32_OperatingSystem")
For Each objItem In colItems
    objShell.Run "cmd /c echo OS Build: " & objItem.BuildNumber, 0
Next
'@

$scriptContent | Set-Content -Path $scriptPath -Encoding ASCII

# Simulate system service executing script deployment (legitimate use case)
# Use mshta.exe for HTML Application execution as might occur during system provisioning
$htalPath = Join-Path $env:TEMP "provisioning_check.hta"
$htaContent = @'
<HTML>
<HEAD>
<HTA:APPLICATION ID="ProvisApp"
    ApplicationName="SystemProvisioning"
    VERSION="1.0"
    Border="thick"
    Scroll="no"
    SysMenu="no"
/>
</HEAD>
<BODY>
System provisioning check complete.
</BODY>
</HTML>
'@

$htaContent | Set-Content -Path $htalPath -Encoding ASCII

# Execute through mshta for system compliance verification
& mshta.exe $htalPath | Out-Null

Start-Sleep -Milliseconds 500

# Execute VBS through cscript for policy remediation
& cscript.exe $scriptPath //NoLogo | Out-Null

# Clean up
Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
Remove-Item -Path $htalPath -Force -ErrorAction SilentlyContinue

# Verify cleanup
Get-Item -Path $scriptPath -ErrorAction SilentlyContinue | Remove-Item -Force
Get-Item -Path $htalPath -ErrorAction SilentlyContinue | Remove-Item -Force

# -- Cluster: singleton_4cb0515f-9798-4245-8051-aa0501bd4056  (1 rule(s)) ---------------------
# Intent:    Detection of script host interpreters (wscript, cscript, mshta) being spawned fr
# Rules:     4cb0515f-9798-4245-8051-aa0501bd4056
# Archetype: System maintenance workflow

$tempDir = [System.IO.Path]::GetTempPath()

# Create a legitimate system configuration audit script
$configScript = Join-Path $env:TEMP "system_config_audit_$(Get-Random).vbs"
$configContent = @'
Dim objShell, objRegistry, strKeyPath, arrValueNames
Set objShell = CreateObject("WScript.Shell")
Set objRegistry = CreateObject("WScript.Shell").RegRead

' Read system configuration for audit
strKeyPath = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\"
objShell.Run "cmd /c echo Auditing system configuration", 0
'@

$configContent | Set-Content -Path $configScript -Encoding ASCII

# Execute configuration audit through cscript
Write-Host "Running system configuration audit..."
& cscript.exe $configScript //NoLogo | Out-Null

# Create mshta-based system monitoring activity
$monitorScript = Join-Path $env:TEMP "monitor_$(Get-Random).hta"
$monitorContent = @'
<HTML>
<HEAD>
<TITLE>System Status Monitor</TITLE>
<SCRIPT LANGUAGE="VBScript">
Sub window_onload
    Dim objShell
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run "cmd /c echo System check", 0
End Sub
</SCRIPT>
</HEAD>
<BODY>
Initializing system monitor...
</BODY>
</HTML>
'@

$monitorContent | Set-Content -Path $monitorScript -Encoding ASCII

# Execute HTA for system status verification
Write-Host "Executing system monitor..."
& mshta.exe $monitorScript | Out-Null

Start-Sleep -Milliseconds 300

# Create WScript-based operational activity log
$logScript = Join-Path $env:TEMP "oplog_$(Get-Random).vbs"
$logContent = @'
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objShell = CreateObject("WScript.Shell")
strLogPath = objShell.ExpandEnvironmentStrings("%TEMP%") & "\\system_ops.log"
Set objFile = objFSO.CreateTextFile(strLogPath, True)
objFile.WriteLine "System operational check: " & Now
objFile.Close
'@

$logContent | Set-Content -Path $logScript -Encoding ASCII

# Execute logging script through wscript
Write-Host "Recording system operations..."
& wscript.exe $logScript | Out-Null

Start-Sleep -Milliseconds 300

# Clean up all temporary scripts and logs
Remove-Item -Path $configScript -Force -ErrorAction SilentlyContinue
Remove-Item -Path $monitorScript -Force -ErrorAction SilentlyContinue
Remove-Item -Path $logScript -Force -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path $env:TEMP "system_ops.log") -Force -ErrorAction SilentlyContinue

Write-Host "System maintenance workflow complete"

# -- Cluster: singleton_d4d5653b-078e-4c38-9c8d-0fe934a485ed  (1 rule(s)) ---------------------
# Intent:    Detects use of BITS (Background Intelligent Transfer Service) to download or exe
# Rules:     d4d5653b-078e-4c38-9c8d-0fe934a485ed
# Archetype: IT admin workflow

# Configuration Manager client deployment scenario
# Administrative task: Stage ConfigMgr update package via BITS for automated rollout

$tempdir = [System.IO.Path]::GetTempPath()
$packageSource = "file:///${tempdir}ccmsetup_staging.bin"
$jobName = "ConfigMgr_CCMSetup_Distribution_$(Get-Random)"

# Create a minimal mock package file to simulate real network payload
$mockPackage = $tempdir + "ccmsetup_staging.bin"
Add-Content -Path $mockPackage -Value ([byte[]](0xMZ)) -Encoding Byte

# Simulate admin creating BITS job for ConfigMgr client installation
# This is what ConfigMgr distribution service or patch management tools do
try {
    # Create BITS transfer job to simulate pulling ConfigMgr client bits
    bitsadmin.exe /create /resume $jobName
    bitsadmin.exe /addfile $jobName $packageSource "${tempdir}ccmsetup_package.bin"

    # Set notification command - ConfigMgr would invoke post-transfer validation
    bitsadmin.exe /setnotifycmdline $jobName cmd.exe "/c echo ConfigMgr package staged for deployment"

    # Resume and wait for completion (simulates admin monitoring deployment)
    bitsadmin.exe /resume $jobName
    Start-Sleep -Seconds 2

    # Query job status to verify deployment readiness
    bitsadmin.exe /info $jobName

    # Complete the transfer
    bitsadmin.exe /complete $jobName
}
finally {
    # Cleanup: remove mock package and cancel any orphaned jobs
    if (Test-Path $mockPackage) { Remove-Item -Path $mockPackage -Force }
    try { bitsadmin.exe /cancel $jobName -ErrorAction SilentlyContinue } catch { }
}

# -- Cluster: singleton_d4d5653b-078e-4c38-9c8d-0fe934a485ed  (1 rule(s)) ---------------------
# Intent:    Detects use of BITS (Background Intelligent Transfer Service) to download or exe
# Rules:     d4d5653b-078e-4c38-9c8d-0fe934a485ed
# Archetype: Software installer/updater workflow

# Intune Management Extension deployment scenario
# Automated workflow: Intune service stage management extension for installation

$tempdir = [System.IO.Path]::GetTempPath()
$jobName = "IntuneManagementExtension_Deploy_$(Get-Random)"
$sourceUrl = "file:///${tempdir}IntuneManagementExtension.bin"

# Mock the Intune extension binary
$extensionBin = $tempdir + "IntuneManagementExtension.bin"
Add-Content -Path $extensionBin -Value ([byte[]](0xMZ)) -Encoding Byte

try {
    # Intune's own delivery mechanism uses BITS to transfer extension packages
    # This simulates legitimate Intune management agent update
    bitsadmin.exe /create /resume $jobName
    bitsadmin.exe /addfile $jobName $sourceUrl "${tempdir}IntuneManagementExtension.exe"

    # Intune would set a post-completion command to validate and install extension
    bitsadmin.exe /setnotifycmdline $jobName cmd.exe "/c echo Intune extension staged for installation"

    # Resume job to trigger download simulation
    bitsadmin.exe /resume $jobName
    Start-Sleep -Seconds 2

    # Check job status before completion
    $jobInfo = bitsadmin.exe /info $jobName /verbose

    # Mark transfer complete
    bitsadmin.exe /complete $jobName
}
finally {
    # Cleanup: remove staged binary and cancel job
    if (Test-Path $extensionBin) { Remove-Item -Path $extensionBin -Force }
    try { bitsadmin.exe /cancel $jobName -ErrorAction SilentlyContinue } catch { }
}

# -- Cluster: singleton_d4d5653b-078e-4c38-9c8d-0fe934a485ed  (1 rule(s)) ---------------------
# Intent:    Detects use of BITS (Background Intelligent Transfer Service) to download or exe
# Rules:     d4d5653b-078e-4c38-9c8d-0fe934a485ed
# Archetype: User-driven workflow

# End-user troubleshooting workflow
# User or support staff verifies ConfigMgr patch transfer status via BITS query

$tempdir = [System.IO.Path]::GetTempPath()
$jobName = "User_CCMSetup_Verify_$(Get-Random)"
$sourceFile = "file:///${tempdir}ccm_update.bin"

# Create mock update package
$mockUpdate = $tempdir + "ccm_update.bin"
Add-Content -Path $mockUpdate -Value ([byte[]](0xMZ)) -Encoding Byte

try {
    # User initiates verification of ConfigMgr update via BITS
    # This is guidance often provided in support documentation
    bitsadmin.exe /create $jobName
    bitsadmin.exe /addfile $jobName $sourceFile "${tempdir}ccm_update_staging.exe"

    # Support script sets notification to inform user when download completes
    bitsadmin.exe /setnotifycmdline $jobName cmd.exe "/c echo ConfigMgr update ready for installation"

    # Resume transfer
    bitsadmin.exe /resume $jobName
    Start-Sleep -Seconds 2

    # User checks job status using standard BITS query (common support step)
    bitsadmin.exe /info $jobName

    # Complete the verification transfer
    bitsadmin.exe /complete $jobName
}
finally {
    # Cleanup
    if (Test-Path $mockUpdate) { Remove-Item -Path $mockUpdate -Force }
    try { bitsadmin.exe /cancel $jobName -ErrorAction SilentlyContinue } catch { }
}

# -- Cluster: singleton_95b7c5ac-00e8-435d-a3bb-f1dcd143fb1f  (1 rule(s)) ---------------------
# Intent:    Detecting adversarial creation of hidden Windows services by injecting service r
# Rules:     95b7c5ac-00e8-435d-a3bb-f1dcd143fb1f
# Archetype: IT admin workflow

# Enterprise IT admin: Create and register a custom monitoring service in svchost container
# This legitimately exercises the Windows service registration pipeline

$serviceName = 'CustomAuditMonitor'
$serviceDisplayName = 'Custom Audit Monitor Service'
$serviceDescription = 'Internal audit event monitoring service'
$svchostGroupPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost'
$svchostGroupName = 'netsvcs'
$servicesPath = 'HKLM:\SYSTEM\CurrentControlSet\Services'

try {
    # Step 1: Create the service via sc.exe command-line
    # This is how legitimate admins register services programmatically
    $scCommand = @(
        'sc.exe', 'create', $serviceName,
        'type=', 'share',
        'start=', 'auto',
        'binpath=', 'svchost.exe -k ' + $svchostGroupName,
        'displayname=', $serviceDisplayName
    )
    & $scCommand[0] $scCommand[1..($scCommand.Length - 1)]
    Start-Sleep -Milliseconds 500

    # Step 2: Add service description via registry (legitimate admin operation)
    if (Test-Path "$servicesPath\$serviceName") {
        Set-ItemProperty -Path "$servicesPath\$serviceName" -Name 'Description' -Value $serviceDescription -Force
    }

    # Step 3: Register service in svchost group via registry
    # This is the legitimate pattern for adding services to svchost containers
    if (Test-Path $svchostGroupPath) {
        $currentServices = @()
        if ((Get-ItemProperty -Path $svchostGroupPath -Name $svchostGroupName -ErrorAction SilentlyContinue).$svchostGroupName) {
            $currentServices = @((Get-ItemProperty -Path $svchostGroupPath -Name $svchostGroupName).$svchostGroupName)
        }

        # Add our service if not already present
        if ($currentServices -notcontains $serviceName) {
            $currentServices += $serviceName
        }

        # Write as REG_MULTI_SZ value (standard Windows service group registration)
        Set-ItemProperty -Path $svchostGroupPath -Name $svchostGroupName -Value $currentServices -Type MultiString -Force
    }

    # Step 4: Set service to run as LocalService account (privilege-restricted, enterprise pattern)
    Set-ItemProperty -Path "$servicesPath\$serviceName" -Name 'ObjectName' -Value 'NT AUTHORITY\LocalService' -Force

    # Verify the service was created
    Start-Sleep -Milliseconds 500
    & sc.exe query $serviceName

} finally {
    # Cleanup: Remove the service and registry entries
    Start-Sleep -Milliseconds 500
    & sc.exe delete $serviceName 2>$null
    Start-Sleep -Milliseconds 500

    if (Test-Path $svchostGroupPath) {
        $currentServices = @((Get-ItemProperty -Path $svchostGroupPath -Name $svchostGroupName -ErrorAction SilentlyContinue).$svchostGroupName)
        $currentServices = @($currentServices | Where-Object { $_ -ne $serviceName })
        if ($currentServices.Count -gt 0) {
            Set-ItemProperty -Path $svchostGroupPath -Name $svchostGroupName -Value $currentServices -Type MultiString -Force
        }
    }
}

# -- Cluster: singleton_95b7c5ac-00e8-435d-a3bb-f1dcd143fb1f  (1 rule(s)) ---------------------
# Intent:    Detecting adversarial creation of hidden Windows services by injecting service r
# Rules:     95b7c5ac-00e8-435d-a3bb-f1dcd143fb1f
# Archetype: Software installer/updater workflow

# Software installer workflow: Register a bundled Windows service
# Legitimate installers often create services that run in svchost containers

$serviceName = 'EnterpriseComponentService'
$serviceDisplayName = 'Enterprise Component Service'
$binPath = 'svchost.exe -k localservicenonetwork'
$svchostGroupPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost'
$svchostGroupName = 'localservicenonetwork'
$servicesPath = 'HKLM:\SYSTEM\CurrentControlSet\Services'
$regSoftwarePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion'

try {
    # Step 1: Create service via sc.exe (standard installer operation)
    # Using localservicenonetwork group for restricted network access
    Write-Output "[*] Creating service: $serviceName"
    cmd /c "sc.exe create $serviceName type= share start= auto binpath= \"$binPath\" displayname= \"$serviceDisplayName\""
    Start-Sleep -Milliseconds 500

    # Step 2: Configure service registry parameters (installer customization)
    if (Test-Path "$servicesPath\$serviceName") {
        Set-ItemProperty -Path "$servicesPath\$serviceName" -Name 'Description' -Value 'Enterprise component service' -Force
        Set-ItemProperty -Path "$servicesPath\$serviceName" -Name 'ObjectName' -Value 'NT AUTHORITY\LocalService' -Force
    }

    # Step 3: Register in svchost group via multi-string registry value
    if (Test-Path $svchostGroupPath) {
        $groupServices = @()
        $existingValue = Get-ItemProperty -Path $svchostGroupPath -Name $svchostGroupName -ErrorAction SilentlyContinue
        if ($existingValue.$svchostGroupName) {
            $groupServices = @($existingValue.$svchostGroupName)
        }

        if ($groupServices -notcontains $serviceName) {
            $groupServices += $serviceName
        }

        Set-ItemProperty -Path $svchostGroupPath -Name $svchostGroupName -Value $groupServices -Type MultiString -Force
    }

    # Step 4: Add installer metadata to registry (realistic installer behavior)
    $installerPath = "$regSoftwarePath\Installer\Components"
    if (-not (Test-Path $installerPath)) {
        New-Item -Path $installerPath -Force | Out-Null
    }
    Set-ItemProperty -Path $installerPath -Name 'LastInstallDate' -Value (Get-Date -Format 'yyyyMMdd') -Force

    # Verify service registered
    Start-Sleep -Milliseconds 500
    cmd /c "sc.exe query $serviceName"

} finally {
    # Cleanup
    Start-Sleep -Milliseconds 500
    cmd /c "sc.exe delete $serviceName" 2>$null
    Start-Sleep -Milliseconds 500

    if (Test-Path $svchostGroupPath) {
        $groupServices = @((Get-ItemProperty -Path $svchostGroupPath -Name $svchostGroupName -ErrorAction SilentlyContinue).$svchostGroupName)
        $groupServices = @($groupServices | Where-Object { $_ -ne $serviceName })
        if ($groupServices.Count -gt 0) {
            Set-ItemProperty -Path $svchostGroupPath -Name $svchostGroupName -Value $groupServices -Type MultiString -Force
        }
    }

    if (Test-Path "$regSoftwarePath\Installer\Components") {
        Remove-ItemProperty -Path "$regSoftwarePath\Installer\Components" -Name 'LastInstallDate' -Force -ErrorAction SilentlyContinue
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
