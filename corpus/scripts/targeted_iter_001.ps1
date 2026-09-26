# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   5  |  Feasible: 5  |  Variants: 15
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_c12c92fd-051f-41b1-b5d4-374f4a02275c  (1 rule(s)) ---------------------
# Intent:    Remote command execution through Service Control Manager (SCM) service host spaw
# Rules:     c12c92fd-051f-41b1-b5d4-374f4a02275c
# Archetype: IT admin workflow

$tempDir = [System.IO.Path]::GetTempPath()
$logFile = Join-Path $tempDir "inventory_$(Get-Random).log"
$scriptFile = Join-Path $tempDir "config_scan_$(Get-Random).ps1"

# Create a realistic inventory scanning script
$inventoryScript = @'
# Enterprise inventory collection
$results = @{}
$targetServer = $env:COMPUTERNAME
$results.Hostname = $targetServer
$results.OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
$results.InstalledApps = @(Get-CimInstance Win32_Product | Select-Object Name, Version)
Write-Host "Inventory collection complete"
'@

Set-Content -Path $scriptFile -Value $inventoryScript

# Simulate SCM executing a PowerShell command with admin share references
# This models legitimate enterprise configuration management pulling from admin shares
try {
    # Reference admin shares in the command line (as would appear in remote admin scenario)
    & powershell.exe -NoProfile -Command "Write-Host 'Checking system shares'; Get-ChildItem -Path $scriptFile -ErrorAction SilentlyContinue | ForEach-Object { Write-Host 'Found config file' }"

    # Simulate command execution with /q /c pattern (quiet mode)
    & cmd.exe /q /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File $scriptFile *>> $logFile
} catch {
    Write-Host "Configuration scan process completed"
}

# Clean up
Remove-Item -Path $scriptFile -Force -ErrorAction SilentlyContinue
Remove-Item -Path $logFile -Force -ErrorAction SilentlyContinue

# SKIPPED variant 'Software installer/updater workflow': blocked pattern: cmd batch syntax ('echo off')

# -- Cluster: singleton_c12c92fd-051f-41b1-b5d4-374f4a02275c  (1 rule(s)) ---------------------
# Intent:    Remote command execution through Service Control Manager (SCM) service host spaw
# Rules:     c12c92fd-051f-41b1-b5d4-374f4a02275c
# Archetype: User-driven workflow

$tempDir = [System.IO.Path]::GetTempPath()
$backupScript = Join-Path $tempDir "backup_verify_$(Get-Random).ps1"
$logPath = Join-Path $tempDir "backup_log_$(Get-Random).txt"

# Create a backup verification script that accesses network resources
$backupContent = @'
# Backup verification workflow
$configFile = "C:\\ProgramData\\BackupConfig.ini"
if (Test-Path -Path $configFile) {
    Write-Host "Backup configuration found"
    Get-Content -Path $configFile -ErrorAction SilentlyContinue | Select-Object -First 5
}
Write-Host "Backup verification complete"
'@

Set-Content -Path $backupScript -Value $backupContent

try {
    # Simulate application accessing admin shares for backup/restore operations
    # This models backup software or remote access tools that spawn shells
    & powershell.exe -NoProfile -Command "Write-Host 'Accessing shared resources'; Write-Host 'Connecting to \\\\$env:COMPUTERNAME\\ipc$'"

    # Execute verification with quiet command execution
    & cmd.exe /q /c powershell.exe -NoProfile -ExecutionPolicy Bypass -File $backupScript *>> $logPath
} catch {
    Write-Host "Backup workflow completed"
}

# Clean up
Remove-Item -Path $backupScript -Force -ErrorAction SilentlyContinue
Remove-Item -Path $logPath -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_4151c10e-1ee4-4a75-8cba-d32c20451715  (1 rule(s)) ---------------------
# Intent:    Remote PowerShell session management and command invocation via cmdlet, which at
# Rules:     4151c10e-1ee4-4a75-8cba-d32c20451715
# Archetype: IT admin workflow

# IT admin: enable remote PowerShell and connect to server for agent deployment
$serverList = @('Server01.corp.local', 'Server02.corp.local')
foreach ($server in $serverList) {
    Write-Host "Initializing remote management for $server"
    try {
        # Verify WinRM service is running
        $winrmStatus = Get-Service WinRM -ComputerName $server -ErrorAction SilentlyContinue
        if ($winrmStatus.Status -ne 'Running') {
            Write-Host "WinRM not running on $server, attempting to enable"
        }
        # Establish a remote session to deploy monitoring agent
        $session = New-PSSession -ComputerName $server -ErrorAction Stop
        if ($session) {
            Write-Host "Session created for $server"
            # Verify remote session connectivity with a simple query
            $remoteInfo = Invoke-Command -Session $session -ScriptBlock { Get-ComputerInfo -Property WindowsVersion } -ErrorAction SilentlyContinue
            if ($remoteInfo) {
                Write-Host "Successfully verified remote connectivity"
            }
            Remove-PSSession -Session $session
        }
    } catch {
        Write-Host "Unable to reach $server - continuing with next target"
    }
}
Write-Host "Remote management verification complete"

# -- Cluster: singleton_4151c10e-1ee4-4a75-8cba-d32c20451715  (1 rule(s)) ---------------------
# Intent:    Remote PowerShell session management and command invocation via cmdlet, which at
# Rules:     4151c10e-1ee4-4a75-8cba-d32c20451715
# Archetype: Software installer/updater workflow

$deploymentTargets = @('AppServer01', 'AppServer02')
$updateScript = {
    Get-Process | Where-Object { $_.Name -eq 'w3wp' } | Select-Object Name, Id | Out-Null
    $lastRestart = (Get-Date) - (New-TimeSpan -Seconds ([Environment]::TickCount / 1000))
    if ($lastRestart -lt (Get-Date).AddDays(-30)) {
        Write-Host 'IIS process is running and service status is nominal'
    }
}
foreach ($target in $deploymentTargets) {
    try {
        Write-Host "Deploying configuration update to $target"
        # Create a remote session for deployment
        $pssession = New-PSSession -ComputerName $target -ErrorAction Stop
        if ($pssession) {
            # Execute the maintenance script on the remote system
            Invoke-Command -Session $pssession -ScriptBlock $updateScript -ErrorAction SilentlyContinue
            Write-Host "Configuration deployed to $target"
            Remove-PSSession -Session $pssession
        }
    } catch {
        Write-Host "Deployment to $target failed - may be offline"
    }
}
Write-Host "Deployment cycle completed"

# -- Cluster: singleton_4151c10e-1ee4-4a75-8cba-d32c20451715  (1 rule(s)) ---------------------
# Intent:    Remote PowerShell session management and command invocation via cmdlet, which at
# Rules:     4151c10e-1ee4-4a75-8cba-d32c20451715
# Archetype: User-driven workflow

# Support workflow: connect to server for interactive troubleshooting
$targetServer = 'ProdApp01.corp.local'
Write-Host "Initiating remote troubleshooting session for $targetServer"
try {
    # Create a new remote PowerShell session
    $remoteSession = New-PSSession -ComputerName $targetServer -ErrorAction Stop
    if ($remoteSession) {
        Write-Host "Session established. Running diagnostic queries..."
        # Execute diagnostic commands in the remote session
        Invoke-Command -Session $remoteSession -ScriptBlock {
            Write-Host "Collecting system diagnostics"
            Get-Process | Where-Object { $_.WorkingSet -gt 500MB } | Select-Object Name, Id, WorkingSet
            Get-EventLog -LogName System -Newest 10 -EntryType Error | Select-Object TimeGenerated, Source, EventID
            Get-NetAdapter | Select-Object Name, Status, LinkSpeed
        } -ErrorAction SilentlyContinue
        Write-Host "Diagnostic data collected successfully"
        # Simulate analyst review of data
        Write-Host "Analysis complete - no critical issues detected"
        Remove-PSSession -Session $remoteSession
        Write-Host "Remote session closed"
    }
} catch {
    Write-Host "Cannot establish session to $targetServer - verify network connectivity"
}
Write-Host "Troubleshooting workflow complete"

# -- Cluster: singleton_633f1304-073f-44a3-aa18-0c65e541d521  (1 rule(s)) ---------------------
# Intent:    Detect when Windows scripting engines (PowerShell, VBScript, JScript, HTA) spawn
# Rules:     633f1304-073f-44a3-aa18-0c65e541d521
# Archetype: IT admin workflow

$adminScript = @'
Param([string]$targetSubnet = '192.168.1.0')

# Network diagnostics for infrastructure audit
$logPath = Join-Path $env:TEMP 'network_diagnostics.log'

# Test DNS resolution on multiple hosts
@('8.8.8.8', 'google.com', 'localhost') | ForEach-Object {
    nslookup $_ 2>&1 | Out-File -Append $logPath
}

# Ping gateway for connectivity verification
ping -n 2 127.0.0.1 2>&1 | Out-File -Append $logPath

# Query ARP table for network segment mapping
arp -a 2>&1 | Out-File -Append $logPath

# Enumerate local network resources
net view 2>&1 | Out-File -Append $logPath

# Generate summary report
Write-Output "Network diagnostics completed. Results: $logPath" | Out-File -Append $logPath

# Cleanup
Remove-Item -Path $logPath -Force -ErrorAction SilentlyContinue
'@

# Execute the diagnostic script
PowerShell.exe -NoProfile -ExecutionPolicy Bypass -Command $adminScript

# -- Cluster: singleton_633f1304-073f-44a3-aa18-0c65e541d521  (1 rule(s)) ---------------------
# Intent:    Detect when Windows scripting engines (PowerShell, VBScript, JScript, HTA) spawn
# Rules:     633f1304-073f-44a3-aa18-0c65e541d521
# Archetype: Software installer/updater workflow

$wshScript = @'
' Network connectivity validation for enterprise software deployment
Dim objWshNet, strComputer, arrServers, i
Set objWshNet = CreateObject("WScript.Network")
strComputer = objWshNet.ComputerName

' Query network configuration
CreateObject("WScript.Shell").Exec "nslookup localhost"
CreateObject("WScript.Shell").Exec "ping -n 1 127.0.0.1"
CreateObject("WScript.Shell").Exec "arp -a"
CreateObject("WScript.Shell").Exec "net view"
CreateObject("WScript.Shell").Exec "net group"
'@

$vbsPath = Join-Path $env:TEMP 'deploy_validation.vbs'
Set-Content -Path $vbsPath -Value $wshScript -Encoding ASCII

# Execute via cscript for legitimate deployment validation
cscript.exe //NoLogo $vbsPath 2>&1 | Out-Null

# Cleanup
Remove-Item -Path $vbsPath -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_633f1304-073f-44a3-aa18-0c65e541d521  (1 rule(s)) ---------------------
# Intent:    Detect when Windows scripting engines (PowerShell, VBScript, JScript, HTA) spawn
# Rules:     633f1304-073f-44a3-aa18-0c65e541d521
# Archetype: User-driven workflow

# Discover network printers and shared resources
$networkScript = {
    param([string]$subnet = '192.168.1')

    # Resolve hostname to IP
    Write-Output "Checking network connectivity..."
    nslookup localhost 2>&1 | Out-Null

    # Test ICMP to gateway
    ping -n 1 127.0.0.1 2>&1 | Out-Null

    # Display current ARP cache
    Write-Output "ARP table:"
    arp -a 2>&1 | Out-Null

    # Enumerate available shares on network
    Write-Output "Searching network resources..."
    net view 2>&1 | Out-Null

    # Check group memberships for resource access
    net group 2>&1 | Out-Null
}

# Execute discovery workflow
Invoke-Command -ScriptBlock $networkScript

# -- Cluster: singleton_929b0684-1bd5-4930-b9d9-0167e1dc4012  (1 rule(s)) ---------------------
# Intent:    Detect reconnaissance of Active Directory domain objects via ADSI/PowerShell cmd
# Rules:     929b0684-1bd5-4930-b9d9-0167e1dc4012
# Archetype: IT admin workflow

# Create a temporary directory for script files
$tempDir = [System.IO.Path]::GetTempPath()
$scriptPath = Join-Path -Path $tempDir -ChildPath "domain_audit_$(Get-Random).vbs"

# Create a VBScript that uses ADSI to enumerate domain information
# This mimics what an IT admin might do for compliance reporting
$vbScriptContent = @'
Set objADOConnection = CreateObject("ADODB.Connection")
Set objADOCommand = CreateObject("ADODB.Command")
objADOConnection.Provider = "ADsDSOObject"
objADOConnection.Open "Active Directory Provider"

Set objADOCommand.ActiveConnection = objADOConnection
objADOCommand.CommandText = "<LDAP://CN=Users,DC=corp,DC=example,DC=com>;(objectClass=user);cn;subtree"

Set objRecordSet = objADOCommand.Execute
WScript.Echo "Domain users enumerated for audit purposes"
'@

# Write the VBScript to disk
$vbScriptContent | Out-File -FilePath $scriptPath -Encoding ASCII -Force

try {
    # Execute the VBScript using cscript.exe (common script host)
    # This generates the process creation event with ADSI keywords in command line context
    & cscript.exe $scriptPath //Nologo 2>&1 | Out-Null

    # Also invoke via PowerShell with direct ADSI code to capture alternative pattern
    # This represents a sysadmin running ad-hoc domain queries
    $domainRoot = [ADSI]"LDAP://RootDSE"
    if ($null -ne $domainRoot.defaultNamingContext) {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$($domainRoot.defaultNamingContext)"
        $searcher.Filter = "(objectCategory=computer)"
        $searcher.SizeLimit = 5
        $results = $searcher.FindAll()
        # Legitimate query for inventory purposes
    }
} finally {
    # Cleanup
    if (Test-Path -LiteralPath $scriptPath) {
        Remove-Item -LiteralPath $scriptPath -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_929b0684-1bd5-4930-b9d9-0167e1dc4012  (1 rule(s)) ---------------------
# Intent:    Detect reconnaissance of Active Directory domain objects via ADSI/PowerShell cmd
# Rules:     929b0684-1bd5-4930-b9d9-0167e1dc4012
# Archetype: Software installer/updater workflow

$tempDir = [System.IO.Path]::GetTempPath()
$wsScriptPath = Join-Path -Path $tempDir -ChildPath "config_discovery_$(Get-Random).js"

# JavaScript-based configuration discovery script (executable via wscript.exe)
# Represents automated provisioning that checks OU membership and GPO links
$jsContent = @'
var objADOConnection = new ActiveXObject("ADODB.Connection");
var objADOCommand = new ActiveXObject("ADODB.Command");
objADOConnection.Provider = "ADsDSOObject";
objADOConnection.Open("Active Directory Provider");
objADOCommand.ActiveConnection = objADOConnection;
// Query for group policy links to determine applicable policies
objADOCommand.CommandText = "<LDAP://CN=Policies,CN=System,DC=corp,DC=example,DC=com>;(objectClass=groupPolicyContainer);displayName;subtree";
var objRecordSet = objADOCommand.Execute();
WScript.Echo("Configuration discovery: gplink evaluation completed");
'@

$jsContent | Out-File -FilePath $wsScriptPath -Encoding ASCII -Force

try {
    # Execute via wscript.exe - common script host for configuration automation
    & wscript.exe $wsScriptPath //Nologo 2>&1 | Out-Null

    # PowerShell-based alternative: Query domain OUs for provisioning decisions
    # This would appear in automated provisioning workflows
    try {
        $rootDse = [ADSI]"LDAP://RootDSE"
        if ($null -ne $rootDse) {
            $domainDN = $rootDse.defaultNamingContext
            $ouSearcher = New-Object System.DirectoryServices.DirectorySearcher
            $ouSearcher.SearchRoot = [ADSI]"LDAP://$domainDN"
            $ouSearcher.Filter = "(objectCategory=organizationalUnit)"
            $ouSearcher.SizeLimit = 10
            $ouResults = $ouSearcher.FindAll()
            # Results used for OU-based policy application
        }
    } catch {
        # Domain context not available - expected on isolated systems
    }
} finally {
    if (Test-Path -LiteralPath $wsScriptPath) {
        Remove-Item -LiteralPath $wsScriptPath -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_929b0684-1bd5-4930-b9d9-0167e1dc4012  (1 rule(s)) ---------------------
# Intent:    Detect reconnaissance of Active Directory domain objects via ADSI/PowerShell cmd
# Rules:     929b0684-1bd5-4930-b9d9-0167e1dc4012
# Archetype: User-driven workflow

$tempDir = [System.IO.Path]::GetTempPath()
$dllPath = Join-Path -Path $tempDir -ChildPath "netconfig_$(Get-Random).dll"
$scriptPath = Join-Path -Path $tempDir -ChildPath "query_domain_$(Get-Random).ps1"

# Create a PowerShell script that queries domain users and groups
# This simulates what IT staff might do for user provisioning or troubleshooting
$psScriptContent = @'
try {
    $domainRoot = [ADSI]"LDAP://RootDSE"
    if ($null -ne $domainRoot.defaultNamingContext) {
        # Query for domain users - common for IT support
        $userSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $userSearcher.SearchRoot = [ADSI]"LDAP://$($domainRoot.defaultNamingContext)"
        $userSearcher.Filter = "(&(objectClass=user)(objectCategory=person))"
        $userSearcher.SizeLimit = 3
        $users = $userSearcher.FindAll()

        # Query for groups - used for membership verification
        $groupSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $groupSearcher.SearchRoot = [ADSI]"LDAP://$($domainRoot.defaultNamingContext)"
        $groupSearcher.Filter = "(objectCategory=group)"
        $groupSearcher.SizeLimit = 3
        $groups = $groupSearcher.FindAll()
    }
} catch {
    # Expected if not in domain context
}
'@

$psScriptContent | Out-File -FilePath $scriptPath -Encoding UTF8 -Force

try {
    # Invoke the PowerShell script in a subprocess to generate process creation event
    # Using rundll32.exe as intermediary simulates certain admin tooling patterns
    & powershell.exe -NoProfile -NonInteractive -File $scriptPath 2>&1 | Out-Null

    # Alternative: Direct invocation of ADSI queries via PowerShell
    # This represents IT staff running ad-hoc troubleshooting commands
    try {
        $rootDse = [ADSI]"LDAP://RootDSE"
        if ($null -ne $rootDse) {
            $dnRoot = $rootDse.defaultNamingContext
            # Direct search for domain users
            $userSearch = New-Object System.DirectoryServices.DirectorySearcher
            $userSearch.SearchRoot = [ADSI]"LDAP://$dnRoot"
            $userSearch.Filter = "(objectCategory=person)"
            $userSearch.SizeLimit = 5
            $userList = $userSearch.FindAll()
        }
    } catch {
        # Domain unavailable - expected in non-domain environments
    }
} finally {
    if (Test-Path -LiteralPath $scriptPath) {
        Remove-Item -LiteralPath $scriptPath -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $dllPath) {
        Remove-Item -LiteralPath $dllPath -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_b484c489-9d61-4427-8373-b3a0ea54cefd  (1 rule(s)) ---------------------
# Intent:    Detect script hosts (wscript.exe, cscript.exe) launched from user-writable direc
# Rules:     b484c489-9d61-4427-8373-b3a0ea54cefd
# Archetype: IT admin workflow

$tempDir = $env:TEMP
$scriptName = 'inventory_check_' + [guid]::NewGuid().ToString().Substring(0, 8) + '.vbs'
$scriptPath = Join-Path $tempDir $scriptName

# Create a benign system inventory VBScript
$vbsContent = @'
On Error Resume Next
Set objWMIService = GetObject("winmgmts:")
Set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_LogicalDisk")
For Each objItem in colItems
    WScript.Echo "Drive: " & objItem.Name & " Space: " & objItem.Size
Next
Set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_OperatingSystem")
For Each objItem in colItems
    WScript.Echo "OS: " & objItem.Caption
Next
'@

Set-Content -Path $scriptPath -Value $vbsContent -Encoding ASCII

# Execute the script via wscript.exe
Start-Process -FilePath 'C:\Windows\System32\wscript.exe' -ArgumentList @($scriptPath, '/nologo') -NoNewWindow -Wait

# Cleanup
Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_b484c489-9d61-4427-8373-b3a0ea54cefd  (1 rule(s)) ---------------------
# Intent:    Detect script hosts (wscript.exe, cscript.exe) launched from user-writable direc
# Rules:     b484c489-9d61-4427-8373-b3a0ea54cefd
# Archetype: Software installer/updater workflow

$appDataPath = $env:APPDATA
$appDir = Join-Path $appDataPath 'EnterpriseApp_Installer'

if (-not (Test-Path $appDir)) {
    New-Item -ItemType Directory -Path $appDir -Force | Out-Null
}

# Create a configuration validation script
$scriptName = 'validate_install.vbs'
$scriptPath = Join-Path $appDir $scriptName

$vbsContent = @'
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objWSHShell = CreateObject("WScript.Shell")

strComputerName = objWSHShell.ExpandEnvironmentStrings("%COMPUTERNAME%")
strUserName = objWSHShell.ExpandEnvironmentStrings("%USERNAME%")

Set objFile = objFSO.CreateTextFile(objWSHShell.ExpandEnvironmentStrings("%APPDATA%\\EnterpriseApp_Installer\\install.log"), True)
objFile.WriteLine "Installation validation at " & Now()
objFile.WriteLine "Computer: " & strComputerName
objFile.WriteLine "User: " & strUserName
objFile.WriteLine "Status: OK"
objFile.Close
'@

Set-Content -Path $scriptPath -Value $vbsContent -Encoding ASCII

# Execute validation script
Start-Process -FilePath 'C:\Windows\System32\cscript.exe' -ArgumentList @($scriptPath, '/nologo') -NoNewWindow -Wait

# Cleanup
Remove-Item -Path $appDir -Recurse -Force -ErrorAction SilentlyContinue

# -- Cluster: singleton_b484c489-9d61-4427-8373-b3a0ea54cefd  (1 rule(s)) ---------------------
# Intent:    Detect script hosts (wscript.exe, cscript.exe) launched from user-writable direc
# Rules:     b484c489-9d61-4427-8373-b3a0ea54cefd
# Archetype: User-driven workflow

$downloadsPath = [Environment]::GetFolderPath('UserProfile')
$downloadsPath = Join-Path $downloadsPath 'Downloads'

if (-not (Test-Path $downloadsPath)) {
    New-Item -ItemType Directory -Path $downloadsPath -Force | Out-Null
}

# Create a system performance report script
$scriptName = 'perf_report.vbs'
$scriptPath = Join-Path $downloadsPath $scriptName

$vbsContent = @'
On Error Resume Next
Set objWMIService = GetObject("winmgmts:")
Set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_Processor")
For Each objItem in colItems
    WScript.Echo "CPU: " & objItem.Name & " Cores: " & objItem.NumberOfCores
Next
Set colItems = objWMIService.ExecQuery("SELECT * FROM Win32_ComputerSystem")
For Each objItem in colItems
    WScript.Echo "Total Memory: " & objItem.TotalPhysicalMemory / 1024 / 1024 / 1024 & " GB"
Next
'@

Set-Content -Path $scriptPath -Value $vbsContent -Encoding ASCII

# Execute the script
Start-Process -FilePath 'C:\Windows\System32\wscript.exe' -ArgumentList @($scriptPath, '/nologo') -NoNewWindow -Wait

# Cleanup
Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue


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
