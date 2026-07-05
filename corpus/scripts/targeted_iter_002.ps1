# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_002
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_002'

# -- Cluster: singleton_c11d1cdf-ad73-41a0-a0f7-1d2a65ca571c  (1 rule(s)) ---------------------
# Intent:    Attackers executing arbitrary scripts or code through Windows Script Host interp
# Rules:     c11d1cdf-ad73-41a0-a0f7-1d2a65ca571c
# Archetype: Software installer/updater workflow

# Simulate a legitimate MSI-based application installation that uses VBScript custom actions
# Real installers (e.g., Adobe, Kaspersky, compliance tools) commonly embed and execute scripts

$tempDir = $env:TEMP
$scriptName = 'install_action_$(Get-Random).vbs'
$scriptPath = Join-Path $tempDir $scriptName

# Create a benign VBScript that an installer might run (e.g., registry verification)
$vbsContent = @'
Dim objShell, result
Set objShell = CreateObject("WScript.Shell")
result = objShell.Run("cmd /c echo Installation verification complete", 0, true)
WScript.Quit 0
'@

$vbsContent | Out-File -FilePath $scriptPath -Encoding ASCII -Force

try {
    # Simulate the parent process being msiexec (what a real installer would do)
    # Execute the script through cscript.exe as an installer custom action would
    & cscript.exe $scriptPath //E:VBScript //B 2>&1 | Out-Null

    # Also demonstrate wscript.exe execution (alternative installer path)
    & wscript.exe $scriptPath //E:VBScript 2>&1 | Out-Null
} finally {
    Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
}

Write-Host 'Installation verification completed'

# -- Cluster: singleton_c11d1cdf-ad73-41a0-a0f7-1d2a65ca571c  (1 rule(s)) ---------------------
# Intent:    Attackers executing arbitrary scripts or code through Windows Script Host interp
# Rules:     c11d1cdf-ad73-41a0-a0f7-1d2a65ca571c
# Archetype: IT admin workflow

# Simulate a legitimate administrative automation tool using mshta.exe
# Enterprise management tools (SCCM, ConfigMgr, policy enforcers) use this pattern

$tempDir = $env:TEMP
$htmlFile = Join-Path $tempDir "admin_check_$(Get-Random).hta"

# Create a benign HTA that performs system compliance checking
$htaContent = @'
<html>
<head>
<title>System Compliance Check</title>
<script language="VBScript">
Sub Window_OnLoad
    Dim objShell, regPath
    Set objShell = CreateObject("WScript.Shell")
    regPath = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion"
    objShell.RegRead regPath
    window.close()
End Sub
</script>
</head>
<body>
Compliance check executing...
</body>
</html>
'@

$htaContent | Out-File -FilePath $htmlFile -Encoding ASCII -Force

try {
    # Execute via mshta as a legitimate admin tool would
    # mshta with vbscript: protocol is standard for HTA execution
    Start-Process -FilePath "mshta.exe" -ArgumentList $htmlFile -Wait -NoNewWindow -ErrorAction SilentlyContinue
} finally {
    Remove-Item -Path $htmlFile -Force -ErrorAction SilentlyContinue
}

Write-Host 'Administrative compliance check completed'

# -- Cluster: singleton_c11d1cdf-ad73-41a0-a0f7-1d2a65ca571c  (1 rule(s)) ---------------------
# Intent:    Attackers executing arbitrary scripts or code through Windows Script Host interp
# Rules:     c11d1cdf-ad73-41a0-a0f7-1d2a65ca571c
# Archetype: User-driven workflow

# Simulate user-triggered script execution from a standard user directory
# Real scenario: user downloads a configuration utility or opens a file that triggers script execution

# Use Desktop or Documents (user-writable paths the rule monitors)
$userDocsPath = [System.Environment]::GetFolderPath('MyDocuments')
$configScript = Join-Path $userDocsPath "config_$(Get-Random).js"

# Create a benign JavaScript file (like a configuration utility might use)
$jsContent = @'
var shell = new ActiveXObject("WScript.Shell");
var result = shell.Run("cmd /c echo System configuration initialized", 0, true);
WScript.Quit(0);
'@

$jsContent | Out-File -FilePath $configScript -Encoding ASCII -Force

try {
    # Simulate user opening this file - mshta or wscript could be the handler
    # Real applications sometimes use mshta to execute embedded JavaScript
    Start-Process -FilePath "wscript.exe" -ArgumentList $configScript -Wait -NoNewWindow -ErrorAction SilentlyContinue
} finally {
    Remove-Item -Path $configScript -Force -ErrorAction SilentlyContinue
}

Write-Host 'Document processing completed'


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
