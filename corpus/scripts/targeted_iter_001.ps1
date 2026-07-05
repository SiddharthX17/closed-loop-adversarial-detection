# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_e348161b-e3f5-44f0-b9bf-8ac826964728  (1 rule(s)) ---------------------
# Intent:    Detects command shell spawning scripting hosts (wscript, cscript, mshta) with in
# Rules:     e348161b-e3f5-44f0-b9bf-8ac826964728
# Archetype: Software installer/updater workflow

$tempDir = $env:TEMP
$scriptName = 'install_config_{0}.vbs' -f [System.IO.Path]::GetRandomFileName()
$scriptPath = Join-Path $tempDir $scriptName

# Simulate MSI installer spawning cmd to generate VBScript
$vbsCode = @'
Dim objShell
Set objShell = CreateObject("WScript.Shell")
objShell.RegWrite "HKLM\SOFTWARE\TestApp\installed", 1, "REG_DWORD"
Set objShell = Nothing
'@

Try {
    # Write VBScript content via cmd.exe echo (realistic for installer scenarios)
    cmd /c "echo. $($vbsCode | ForEach-Object { $_ }) > `"$scriptPath`""

    # Verify file was created
    if (Test-Path $scriptPath) {
        Write-Host "VBScript created successfully"
    }

    # Execute the VBScript using cscript.exe (child process of cmd from the installer context)
    cscript.exe $scriptPath //Nologo

    # Simulate what real installers do: check result and clean up
    Start-Sleep -Milliseconds 500
}
Catch {
    Write-Host "Script execution error: $_"
}
Finally {
    # Clean up the temporary script
    if (Test-Path $scriptPath) {
        Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
    }

    # Clean up registry entry created by script
    if (Test-Path 'HKLM:\SOFTWARE\TestApp') {
        Remove-Item 'HKLM:\SOFTWARE\TestApp' -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_e348161b-e3f5-44f0-b9bf-8ac826964728  (1 rule(s)) ---------------------
# Intent:    Detects command shell spawning scripting hosts (wscript, cscript, mshta) with in
# Rules:     e348161b-e3f5-44f0-b9bf-8ac826964728
# Archetype: IT admin workflow

$tempDir = $env:TEMP
$jsName = 'wmi_query_{0}.js' -f [System.IO.Path]::GetRandomFileName()
$jsPath = Join-Path $tempDir $jsName

# JavaScript WMI query for system information gathering (legitimate admin task)
$jsCode = @'
var locator = new ActiveXObject("WbemScripting.SWbemLocator");
var service = locator.ConnectServer(".", "root\\cimv2");
var processes = service.ExecQuery("Select Name from Win32_Process");
WScript.Echo("Process count retrieved via WMI");
'@

Try {
    # Write JavaScript inline using cmd echo - common pattern in batch automation
    $cmd = "echo. $($jsCode | ForEach-Object { $_ }) > `"$jsPath`""
    cmd /c $cmd

    if (Test-Path $jsPath) {
        Write-Host "JavaScript WMI script created"
    }

    # Execute via cscript.exe (admin performing WMI query)
    cscript.exe $jsPath //Nologo

    Start-Sleep -Milliseconds 300
}
Catch {
    Write-Host "WMI script error: $_"
}
Finally {
    # Clean up temporary JavaScript file
    if (Test-Path $jsPath) {
        Remove-Item $jsPath -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_e348161b-e3f5-44f0-b9bf-8ac826964728  (1 rule(s)) ---------------------
# Intent:    Detects command shell spawning scripting hosts (wscript, cscript, mshta) with in
# Rules:     e348161b-e3f5-44f0-b9bf-8ac826964728
# Archetype: Document/file operation workflow

$tempDir = $env:TEMP
$htaName = 'docprocess_{0}.hta' -f [System.IO.Path]::GetRandomFileName()
$htaPath = Join-Path $tempDir $htaName
$vbsName = 'converter_{0}.vbs' -f [System.IO.Path]::GetRandomFileName()
$vbsPath = Join-Path $tempDir $vbsName

# HTA content that calls CreateObject and spawns cmd to run VBScript
$htaCode = @'
<HTML>
<HEAD>
<TITLE>Document Processor</TITLE>
<HTA:APPLICATION ID="docapp" VERSION="1.0" />
</HEAD>
<BODY>
<SCRIPT language="VBScript">
Dim shell
Set shell = CreateObject("WScript.Shell")
shell.Run "cmd /c echo Dim fso | Set fso = CreateObject(""Scripting.FileSystemObject""^) >> $vbsPath && cscript.exe $vbsPath"
Set shell = Nothing
</SCRIPT>
</BODY>
</HTML>
'@

$vbsCode = @'
Dim fso
Set fso = CreateObject("Scripting.FileSystemObject")
WScript.Echo("File operations initialized")
Set fso = Nothing
'@

Try {
    # Create the HTA file
    $htaCode | Out-File -FilePath $htaPath -Encoding ASCII

    if (Test-Path $htaPath) {
        Write-Host "HTA document processor created"
    }

    # HTA execution (mshta.exe invokes the HTA which contains createobject)
    # The HTA internally runs: cmd /c [echo ... vbs code] && cscript
    mshta.exe $htaPath

    Start-Sleep -Milliseconds 500
}
Catch {
    Write-Host "HTA processing error: $_"
}
Finally {
    # Clean up temporary files
    @($htaPath, $vbsPath) | ForEach-Object {
        if (Test-Path $_) {
            Remove-Item $_ -Force -ErrorAction SilentlyContinue
        }
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
