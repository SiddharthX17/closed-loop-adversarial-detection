# Auto-generated corpus stress-test script
# Pipeline: closed-loop-adversarial-detection
# Iteration:  iter_001
# Clusters:   1  |  Feasible: 1  |  Variants: 3
# Runner:     corpus_runner.yml (GH Actions)

$ProgressPreference    = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'

$iterationId = 'iter_001'

# -- Cluster: singleton_e3527e5e-b29b-4913-9d7b-28e156610827  (1 rule(s)) ---------------------
# Intent:    Detection of mshta.exe being invoked with remote URLs from scripting hosts or cm
# Rules:     e3527e5e-b29b-4913-9d7b-28e156610827
# Archetype: IT admin workflow

# IT Administrator testing HTML help system functionality
$tempDir = Join-Path -Path $env:TEMP -ChildPath "HtmlHelpTest_$(Get-Random)"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

try {
    # Create a minimal legitimate HTML help file locally
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head><title>System Help</title></head>
<body>
<h1>Help Documentation</h1>
<p>This is system help content.</p>
</body>
</html>
"@

    $htmlFile = Join-Path -Path $tempDir -ChildPath "help.html"
    Set-Content -Path $htmlFile -Value $htmlContent -Force

    # Start a temporary HTTP server to serve the HTML
    $port = 8765
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://127.0.0.1:$port/")
    $listener.Start()

    # Background task to handle HTTP requests
    $job = Start-Job -ScriptBlock {
        param($listener, $htmlFile)
        $listener.GetContext() | ForEach-Object {
            $response = $_.Response
            $html = Get-Content -Path $htmlFile -Raw
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
            $response.OutputStream.Close()
        }
    } -ArgumentList $listener, $htmlFile

    Start-Sleep -Milliseconds 500

    # Admin testing: launch mshta with the local HTTP URL to verify rendering
    & cmd.exe /c "mshta http://127.0.0.1:$port/help.html"

    Start-Sleep -Milliseconds 100

    $listener.Stop()
    Stop-Job -Job $job -Force 2>$null

} finally {
    # Cleanup
    if (Test-Path -Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_e3527e5e-b29b-4913-9d7b-28e156610827  (1 rule(s)) ---------------------
# Intent:    Detection of mshta.exe being invoked with remote URLs from scripting hosts or cm
# Rules:     e3527e5e-b29b-4913-9d7b-28e156610827
# Archetype: User-driven workflow

# User scenario: Opening HTML application content from intranet/local resource
$tempDir = Join-Path -Path $env:TEMP -ChildPath "HtmlAppTest_$(Get-Random)"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

try {
    # Create a VBScript file that will invoke mshta with a URL (simulating automated tool invocation)
    $vbsContent = @"
Set objHTTP = CreateObject("MSXML2.XMLHTTP")
objHTTP.Open "GET", "http://127.0.0.1:9999/app.html", False
objHTTP.Send
Set shell = CreateObject("WScript.Shell")
shell.Run "mshta http://127.0.0.1:9999/app.html"
"@

    $vbsFile = Join-Path -Path $tempDir -ChildPath "launcher.vbs"
    Set-Content -Path $vbsFile -Value $vbsContent -Force

    # Create HTML application content
    $htaContent = @"
<html>
<head>
<title>Enterprise Tool</title>
</head>
<body>
<h1>Application Content</h1>
<p>Loading application interface...</p>
</body>
</html>
"@

    $htmlFile = Join-Path -Path $tempDir -ChildPath "app.html"
    Set-Content -Path $htmlFile -Value $htaContent -Force

    # Start HTTP listener for the application content
    $port = 9999
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://127.0.0.1:$port/")
    $listener.Start()

    # Background job to serve HTML
    $job = Start-Job -ScriptBlock {
        param($listener, $htmlFile)
        $maxRequests = 2
        $count = 0
        while ($count -lt $maxRequests) {
            try {
                $context = $listener.GetContext()
                $response = $context.Response
                $html = Get-Content -Path $htmlFile -Raw
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
                $response.OutputStream.Close()
                $count++
            } catch {}
        }
    } -ArgumentList $listener, $htmlFile

    Start-Sleep -Milliseconds 500

    # User invokes via wscript (simulating legitimate HTML app invocation)
    & cscript.exe $vbsFile 2>$null

    Start-Sleep -Milliseconds 500

    $listener.Stop()
    Stop-Job -Job $job -Force 2>$null

} finally {
    # Cleanup
    if (Test-Path -Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# -- Cluster: singleton_e3527e5e-b29b-4913-9d7b-28e156610827  (1 rule(s)) ---------------------
# Intent:    Detection of mshta.exe being invoked with remote URLs from scripting hosts or cm
# Rules:     e3527e5e-b29b-4913-9d7b-28e156610827
# Archetype: Software installer/updater workflow

# Software deployment: PowerShell-based installer checking and launching HTML wizard
$tempDir = Join-Path -Path $env:TEMP -ChildPath "SoftwareSetup_$(Get-Random)"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

try {
    # Create installation wizard HTML
    $wizardHtml = @"
<!DOCTYPE html>
<html>
<head>
<title>Installation Wizard</title>
<style>
body { font-family: Arial; }
</style>
</head>
<body>
<h2>Software Installation Wizard</h2>
<p>Installation in progress...</p>
<p>License Agreement Accepted</p>
<p>Installation path: C:\\Program Files\\MyApp</p>
</body>
</html>
"@

    $wizardFile = Join-Path -Path $tempDir -ChildPath "wizard.html"
    Set-Content -Path $wizardFile -Value $wizardHtml -Force

    # Setup HTTP listener for wizard content distribution
    $port = 7654
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://127.0.0.1:$port/")
    $listener.Start()

    # Background job to serve wizard content
    $job = Start-Job -ScriptBlock {
        param($listener, $wizardFile)
        $context = $listener.GetContext()
        $response = $context.Response
        $html = Get-Content -Path $wizardFile -Raw
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
        $response.ContentLength64 = $buffer.Length
        $response.OutputStream.Write($buffer, 0, $buffer.Length)
        $response.OutputStream.Close()
    } -ArgumentList $listener, $wizardFile

    Start-Sleep -Milliseconds 500

    # PowerShell-based installer launches mshta to display wizard
    # This simulates legitimate software deployment using mshta for GUI rendering
    & powershell.exe -NoProfile -Command @"
Start-Process -FilePath mshta.exe -ArgumentList 'http://127.0.0.1:$port/wizard.html' -Wait
"@

    Start-Sleep -Milliseconds 100

    $listener.Stop()
    Stop-Job -Job $job -Force 2>$null

} finally {
    # Cleanup
    if (Test-Path -Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
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
