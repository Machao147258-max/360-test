# avtest_run.ps1 - automated A/B test loop for the lab-c2 payload. ASCII ONLY.
#
# Per round: fresh build -> push (fixed path) -> on-demand AV scan -> WMI launch ->
# sample session liveness -> collect trace + AV events -> append one CSV row.
#
# Fixed remote path on purpose: the variable under test is the BINARY (new hash per
# build), not the path. Same binary at the same path behaved differently over time
# (rc=0 at 16:49, rc=8 at 16:51), so always rebuild before measuring anything.
#
# usage:
#   pwsh -NoProfile -File tools\avtest_run.ps1 -Vmx '<vmx>' -Lab '<lab-c2>' -Rounds 3
#   ... -SampleMin 30   (minutes to watch each round; default 5 for a quick pass)
param(
    [Parameter(Mandatory = $true)][string]$Vmx,
    [Parameter(Mandatory = $true)][string]$Lab,
    [int]$Rounds = 3,
    [int]$SampleMin = 5,
    [int]$PollSec = 15,
    [string]$Sid = '6:vix:s0'
)
$ErrorActionPreference = 'Continue'
$vm = 'D:\viscalsoftware\vmctl.ps1'
$runs = Join-Path $Lab 'runs'
$ctl = Join-Path $Lab 'tools\c2ctl.py'
$evi = Join-Path $runs 'evidence'
$gs = Join-Path $runs 'guest-scripts'
$csv = Join-Path $evi 'avtest_matrix.csv'
New-Item -ItemType Directory -Force -Path $evi | Out-Null
if (-not (Test-Path $csv)) {
    'time,build_sha16,write_verdict,scan_verdict,launch_rc,online_at,lost_at,alive_s,verdict_name,note' |
        Out-File -Encoding ascii $csv
}

function Guest([string]$action, [string]$a1 = '', [string]$a2 = '', [int]$timeout = 120) {
    if ($a1 -and $a2) { & $vm -Vmx $Vmx -Vp '123456789' -Gu vix -Gp 'Passw0rd!' -TimeoutSec $timeout $action $a1 $a2 }
    elseif ($a1) { & $vm -Vmx $Vmx -Vp '123456789' -Gu vix -Gp 'Passw0rd!' -TimeoutSec $timeout $action $a1 }
    else { & $vm -Vmx $Vmx -Vp '123456789' -Gu vix -Gp 'Passw0rd!' -TimeoutSec $timeout $action }
}
function GuestRun([string]$bat, [int]$timeout = 300) {
    Guest 'script' ("C:\Users\Public\" + $bat) '' $timeout | Out-Null
}
function Pull([string]$remote, [string]$local) {
    if (Test-Path $local) { Remove-Item $local -Force }
    Guest 'pull' $remote $local 60 | Out-Null
}

for ($r = 1; $r -le $Rounds; $r++) {
    $stamp = Get-Date -Format 'HHmmss'
    Write-Host ("===== ROUND $r / $Rounds  ($stamp) =====")

    # 1) fresh build
    Push-Location $Lab
    cmd.exe /c 'call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1 && build.bat build\beacon.exe force > build_log_force.txt 2>&1'
    $buildExit = $LASTEXITCODE
    Pop-Location
    if ($buildExit -ne 0) { Write-Host "BUILD FAILED ($buildExit) - aborting"; exit 1 }
    $payload = Join-Path $Lab 'build\loader.exe'
    $sha = (Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash.Substring(0, 16)
    Write-Host ("payload sha256_16=" + $sha)

    # 2) push + launcher
    Guest 'push' $payload 'C:\Users\Public\ldr.exe' 180 | Out-Null
    Guest 'push' (Join-Path $gs 'avtest.bat') 'C:\Users\Public\avtest.bat' 60 | Out-Null
    Guest 'push' (Join-Path $gs 'runldr.bat') 'C:\Users\Public\runldr.bat' 60 | Out-Null
    Guest 'push' (Join-Path $gs 'diag2.bat') 'C:\Users\Public\diag2.bat' 60 | Out-Null

    # 3) write-verdict (real-time detection at push time) is captured by diag2 -> scan
    Write-Host 'static: on-demand scan'
    GuestRun 'avtest.bat' 240
    $scanFile = Join-Path $evi ("avtest_$stamp.txt")
    Pull 'C:\Users\Public\avtest.txt' $scanFile
    $scanVerdict = 'unknown'
    if (Test-Path $scanFile) {
        $t = Get-Content $scanFile -Raw
        if ($t -match 'found no threats') { $scanVerdict = 'clean' }
        elseif ($t -match 'ThreatName\s*:\s*(\S+)') { $scanVerdict = $Matches[1] }
        else { $scanVerdict = 'no-result' }
    }
    Write-Host ("scan => " + $scanVerdict)

    # 4) launch
    Write-Host 'launch via WMI'
    GuestRun 'runldr.bat' 120
    $lf = Join-Path $evi ("launch_$stamp.txt")
    Pull 'C:\Users\Public\launch.txt' $lf
    $launchRc = 'n/a'
    if (Test-Path $lf) {
        $lt = Get-Content $lf -Raw
        if ($lt -match 'rc=(\d+)') { $launchRc = $Matches[1] }
    }
    Write-Host ("launch rc=" + $launchRc)

    # 5) sample liveness
    $onlineAt = ''
    $lostAt = ''
    $misses = 0
    $deadline = (Get-Date).AddMinutes($SampleMin)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $PollSec
        $o = (python $ctl sessions 2>&1 | Out-String)
        $live = ($o -match 'LIVE_SESSIONS=[1-9]')
        if ($live) {
            if (-not $onlineAt) { $onlineAt = Get-Date -Format 'HH:mm:ss' }
            $misses = 0
        }
        else {
            $misses++
            if ($misses -ge 2 -and -not $lostAt) { $lostAt = Get-Date -Format 'HH:mm:ss'; break }
        }
    }

    # 6) collect AV events + trace
    GuestRun 'diag2.bat' 240
    $df = Join-Path $evi ("diag_$stamp.txt")
    Pull 'C:\Users\Public\diag2.txt' $df
    $verdictName = ''
    if (Test-Path $df) {
        $dt = Get-Content $df -Raw
        if ($dt -match 'ThreatName\s*:\s*(\S+)') { $verdictName = $Matches[1] }
    }
    Pull 'C:\Users\Public\lcs_trace.log' (Join-Path $runs ("logs\lcs_trace_$stamp.log"))

    # 7) row
    $alive = ''
    if ($onlineAt -and $lostAt) {
        $alive = [int](([datetime]::Parse($lostAt)) - ([datetime]::Parse($onlineAt))).TotalSeconds
    }
    elseif ($onlineAt) { $alive = 'still-up' }
    $row = @(
        (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $sha, 'see-diag', $scanVerdict,
        $launchRc, $onlineAt, $lostAt, $alive, $verdictName, ("round $r")
    ) -join ','
    $row | Out-File -Append -Encoding ascii $csv
    Write-Host ("ROUND $r => " + $row)
}
Write-Host ('matrix: ' + $csv)
