@echo off
REM avtest.bat - Defender on-demand scan rig (guest side).
REM Pushed to the guest and run via runProgramInGuest, then pull avtest.txt back.
REM usage: avtest.bat [C:\path\to\sample.exe]   (default C:\Users\Public\loader.exe)
REM Why: gives a per-build STATIC verdict baseline, so evasion changes are measurable
REM instead of guessed. Dynamic (behavioural) verdicts come from Get-MpThreatDetection.
setlocal
set OUT=C:\Users\Public\avtest.txt
set TARGET=%~1
if "%TARGET%"=="" set TARGET=C:\Users\Public\loader.exe
if exist "%TARGET%" (set SIZE=%~z1) else (set SIZE=missing)
del "%OUT%" 2>nul
echo == sample %TARGET% size=%SIZE% >> "%OUT%"
echo == scan start %DATE% %TIME% >> "%OUT%"
set MPC=C:\Program Files\Windows Defender\MpCmdRun.exe
if not exist "%MPC%" set MPC=C:\ProgramData\Microsoft\Windows Defender\Platform\MpCmdRun.exe
if exist "%MPC%" (
  "%MPC%" -Scan -ScanType 3 -File "%TARGET%" >> "%OUT%" 2>&1
  echo == mpc exit=%ERRORLEVEL% >> "%OUT%"
) else (
  echo == MpCmdRun not found >> "%OUT%"
)
echo == defender threats (catalog) >> "%OUT%"
powershell -nop -c "Get-MpThreat | Select-Object -First 3 ThreatName,IsActive | Format-List | Out-String" >> "%OUT%" 2>&1
echo == defender detections (last 3, with process resource) >> "%OUT%"
powershell -nop -c "Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 3 ThreatID,Resources,InitialDetectionTime | Format-List | Out-String" >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
endlocal
