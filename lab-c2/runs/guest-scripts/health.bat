@echo off
REM health.bat - one-shot guest health snapshot. Pushed, run via runProgramInGuest,
REM then pulled back. Every line appends immediately so a force-kill keeps evidence.
set OUT=C:\Users\Public\health.txt
del "%OUT%" 2>nul
echo == time %DATE% %TIME% >> "%OUT%"
echo == uptime / boot >> "%OUT%"
powershell -nop -c "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime" >> "%OUT%" 2>&1
echo == sessions >> "%OUT%"
query user >> "%OUT%" 2>&1
echo == services >> "%OUT%"
sc query Winmgmt | findstr /C:"STATE" >> "%OUT%" 2>&1
sc query Schedule | findstr /C:"STATE" >> "%OUT%" 2>&1
sc query TermService | findstr /C:"STATE" >> "%OUT%" 2>&1
sc query VMTools | findstr /C:"STATE" >> "%OUT%" 2>&1
echo == reg write HKLM >> "%OUT%"
reg add "HKLM\SOFTWARE\LCSLab" /v t /t REG_SZ /d ok /f >> "%OUT%" 2>&1
echo rc=%ERRORLEVEL% >> "%OUT%"
echo == reg write HKCU >> "%OUT%"
reg add "HKCU\SOFTWARE\LCSLab" /v t /t REG_SZ /d ok /f >> "%OUT%" 2>&1
echo rc=%ERRORLEVEL% >> "%OUT%"
echo == redirect test >> "%OUT%"
echo HELLO-REDIRECT > C:\Users\Public\probe.txt
type C:\Users\Public\probe.txt >> "%OUT%" 2>&1
echo == wmi create test >> "%OUT%"
powershell -nop -c "$r=Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='cmd /c echo wmi-ok > C:\Users\Public\wmi_probe.txt'}; 'pid=' + $r.ProcessId + ' rc=' + $r.ReturnValue" >> "%OUT%" 2>&1
echo == task scheduler create test >> "%OUT%"
schtasks /create /tn lcs_health /tr "C:\Windows\System32\cmd.exe /c echo task-ok" /sc once /st 23:59 /f >> "%OUT%" 2>&1
echo rc=%ERRORLEVEL% >> "%OUT%"
echo == defender >> "%OUT%"
powershell -nop -c "(Get-MpComputerStatus).RealTimeProtectionEnabled" >> "%OUT%" 2>&1
powershell -nop -c "((Get-MpPreference).ExclusionPath -join ';')" >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
