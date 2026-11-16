@echo off
REM hrkeys2.bat - ASCII only. Generic runner: executes TARGET inside the logged-on session
REM via an interactive (/it) task, then pulls the helper's logs back into one file.
set OUT=C:\Users\Public\hrkeys2.txt
set TARGET=C:\Users\Public\hmclick2.bat
del "%OUT%" 2>nul
echo == task for %TARGET% >> "%OUT%"
schtasks /delete /tn lcs_key2 /f >> "%OUT%" 2>&1
schtasks /create /tn lcs_key2 /tr "%TARGET%" /sc once /st 23:59 /ru vix /rp Passw0rd! /rl highest /it /f >> "%OUT%" 2>&1
echo rc=%ERRORLEVEL% >> "%OUT%"
schtasks /run /tn lcs_key2 >> "%OUT%" 2>&1
ping -n 70 127.0.0.1 >nul
echo == helper log >> "%OUT%"
type C:\Users\Public\hrmouse.txt >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
