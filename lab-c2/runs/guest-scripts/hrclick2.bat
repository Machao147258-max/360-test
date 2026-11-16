@echo off
REM hrclick2.bat - ASCII only. Creates and runs an INTERACTIVE (/it) task that executes
REM hrdo.bat inside the logged-on session, then reports what happened.
set OUT=C:\Users\Public\hrclick2.txt
del "%OUT%" 2>nul
echo == create /it click task >> "%OUT%"
schtasks /create /tn lcs_hrclick /tr "C:\Users\Public\hrdo.bat" /sc once /st 23:59 /ru vix /rp Passw0rd! /rl highest /it /f >> "%OUT%" 2>&1
echo rc=%ERRORLEVEL% >> "%OUT%"
schtasks /run /tn lcs_hrclick >> "%OUT%" 2>&1
ping -n 12 127.0.0.1 >nul
echo == hrdo.txt (what the clicker saw) >> "%OUT%"
type C:\Users\Public\hrdo.txt >> "%OUT%" 2>&1
echo == install state >> "%OUT%"
sc query Sysdiag >> "%OUT%" 2>&1
dir /b "C:\Program Files\Huorong" >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
