@echo off
REM hrkeys.bat - ASCII only. Runs a key-sending helper INSIDE the logged-on session by
REM creating an interactive (/it) scheduled task, then reports what it saw.
REM Generic wrapper: edit the TARGET line to point at a different helper.
set OUT=C:\Users\Public\hrkeys.txt
set TARGET=C:\Users\Public\hrdo2.bat
del "%OUT%" 2>nul
echo == create /it task for %TARGET% >> "%OUT%"
schtasks /delete /tn lcs_key /f >> "%OUT%" 2>&1
schtasks /create /tn lcs_key /tr "%TARGET%" /sc once /st 23:59 /ru vix /rp Passw0rd! /rl highest /it /f >> "%OUT%" 2>&1
echo rc=%ERRORLEVEL% >> "%OUT%"
schtasks /run /tn lcs_key >> "%OUT%" 2>&1
ping -n 14 127.0.0.1 >nul
echo == helper log >> "%OUT%"
type C:\Users\Public\hrdo2b.txt >> "%OUT%" 2>&1
echo == helper stdout >> "%OUT%"
type C:\Users\Public\hrdo2.txt >> "%OUT%" 2>&1
echo == install state >> "%OUT%"
sc query Sysdiag >> "%OUT%" 2>&1
dir /b "C:\Program Files\Huorong" >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
