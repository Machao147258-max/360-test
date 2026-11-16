@echo off
REM hrinstall.bat - argument-free: run the Huorong installer with a privileged task.
REM
REM Why not vmctl run / -interactive: measured 18:09, vmrun answered
REM "A program could not run on the guest operating system" -- the installer needs
REM elevation and UAC cannot prompt in that context. The scheduled-task path with
REM /rl highest is the shape already proven to work in this guest (persistence +
REM killall both ran through it).
set OUT=C:\Users\Public\hrinstall.txt
del "%OUT%" 2>nul
echo == attempt 1: silent /S via privileged task >> "%OUT%"
schtasks /create /tn lcs_hr /tr "C:\Users\Public\huorong.exe /S" /sc once /st 23:59 /ru vix /rp Passw0rd! /rl highest /f >> "%OUT%" 2>&1
schtasks /run /tn lcs_hr >> "%OUT%" 2>&1
ping -n 25 127.0.0.1 >nul
echo == state after 20s >> "%OUT%"
sc query Sysdiag >> "%OUT%" 2>&1
tasklist | findstr /I "Hips huorong sysdiag" >> "%OUT%" 2>&1
dir /b "C:\Program Files\Huorong" >> "%OUT%" 2>&1
echo == attempt 2: interactive session launch >> "%OUT%"
schtasks /create /tn lcs_hr2 /tr "C:\Users\Public\huorong.exe" /sc once /st 23:59 /ru vix /rp Passw0rd! /rl highest /it /f >> "%OUT%" 2>&1
schtasks /run /tn lcs_hr2 >> "%OUT%" 2>&1
ping -n 15 127.0.0.1 >nul
echo == processes (is the installer sitting in a session?) >> "%OUT%"
tasklist | findstr /I "huorong Hips" >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
