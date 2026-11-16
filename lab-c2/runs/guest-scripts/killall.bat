@echo off
REM killall.bat - argument-free: kill every ldr.exe instance with a privileged context.
REM
REM Why not just "taskkill" through runProgramInGuest: measured 17:28, that returns
REM exit 1 and kills nothing. The VIX guest-ops token does not carry usable
REM SeDebugPrivilege, and one of the instances lives in another session (Console/1).
REM A scheduled task with /rl highest (same shape as our persistence tasks, which the
REM trace proved DO have privileges enabled) can kill across sessions.
set OUT=C:\Users\Public\kill.txt
del "%OUT%" 2>nul
echo == before >> "%OUT%"
tasklist /FI "IMAGENAME eq ldr.exe" >> "%OUT%" 2>&1
echo == create+run privileged kill task >> "%OUT%"
schtasks /create /tn lcs_kill /tr "taskkill /IM ldr.exe /F" /sc once /st 23:59 /ru vix /rp Passw0rd! /rl highest /f >> "%OUT%" 2>&1
schtasks /run /tn lcs_kill >> "%OUT%" 2>&1
ping -n 7 127.0.0.1 >nul
echo == after >> "%OUT%"
tasklist /FI "IMAGENAME eq ldr.exe" >> "%OUT%" 2>&1
schtasks /delete /tn lcs_kill /f >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
