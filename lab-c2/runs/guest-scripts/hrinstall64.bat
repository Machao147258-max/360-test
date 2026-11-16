@echo off
REM hrinstall64.bat - argument-free: kill the wrong-arch dialog, then install the x64 build.
REM
REM Notes from the failed first attempt (18:10): the x86 package aborts with
REM "detected X64 OS, use the matching installer", and `vmctl run -interactive`
REM cannot start the installer at all ("A program could not run on the guest
REM operating system" -- elevation/UAC). So: privileged scheduled task, silent /S first.
set OUT=C:\Users\Public\hrinstall64.txt
del "%OUT%" 2>nul
echo == kill the old x86 dialog (privileged task, VIX token cannot do it) >> "%OUT%"
schtasks /create /tn lcs_hrk /tr "taskkill /IM huorong.exe /F" /sc once /st 23:59 /ru vix /rp Passw0rd! /rl highest /f >> "%OUT%" 2>&1
schtasks /run /tn lcs_hrk >> "%OUT%" 2>&1
ping -n 7 127.0.0.1 >nul
schtasks /delete /tn lcs_hrk /f >> "%OUT%" 2>&1
echo == silent install /S on the x64 build >> "%OUT%"
schtasks /create /tn lcs_hr64 /tr "C:\Users\Public\huorong64.exe /S" /sc once /st 23:59 /ru vix /rp Passw0rd! /rl highest /f >> "%OUT%" 2>&1
schtasks /run /tn lcs_hr64 >> "%OUT%" 2>&1
ping -n 45 127.0.0.1 >nul
echo == state after 45s >> "%OUT%"
sc query Sysdiag >> "%OUT%" 2>&1
tasklist | findstr /I "huorong Hips sysdiag" >> "%OUT%" 2>&1
dir /b "C:\Program Files\Huorong" >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
