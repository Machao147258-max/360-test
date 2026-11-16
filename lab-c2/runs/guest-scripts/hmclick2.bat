@echo off
REM hmclick2.bat - ASCII only. Runs the mouse-input experiment inside the interactive session.
set LOG=C:\Users\Public\hmclick2.txt
del "%LOG%" 2>nul
powershell -nop -ExecutionPolicy Bypass -File C:\Users\Public\hmclick2.ps1 >> "%LOG%" 2>&1
type C:\Users\Public\hm_result.txt >> "%LOG%" 2>&1
ping -n 10 127.0.0.1 >nul
sc query Sysdiag >> "%LOG%" 2>&1
dir /b "C:\Program Files\Huorong" >> "%LOG%" 2>&1
tasklist | findstr /I "huorong Hips sysdiag" >> "%LOG%" 2>&1
echo == end %TIME% >> "%LOG%"
