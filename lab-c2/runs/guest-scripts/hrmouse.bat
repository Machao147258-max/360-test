@echo off
REM hrmouse.bat - ASCII only. Runs hrmouse.ps1 (real mouse click) then reports install state.
REM Meant to be launched by an interactive (/it) task so the click lands in the
REM session that owns the installer window.
set LOG=C:\Users\Public\hrmouse.txt
del "%LOG%" 2>nul
echo == mouse click >> "%LOG%"
powershell -nop -ExecutionPolicy Bypass -File C:\Users\Public\hrmouse.ps1 >> "%LOG%" 2>&1
echo == clicker said >> "%LOG%"
type C:\Users\Public\hrmouse_b.txt >> "%LOG%" 2>&1
ping -n 55 127.0.0.1 >nul
echo == install state after 50s >> "%LOG%"
sc query Sysdiag >> "%LOG%" 2>&1
dir /b "C:\Program Files\Huorong" >> "%LOG%" 2>&1
tasklist | findstr /I "huorong Hips sysdiag usysdiag" >> "%LOG%" 2>&1
echo == end %TIME% >> "%LOG%"
