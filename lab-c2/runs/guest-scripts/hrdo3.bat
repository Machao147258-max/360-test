@echo off
REM hrdo3.bat - ASCII only, runs in the interactive session via a /it task.
REM Sends ONE Enter to the Huorong wizard. Rationale: the wizard's primary button is the
REM default button, but the earlier attempt prepended {TAB} which moved focus to the
REM title-bar X and raised "confirm exit?". UIA is not an option: the wizard is custom
REM drawn, so its UIA tree exposes no Button (measured: NO-BUTTON).
set LOG=C:\Users\Public\hrdo3.txt
del "%LOG%" 2>nul
powershell -nop -c "$s=New-Object -ComObject wscript.shell; $p=Get-Process huorong64 -EA SilentlyContinue | Select-Object -First 1; if(-not $p){ 'NO-WINDOW' | Out-File -Encoding ascii C:\Users\Public\hrdo3b.txt; exit }; $null=$s.AppActivate($p.Id); Start-Sleep -Milliseconds 1000; $s.SendKeys('{ENTER}'); ('ENTER-SENT pid=' + $p.Id) | Out-File -Encoding ascii C:\Users\Public\hrdo3b.txt" >> "%LOG%" 2>&1
ping -n 50 127.0.0.1 >nul
echo == install state after 45s >> "%LOG%"
sc query Sysdiag >> "%LOG%" 2>&1
dir /b "C:\Program Files\Huorong" >> "%LOG%" 2>&1
tasklist | findstr /I "huorong Hips sysdiag usysdiag" >> "%LOG%" 2>&1
echo == end %TIME% >> "%LOG%"
