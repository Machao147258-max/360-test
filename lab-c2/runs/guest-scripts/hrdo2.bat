@echo off
REM hrdo2.bat - ASCII only, runs inside the interactive session via a /it task.
REM Sequence, derived from the 18:21 screenshot:
REM   the wizard has ONE primary button; my earlier {TAB}{ENTER} landed on the title-bar
REM   X and raised "confirm exit?", so now:
REM     1) {TAB} moves focus to the second button of that dialog (取消), {ENTER} dismisses it
REM     2) {ENTER} then hits the wizard's default button to start the install
REM Log goes to hrdo2b.txt to avoid the redirect/file-lock clash seen with hrdo.txt.
set LOG=C:\Users\Public\hrdo2.txt
del "%LOG%" 2>nul
powershell -nop -c "$s=New-Object -ComObject wscript.shell; $p=Get-Process huorong64 -EA SilentlyContinue | Select-Object -First 1; if(-not $p){ 'NO-WINDOW' | Out-File -Encoding ascii C:\Users\Public\hrdo2b.txt; exit }; $null=$s.AppActivate($p.Id); Start-Sleep -Milliseconds 800; $s.SendKeys('{TAB}'); Start-Sleep -Milliseconds 500; $s.SendKeys('{ENTER}'); Start-Sleep -Milliseconds 1500; $s.SendKeys('{ENTER}'); ('SENT pid=' + $p.Id) | Out-File -Encoding ascii C:\Users\Public\hrdo2b.txt" >> "%LOG%" 2>&1
ping -n 12 127.0.0.1 >nul
echo == processes >> "%LOG%"
tasklist | findstr /I "huorong Hips sysdiag" >> "%LOG%" 2>&1
echo == service >> "%LOG%"
sc query Sysdiag >> "%LOG%" 2>&1
echo == end %TIME% >> "%LOG%"
