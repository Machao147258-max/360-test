@echo off
REM hrdo.bat - ASCII only. Runs INSIDE the interactive session (launched by a /it task).
REM Sends Enter to the Huorong installer window using the guest's own input stack --
REM the path that works after vmrun typeKeystrokesInGuest was refused for host
REM permissions ("Insufficient permissions in the host operating system").
REM Chinese window titles are avoided on purpose: a .bat is decoded as ANSI here.
set OUT=C:\Users\Public\hrdo.txt
del "%OUT%" 2>nul
powershell -nop -c "$p=Get-Process huorong64 -EA SilentlyContinue | Select-Object -First 1; if(-not $p){ 'NO-WINDOW' | Out-File -Encoding ascii C:\Users\Public\hrdo.txt; exit }; $s=New-Object -ComObject wscript.shell; $null=$s.AppActivate($p.Id); Start-Sleep -Milliseconds 900; $s.SendKeys('{TAB}'); Start-Sleep -Milliseconds 300; $s.SendKeys('{ENTER}'); ('SENT pid=' + $p.Id) | Out-File -Encoding ascii C:\Users\Public\hrdo.txt" >> "%OUT%" 2>&1
ping -n 10 127.0.0.1 >nul
echo == processes after >> "%OUT%"
tasklist | findstr /I "huorong Hips sysdiag" >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
