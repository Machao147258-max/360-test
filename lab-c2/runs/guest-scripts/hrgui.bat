@echo off
REM hrgui.bat - argument-free: launch the x64 Huorong installer GUI in the INTERACTIVE session.
REM
REM Why: /S silent install does nothing (measured 18:19 - no Sysdiag service, no install
REM dir), so the GUI wizard is the only path. It must run in the logged-on session (/it)
REM because that is where a desktop exists and where VIX sendKeys can reach it.
set OUT=C:\Users\Public\hrgui.txt
del "%OUT%" 2>nul
echo == create interactive task >> "%OUT%"
schtasks /create /tn lcs_hrgui /tr "C:\Users\Public\huorong64.exe" /sc once /st 23:59 /ru vix /rp Passw0rd! /rl highest /it /f >> "%OUT%" 2>&1
echo rc=%ERRORLEVEL% >> "%OUT%"
schtasks /run /tn lcs_hrgui >> "%OUT%" 2>&1
ping -n 14 127.0.0.1 >nul
echo == installer process >> "%OUT%"
tasklist | findstr /I "huorong" >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
