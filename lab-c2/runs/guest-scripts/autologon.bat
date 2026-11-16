@echo off
REM autologon.bat - argument-free: make the guest log itself in at boot.
REM
REM Why this is the answer to "can you get into the desktop yourself": vmrun exposes no
REM VIX logon call, Win11 Home has no RDP server, and host-side key injection into the
REM guest is broken on Workstation 25. Autologon is the only mechanism that puts a
REM real interactive desktop session in place without anyone typing.
REM Lab tradeoff: it stores a plaintext password in the registry. Revert with:
REM   reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 0 /f
set OUT=C:\Users\Public\autologon.txt
set W=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
del "%OUT%" 2>nul
echo == set >> "%OUT%"
reg add "%W%" /v AutoAdminLogon /t REG_SZ /d 1 /f >> "%OUT%" 2>&1
reg add "%W%" /v DefaultUserName /t REG_SZ /d vix /f >> "%OUT%" 2>&1
reg add "%W%" /v DefaultPassword /t REG_SZ /d Passw0rd! /f >> "%OUT%" 2>&1
reg add "%W%" /v DefaultDomainName /t REG_SZ /d XIAOJIE /f >> "%OUT%" 2>&1
echo == verify >> "%OUT%"
reg query "%W%" /v AutoAdminLogon >> "%OUT%" 2>&1
reg query "%W%" /v DefaultUserName >> "%OUT%" 2>&1
reg query "%W%" /v DefaultDomainName >> "%OUT%" 2>&1
echo == current interactive session >> "%OUT%"
tasklist /FI "IMAGENAME eq explorer.exe" >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
