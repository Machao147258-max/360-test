@echo off
REM verify.bat - argument-free state dump used by the reboot / self-heal verification.
REM Invoked via vmctl -script with NO arguments (that is the only reliable form), then
REM verify.txt is pulled back and read host-side.
set OUT=C:\Users\Public\verify.txt
del "%OUT%" 2>nul
echo == time %DATE% %TIME% >> "%OUT%"
echo == boot time >> "%OUT%"
powershell -nop -c "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime" >> "%OUT%" 2>&1
echo == loader process (ldr.exe) >> "%OUT%"
tasklist /FI "IMAGENAME eq ldr.exe" >> "%OUT%" 2>&1
echo == HKCU Run >> "%OUT%"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v lcs >> "%OUT%" 2>&1
echo == HKLM Run >> "%OUT%"
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v lcs >> "%OUT%" 2>&1
echo == task lcs_onlogon >> "%OUT%"
schtasks /query /tn lcs_onlogon /fo list >> "%OUT%" 2>&1
echo == task lcs_5min >> "%OUT%"
schtasks /query /tn lcs_5min /fo list >> "%OUT%" 2>&1
echo == trace tail >> "%OUT%"
powershell -nop -c "Get-Content C:\Users\Public\lcs_trace.log -Tail 12 -ErrorAction SilentlyContinue" >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
