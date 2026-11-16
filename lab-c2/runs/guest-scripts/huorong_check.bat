@echo off
REM huorong_check.bat - argument-free probe for the Huorong (火绒) round.
REM Answers: is it installed, is it the active AV in Security Center, and did it
REM displace Defender. Run via vmctl -script (NO arguments), then pull huorong.txt.
set OUT=C:\Users\Public\huorong.txt
del "%OUT%" 2>nul
echo == time %DATE% %TIME% >> "%OUT%"
echo == huorong processes >> "%OUT%"
tasklist >> "%OUT%.tmp" 2>&1
findstr /I "Hips HrsWord huorong Sysdiag wsctrl usysdiag" "%OUT%.tmp" >> "%OUT%" 2>&1
del "%OUT%.tmp" 2>nul
echo == huorong services >> "%OUT%"
sc query Sysdiag >> "%OUT%" 2>&1
sc query HipsDaemon >> "%OUT%" 2>&1
echo == install dirs >> "%OUT%"
dir /b "C:\Program Files\Huorong" >> "%OUT%" 2>&1
dir /b "C:\Program Files (x86)\Huorong" >> "%OUT%" 2>&1
echo == security center: which AV is registered/active >> "%OUT%"
powershell -nop -c "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState,pathToSignedProductExe | Format-List | Out-String" >> "%OUT%" 2>&1
echo == defender realtime still on? >> "%OUT%"
powershell -nop -c "(Get-MpComputerStatus).RealTimeProtectionEnabled" >> "%OUT%" 2>&1
echo == defender exclusions (lab artifact, should be reverted before final scoring) >> "%OUT%"
powershell -nop -c "((Get-MpPreference).ExclusionPath -join ';')" >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
