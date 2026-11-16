@echo off
REM diag2.bat - is the beacon still alive, and did Defender terminate it?
set OUT=C:\Users\Public\diag2.txt
del "%OUT%" 2>nul
echo == time %TIME% >> "%OUT%"
echo == loader process >> "%OUT%"
tasklist /FI "IMAGENAME eq loader.exe" >> "%OUT%" 2>&1
echo == trace (full) >> "%OUT%"
type C:\Users\Public\lcs_trace.log >> "%OUT%" 2>&1
echo == defender active detections >> "%OUT%"
powershell -nop -c "Get-MpThreatDetection | Select-Object -First 5 ThreatID,Resources,InitialDetectionTime,ActionSuccess | Format-List | Out-String" >> "%OUT%" 2>&1
echo == defender threat catalog >> "%OUT%"
powershell -nop -c "Get-MpThreat | Select-Object -First 5 ThreatName,Resources,IsActive | Format-List | Out-String" >> "%OUT%" 2>&1
echo == defender operational log (last 12) >> "%OUT%"
powershell -nop -c "Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 12 | Select-Object TimeCreated,Id,LevelDisplayName | Format-Table -AutoSize | Out-String" >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
