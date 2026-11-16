@echo off
REM diskclean2.bat - ASCII only, argument free. Reclaim the guest's big safe chunks.
REM Map from diskscan (18:48): volume 29.0 GB, used 22.6 GB, free ~300 MB.
REM   C:\Windows\SoftwareDistribution  3406 MB  <- Windows Update cache, the real win
REM   C:\Users                         ~3400 MB
REM   C:\Windows\Logs                    100 MB
REM   C:\Users\Public                     76 MB  (our own artifacts)
REM NOTE: C:\Windows "30032 MB" from dir /s is hard-link double counting (WinSxS), not real.
set OUT=C:\Users\Public\diskclean2.txt
del "%OUT%" 2>nul
echo == BEFORE >> "%OUT%"
fsutil volume diskfree C: >> "%OUT%" 2>&1
echo == stop update services >> "%OUT%"
net stop wuauserv >> "%OUT%" 2>&1
net stop bits >> "%OUT%" 2>&1
echo == clear Windows Update download cache >> "%OUT%"
del /f /s /q C:\Windows\SoftwareDistribution\Download\* >> "%OUT%" 2>&1
rd /s /q C:\Windows\SoftwareDistribution\Download >> "%OUT%" 2>&1
md C:\Windows\SoftwareDistribution\Download >> "%OUT%" 2>&1
echo == clear update DB logs >> "%OUT%"
del /f /s /q C:\Windows\SoftwareDistribution\DataStore\Logs\* >> "%OUT%" 2>&1
echo == clear CBS logs >> "%OUT%" 2>&1 >> "%OUT%"
del /f /s /q C:\Windows\Logs\CBS\* >> "%OUT%" 2>&1
echo == clear per-user temp >> "%OUT%"
del /f /s /q C:\Users\vix\AppData\Local\Temp\* >> "%OUT%" 2>&1
echo == restart update service >> "%OUT%"
net start wuauserv >> "%OUT%" 2>&1
echo == AFTER >> "%OUT%"
fsutil volume diskfree C: >> "%OUT%" 2>&1
echo == biggest remaining dirs (top-level walk, sizes via powershell) >> "%OUT%"
powershell -nop -c "foreach($d in @('C:\Windows\SoftwareDistribution','C:\Users','C:\Windows\Logs','C:\Windows\Temp','C:\Users\Public')){ $s=(Get-ChildItem -LiteralPath $d -Recurse -File -Force -EA SilentlyContinue | Measure-Object Length -Sum).Sum; if(-not $s){$s=0}; ('{0,10:N0} MB  {1}' -f ($s/1MB), $d) }" >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
