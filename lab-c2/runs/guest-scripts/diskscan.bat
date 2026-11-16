@echo off
REM diskscan.bat - ASCII only, argument free. Where did the guest's 22.9 GB go?
set OUT=C:\Users\Public\diskscan.txt
del "%OUT%" 2>nul
echo == free space >> "%OUT%"
fsutil volume diskfree C: >> "%OUT%" 2>&1
echo == volumes present >> "%OUT%"
wmic logicaldisk get caption,size,freespace >> "%OUT%" 2>&1
for %%P in (C:\Windows C:\Windows\WinSxS C:\Windows\Installer C:\Windows\SoftwareDistribution C:\Windows\Logs C:\Windows\Temp "C:\Program Files" "C:\Program Files (x86)" C:\Users C:\Users\vix C:\inetpub C:\PerfLogs C:\Users\Public) do (
  echo == %%P >> "%OUT%"
  dir /s /-c "%%P" 2>nul | findstr /C:"File(s)" >> "%OUT%" 2>&1
)
echo == pagefile / hiberfil present? >> "%OUT%"
if exist C:\pagefile.sys (echo   pagefile.sys EXISTS >> "%OUT%") else (echo   pagefile.sys absent >> "%OUT%")
if exist C:\hiberfil.sys (echo   hiberfil.sys EXISTS >> "%OUT%") else (echo   hiberfil.sys absent >> "%OUT%")
echo == end %TIME% >> "%OUT%"
