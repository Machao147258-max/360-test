@echo off
REM drives.bat - ASCII only, argument free. Reports guest volumes and whether E: is usable.
REM Output kept small on purpose: build the numbers with PowerShell, never dir /s
REM (that prints a "File(s)" line per directory and floods the console).
set OUT=C:\Users\Public\drives.txt
del "%OUT%" 2>nul
echo == volumes >> "%OUT%"
powershell -nop -c "Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,DriveType,FileSystem,@{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}},@{n='FreeGB';e={[math]::Round($_.FreeSpace/1GB,1)}} | Format-Table -AutoSize | Out-String" >> "%OUT%" 2>&1
echo == E: writable test >> "%OUT%"
if exist E:\ (
  if not exist E:\lab mkdir E:\lab
  echo wtest > E:\lab\_wtest.txt
  if exist E:\lab\_wtest.txt (echo   E:\lab WRITABLE >> "%OUT%") else (echo   E:\lab NOT-writable >> "%OUT%")
  del /q E:\lab\_wtest.txt 2>nul
) else (
  echo   E: NOT PRESENT >> "%OUT%"
)
echo == C:\Users\Public top 12 by size >> "%OUT%"
powershell -nop -c "Get-ChildItem 'C:\Users\Public' -File -Force -EA SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 12 | ForEach-Object { '{0,12:N0}  {1}' -f $_.Length, $_.Name }" >> "%OUT%" 2>&1
echo == free space >> "%OUT%"
fsutil volume diskfree C: | findstr /C:"Total free bytes" >> "%OUT%" 2>&1
if exist E:\ fsutil volume diskfree E: | findstr /C:"Total free bytes" >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
