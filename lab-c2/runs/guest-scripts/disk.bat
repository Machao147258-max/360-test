@echo off
REM disk.bat - ASCII only, argument free. Reports where the guest's C: space went.
set OUT=C:\Users\Public\disk.txt
del "%OUT%" 2>nul
echo == free space on C: >> "%OUT%"
fsutil volume diskfree C: >> "%OUT%" 2>&1
echo == C:\Users\Public total >> "%OUT%"
dir /s /-c C:\Users\Public 2>nul | findstr /C:"File(s)" >> "%OUT%" 2>&1
echo == C:\Users\Public top level (big items first) >> "%OUT%"
for %%F in (huorong64.exe huorong.exe ldr.exe ldr_165300.exe ctrl_cmd.exe) do (
  if exist "C:\Users\Public\%%F" for %%A in ("C:\Users\Public\%%F") do echo   %%F = %%~zA bytes >> "%OUT%"
)
echo == C:\Windows\Temp total >> "%OUT%"
dir /s /-c C:\Windows\Temp 2>nul | findstr /C:"File(s)" >> "%OUT%" 2>&1
echo == user temp total >> "%OUT%"
dir /s /-c "%TEMP%" 2>nul | findstr /C:"File(s)" >> "%OUT%" 2>&1
echo == recycle bin total >> "%OUT%"
dir /s /-c C:\$Recycle.Bin 2>nul | findstr /C:"File(s)" >> "%OUT%" 2>&1
echo == top level of C: >> "%OUT%"
dir /-c C:\ >> "%OUT%" 2>&1
echo == pagefile / hiberfil >> "%OUT%"
dir /-c C:\pagefile.sys C:\hiberfil.sys C:\swapfile.sys >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
