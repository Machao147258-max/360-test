@echo off
REM diskclean.bat - ASCII only, argument free. Frees space on the GUEST's C:.
REM Measured first (18:46): 29.0 GB volume, only 250.9 MB free. Targets, biggest first:
REM   C:\Windows.old        <- the 2026-09-26 previous Windows install (the real hog)
REM   C:\Windows\Temp       117 MB
REM   %TEMP%                152 MB
REM   C:\Users\Public\huorong.exe  54.9 MB  (x86 build: unusable on this x64 guest)
REM Kept on purpose: huorong64.exe (the pending install wizard needs it) and the
REM 375 KB payload + bat tooling.
REM NOTE: removing Windows.old gives up the "roll back to the previous Windows" option.
set OUT=C:\Users\Public\diskclean.txt
del "%OUT%" 2>nul
echo == BEFORE >> "%OUT%"
fsutil volume diskfree C: >> "%OUT%" 2>&1
echo == C:\Windows.old size before removal >> "%OUT%"
dir /s /-c C:\Windows.old 2>nul | findstr /C:"File(s)" >> "%OUT%" 2>&1
echo == 1) delete the x86 installer >> "%OUT%"
del /f /q C:\Users\Public\huorong.exe >> "%OUT%" 2>&1
echo rc=%ERRORLEVEL% >> "%OUT%"
echo == 2) clear system temp >> "%OUT%"
del /f /s /q C:\Windows\Temp\* >> "%OUT%" 2>&1
echo == 3) clear user temp >> "%OUT%"
del /f /s /q "%TEMP%\*" >> "%OUT%" 2>&1
echo == 4) remove Windows.old (takeown + icacls + rd) >> "%OUT%"
takeown /f C:\Windows.old /r /d y >> "%OUT%" 2>&1
icacls C:\Windows.old /grant *S-1-5-32-544:F /t /c >> "%OUT%" 2>&1
rd /s /q C:\Windows.old >> "%OUT%" 2>&1
echo rd_rc=%ERRORLEVEL% >> "%OUT%"
echo == leftovers under Windows.old (should be tiny/none) >> "%OUT%"
if exist C:\Windows.old (dir /s /-c C:\Windows.old 2>nul | findstr /C:"File(s)" >> "%OUT%" 2>&1) else (echo   gone >> "%OUT%")
echo == AFTER >> "%OUT%"
fsutil volume diskfree C: >> "%OUT%" 2>&1
echo == end %TIME% >> "%OUT%"
