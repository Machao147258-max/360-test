@echo off
REM go.bat - launch the loader detached so runProgramInGuest returns immediately.
REM The beacon is a forever-loop; running it in the foreground would block vmrun
REM until its timeout and leave the guest process killed with the parent.
set OUT=C:\Users\Public\launch.txt
del "%OUT%" 2>nul
start "" "C:\Users\Public\loader.exe"
echo launched %TIME% > "%OUT%"
