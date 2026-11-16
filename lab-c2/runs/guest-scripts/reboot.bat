@echo off
REM reboot.bat - argument-free guest reboot trigger (5s delay, forced).
REM Kept in a bat because inline command strings with arguments are unreliable here.
shutdown /r /t 5 /f
