@echo off
REM runldr.bat - hardcoded, ARGUMENT-FREE launcher for C:\Users\Public\ldr.exe
REM
REM Measured 2026-10-04: a .bat invoked through vmctl -script WITH arguments exits
REM 255 and never writes its first output line, while the same bat without
REM arguments runs cleanly (health.bat proved it). So this path uses no %1 at all.
REM Launch is via WMI Win32_Process::Create: a child of WmiPrvSE, i.e. outside the
REM VIX job object that otherwise kills everything when runProgramInGuest returns.
set OUT=C:\Users\Public\launch.txt
del "%OUT%" 2>nul
del C:\Users\Public\lcs_trace.log 2>nul
powershell -nop -c "$r=Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='C:\Users\Public\ldr.exe'}; ('pid=' + $r.ProcessId + ' rc=' + $r.ReturnValue) | Out-File -Encoding ascii C:\Users\Public\launch.txt"
