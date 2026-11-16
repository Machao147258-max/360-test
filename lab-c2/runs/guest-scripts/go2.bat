@echo off
REM go2.bat - launch a payload detached via WMI Win32_Process::Create.
REM Arg %1 = full path of the binary (default C:\Users\Public\loader.exe).
REM
REM Why WMI and not "start": a process launched by cmd stays inside the VIX job
REM object, so runProgramInGuest blocks until the payload exits -- and a beacon
REM never exits. A WMI-created process is a child of WmiPrvSE, outside that job.
setlocal
set TARGET=%~1
if "%TARGET%"=="" set TARGET=C:\Users\Public\loader.exe
del C:\Users\Public\lcs_trace.log 2>nul
del C:\Users\Public\launch.txt 2>nul
powershell -nop -c "$r=Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='%TARGET%'}; ('target=%TARGET% pid=' + $r.ProcessId + ' rc=' + $r.ReturnValue) | Out-File -Encoding ascii C:\Users\Public\launch.txt"
endlocal
