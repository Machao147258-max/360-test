@echo off
REM go_priv.bat -- variant 3: token privilege shellcode (enable a privilege)
REM usage: go_priv.bat [PrivilegeName]    (default SeDebugPrivilege)
REM steps: generate src\priv_sc.c; compile; carve .text$sc; verify flip with full table
cd /d "%~dp0"
if not exist build mkdir build
if not exist bin mkdir bin
set PRIV=%1
if "%PRIV%"=="" set PRIV=SeDebugPrivilege
del /q build\priv_sc.obj bin\priv_sc.bin src\priv_sc.c 2>nul
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
echo === 0) generate src\priv_sc.c for %PRIV% ===
python tools\gen_priv.py --priv %PRIV%
if errorlevel 1 ( exit /b 1 )
echo.
echo === 1) compile (cl /c) ===
cl /nologo /c /O2 /GS- /Gy /Fobuild\priv_sc.obj src\priv_sc.c
if errorlevel 1 ( echo [!] compile failed & exit /b 1 )
echo.
echo === 2) extract .text$sc to bin\priv_sc.bin ===
python tools\extract.py build\priv_sc.obj .text$sc bin\priv_sc.bin
if errorlevel 1 ( exit /b 1 )
echo.
echo === 3) verify privilege flip (full table) ===
python tools\loader_priv.py bin\priv_sc.bin %PRIV%
