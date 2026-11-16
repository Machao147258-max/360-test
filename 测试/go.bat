@echo off
REM go.bat -- variant 1: C shellcode (WinExec calc.exe)
REM steps: compile with cl; carve .text$sc; run C payload; run carved bytes via RWX
cd /d "%~dp0"
if not exist build mkdir build
if not exist bin mkdir bin
del /q build\shellcode.obj build\shellcode.exe bin\shellcode.bin 2>nul
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
echo === 1) build (cl) ===
cl /nologo /O2 /GS- /Gy /D_CRT_SECURE_NO_WARNINGS /Fobuild\shellcode.obj /Febuild\shellcode.exe src\shellcode.c
if errorlevel 1 ( echo [!] build failed & exit /b 1 )
echo.
echo === 2) extract .text$sc to bin\shellcode.bin ===
python tools\extract.py build\shellcode.obj .text$sc bin\shellcode.bin
if errorlevel 1 ( exit /b 1 )
echo.
echo === 3) run C payload (build\shellcode.exe) ===
build\shellcode.exe
echo.
echo === 4) run carved shellcode via RWX ===
python tools\loader.py bin\shellcode.bin
