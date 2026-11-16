@echo off
REM go_asm.bat -- variant 2: hand-written null-free asm shellcode (WinExec calc.exe)
REM steps: assemble with ml64; carve .text$mn; run carved bytes via RWX
cd /d "%~dp0"
if not exist build mkdir build
if not exist bin mkdir bin
del /q build\calc_nf.obj bin\shellcode_asm.bin 2>nul
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
echo === 1) assemble (ml64) ===
ml64 /nologo /c /Fo build\calc_nf.obj src\calc_nf.asm
if errorlevel 1 ( echo [!] ml64 failed & exit /b 1 )
echo.
echo === 2) extract .text$mn to bin\shellcode_asm.bin ===
python tools\extract.py build\calc_nf.obj .text$mn bin\shellcode_asm.bin
if errorlevel 1 ( exit /b 1 )
echo.
echo === 3) run carved shellcode via RWX ===
python tools\loader.py bin\shellcode_asm.bin
