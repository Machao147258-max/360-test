@echo off
cd /d "%~dp0"
del /q calc_nf.obj calc_nf.exe shellcode_asm.bin 2>nul
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
echo === 1) assemble (ml64) ===
ml64 /nologo /c /Fo calc_nf.obj calc_nf.asm
if errorlevel 1 ( echo [!] ml64 failed & exit /b 1 )
echo.
echo === 2) extract .text -> shellcode_asm.bin ===
python extract.py calc_nf.obj .text$mn shellcode_asm.bin
if errorlevel 1 ( exit /b 1 )
echo.
echo === 3) run carved shellcode via RWX (loader.py) ===
python loader.py shellcode_asm.bin
