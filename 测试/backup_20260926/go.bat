@echo off
cd /d "%~dp0"
del /q shellcode.obj shellcode.exe shellcode.bin 2>nul
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
echo === 1) build (cl) ===
cl /nologo /O2 /GS- /Gy /D_CRT_SECURE_NO_WARNINGS shellcode.c
if errorlevel 1 ( echo [!] build failed & exit /b 1 )
echo.
echo === 2) extract .text$sc -> shellcode.bin ===
python extract.py
if errorlevel 1 ( echo [!] extract failed & exit /b 1 )
echo.
echo === 3) run C payload (shellcode.exe) ===
shellcode.exe
echo.
echo === 4) run carved shellcode via RWX (loader.py) ===
python loader.py
