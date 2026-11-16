@echo off
cd /d "%~dp0"
del /q priv_sc.obj priv_sc.bin 2>nul
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
echo === 1) compile (cl /c) ===
cl /nologo /c /O2 /GS- /Gy priv_sc.c
if errorlevel 1 ( echo [!] compile failed & exit /b 1 )
echo.
echo === 2) extract .text$sc -> priv_sc.bin ===
python extract.py priv_sc.obj .text$sc priv_sc.bin
if errorlevel 1 ( exit /b 1 )
echo.
echo === 3) verify privilege flip ===
python loader_priv.py priv_sc.bin
