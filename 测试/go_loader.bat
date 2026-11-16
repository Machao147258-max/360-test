@echo off
REM go_loader.bat -- build a benign target DLL and a hand-written in-memory PE loader, then run it
REM   manual map: headers, sections, .reloc, IAT via INT, protections, DllMain, export
cd /d "%~dp0"
if not exist build mkdir build
if not exist bin mkdir bin
del /q bin\payload_dll.dll bin\payload_dll.lib bin\payload_dll.exp build\payload_dll.obj build\pe_loader.obj build\pe_loader.exe 2>nul
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
echo === 1) build target DLL (payload_dll.dll) ===
cl /nologo /O2 /MT /LD /utf-8 /Febin\payload_dll.dll /Fobuild\payload_dll.obj src\payload_dll.c user32.lib
if errorlevel 1 ( echo [!] dll build failed & exit /b 1 )
echo.
echo === 2) build loader (pe_loader.exe) ===
cl /nologo /O2 /utf-8 /Febuild\pe_loader.exe /Fobuild\pe_loader.obj src\pe_loader.c
if errorlevel 1 ( echo [!] loader build failed & exit /b 1 )
echo.
echo === 3) manual-map the DLL from memory ===
build\pe_loader.exe bin\payload_dll.dll
echo.
if exist mapped_marker.txt ( echo [+] proof: mapped_marker.txt was created by the mapped DLL ) else ( echo [!] marker not found )
