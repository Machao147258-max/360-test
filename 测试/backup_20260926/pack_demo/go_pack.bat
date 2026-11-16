@echo off
REM go_pack.bat -- "壳" demo: pack a benign payload into a stub that self-decrypts and memory-loads it
REM   step 0: build benign payload DLL
REM   step 1: packer.py  -> XOR-encrypt payload, emit .rc resource
REM   step 2: rc         -> compile resource
REM   step 3: cl         -> link stub + resource = packed.exe
REM   step 4: run packed.exe
cd /d "%~dp0"
if not exist build mkdir build
if not exist bin mkdir bin
del /q bin\payload_dll.dll bin\payload_dll.lib bin\payload_dll.exp build\payload_dll.obj ^
       build\payload.enc build\packed.rc build\packed.res build\stub.obj bin\packed.exe mapped_marker.txt 2>nul
call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
echo === 0) build benign payload DLL ===
cl /nologo /O2 /MT /LD /utf-8 /Febin\payload_dll.dll /Fobuild\payload_dll.obj src\payload_dll.c user32.lib
if errorlevel 1 ( echo [!] payload build failed & exit /b 1 )
echo.
echo === 1) packer: encrypt payload -> resource ===
python tools\packer.py
if errorlevel 1 ( exit /b 1 )
echo.
echo === 2) compile resource (rc) ===
rc /nologo /fo build\packed.res build\packed.rc
if errorlevel 1 ( echo [!] rc failed & exit /b 1 )
echo.
echo === 3) build packed.exe (stub + embedded encrypted payload) ===
cl /nologo /O2 /MT /utf-8 /Fobuild\stub.obj /Febin\packed.exe src\stub.c build\packed.res user32.lib
if errorlevel 1 ( echo [!] stub build failed & exit /b 1 )
echo.
echo === 4) run packed.exe (self-decrypt + memory-load payload) ===
bin\packed.exe
echo.
if exist mapped_marker.txt ( echo [+] proof: mapped_marker.txt created by the packed payload ) else ( echo [!] marker not found )
