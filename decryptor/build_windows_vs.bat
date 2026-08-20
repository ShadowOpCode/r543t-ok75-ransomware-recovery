@echo off
setlocal

rem Run from an "x64 Native Tools Command Prompt for VS 2022".
cl /nologo /std:c17 /O2 /W3 /MT /TC r543t_recover.c /Fe:r543t_recover_windows_x64.exe
if errorlevel 1 exit /b %errorlevel%

r543t_recover_windows_x64.exe --self-test
exit /b %errorlevel%
