START /B /wait powershell -Command "Invoke-WebRequest https://raw.githubusercontent.com/Wittstock-ElkomPlan/Win11-Script/main/Win11-Script.ps1 -OutFile '%~dp0\Win11-Script.ps1'"
PowerShell.exe -ExecutionPolicy Bypass -File "%~dp0\Win11-Script.ps1" 
pause
