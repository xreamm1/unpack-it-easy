@echo off
cd /d "%~dp0"
if not exist "UIE.exe" (echo Download UIE.exe from Releases and place it beside this script.& exit /b 1)
"%~dp0UIE.exe" --prepare-offline all
if errorlevel 1 (echo Offline preparation failed. See engines\offline-preparation.& exit /b 1)
echo Offline bundle ready in engines.
