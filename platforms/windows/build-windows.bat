@echo off
REM Build standalone Windows executables (PyInstaller)
cd /d "%~dp0\..\.."

call .venv\Scripts\activate.bat 2>nul
if errorlevel 1 (
    echo Run platforms\windows\install.bat first
    pause
    exit /b 1
)

pip install -q pyinstaller

echo Building CLI...
pyinstaller --onefile --name focp-sec-win-cli ^
  --add-data "src/focp_sec/templates;focp_sec/templates" ^
  --add-data "config.yaml;." ^
  --paths src ^
  --console ^
  src/focp_sec/cli/main.py

echo Building GUI...
pyinstaller --onefile --name focp-sec-win-gui ^
  --add-data "src/focp_sec/templates;focp_sec/templates" ^
  --add-data "config.yaml;." ^
  --paths src ^
  --windowed ^
  --hidden-import focp_sec.gui ^
  src/focp_sec/gui/app.py

echo.
echo Binaries:
echo   dist\focp-sec-win-cli.exe
echo   dist\focp-sec-win-gui.exe
pause
