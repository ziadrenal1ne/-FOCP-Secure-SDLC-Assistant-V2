@echo off
REM First-time setup for Windows 11
cd /d "%~dp0\..\.."

echo === FOCP Secure SDLC Assistant - Windows install ===

python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Install Python 3.13+ from https://www.python.org/
    echo Enable "Add Python to PATH" during installation.
    pause
    exit /b 1
)

python -m venv .venv
call .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -e ".[dev]"

echo.
echo Done. Run:
echo   RUN-ON-WINDOWS.bat              GUI
echo   RUN-ON-WINDOWS-CLI.bat scan C:\path\to\project
pause
