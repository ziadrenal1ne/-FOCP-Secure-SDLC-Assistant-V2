@echo off
REM =============================================================================
REM FOCP Secure SDLC Assistant — WINDOWS 11 (Terminal CLI)
REM =============================================================================
REM Run from cmd or PowerShell:
REM   RUN-ON-WINDOWS-CLI.bat
REM   RUN-ON-WINDOWS-CLI.bat scan C:\Projects\myapp
REM   RUN-ON-WINDOWS-CLI.bat score C:\Projects\myapp
REM =============================================================================

setlocal EnableDelayedExpansion
cd /d "%~dp0"

title FOCP Secure SDLC Assistant - Windows CLI

echo.
echo  ============================================================
echo   FOCP Secure SDLC Assistant - Windows 11 (Terminal CLI)
echo  ============================================================
echo.

call :EnsureEnv
if errorlevel 1 exit /b 1

if "%~1"=="" (
    echo Examples:
    echo   RUN-ON-WINDOWS-CLI.bat scan C:\Projects\myapp
    echo   RUN-ON-WINDOWS-CLI.bat score C:\Projects\myapp
    echo   RUN-ON-WINDOWS-CLI.bat checklist C:\Projects\myapp
    echo.
    echo For desktop GUI, run: RUN-ON-WINDOWS.bat
    echo.
    focp-sec --help
    exit /b 0
)

focp-sec %*
exit /b %ERRORLEVEL%

:EnsureEnv
if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo ERROR: Python not found. Install Python 3.13+ from https://www.python.org/
        pause
        exit /b 1
    )
)

call .venv\Scripts\activate.bat

python -c "import focp_sec" 2>nul
if errorlevel 1 (
    echo Installing dependencies ^(first run^)...
    python -m pip install -q --upgrade pip
    pip install -q -e .
)
exit /b 0
