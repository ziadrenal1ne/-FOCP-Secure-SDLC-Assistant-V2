@echo off
REM =============================================================================
REM FOCP Secure SDLC Assistant — WINDOWS 11 (Desktop GUI)
REM =============================================================================
REM Double-click this file in Explorer, or run from cmd / PowerShell:
REM   RUN-ON-WINDOWS.bat
REM   RUN-ON-WINDOWS.bat scan C:\Projects\myapp
REM =============================================================================

setlocal EnableDelayedExpansion
cd /d "%~dp0"

title FOCP Secure SDLC Assistant - Windows 11

echo.
echo  ============================================================
echo   FOCP Secure SDLC Assistant - Windows 11 (GUI)
echo  ============================================================
echo.

call :EnsureEnv
if errorlevel 1 exit /b 1

if "%~1"=="" (
    echo Starting desktop GUI...
    echo For terminal-only use, run: RUN-ON-WINDOWS-CLI.bat
    echo.
    focp-sec gui
    exit /b %ERRORLEVEL%
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
