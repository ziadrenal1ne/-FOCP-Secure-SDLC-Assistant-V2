================================================================================
  FOCP Secure SDLC Assistant — WINDOWS 11
================================================================================

PRIMARY LAUNCHER (desktop GUI — recommended on Windows):
  ..\..\RUN-ON-WINDOWS.bat
  (double-click in File Explorer)

TERMINAL CLI:
  ..\..\RUN-ON-WINDOWS-CLI.bat

FIRST-TIME SETUP:
  install.bat

BUILD STANDALONE EXE:
  build-windows.bat
  -> dist\focp-sec-win-cli.exe
  -> dist\focp-sec-win-gui.exe

EXAMPLES (cmd or PowerShell, from project root):
  RUN-ON-WINDOWS-CLI.bat scan C:\Projects\myapp
  RUN-ON-WINDOWS-CLI.bat score C:\Projects\myapp
  RUN-ON-WINDOWS.bat

REQUIREMENTS:
  - Python 3.13+ with "Add to PATH" enabled
  - Windows 11 (Windows 10 also works)

================================================================================
