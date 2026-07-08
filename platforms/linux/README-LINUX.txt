================================================================================
  FOCP Secure SDLC Assistant — LINUX / OMARCHY
================================================================================

PRIMARY LAUNCHER (terminal — recommended on Omarchy):
  ../../RUN-ON-LINUX.sh

OPTIONAL GUI (Hyprland / Wayland with display):
  ../../RUN-ON-LINUX-GUI.sh

FIRST-TIME SETUP:
  ./install.sh

BUILD STANDALONE BINARY:
  ./build-linux.sh
  -> dist/focp-sec-linux

EXAMPLES (from project root):
  ./RUN-ON-LINUX.sh scan ~/Projects/myapp
  ./RUN-ON-LINUX.sh score ./tests/sample_project
  ./RUN-ON-LINUX.sh threats ~/Projects/myapp
  ./RUN-ON-LINUX.sh list-scans

OMARCHY NOTES:
  - Use foot, kitty, or alacritty to run RUN-ON-LINUX.sh
  - CLI is the default; GUI needs WAYLAND_DISPLAY or DISPLAY set
  - Python: pacman -S python python-pip (if not installed)

================================================================================
