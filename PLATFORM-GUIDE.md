# Platform Guide — What to Run Where

| Your system | Main file to run | Interface |
|-------------|------------------|-----------|
| **Linux / Omarchy** | [`RUN-ON-LINUX.sh`](RUN-ON-LINUX.sh) | Terminal CLI |
| **Linux GUI (optional)** | [`RUN-ON-LINUX-GUI.sh`](RUN-ON-LINUX-GUI.sh) | Desktop GUI |
| **Windows 11** | [`RUN-ON-WINDOWS.bat`](RUN-ON-WINDOWS.bat) | Desktop GUI |
| **Windows 11 CLI** | [`RUN-ON-WINDOWS-CLI.bat`](RUN-ON-WINDOWS-CLI.bat) | Terminal CLI |

Open [`WHICH-PLATFORM.txt`](WHICH-PLATFORM.txt) in the project root for a quick reference.

---

## Linux / Omarchy (terminal)

Omarchy and most Linux setups use the **terminal CLI** as the primary entry point.

```bash
chmod +x RUN-ON-LINUX.sh RUN-ON-LINUX-GUI.sh
./RUN-ON-LINUX.sh scan ~/Projects/myapp
```

First-time setup:

```bash
./platforms/linux/install.sh
```

Build a standalone binary:

```bash
./platforms/linux/build-linux.sh
./dist/focp-sec-linux scan ~/Projects/myapp
```

See [`platforms/linux/README-LINUX.txt`](platforms/linux/README-LINUX.txt).

---

## Windows 11

On Windows, the **GUI launcher** is the default; use the CLI batch file for automation or cmd/PowerShell.

```cmd
RUN-ON-WINDOWS.bat
RUN-ON-WINDOWS-CLI.bat scan C:\Projects\myapp
```

First-time setup:

```cmd
platforms\windows\install.bat
```

Build standalone `.exe` files:

```cmd
platforms\windows\build-windows.bat
dist\focp-sec-win-gui.exe
dist\focp-sec-win-cli.exe scan C:\Projects\myapp
```

See [`platforms/windows/README-WINDOWS.txt`](platforms/windows/README-WINDOWS.txt).

---

## Project layout (platform files)

```
scanner/
├── WHICH-PLATFORM.txt      ← Quick “which file do I run?”
├── PLATFORM-GUIDE.md       ← This guide
├── RUN-ON-LINUX.sh         ← Linux / Omarchy (CLI)
├── RUN-ON-LINUX-GUI.sh     ← Linux GUI (optional)
├── RUN-ON-WINDOWS.bat      ← Windows 11 (GUI)
├── RUN-ON-WINDOWS-CLI.bat  ← Windows 11 (CLI)
└── platforms/
    ├── linux/
    │   ├── README-LINUX.txt
    │   ├── install.sh
    │   └── build-linux.sh
    └── windows/
        ├── README-WINDOWS.txt
        ├── install.bat
        └── build-windows.bat
```
