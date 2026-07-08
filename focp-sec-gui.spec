# PyInstaller spec for FOCP Secure SDLC Assistant

block_cipher = None

a = Analysis(
    ['src/focp_sec/gui/app.py'],
    pathex=['src'],
    binaries=[],
    datas=[
        ('src/focp_sec/templates', 'focp_sec/templates'),
        ('config.yaml', '.'),
    ],
    hiddenimports=[
        'focp_sec', 'focp_sec.cli', 'focp_sec.gui', 'focp_sec.core',
        'focp_sec.analyzers', 'focp_sec.integrations', 'focp_sec.reports',
        'jinja2', 'reportlab', 'yaml', 'git', 'bandit',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='focp-sec-gui',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
