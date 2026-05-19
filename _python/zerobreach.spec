# zerobreach.spec
# Build: pyinstaller zerobreach.spec

import sys
from pathlib import Path

block_cipher = None

a = Analysis(
    ['server.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('gui/templates', 'gui/templates'),
        ('gui/static', 'gui/static'),
        ('data', 'data'),
        ('ZeroBreach-V23.ps1', '.'),
    ],
    hiddenimports=[
        'engineio.async_drivers.threading',
        'flask_socketio',
        'psutil',
        'eventlet',
        'eventlet.hubs.selects',
        'eventlet.hubs.poll',
        'dns',
        'dns.resolver',
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
    name='ZeroBreach',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # No console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/icon.ico',  # Add your icon here
    version='version_info.txt',
    uac_admin=True,          # Request admin on launch
)
