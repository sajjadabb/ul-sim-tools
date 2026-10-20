# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['..\\tools\\msl_ui.py'],
    pathex=['tools'],
    binaries=[],
    datas=[('C:\\Users\\user\\Projects\\msl-checking\\tools\\ui\\index.html', 'ui')],
    hiddenimports=['msl_tool', 'mslcore'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='MSL Checker',
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
