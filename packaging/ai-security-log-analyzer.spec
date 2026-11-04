from pathlib import Path


ROOT = Path(SPECPATH).resolve().parent
ASSETS = (
    "frontend/index.html",
    "frontend/style.css",
    "frontend/app.js",
    "frontend/input-quality-ui-36-12b.js",
    "frontend/review-queue-ui-36-13a.js",
    "frontend/investigation-review-state-36-14d.js",
    "frontend/linux-audit.js",
    "frontend/live-monitoring.js",
    "frontend/multi-source-live.js",
    "data/account_metadata.json",
    "app/knowledge_corpus_33_1/corpus.json",
    "app/knowledge_corpus_33_1/manifest.json",
    "sample_logs/brute_force.log",
    "sample_logs/ssh_auth.log",
    "sample_logs/web_shell.log",
)
datas = [
    (str(ROOT / item), str(Path(item).parent))
    for item in ASSETS
]

a = Analysis(
    [str(ROOT / "scripts" / "standalone_entrypoint.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "hypothesis", "schemathesis", "tests", "app.evaluation"],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="ai-security-log-analyzer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="ai-security-log-analyzer",
)
