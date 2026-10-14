#!/usr/bin/env python3
"""Remove generated demo directories only; preserve source and verification receipts."""
from pathlib import Path
import shutil
ROOT = Path(__file__).resolve().parents[1]
removed = 0
for path in (ROOT / '.local-runs').glob('demo-*'):
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path); removed += 1
print(f'Removed {removed} generated demo directories. Source and other evidence retained.')
