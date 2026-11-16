"""Make the pinned py-genlayer runner visible to genlayer-test 0.29.2.

That release downloads only ``genvm-universal.tar.xz``. The GenVM tag that
contains ``py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6``
publishes the same bundle as ``genvm-runners-all.tar.xz``. genvm-linter 0.11.0
already accepts the new filename. This seeds the directory gltest reads.
"""

from __future__ import annotations

import shutil
import urllib.request
from pathlib import Path

TAG = "v0.3.0-rc7"
ASSET = "genvm-runners-all.tar.xz"
URL = f"https://github.com/genlayerlabs/genvm/releases/download/{TAG}/{ASSET}"


def seed() -> None:
    dest_dir = Path.home() / ".cache" / "gltest-direct"
    dest = dest_dir / f"genvm-universal-{TAG}.tar.xz"
    if dest.exists() and dest.stat().st_size > 0:
        return
    dest_dir.mkdir(parents=True, exist_ok=True)
    linter_copy = Path.home() / ".cache" / "genvm-linter" / f"genvm-universal-{TAG}.tar.xz"
    if linter_copy.exists() and linter_copy.stat().st_size > 0:
        shutil.copyfile(linter_copy, dest)
        return
    tmp = dest.with_suffix(".tar.xz.partial")
    req = urllib.request.Request(URL, headers={"User-Agent": "license-guard-tests"})
    with urllib.request.urlopen(req, timeout=300) as resp, tmp.open("wb") as out:
        shutil.copyfileobj(resp, out)
    tmp.replace(dest)
