"""Package the SC4N Chrome extension for the Chrome Web Store.

    python extension/build.py

Writes extension/sc4n-extension-<version>.zip with only the files Chrome needs (not the store
screenshots or this script). Raise "version" in manifest.json before every upload.
"""
import json
import pathlib
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
PACKAGE = ["manifest.json", "background.js", "popup.html", "popup.js", "popup.css",
           "icons/icon-16.png", "icons/icon-32.png", "icons/icon-48.png", "icons/icon-128.png",
           "fonts/jetbrains-mono.woff2", "fonts/LICENSE.txt"]

version = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))["version"]
out = HERE / f"sc4n-extension-{version}.zip"
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for name in PACKAGE:
        z.write(HERE / name, name)
print(f"wrote {out.name} ({out.stat().st_size // 1024} KB, {len(PACKAGE)} files)")
