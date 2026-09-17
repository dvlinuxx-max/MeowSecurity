"""Build the Microsoft Store MSIX package.

    python msix/build_msix.py

Identity defaults come from Partner Center > Product management > Product identity and are
recorded in PACKAGING.md. Override them only if that page changes.

The three executables are published self-contained but NOT single-file, into one folder, so
they share a single copy of the .NET runtime. Three single-file publishes would put three
copies of it in the package for no benefit — the Store pays for the size and so does every
person who installs it.
"""
import argparse
import glob
import os
import shutil
import subprocess
import sys
import tempfile
from xml.sax.saxutils import escape

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import make_assets  # noqa: E402

# Partner Center, confirmed 17 September 2026.
IDENTITY_NAME = "MohammedAbdAlrahman.MeowSecurity"
PUBLISHER = "CN=D81C7D5E-634A-451A-B6B5-3B12E63A7945"
PUBLISHER_DISPLAY = "Mohammed Abd Alrahman"

PROJECTS = [
    ("MeowSecurity.Gui", "MeowSecurity.Gui.csproj"),
    ("MeowSecurity.Engine", "MeowSecurity.Engine.csproj"),
    ("MeowSecurity.Cli", "MeowSecurity.Cli.csproj"),
]


def sdk_tool(name):
    hits = sorted(glob.glob(rf"C:\Program Files (x86)\Windows Kits\10\bin\10.*\x64\{name}"))
    if not hits:
        sys.exit(f"{name} not found — install the Windows SDK")
    return hits[-1]


def run(cmd, **kw):
    print(">", " ".join(str(c) for c in cmd))
    subprocess.run(cmd, check=True, **kw)


def use_utf8_output():
    """
    This repository lives under an Arabic path, and Python's console encoding on Windows is
    still the ANSI code page — so merely echoing the command it is about to run raises
    UnicodeEncodeError before anything has been built. Fixed here rather than left as an
    environment variable somebody has to remember.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main():
    use_utf8_output()

    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="0.9.0.0")
    ap.add_argument("--name", default=IDENTITY_NAME)
    ap.add_argument("--publisher", default=PUBLISHER)
    ap.add_argument("--display", default=PUBLISHER_DISPLAY)
    ap.add_argument("--skip-build", action="store_true")
    args = ap.parse_args()

    # The Store rejects a package whose fourth version part is not zero; it reserves that part
    # for its own use. Catching it here beats catching it after an upload.
    if not args.version.endswith(".0") or len(args.version.split(".")) != 4:
        sys.exit("the Store requires a four-part version whose last part is 0, e.g. 0.9.0.0")

    work = os.path.join(tempfile.gettempdir(), "meow_msix")
    layout = os.path.join(work, "layout")
    payload = os.path.join(layout, "MeowSecurity")

    shutil.rmtree(layout, ignore_errors=True)
    os.makedirs(payload, exist_ok=True)

    if not args.skip_build:
        for folder, proj in PROJECTS:
            run(["dotnet", "publish", os.path.join(ROOT, folder, proj),
                 "-c", "Release", "-r", "win-x64", "--self-contained", "true",
                 "-p:PublishSingleFile=false", "-p:DebugType=none",
                 # .NET ships its own framework messages translated into fourteen languages.
                 # Left in, MakePri indexes them and the package claims to support every one of
                 # them — so the Store would offer this product in Chinese and German, which it
                 # does not speak, and Store policy expects the listing's language to be the
                 # app's. This application says everything it says through its own string table,
                 # in Arabic and English, and neither needs these.
                 "-p:SatelliteResourceLanguages=en",
                 "-o", payload])

    make_assets.build(os.path.join(layout, "Assets"))

    with open(os.path.join(HERE, "AppxManifest.template.xml"), encoding="utf-8") as f:
        manifest = f.read()
    for key, value in (("{IDENTITY_NAME}", args.name),
                       ("{PUBLISHER}", args.publisher),
                       ("{PUBLISHER_DISPLAY_NAME}", args.display),
                       ("{VERSION}", args.version)):
        manifest = manifest.replace(key, escape(value, {'"': "&quot;"}))
    with open(os.path.join(layout, "AppxManifest.xml"), "w", encoding="utf-8") as f:
        f.write(manifest)

    # Both languages the application actually speaks, so the Store listing can offer both.
    priconfig = os.path.join(work, "priconfig.xml")
    run([sdk_tool("makepri.exe"), "createconfig", "/cf", priconfig, "/dq", "ar_en", "/o"])
    run([sdk_tool("makepri.exe"), "new", "/pr", layout, "/cf", priconfig,
         "/mn", os.path.join(layout, "AppxManifest.xml"),
         "/of", os.path.join(layout, "resources.pri"), "/o"])

    out_dir = os.path.join(HERE, "out")
    os.makedirs(out_dir, exist_ok=True)
    msix = os.path.join(out_dir, f"MeowSecurity_{args.version}_x64.msix")
    run([sdk_tool("makeappx.exe"), "pack", "/d", layout, "/p", msix, "/o"])

    size = os.path.getsize(msix) / (1024 * 1024)
    print(f"\npackage: {msix}  ({size:.0f} MB)")
    print(f"layout:  {layout}")
    print("\nThe package is unsigned: the Store signs it. To install it locally for testing")
    print("you need a self-signed certificate — see msix/README.md.")


if __name__ == "__main__":
    main()
