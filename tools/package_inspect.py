from pathlib import Path
import tarfile
import zipfile

PACKAGE = "embit"

wheel = sorted(Path("dist").glob(PACKAGE + "-*.whl"))[-1]
sdist = sorted(Path("dist").glob(PACKAGE + "-*.tar.gz"))[-1]

with zipfile.ZipFile(wheel) as zf:
    meta = [n for n in zf.namelist() if n.endswith(".dist-info/METADATA")][0]
    data = zf.read(meta).decode()

print(f"# PACKAGE CONTENT OF \"{PACKAGE}\"")
print("\n## METADATA\n")
for line in data.splitlines():
    if line.startswith(("Name:", "Version:", "Requires-Python:", "Project-URL:", "Requires-Dist:", "Provides-Extra:")):
        print(line, "  ")

print("\n## SDIST FILE LIST\n")
with tarfile.open(sdist, "r:gz") as tf:
    for member in tf.getmembers():
        print(member.name, "  ")

print("\n## WHEEL FILE LIST\n")
with zipfile.ZipFile(wheel) as zf:
    for name in zf.namelist():
        print(name, "  ")
