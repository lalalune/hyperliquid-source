"""Compare versioned glibc imports to two signed Ubuntu archive providers."""
from hashlib import sha256
from io import BytesIO
import lzma
from pathlib import Path
import re
import subprocess as sp
import sys
import tarfile

NODE = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIGNER = "F6ECB3762474EDA9D21B7022871920D1991BC93C"
cache, keyring = map(Path, sys.argv[1:3])
target = Path("artifacts/node/115/hl-node")
assert sha256(target.read_bytes()).hexdigest() == NODE


def elf(tool_args, image):
    return sp.check_output(["readelf", *tool_args, str(image)], text=True)


def symbols(image):
    for line in elf(["--dyn-syms", "-W"], image).splitlines():
        cols = line.split()
        if len(cols) >= 8 and cols[0].removesuffix(":").isdigit():
            name, sep, version = cols[7].partition("@")
            if sep and version.lstrip("@").startswith("GLIBC_"):
                yield (name, version.lstrip("@"), cols[3]), cols[6], cols[4], cols[7:]


files = {}
owner = None
for line in elf(["-VW"], target).splitlines():
    match = re.search(r"File: (\S+)", line)
    if match:
        owner = match[1]
    match = re.search(r"Name: GLIBC_\S+.*Version: (\d+)", line)
    if match:
        files[int(match[1])] = owner
needs = {name: set() for name in ("libc.so.6", "libm.so.6", "ld-linux-x86-64.so.2")}
for symbol, index, binding, tail in symbols(target):
    if index == "UND":
        assert binding in ("GLOBAL", "WEAK")
        needs[files[int(tail[1].strip("()"))]].add(symbol)
assert all(needs.values())
print("Linux x86-64 node #115 SHA-256", NODE)
for suite, package in (("jammy", "libc6"), ("noble", "libc6")):
    release = cache / f"{suite}.InRelease"
    status = sp.check_output(["gpgv", "--keyring", str(keyring.resolve()),
                              "--status-fd", "1", str(release)], text=True)
    assert any(line.startswith("[GNUPG:] VALIDSIG " + SIGNER + " ")
               for line in status.splitlines())
    signed_hashes = release.read_text().split("SHA256:\n", 1)[1]
    check = re.search(r"^ ([a-f0-9]{64}) +(\d+) main/binary-amd64/Packages\.xz$",
                      signed_hashes, re.M)
    packages = (cache / f"{suite}.Packages.xz").read_bytes()
    assert sha256(packages).hexdigest() == check[1] and len(packages) == int(check[2])
    stanza, = (s for s in lzma.decompress(packages).decode().split("\n\n")
                if s.startswith(f"Package: {package}\n"))
    fields = {key: val for line in stanza.splitlines() if ": " in line and not line.startswith(" ")
              for key, val in [line.split(": ", 1)]}
    debfile = cache / f"{suite}.libc6.deb"
    assert sha256(debfile.read_bytes()).hexdigest() == fields["SHA256"]
    print(suite, fields["Version"], fields["SHA256"])
    member, = [s for s in sp.check_output(["ar", "t", str(debfile)], text=True).splitlines()
               if s.startswith("data.tar.")]
    compressed = sp.check_output(["ar", "p", str(debfile), member])
    if member.endswith(".zst"):
        stream = BytesIO(sp.check_output(["zstd", "-dc"], input=compressed))
    else:
        stream = BytesIO(compressed)
    with tarfile.open(fileobj=stream, mode="r:*") as archive:
        for soname, required in needs.items():
            entry, = [e for e in archive.getmembers() if e.isfile() and Path(e.name).name == soname]
            image = cache / f"{suite}.{soname}"
            image.write_bytes(archive.extractfile(entry).read())
            assert re.search(r"\(SONAME\).*\[" + re.escape(soname) + r"\]", elf(["-dW"], image))
            provides = {(s[0], s[1], "FUNC" if s[2] == "IFUNC" else s[2]) for s, ndx, binding, _ in symbols(image)
                        if ndx != "UND" and binding in ("GLOBAL", "WEAK")}
            absent = sorted(required - provides)
            print(soname, f"{len(required) - len(absent)}/{len(required)} match", "missing", absent)
            name, version, kind = sorted(required)[0]
            assert (name, version + "_control", kind) not in provides
            print("wrong-version control rejected", name)
