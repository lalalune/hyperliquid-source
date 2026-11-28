#!/usr/bin/env python3
"""Audit the static ELF runtime closure against one signed Ubuntu release at a time."""
import argparse
from hashlib import sha256
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / "artifacts/node/115/hl-node"
NODE_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
ARCHIVE = "https://archive.ubuntu.com/ubuntu/"
INDEX = "main/binary-amd64/Packages.xz"
SIGNER = "F6ECB3762474EDA9D21B7022871920D1991BC93C"
RELEASES = {"noble": "cdb2f31d809f589719a53c6ad15f255b27569c4059542ada282aaa21b8e164b0",
            "jammy": "c14060cd8c6d625874dfcb9523a35a395bf4865c28b6b6a82569ef326fe92dc6"}
LIBDIRS = ("/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib", "/usr/lib")


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def run(args, data=None):
    return subprocess.check_output(args, input=data, env=dict(os.environ, LC_ALL="C"))


def digest(data):
    return sha256(data).hexdigest()


def resource(file, url, expected, fetch):
    if not file.exists() and fetch:
        data = run(["curl", "-fsSL", "--retry", "2", url])
        require(digest(data) == expected, f"download digest failed for {url}")
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(data)
    data = file.read_bytes()
    require(digest(data) == expected, f"input digest failed for {file.name}")
    return data


def package_set(suite, cache, keyring, fetch):
    directory = cache / suite
    base = ARCHIVE + "dists/" + suite + "/"
    release = resource(directory / "InRelease", base + "InRelease", RELEASES[suite], fetch)
    status = run(["gpgv", "--status-fd", "1", "--keyring", str(keyring), str(directory / "InRelease")])
    require(SIGNER in re.findall(r"^\[GNUPG:\] VALIDSIG ([A-F0-9]+) ", status.decode(), re.M),
            "Ubuntu archive signer missing")
    section = re.search(rb"^SHA256:\n((?: [^\n]+\n)+)", release, re.M)[1].decode()
    (index_hash, size, _), = [row.split() for row in section.splitlines() if row.split()[-1] == INDEX]
    compressed = resource(directory / "Packages.xz", base + INDEX, index_hash, fetch)
    require(len(compressed) == int(size), "wrong Packages.xz length")
    paragraphs = lzma.decompress(compressed).decode().split("\n\n")
    names = ["base-files", "libc6", "libgcc-s1", "libstdc++6", "libssl3t64" if suite == "noble" else "libssl3"]
    packages, files, links = {}, {}, {}
    for name in names:
        paragraph, = [r for r in paragraphs if r.startswith(f"Package: {name}\n")]
        fields = dict(line.split(": ", 1) for line in paragraph.splitlines() if ": " in line and not line.startswith(" "))
        require(fields["Architecture"] == "amd64", "wrong architecture")
        path = directory / (name + ".deb")
        deb = resource(path, ARCHIVE + fields["Filename"], fields["SHA256"], fetch)
        require(len(deb) == int(fields["Size"]), "wrong package size")
        packages[name] = {k: fields[k] for k in ("Version", "Filename", "SHA256", "Size")}
        member, = [m for m in run(["ar", "t", str(path)]).decode().split() if m.startswith("data.tar.")]
        packed = run(["ar", "p", str(path), member])
        raw = run(["zstd", "-qdc"], packed) if member.endswith(".zst") else packed
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
            for entry in tar:
                absolute = "/" + entry.name.removeprefix("./")
                if entry.issym():
                    links[absolute] = (name, entry.linkname)
                elif entry.isfile() and ".so" in PurePosixPath(absolute).name:
                    data = tar.extractfile(entry).read()
                    if data.startswith(b"\x7fELF"):
                        files[absolute] = (name, data)
    return index_hash, packages, files, links


def resolve(path, files, links):
    trail = []
    while True:
        parts = PurePosixPath(path).parts[1:]
        for i in range(1, len(parts) + 1):
            prefix = "/" + "/".join(parts[:i])
            if prefix not in links:
                continue
            owner, target = links[prefix]
            require(prefix not in [x[0] for x in trail], "package symlink cycle")
            trail.append((prefix, owner, target))
            path = posixpath.normpath(posixpath.join(posixpath.dirname(prefix), target, *parts[i:]))
            break
        else:
            return (path, trail) if path in files else None


def inspect(file):
    with file.open("rb") as handle:
        header = handle.read(20)
    require(header[:6] == b"\x7fELF\x02\x01" and header[16:20] == b"\x03\x00\x3e\x00",
            "expected an ELF64 little-endian x86-64 ET_DYN")
    dyn = run(["readelf", "-Wd", str(file)]).decode()
    require("(RPATH)" not in dyn and "(RUNPATH)" not in dyn, "non-default library path")
    needed = re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", dyn)
    soname = re.findall(r"\(SONAME\).*?\[([^\]]+)\]", dyn)
    versions = run(["readelf", "-WV", str(file)]).decode()
    ids, defs = {}, set()
    owner = None
    for line in versions.splitlines():
        node = re.search(r"Rev: \d+\s+Flags: .*?\s+Index: \d+.*?\bName: (\S+)", line)
        if node:
            defs.add(node[1])
        file_name = re.search(r"\bFile: (\S+)\s+Cnt:", line)
        req = re.search(r"\bName: (\S+)\s+Flags: .*?\s+Version: (\d+)", line)
        if file_name:
            owner = file_name[1]
        elif req:
            require(owner in needed, "version requirement has no direct owner")
            ids[req[2]] = (owner, req[1])
    imports, exports, plain = [], set(), []
    for line in run(["readelf", "-W", "--dyn-syms", str(file)]).decode().splitlines():
        fields = line.split()
        if len(fields) < 8 or not re.fullmatch(r"\d+:", fields[0]):
            continue
        _, _, _, typ, binding, vis, ndx, symbol, *tail = fields
        if ndx == "UND":
            if "@" in symbol:
                name, version = symbol.rsplit("@", 1)
                provider, expected = ids[tail[0].strip("()")]
                require(version == expected, "version owner mismatch")
                imports.append((provider, name, version))
            else:
                plain.append((binding, symbol))
        elif binding in ("GLOBAL", "WEAK", "UNIQUE") and vis in ("DEFAULT", "PROTECTED"):
            exports.add(symbol.replace("@@", "@"))
    return dict(needed=needed, soname=soname, defs=defs, versions=set(ids.values()), imports=imports,
                exports=exports, plain=plain)


def suite_report(suite, cache, keyring, fetch, tmp):
    index_sha, packages, files, links = package_set(suite, cache, keyring, fetch)
    interp, = re.findall(r"Requesting program interpreter: ([^\]]+)", run(["readelf", "-Wl", str(TARGET)]).decode())
    actual, trail = resolve(interp, files, links)
    aliases = {"node115": inspect(TARGET)}
    paths = {}
    queue = ["node115"]
    for caller in queue:
        for name in aliases[caller]["needed"]:
            if name in aliases:
                continue
            candidates = [(directory + "/" + name, resolve(directory + "/" + name, files, links)) for directory in LIBDIRS]
            found = [(path, value) for path, value in candidates if value]
            require(found and len({value[0] for _, value in found}) == 1, f"missing or ambiguous {name}")
            requested, (final, chain) = found[0]
            package, body = files[final]
            elf = tmp / name
            elf.write_bytes(body)
            aliases[name] = inspect(elf)
            require(aliases[name]["soname"] == [name], f"wrong SONAME: {final}")
            paths[name] = dict(lookup=requested, member=final, package=package, links=chain, sha256=digest(body))
            queue.append(name)
    require(paths[posixpath.basename(interp)]["member"] == actual, "PT_INTERP and loader dependency differ")
    edges = []
    for caller, elf in aliases.items():
        for name in elf["needed"]:
            provider = aliases[name]
            nodes = sorted(version for owner, version in elf["versions"] if owner == name)
            required = sorted(symbol + "@" + version for owner, symbol, version in elf["imports"] if owner == name)
            missing = sorted(set(required) - provider["exports"])
            edges.append(dict(caller=caller, provider=name, version_nodes=nodes,
                              missing_nodes=sorted(set(nodes) - provider["defs"]),
                              symbol_count=len(required), symbol_list_sha256=digest("\n".join(required).encode()),
                              missing_symbols=missing))
    return dict(inrelease_sha256=RELEASES[suite], index_sha256=index_sha, packages=packages,
                interpreter=dict(requested=interp, member=actual, symlinks=trail),
                providers=paths, edges=edges, unversioned_imports={c: e["plain"] for c, e in aliases.items() if e["plain"]})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--keyring", type=Path, required=True, help="Ubuntu archive keyring with 2018 signing key")
    parser.add_argument("--fetch", action="store_true")
    args = parser.parse_args()
    require(digest(TARGET.read_bytes()) == NODE_SHA, "wrong node #115")
    with tempfile.TemporaryDirectory() as tmp:
        suites = {s: suite_report(s, args.cache, args.keyring.resolve(), args.fetch, Path(tmp)) for s in RELEASES}
    print(json.dumps(dict(target_sha256=NODE_SHA, ubuntu_signer=SIGNER, suites=suites), indent=2, sort_keys=True))
