#!/usr/bin/env python3
"""Compare the target's /rust/deps paths with official rust-src and Linux rust-std."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import struct
import sys
import tarfile
import tomllib

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections
sys.path.insert(0, str(PACKET.parent / "RE-002-node115-std-census"))
from census import ar_members

PINS = {
    "1.95.0": ("67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363",
               "047ea7098803d3500fa1072e9cee5392697e21525559e4458128a2bf874aa382"),
    "1.94.1": ("cb3756156fe6d2d6cedad327c94ad3721b612c4cd20dfb226d7543250788b66c",
               "74109ee2c19098f1d7122087dd338a8f643203b3ce678c9d58169db733e17a03"),
}
PATH = re.compile(rb"/rust/deps/([a-zA-Z0-9_-]+)-([0-9]+\.[0-9]+\.[0-9]+)/([A-Za-z0-9_./-]+?\.rs)")
TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def authenticate(path, checksum):
    with path.open("rb") as f:
        actual = sha256()
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            actual.update(chunk)
    if actual.hexdigest() != checksum:
        raise ValueError(f"unexpected digest for {path.name}")


def scan(content):
    for sec in sections(content):
        if sec["type"] != 1 or not sec["flags"] & 2 or sec["flags"] & 4:
            continue
        off = sec["offset"]
        for match in PATH.finditer(content, off, off + sec["size"]):
            yield (match[1].decode(), match[2].decode(), match[3].decode()), {
                "section": sec["name"], "section_offset": match.start() - off,
                "file_offset": match.start(),
            }


def dependency_edges(archive, release, names):
    path = f"rust-src-{release}/rust-src/lib/rustlib/src/rust/library/Cargo.lock"
    lock = archive.extractfile(path).read()
    packages = tomllib.loads(lock.decode())["package"]
    relevant = names | {"std"}
    by_name = {}
    for package in packages:
        if package["name"] in relevant:
            if package["name"] in by_name:
                raise ValueError("ambiguous lock package name")
            by_name[package["name"]] = package
    paths = {}
    queue = [["std"]]
    while queue:
        route = queue.pop(0)
        for dep in by_name[route[-1]].get("dependencies", []):
            name = dep.split()[0]
            if name in names and name not in paths:
                paths[name] = route + [name]
                queue.append(paths[name])
    if paths.keys() != names:
        raise ValueError("stdlib lock path missing")
    return sha256(lock).hexdigest(), {
        n: {"version": by_name[n]["version"], "package_checksum": by_name[n]["checksum"],
            "dependency_path": paths[n]} for n in sorted(names)}


def demangler_locations(obj):
    """Find absolute ET_REL fixups from a Location-shaped object to a file label."""
    secs = sections(obj)
    shoff = struct.unpack_from("<Q", obj, 40)[0]
    stride = struct.unpack_from("<H", obj, 58)[0]
    strings = {where["file_offset"]: (suffix, name, version)
               for (name, version, suffix), where in scan(obj) if name == "rustc-demangle"}
    points = []
    for index, rela in enumerate(secs):
        if rela["type"] != 4:
            continue
        link, owner = struct.unpack_from("<II", obj, shoff + index * stride + 40)
        dest = secs[owner]
        if not dest["name"].startswith(".data.rel.ro.") or dest["size"] != 24:
            continue
        for where, info, addend in struct.iter_unpack("<QQq", obj[rela["offset"]:rela["offset"] + rela["size"]]):
            if where != 0 or info & 0xffffffff != 1:
                continue
            sym = secs[link]["offset"] + (info >> 32) * 24
            section, value = struct.unpack_from("<HQ", obj, sym + 6)
            if not 0 < section < len(secs):
                continue
            label = strings.get(secs[section]["offset"] + value + addend)
            if label:
                suffix, name, version = label
                length, line, col = struct.unpack_from("<QII", obj, dest["offset"] + 8)
                if length == len(f"/rust/deps/{name}-{version}/{suffix}"):
                    points.append((suffix, line, col))
    return sorted(points)


def linked_locations(image, target):
    secs = {s["name"]: s for s in sections(image)}
    rodata, pointers, rela = (secs[k] for k in (".rodata", ".data.rel.ro", ".rela.dyn"))
    labels = {rodata["address"] + row["section_offset"]: (name, ver, suffix)
              for (name, ver, suffix), row in target if name == "rustc-demangle" and row["section"] == ".rodata"}
    points = []
    for where, info, addend in struct.iter_unpack("<QQq", image[rela["offset"]:rela["offset"] + rela["size"]]):
        if info != 8 or addend not in labels or not 0 <= where - pointers["address"] <= pointers["size"] - 24:
            continue
        name, ver, suffix = labels[addend]
        off = pointers["offset"] + where - pointers["address"]
        length, line, col = struct.unpack_from("<QII", image, off + 8)
        if length == len(f"/rust/deps/{name}-{ver}/{suffix}"):
            points.append((suffix, line, col, hex(where)))
    return sorted(points)


def distributions(archive, wanted):
    found = []
    locations = []
    archive_count = object_count = 0
    for entry in archive:
        if not entry.isfile() or not entry.name.endswith(".rlib"):
            continue
        archive_count += 1
        data = archive.extractfile(entry).read()
        for member, obj in ar_members(data):
            if not member.endswith(".o") or obj[:6] != b"\x7fELF\x02\x01":
                continue
            object_count += 1
            if b"/rust/deps/" not in obj:
                continue
            if Path(entry.name).name.startswith("librustc_demangle-"):
                locations.extend(demangler_locations(obj))
            for (name, version, suffix), record in scan(obj):
                if (name, suffix) in wanted:
                    found.append(dict(record, path=f"/rust/deps/{name}-{version}/{suffix}",
                                      rlib=Path(entry.name).name, member=member,
                                      member_sha256=sha256(obj).hexdigest()))
    return archive_count, object_count, sorted(locations), sorted(found, key=lambda r: (r["path"], r["rlib"], r["member"], r["file_offset"]))


def collect(cache):
    image = ROOT / "artifacts/node/115/hl-node"
    authenticate(image, TARGET_SHA)
    content = image.read_bytes()
    target = list(scan(content))
    wanted = {(name, suffix) for (name, version, suffix), row in target}
    names = {name for name, suffix in wanted}
    result = {"target_sha256": TARGET_SHA, "target": [
        dict(row, path=f"/rust/deps/{name}-{v}/{s}") for (name, v, s), row in target], "releases": {}}
    result["target_demangler_locations"] = linked_locations(content, target)
    for release, (src_digest, std_digest) in PINS.items():
        src = cache / f"rust-src-{release}.tar.xz"
        std = cache / f"rust-std-{release}.tar.xz"
        authenticate(src, src_digest)
        authenticate(std, std_digest)
        with tarfile.open(src) as archive:
            lock_sha, packages = dependency_edges(archive, release, names)
        with tarfile.open(std, mode="r|xz") as archive:
            archives, objects, locations, found = distributions(archive, wanted)
        result["releases"][release] = {"rust_src_sha256": src_digest, "rust_std_sha256": std_digest,
                                       "lock_sha256": lock_sha, "packages": packages,
                                       "rlibs_scanned": archives, "elf_members_scanned": objects,
                                       "demangler_locations": locations, "observations": found}
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache", type=Path, help="directory with the four pinned distribution files")
    print(json.dumps(collect(parser.parse_args().cache), indent=2))
