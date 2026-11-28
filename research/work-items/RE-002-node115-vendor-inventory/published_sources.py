"""Resolve node #115's versioned vendor locations against checksummed registry sources."""
import argparse
from collections import defaultdict
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import struct
import sys
import tarfile
from urllib.request import urlopen

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections

NODE_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
INVENTORY_SHA = "c3ca48f434b4476e7fee9ac9f5a7f076d2cd86a7e3973241ad092fb723bef66b"


def read_archive(cache, package, checksum, fetch):
    name = package["crate"]
    stem = package["directory"] + ".crate"
    path = cache / stem
    if fetch and not path.exists():
        with urlopen(f"https://static.crates.io/crates/{name}/{stem}", timeout=60) as response:
            data = response.read()
    else:
        data = path.read_bytes()
    if sha256(data).hexdigest() != checksum:
        raise ValueError(f"{stem}: registry checksum mismatch")
    if fetch and not path.exists():
        path.write_bytes(data)
    return data


def source_lines(data, directory, paths):
    wanted = {f"{directory}/{path}": path for path in paths}
    sources = {}
    with tarfile.open(fileobj=BytesIO(data), mode="r:gz") as archive:
        for entry in archive:
            if entry.name in wanted and entry.isfile():
                path = wanted[entry.name]
                if path in sources:
                    raise ValueError(f"duplicate source archive member {path}")
                sources[path] = archive.extractfile(entry).read().decode().splitlines()
    return sources


def coordinates(image, packages):
    if sha256(image).hexdigest() != NODE_SHA:
        raise ValueError("node #115 capture digest mismatch")
    by_name = {row["name"]: row for row in sections(image)}
    strings, storage, rel = (by_name[n] for n in (".rodata", ".data.rel.ro", ".rela.dyn"))
    ro = image[strings["offset"]:strings["offset"] + strings["size"]]
    backrefs = defaultdict(list)
    for va, kind, pointee in struct.iter_unpack("<QQq", image[rel["offset"]:rel["offset"] + rel["size"]]):
        if kind == 8 and storage["address"] <= va <= storage["address"] + storage["size"] - 24:
            off = va - storage["address"] + storage["offset"]
            backrefs[pointee].append(struct.unpack_from("<QII", image, off + 8))
    matches = {}
    for package in packages:
        for file in package["source_files"]:
            key = (package["directory"], file)
            suffix = f"z_vendor/{key[0]}/{file}".encode()
            matches[key] = set()
            for prefix in (b"/home/ubuntu/hl/code_Mainnet/", b""):
                path = prefix + suffix
                start = ro.find(path)
                while start >= 0:
                    for length, line, column in backrefs.get(strings["address"] + start, ()):
                        if length == len(path) and line and column:
                            matches[key].add((line, column))
                    start = ro.find(path, start + 1)
    return matches


def score(files, coords):
    pairs = [(path, line, col) for path in coords for line, col in coords[path]]
    # rustc reports one-based character columns; only positions on a character
    # count as inside the named line. EOF or an immediately following column
    # is retained as an outside position, not silently rounded inside.
    outside = [(path, line, col) for path, line, col in pairs
               if path not in files or line > len(files[path]) or col > len(files[path][line - 1])]
    return {"files_present": sum(p in files for p in coords), "coordinates": len(pairs),
            "inside_line": len(pairs) - len(outside), "outside": sorted(outside)}


def measure(node, cache, fetch):
    inv = (HERE / "inventory.json").read_bytes()
    if sha256(inv).hexdigest() != INVENTORY_SHA:
        raise ValueError("historical inventory digest mismatch")
    packages = [p for p in json.loads(inv)["vendored"] if p["version_in_path"]]
    pins = json.loads((HERE / "archive-checksums.json").read_text())
    if set(pins) != {p["directory"] for p in packages}:
        raise ValueError("archive pins do not match the versioned directory inventory")
    locs = coordinates(node.read_bytes(), packages)
    if fetch:
        cache.mkdir(parents=True, exist_ok=True)
    results = []
    for provider in packages:
        peers = [p for p in packages if p["crate"] == provider["crate"]]
        files = {f for peer in peers for f in peer["source_files"]}
        archive = read_archive(cache, provider, pins[provider["directory"]], fetch)
        sources = source_lines(archive, provider["directory"], files)
        for origin in peers:
            selected = {f: locs[origin["directory"], f] for f in origin["source_files"]}
            results.append({"recorded_directory": origin["directory"], "public_archive": provider["directory"],
                            "files_recorded": len(selected), **score(sources, selected)})
    return {"node_sha256": NODE_SHA, "inventory_sha256": INVENTORY_SHA, "comparisons": results}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--fetch", action="store_true", help="download missing public crate archives")
    parser.add_argument("--node", type=Path, default=ROOT / "artifacts/node/115/hl-node")
    args = parser.parse_args()
    print(json.dumps(measure(args.node, args.cache, args.fetch), indent=2))
