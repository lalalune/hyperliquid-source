"""Rebuild the selected Rust core and compiler-builtins functions from release source."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile

PACKET = Path(__file__).resolve().parent
ITEMS = PACKET.parent
CENSUS = ITEMS / "RE-002-node115-std-census"
# Each address selects one previously registered extent. The full upstream symbol
# at that address (including all module, type and generic identifiers) selects
# the function from the newly compiled objects.
SELECTION = {
    "udivti3": 0x63EFEC0,
    "floattidf": 0x63F0160,
    "trunc": 0x63EFF80,
    "decimal-round": 0x167E8D0,
    "cstr-from-bytes-with-nul": 0x167E030,
    "memchr-aligned": 0x16818B0,
    "powidf2": 0x63F0080,
    "lemire-compute-float": 0x167C730,
    "count-chars": 0x1681020,
    "grapheme-extend": 0x1682BF0,
}


def module_from_path(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sys.dont_write_bytecode = True
source_refs = module_from_path("source_refs", PACKET / "source_refs.py")
release_build = module_from_path("umod_release_build", ITEMS / "RE-002-node115-umodti3-source-build/build.py")
census = module_from_path("published_std_census", CENSUS / "census.py")


def crate_independent_symbol(name):
    # Only the crate disambiguator can change. Do not relax suffixes, CGU/body
    # lengths, or semantic-looking fragments of one or more candidates.
    return re.sub(r"Cs[0-9A-Za-z]+_(?=17compiler_builtins|4core)", "Cs_", name, count=1)


def prior_rows():
    rows = json.loads((CENSUS / "census.json").read_text())["records"]
    result = {}
    for key, start in SELECTION.items():
        row, = [r for r in rows if r["start"] == start]
        result[key] = row
    return result


def section_and_targets(objdump, obj, symbol, body, relocations):
    table = subprocess.check_output([objdump, "-t", obj], text=True)
    definition, = [line.split() for line in table.splitlines() if line.split() and line.split()[-1] == symbol]
    section, = [field for field in definition[:-1] if field.startswith(".text")]
    if ("F" not in definition or int(definition[0], 16) != 0
            or int(definition[definition.index(section) + 1], 16) != len(body)):
        raise ValueError(f"not a whole, zero-offset function: {symbol}")
    output = subprocess.check_output([objdump, "-r", "-j", section, obj], text=True, env={**os.environ, "LC_ALL": "C"})
    targets = []
    for line in output.splitlines():
        match = re.fullmatch(r"\s*([0-9a-f]+)\s+R_X86_64_(\w+)\s+(.+?)\s*", line)
        if not match:
            continue
        offset, kind, expression = match.groups()
        targets.append({"offset": int(offset, 16), "kind_name": kind, "expression": expression})
    if [(t["offset"], t["kind_name"]) for t in targets] != [(o, census.PCREL[k]) for o, k, _ in relocations]:
        raise ValueError(f"ELF relocation table and GNU objdump disagree: {symbol}")
    return section, targets


def extract_archives(archives, rows, work, objdump):
    wanted = {crate_independent_symbol(row["symbol"]): key for key, row in rows.items()}
    if len(wanted) != len(rows):
        raise ValueError("selected source symbols are ambiguous")
    found, archive_ids = {}, {}
    for dependency, archive in archives.items():
        contents = archive.read_bytes()
        archive_ids[dependency] = {"file": archive.name, "sha256": census.sha(contents)}
        for member, obj in census.ar_members(contents):
            if not member.endswith(".o") or not obj.startswith(b"\x7fELF"):
                continue
            if obj[:6] != b"\x7fELF\x02\x01" or obj[16:20] != bytes.fromhex("01003e00"):
                raise ValueError(f"unexpected architecture in {member}")
            for symbols, body, rel in census.object_functions(obj):
                for symbol in symbols:
                    key = wanted.get(crate_independent_symbol(symbol))
                    if key is None:
                        continue
                    baseline = rows[key]
                    if key in found or baseline["dependency"] != dependency:
                        raise ValueError(f"ambiguous source for {key}")
                    offsets = [o + i for o, _, _ in rel for i in range(4)]
                    if len(set(offsets)) != len(offsets) or any(i >= len(body) for i in offsets):
                        raise ValueError(f"invalid relocation coverage for {key}")
                    obj_path = work / "selected.o"
                    obj_path.write_bytes(obj)
                    section, targets = section_and_targets(objdump, obj_path, symbol, body, rel)
                    record = dict(id=key, dependency=dependency, symbol=symbol, census_symbol=baseline["symbol"],
                                  start=baseline["start"], end=baseline["end"], target_body_sha256=baseline["target_body_sha256"],
                                  member=member, member_sha256=census.sha(obj), section=section, symbol_offset=0,
                                  source_size=len(body), source_body_sha256=census.sha(body),
                                  relocations=[dict(offset=o, kind=k, width=4, addend=a) for o, k, a in rel],
                                  relocation_targets=targets)
                    found[key] = (record, body)
    records, blob = [], bytearray()
    for key in SELECTION:
        if key not in found:
            raise ValueError(f"function was not found in the rebuilt libraries: {key}")
        record, body = found[key]
        record["source_offset"] = len(blob)
        records.append(record)
        blob.extend(body)
    return records, bytes(blob), archive_ids


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["provision", "run"])
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--output", type=Path, help="new directory for replay evidence")
    parser.add_argument("--binutils-dir", type=Path)
    args = parser.parse_args()
    provision = args.action == "provision"
    if not provision and (args.output is None or args.output.exists()):
        parser.error("run requires an unused --output directory")
    cache = args.cache.resolve()
    if provision:
        cache.mkdir(parents=True, exist_ok=True)
    rows = prior_rows()
    tools = {} if provision else release_build.binutils(args.binutils_dir)
    builds, blobs, references = [], [], []
    with tempfile.TemporaryDirectory(prefix="rust-release-source-cohort-") as scratch:
        root = Path(scratch).resolve()
        for version in release_build.RELEASES:
            library = release_build.sources(cache, root, version, provision)
            labels = ["fetch"] if provision else (["build-a", "build-b"] if version == "1.95.0" else ["control"])
            for label in labels:
                work = root / f"{version}-{label}"
                job = release_build.cargo_job(work, cache, library, version, provision)
                if provision:
                    continue
                builtins, compiler, cargo = job
                # cargo_job uses an entirely new target tree for each call; its
                # -Zbuild-std request compiles core as well as compiler_builtins.
                core, = list(builtins.parent.glob("libcore-*.rlib"))
                dep_info = core.with_name(core.name.removeprefix("lib")).with_suffix(".d")
                if str(library / "core/src/lib.rs") not in dep_info.read_text().replace(r"\ ", " "):
                    raise ValueError("core dependency record does not name the authenticated release source")
                artifacts = {"compiler-builtins": builtins, "rust-core": core}
                record, body, archives = extract_archives(artifacts, rows, work, tools["objdump"])
                if version == "1.95.0":
                    references.append(source_refs.measure(artifacts, record, census))
                builds.append(dict(label=label, rust_release=version, rustc_commit=release_build.RELEASES[version][0],
                                   rustc_verbose=compiler, cargo_version=cargo, archives=archives, records=record))
                blobs.append(body)
    if provision:
        return
    if blobs[0] != blobs[1] or builds[0]["records"] != builds[1]["records"] or builds[0]["archives"] != builds[1]["archives"]:
        raise ValueError("independent builds of the same release disagreed")
    if references[0] != references[1]:
        raise ValueError("data behind the source objects' relocations differed")
    evidence = dict(target=release_build.TARGET, host=f"{platform.system()} {platform.machine()}",
                    source_archives={v: pair[1] for v, pair in release_build.RELEASES.items()},
                    objdump_version=subprocess.check_output([tools["objdump"], "--version"], text=True).splitlines()[0],
                    records=builds[0]["records"], builds=builds)
    args.output.mkdir(parents=True)
    (args.output / "build-results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    ref_doc = {"rust_release": "1.95.0", "references": references[0]}
    (args.output / "source-referents.json").write_text(json.dumps(ref_doc, indent=2) + "\n")
    (args.output / "bodies.bin").write_bytes(blobs[0])
    (args.output / "control-1.94.1.bin").write_bytes(blobs[2])


if __name__ == "__main__":
    main()
