#!/usr/bin/env python3
"""Recover the Linux lookup operands statically; exercise the public sources in a temporary fixture root."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from byte_progress import compare, require
from elf_index import sections

PINS = {"0.1.51": "f5a6ef98976b22b3b7f2f3a806f858cb862044cfa66805aa3ad84cb3d3b785ed",
        "0.1.60": "e7ffbb5a1b541ea2561f8c41c087286cc091e21e556a4f09a8f6cbf17b69b141",
        "0.1.63": "b0c919e5debc312ad217002b8048a17b7d83f80703865bbfcfebb0458b0b27d8",
        "0.1.65": "e31bc9ad994ba00e440a8aa5c9ef0ec67d5cb5e5cb0cc7f8b744a35b389cc470"}
PREFIXES = ["/usr/share/zoneinfo/", "../usr/share/zoneinfo/", "/etc/zoneinfo/", "../etc/zoneinfo/"]


def checked(path, checksum):
    data = path.read_bytes()
    require(sha256(data).hexdigest() == checksum, f"input identity: {path.name}")
    return data


def from_target():
    data = checked(ROOT / "artifacts/node/115/hl-node",
                   "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    secs = {s["name"]: s for s in sections(data)}
    def read(va, length, section=".text"):
        s = secs[section]
        rel = va - s["address"]
        require(0 <= rel <= s["size"] - length, f"address outside {section}")
        return data[s["offset"] + rel:s["offset"] + rel + length]

    directory = HERE.parent / "RE-002-node115-thinlto-std-vendor-census"
    census = json.loads(checked(directory / "census.json",
                       "422963cb59ad7cf883aaa834cf1ba20e9ee13719cc46ad61abbf4e92c8bd05c5"))
    rows = [r for r in census["records"] if r["crate"] == "iana-time-zone"]
    blob = (directory / "bodies.bin").read_bytes()
    for r in rows:
        size = r["end"] - r["start"]
        target = read(r["start"], size)
        source = blob[r["source_offset"]:r["source_offset"] + size]
        require(sha256(target).hexdigest() == r["target_body_sha256"] and
                sha256(source).hexdigest() == r["source_body_sha256"] and
                compare(source, target, r["relocations"])["relocation_qualified"], "census mismatch")

    def rel(field):
        return field + 4 + struct.unpack("<i", read(field, 4))[0]

    def literal(field, length):
        return read(rel(field), length, ".rodata")

    # Overlapping loads compare the same bytes of the input at different offsets.
    def overlap(a, b, displacement):
        require(a[displacement:] == b[:len(a)-displacement], "overlap bytes disagree")
        return a[:displacement] + b

    paths = [overlap(read(0x2e9ba2f, 8), read(0x2e9ba20, 8), 6).decode(),
             literal(0x2e9bbf2, read(0x2e9bbfc, 1)[0]).decode(),
             (literal(0x2e9af3a, 16) + read(0x2e9af4e, 2)).decode()]
    prefixes = [(literal(0x2e9bb11, 16) + literal(0x2e9bb09, 4)).decode(),
                overlap(literal(0x2e9bb46, 16), literal(0x2e9bb3e, 16), 6).decode(),
                overlap(read(0x2e9bb5b, 8), read(0x2e9bb69, 8), 6).decode(),
                literal(0x2e9bb8e, 16).decode()]
    lengths = [int.from_bytes(read(p, 4), "little") for p in (0x2e9bbb0, 0x2e9bbb7, 0x2e9bba9, 0x2e9bba2)]
    require(paths == ["/etc/localtime", "/etc/timezone", "/etc/config/system"] and prefixes == PREFIXES and
            lengths == list(map(len, prefixes)), "lookup path or prefix lengths differ")
    require(read(0x2e9bc33, 1) == b"\xe8" and rel(0x2e9bc34) == 0x2e9af00 and
            {r["start"] for r in rows} == {0x2e9ba00, 0x2e9af00}, "wrong OpenWrt fallback")
    return {"paths": paths, "prefixes": prefixes, "prefix_lengths": lengths, "openwrt_call": "0x2e9bc33"}


# These cases use real filesystem reads, regular files and dangling symlinks.
# None requires the TZ database or valid IANA names to exist on this machine.
UCI = "config system\n option timezone 'POSIX'\n option zonename 'Area/Primary'\n"
CASES = [
    *[(p, p + "Area/City", "Fallback", UCI, "Area/City") for p in PREFIXES],
    ("unknown prefix", "/unrecognized/Area/City", "  Other/City \t\n", UCI, "  Other/City"),
    ("empty zonefile", None, "", UCI, ""),
    ("OpenWrt preferred name", None, None, UCI, "Area/Primary"),
    ("OpenWrt POSIX only", None, None, "config system\noption timezone 'POSIX'\n", "POSIX"),
    ("non-system section", None, None, "config interface\noption zonename 'Ignored'\n", None),
    ("all absent", None, None, None, None),
    ("unrecognized names accepted", "/etc/zoneinfo/Unknown/Name", None, None, "Unknown/Name"),
    ("invalid zonefile utf8", None, b"\xff", UCI, "Area/Primary"),
]


def probe(version, archive, root):
    checked(archive, PINS[version])
    with tarfile.open(archive) as ar:
        source = ar.extractfile(f"iana-time-zone-{version}/src/tz_linux.rs").read().decode()
    calls = [("localtime", "read_link"), ("timezone", "read_to_string")]
    if version != "0.1.51":
        calls.append(("config/system", ".open"))
    for name, call in calls:
        old = f'{call}("/etc/{name}")'
        require(source.count(old) == 1, "fixture substitution count")
        source = source.replace(old, f'{call}(std::path::Path::new(&std::env::args_os().nth(1).unwrap()).join("{name}"))')
    (root / "platform.rs").write_text(source)
    (root / "main.rs").write_text("""
mod platform;
pub enum GetTimezoneError { FailedParsingString, IoError(std::io::Error), OsError }
impl From<std::io::Error> for GetTimezoneError {
    fn from(e: std::io::Error) -> Self { Self::IoError(e) }
}
fn main() {
    match platform::get_timezone_inner() {
        Ok(value) => print!("{}", value),
        Err(_) => std::process::exit(3),
    }
}
""")
    exe = root / "oracle"
    subprocess.run(["rustup", "run", "1.95.0", "rustc", "--edition=2021", str(root / "main.rs"), "-o", str(exe)], check=True)
    results = {}
    for i, (case, link, timezone, config, expected) in enumerate(CASES):
        folder = root / str(i)
        (folder / "config").mkdir(parents=True)
        if link is not None:
            (folder / "localtime").symlink_to(link)
        if timezone is not None:
            (folder / "timezone").write_bytes(timezone if isinstance(timezone, bytes) else timezone.encode())
        if config is not None:
            (folder / "config/system").write_text(config)
        if version == "0.1.51":
            if case in PREFIXES[2:]:
                expected = "Fallback"
            if case in ("OpenWrt preferred name", "OpenWrt POSIX only", "invalid zonefile utf8",
                        "unrecognized names accepted"):
                expected = None
        proc = subprocess.run([str(exe), str(folder)], capture_output=True, check=False)
        require(proc.returncode == (3 if expected is None else 0) and
                proc.stdout == (b"" if expected is None else expected.encode()), f"{version}: {case} failed")
        results[case] = expected
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache", type=Path, help="directory containing VERSION.crate for the four releases")
    args = parser.parse_args()
    result = {"target": from_target(), "oracles": {}}
    for v in PINS:
        with tempfile.TemporaryDirectory() as tmp:
            result["oracles"][v] = probe(v, args.cache / (v + ".crate"), Path(tmp))
    print(json.dumps(result, indent=2))
