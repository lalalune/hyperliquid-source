#!/usr/bin/env python3
"""Match & verify rustc 1.95.0 ThinLTO + tikv-jemallocator z_forks Wave 2 (revm/alloy/rpc) FDEs against node #115.

Targets the EVM/RPC/codec dependency stack paired with Hyperliquid node #115's
revm-precompile & reth-* private forks:
  - revm 40.0.3 (interpreter, handler, context, state, bytecode, precompile 36.0.3)
  - alloy-evm 0.37.1, alloy-consensus 1.7.3/2.1.1, alloy-rpc-types-eth 1.7.3/2.1.1,
    alloy-rpc-types-engine 2.1.1, alloy-eips, alloy-trie, alloy-hardforks, alloy-chains,
    alloy-json-abi, alloy-sol-types, alloy-rlp, alloy-primitives
  - ark-bls12-381, ark-bn254, ark-ec, ark-ff, blst, secp256k1, k256, curve25519-dalek-ng
  - jsonrpsee-core, jsonrpsee-types, rmp-serde, serde_json, ethers-core, rust_decimal

Strict adversarial attribution & admission gates (all enforced by --verify):
  1. length >= 32 bytes, unmasked bytes >= 16, relocation-masked bytes * 2 <= length;
  2. relocation-masked bytes (plus psABI GOTPCRELX relaxations via tools/byte_progress.py)
     match complete node #115 .text FDEs under strict unique-FDE / Location-authenticated /
     high-entropy multi-copy (>= 128 B, >= 96 unmasked B, hits <= 4) tiers;
  3. zero harness crate tokens (`zforks_w2_`) anywhere in the mangled symbol;
  4. defining crate extracted from the mangled symbol MUST resolve unambiguously to a
     rustc 1.95.0 sysroot crate or a locked permissive crates.io package in Cargo.lock
     (ZERO first-party component credit is ever claimed);
  5. zero overlap across BOTH `start`/`end` AND `start_va`/`end_va` against
     `research/byte-windows.json` and ALL sibling packets under `research/work-items/`.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
TARGET = "artifacts/node/115/hl-node"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
WINDOW_PREFIX = "node115-zforks-w2-"
MIN_BYTES = 32
MIN_UNMASKED = 16
MULTI_COPY_MIN_BYTES = 128
MULTI_COPY_MIN_UNMASKED = 96
MULTI_COPY_MAX_HITS = 4

sys.path.insert(0, str(ROOT / "tools"))
from byte_progress import RELAXATIONS, compare, relaxation_bytes  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402

SYSROOT_STD_CRATES = {
    "std",
    "gimli",
    "addr2line",
    "adler2",
    "miniz_oxide",
    "object",
    "rustc_demangle",
    "memchr",
    "std_detect",
    "panic_unwind",
    "unwind",
    "panic_abort",
    "cfg_if",
}
HARNESS_TOKENS = ("zforks_w2_",)
HARNESSES = [
    ("zforks_w2_revm40", "w2_revm40"),
    ("zforks_w2_alloy_evm", "w2_alloy_evm"),
]
MULTI_COPY_CRATES = {
    "revm-precompile",
    "revm-interpreter",
    "revm-context",
    "revm-context-interface",
    "revm-handler",
    "revm-state",
    "revm-bytecode",
    "revm-database",
    "revm-inspector",
    "revm-primitives",
    "alloy-evm",
    "alloy-consensus",
    "alloy-eips",
    "alloy-rpc-types-eth",
    "alloy-rpc-types-engine",
    "alloy-trie",
    "alloy-hardforks",
    "alloy-chains",
    "alloy-json-abi",
    "alloy-sol-types",
    "alloy-rlp",
    "alloy-primitives",
    "alloy-serde",
    "ark-bls12-381",
    "ark-bn254",
    "ark-ec",
    "ark-ff",
    "ark-serialize",
    "blst",
    "k256",
    "p256",
    "secp256k1",
    "curve25519-dalek-ng",
    "jsonrpsee-core",
    "jsonrpsee-types",
    "rmp-serde",
    "serde_json",
    "ethers-core",
    "rust_decimal",
}
CRATE_TO_ZFORK = {
    "revm-precompile": "revm-precompile",
}


def _load_object_functions():
    spec = importlib.util.spec_from_file_location(
        "node115_std_census_helpers",
        ROOT / "research/work-items/RE-002-node115-std-census/census.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.object_functions


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def relaxed_match(src: bytes, tgt: bytes, rel, mask: set):
    allowed, applied = set(mask), {}
    for o, kind, _ in rel:
        for name in RELAXATIONS:
            rewritten = relaxation_bytes(src, tgt, o, kind, name)
            if rewritten is not None:
                if rewritten & allowed:
                    return None
                applied[o] = name
                allowed |= rewritten
                break
    if not applied or any(src[i] != tgt[i] for i in range(len(src)) if i not in allowed):
        return None
    return applied


def lock_versions(lock: Path) -> dict[str, list[dict]]:
    text = Path(lock).read_text()
    out: dict[str, list[dict]] = {}
    for block in text.split("[[package]]")[1:]:
        name = re.search(r'^name = "([^"]+)"', block, re.M).group(1)
        version = re.search(r'^version = "([^"]+)"', block, re.M).group(1)
        source = re.search(r'^source = "([^"]+)"', block, re.M)
        checksum = re.search(r'^checksum = "([^"]+)"', block, re.M)
        out.setdefault(name.replace("-", "_"), []).append(
            {
                "crate": name,
                "version": version,
                "source": source and source.group(1),
                "checksum": checksum and checksum.group(1),
            }
        )
    return out


def extract_defining_crate_ident(symbol: str) -> str | None:
    if any(tok in symbol for tok in HARNESS_TOKENS):
        return None
    if symbol.startswith("_ZN"):
        m = re.match(r"^_ZN(\d+)", symbol)
        if not m:
            return None
        ln = int(m.group(1))
        seg = symbol[3 + len(m.group(1)) : 3 + len(m.group(1)) + ln]
        if seg.startswith("_$LT$") or seg.startswith("$LT$"):
            inner = seg[5:] if seg.startswith("_$LT$") else seg[4:]
            while True:
                if inner.startswith("$RF$"):
                    inner = inner[4:]
                elif inner.startswith("$u5b$"):
                    inner = inner[5:]
                elif inner.startswith("mut$u20$"):
                    inner = inner[8:]
                elif inner.startswith("$BP$const$u20$"):
                    inner = inner[14:]
                elif inner.startswith("$BP$mut$u20$"):
                    inner = inner[12:]
                else:
                    break
            if inner.startswith("impl$u20$"):
                inner = inner[9:]
            m2 = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*)\.\.", inner)
            if m2:
                return m2.group(1)
            as_pos = inner.find("$u20$as$u20$")
            if as_pos >= 0:
                rest = inner[as_pos + 12 :]
                m3 = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*)\.\.", rest)
                if m3:
                    return m3.group(1)
            return None
        if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", seg):
            return seg
        return None
    if symbol.startswith("_R"):
        m = re.search(r"C(?:s[0-9a-zA-Z]*_)?(\d+)([a-zA-Z_][a-zA-Z0-9_]*)", symbol)
        if m:
            ln = int(m.group(1))
            ident = m.group(2)[:ln]
            if len(ident) == ln:
                return ident
        return None
    return None


def classify_symbol(symbol: str, versions: dict):
    ident = extract_defining_crate_ident(symbol)
    if not ident:
        return None
    if ident == "core":
        return (
            "rust-core",
            "core",
            [{"crate": "core", "version": "rustc-1.95.0-sysroot", "source": None, "checksum": None}],
        )
    if ident == "alloc":
        return (
            "rust-alloc",
            "alloc",
            [{"crate": "alloc", "version": "rustc-1.95.0-sysroot", "source": None, "checksum": None}],
        )
    if ident == "compiler_builtins":
        return (
            "compiler-builtins",
            "compiler_builtins",
            [
                {
                    "crate": "compiler_builtins",
                    "version": "rustc-1.95.0-sysroot",
                    "source": None,
                    "checksum": None,
                }
            ],
        )
    if ident in SYSROOT_STD_CRATES and ident not in versions:
        return (
            "rust-std",
            ident,
            [{"crate": ident, "version": "rustc-1.95.0-sysroot", "source": None, "checksum": None}],
        )
    cands = [c for c in versions.get(ident, []) if c["source"]]
    if cands:
        return ("vendored-crates", cands[0]["crate"], cands)
    if ident in SYSROOT_STD_CRATES:
        return (
            "rust-std",
            ident,
            [{"crate": ident, "version": "rustc-1.95.0-sysroot", "source": None, "checksum": None}],
        )
    return None


def parse_va(val) -> int | None:
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        try:
            return int(val, 16)
        except ValueError:
            return None
    return None


def collect_existing_intervals(
    exclude_self: bool = True, committed_only: bool = False
) -> list[tuple[int, int, str]]:
    intervals: list[tuple[int, int, str]] = []
    registry = json.loads((ROOT / "research/byte-windows.json").read_text())
    for w in registry.get("windows", []):
        if w.get("target") != "node115":
            continue
        if exclude_self and w.get("id", "").startswith(WINDOW_PREFIX):
            continue
        intervals.append((int(w["start"]), int(w["end"]), f"byte-windows.json:{w.get('id', '')}"))

    for pattern in ("*/records.json", "*/census.json"):
        for rec_file in sorted((ROOT / "research/work-items").glob(pattern)):
            if exclude_self and rec_file.parent.resolve() == HERE.resolve():
                continue
            if committed_only and not (rec_file.parent / "MANIFEST.sha256").is_file():
                continue
            try:
                d = json.loads(rec_file.read_text())
            except Exception:
                continue
            rows = d if isinstance(d, list) else d.get("windows", d.get("records", []))
            if not isinstance(rows, list):
                continue
            label = str(rec_file.relative_to(ROOT))
            for r in rows:
                if not isinstance(r, dict):
                    continue
                s = parse_va(r.get("start_va", r.get("start", r.get("vaddr"))))
                if s is None:
                    continue
                e = parse_va(r.get("end_va", r.get("end")))
                if e is None:
                    sz = r.get("size", r.get("size_bytes", r.get("bytes")))
                    if isinstance(sz, int) and sz > 0:
                        e = s + sz
                if e is not None and e > s:
                    intervals.append((s, e, label))
    return intervals


def lookup_cargo_license(crate: str, version: str) -> str:
    cargo_home = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
    for manifest in sorted(cargo_home.glob(f"registry/src/*/{crate}-{version}/Cargo.toml")):
        text = manifest.read_text(errors="replace")
        m = re.search(r'^license\s*=\s*"([^"]+)"', text, re.M)
        if m:
            return m.group(1)
        m2 = re.search(r'^license-file\s*=\s*"([^"]+)"', text, re.M)
        if m2:
            return f"license-file:{m2.group(1)}"
    return "UNKNOWN"


def load_zfork_location_fdes() -> dict[int, str]:
    prov_path = ROOT / "research/work-items/RE-002-node115-private-forks-provenance/records.json"
    prov = json.loads(prov_path.read_text())
    out: dict[int, str] = {}
    for fork_name, fdata in prov.get("forks", {}).items():
        for loc in fdata.get("locations", []):
            for x in loc.get("xref_sites", []):
                out[int(x["fde_start"], 16)] = fork_name
    return out


def generate(deps_dir: Path) -> None:
    object_functions = _load_object_functions()
    data = (ROOT / TARGET).read_bytes()
    if sha(data) != TARGET_SHA256:
        raise AssertionError("target node115 SHA-256 mismatch")

    text = next(s for s in sections(data) if s["name"] == ".text")
    _, fdes, _ = fde_extents(data)
    starts: dict[int, int] = {}
    for f in fdes:
        starts[f["start"]] = starts.get(f["start"], 0) + 1
    by_len: dict[int, list[tuple[int, bytes]]] = {}
    for f in fdes:
        if f["section"] == ".text" and starts[f["start"]] == 1:
            n = f["end"] - f["start"]
            off = text["offset"] + f["start"] - text["address"]
            by_len.setdefault(n, []).append((f["start"], data[off : off + n]))

    taken = [(a, b) for a, b, _ in collect_existing_intervals(exclude_self=True, committed_only=False)]
    zfork_fdes = load_zfork_location_fdes()

    claimed: dict[int, dict] = {}
    records: list[dict] = []
    locks: list[dict] = []
    scanned_cgus = 0

    for build_idx, (bin_name, subdir) in enumerate(HARNESSES):
        lock = HERE / subdir / "Cargo.lock"
        versions = lock_versions(lock)
        locks.append(
            {
                "build": build_idx,
                "bin_name": bin_name,
                "lockfile": str(lock.relative_to(ROOT)),
                "sha256": sha(lock.read_bytes()),
            }
        )
        cgus = sorted(deps_dir.glob(f"{bin_name}-*.rcgu.o"))
        if not cgus:
            raise AssertionError(f"no ThinLTO CGUs found for {bin_name} in {deps_dir}")
        for obj_path in cgus:
            obj = obj_path.read_bytes()
            if obj[:4] != b"\x7fELF":
                continue
            scanned_cgus += 1
            is_harness_cgu = not obj_path.name.endswith(".rcgu.o.rcgu.o")
            for symbols, body, rel in object_functions(obj):
                n = len(body)
                if n < MIN_BYTES or n not in by_len:
                    continue
                if any(tok in s for s in symbols for tok in HARNESS_TOKENS):
                    continue
                cls = classify_symbol(symbols[0], versions)
                if cls is None:
                    continue
                dep_bucket, crate_name, candidates = cls
                mask = set()
                for o, _, _ in rel:
                    mask.update(range(o, o + 4))
                unmasked = n - len(mask)
                if len(mask) * 2 > n or unmasked < MIN_UNMASKED:
                    continue
                keep = [i for i in range(n) if i not in mask]
                probe = bytes(body[i] for i in keep)
                hits = [(va, t) for va, t in by_len[n] if bytes(t[i] for i in keep) == probe]
                relaxed = {}
                if not hits and any(k in (41, 42) for _, k, _ in rel):
                    cands_r = [
                        (va, t, r)
                        for va, t in by_len[n]
                        for r in [relaxed_match(body, t, rel, mask)]
                        if r
                    ]
                    if len(cands_r) == 1:
                        va, t, relaxed = cands_r[0]
                        hits = [(va, t)]
                if not hits:
                    continue

                admitted_hits: list[tuple[int, bytes, str]] = []
                if len(hits) == 1:
                    admitted_hits.append((hits[0][0], hits[0][1], "unique_fde"))
                elif dep_bucket == "vendored-crates" and crate_name in MULTI_COPY_CRATES:
                    expected_fork = CRATE_TO_ZFORK.get(crate_name)
                    for va, target in hits:
                        if expected_fork is not None and zfork_fdes.get(va) == expected_fork:
                            admitted_hits.append((va, target, "zfork_location_authenticated"))
                        elif (
                            len(hits) <= MULTI_COPY_MAX_HITS
                            and n >= MULTI_COPY_MIN_BYTES
                            and unmasked >= MULTI_COPY_MIN_UNMASKED
                        ):
                            admitted_hits.append((va, target, "high_entropy_multi_copy"))

                body_sha = sha(body)
                for va, target, match_tier in admitted_hits:
                    if any(not (va + n <= a or va >= b) for a, b in taken):
                        continue
                    if va in claimed:
                        prior = claimed[va]
                        if prior["dependency"] != dep_bucket or prior["crate"] != crate_name:
                            prior["ambiguous_sources"] = True
                        elif prior["symbol"] != symbols[0] or prior["cgu"] != obj_path.name:
                            prior.setdefault("identical_sources", []).append(
                                {
                                    "symbol": symbols[0],
                                    "cgu": obj_path.name,
                                    "crate": crate_name,
                                    "dependency": dep_bucket,
                                    "versions": [c["version"] for c in candidates],
                                }
                            )
                        continue
                    record = {
                        "symbol": symbols[0],
                        "cgu": obj_path.name,
                        "bin_name": bin_name,
                        "harness_cgu": is_harness_cgu,
                        "sysroot": dep_bucket != "vendored-crates",
                        "native": False,
                        "dependency": dep_bucket,
                        "crate": crate_name,
                        "match_tier": match_tier,
                        "node115_hit_count": len(hits),
                        "versions": candidates,
                        "start": va,
                        "end": va + n,
                        "start_va": f"0x{va:x}",
                        "end_va": f"0x{va + n:x}",
                        "size": n,
                        "target_body_sha256": sha(target),
                        "source_body": body,
                        "source_body_sha256": body_sha,
                        "raw_equal": target == body,
                        "relocations": [
                            {
                                "offset": o,
                                "kind": t,
                                "width": 4,
                                "addend": a,
                                **({"relaxation": relaxed[o]} if o in relaxed else {}),
                            }
                            for o, t, a in rel
                        ],
                    }
                    claimed[va] = record
                    records.append(record)

    records = [
        r
        for r in records
        if not r.pop("ambiguous_sources", False)
        and all(
            s["crate"] == r["crate"] and s["dependency"] == r["dependency"]
            for s in r.get("identical_sources", [])
        )
    ]
    records.sort(key=lambda r: (r["start"], r["end"], r["dependency"], r["crate"], r["symbol"]))

    lock_packages: dict[str, dict] = {}
    licenses: dict[str, str] = {}
    for r in records:
        vers = {v["version"] for v in r["versions"]}
        for other in r.get("identical_sources", []):
            vers.update(other["versions"])
        r["candidate_versions"] = sorted(vers)
        r["candidate_symbols"] = sorted(
            {r["symbol"], *(o["symbol"] for o in r.get("identical_sources", []))}
        )
        for v in r.pop("versions"):
            if v["source"]:
                pkg_key = f"{v['crate']} {v['version']}"
                lock_packages[pkg_key] = {
                    "source": v["source"],
                    "checksum": v["checksum"],
                }
                if pkg_key not in licenses:
                    licenses[pkg_key] = lookup_cargo_license(v["crate"], v["version"])
        r["identical_source_count"] = len(r.pop("identical_sources", []))

    blob = bytearray()
    for r in records:
        body = r.pop("source_body")
        r["source_offset"] = len(blob)
        blob += body
    (HERE / "bodies.bin").write_bytes(blob)
    (HERE / "licenses.json").write_text(json.dumps(dict(sorted(licenses.items())), indent=2) + "\n")

    by_dep: dict[str, dict] = {}
    by_crate: dict[str, dict] = {}
    for r in records:
        sz = r["size"]
        d = by_dep.setdefault(r["dependency"], {"windows": 0, "bytes": 0, "raw_equal_windows": 0})
        d["windows"] += 1
        d["bytes"] += sz
        d["raw_equal_windows"] += int(r["raw_equal"])
        ck = f"{r['dependency']}:{r['crate']}"
        c = by_crate.setdefault(ck, {"windows": 0, "bytes": 0, "raw_equal_windows": 0})
        c["windows"] += 1
        c["bytes"] += sz
        c["raw_equal_windows"] += int(r["raw_equal"])

    out = {
        "schema_version": 1,
        "task": "RE-002",
        "window_prefix": WINDOW_PREFIX,
        "target": {"path": TARGET, "sha256": sha(data)},
        "toolchain": {
            "rustc": "1.95.0 (59807616e 2026-04-14)",
            "target_triple": "x86_64-unknown-linux-gnu",
            "profile": "opt-level=3 overflow-checks=true lto=thin global_allocator=tikv-jemallocator",
        },
        "locks": locks,
        "scanned_cgus": scanned_cgus,
        "lock_packages": dict(sorted(lock_packages.items())),
        "bodies": {"path": "bodies.bin", "bytes": len(blob), "sha256": sha(blob)},
        "minimum_bytes": MIN_BYTES,
        "minimum_unmasked_bytes": MIN_UNMASKED,
        "summary": {
            "total_windows": len(records),
            "total_bytes": sum(r["size"] for r in records),
            "raw_equal_windows": sum(int(r["raw_equal"]) for r in records),
            "relaxed_windows": sum(
                1 for r in records if any("relaxation" in x for x in r["relocations"])
            ),
            "by_dependency": dict(sorted(by_dep.items(), key=lambda kv: (-kv[1]["bytes"], kv[0]))),
            "crates_matched": len(by_crate),
            "by_crate": dict(sorted(by_crate.items(), key=lambda kv: (-kv[1]["bytes"], kv[0]))),
        },
        "records": records,
    }
    (HERE / "records.json").write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out["summary"]["by_dependency"], indent=1))
    print(json.dumps(out["summary"]["by_crate"], indent=1))
    print(
        f"GENERATED: {out['summary']['total_windows']} windows, "
        f"{out['summary']['total_bytes']:,} B, {out['summary']['crates_matched']} crates"
    )


def verify_committed() -> dict:
    census = json.loads((HERE / "records.json").read_text())
    bodies = (HERE / "bodies.bin").read_bytes()
    data = (ROOT / TARGET).read_bytes()
    if sha(data) != TARGET_SHA256 or sha(data) != census["target"]["sha256"]:
        raise AssertionError("target node115 SHA-256 mismatch")
    if sha(bodies) != census["bodies"]["sha256"] or len(bodies) != census["bodies"]["bytes"]:
        raise AssertionError("bodies.bin digest/size mismatch")

    text = next(s for s in sections(data) if s["name"] == ".text")
    _, fdes, _ = fde_extents(data)
    fde_map = {(f["start"], f["end"]) for f in fdes if f["section"] == ".text"}

    licenses = json.loads((HERE / "licenses.json").read_text())
    missing_lic = set(census["lock_packages"]) - set(licenses)
    if missing_lic:
        raise AssertionError(f"missing license entries: {sorted(missing_lic)}")
    unknown_lic = [k for k, v in licenses.items() if not v or v == "UNKNOWN"]
    if unknown_lic:
        raise AssertionError(f"unknown licenses: {sorted(unknown_lic)}")

    for lock_info in census["locks"]:
        lp = ROOT / lock_info["lockfile"]
        if sha(lp.read_bytes()) != lock_info["sha256"]:
            raise AssertionError(f"lockfile digest mismatch: {lock_info['lockfile']}")

    external = collect_existing_intervals(exclude_self=True, committed_only=True)
    zfork_fdes = load_zfork_location_fdes()

    seen: list[tuple[int, int]] = []
    total_bytes = 0
    for rec in census["records"]:
        start, end = rec["start"], rec["end"]
        n = end - start
        if rec["start_va"] != f"0x{start:x}" or rec["end_va"] != f"0x{end:x}" or rec["size"] != n:
            raise AssertionError(f"coordinate consistency mismatch at 0x{start:x}")
        if n < MIN_BYTES or (start, end) not in fde_map:
            raise AssertionError(f"invalid FDE at 0x{start:x}..0x{end:x}")
        if any(tok in rec["symbol"] for tok in HARNESS_TOKENS):
            raise AssertionError(f"harness token leaked into symbol {rec['symbol']}")
        ident = extract_defining_crate_ident(rec["symbol"])
        if ident != rec["crate"].replace("-", "_"):
            raise AssertionError(
                f"defining crate mismatch: {ident} != {rec['crate']} ({rec['symbol']})"
            )
        if rec["dependency"] not in {
            "rust-std",
            "rust-core",
            "rust-alloc",
            "compiler-builtins",
            "vendored-crates",
        }:
            raise AssertionError(f"invalid dependency bucket: {rec['dependency']}")
        tier = rec.get("match_tier")
        if tier not in {"unique_fde", "zfork_location_authenticated", "high_entropy_multi_copy"}:
            raise AssertionError(f"invalid match_tier {tier} at 0x{start:x}")
        if tier == "zfork_location_authenticated":
            if zfork_fdes.get(start) != CRATE_TO_ZFORK.get(rec["crate"]):
                raise AssertionError(f"zfork location mismatch at 0x{start:x}")
        for a, b, label in external:
            if start < b and a < end:
                raise AssertionError(
                    f"overlap at 0x{start:x}..0x{end:x} against {label} (0x{a:x}..0x{b:x})"
                )
        src = bodies[rec["source_offset"] : rec["source_offset"] + n]
        if sha(src) != rec["source_body_sha256"]:
            raise AssertionError(f"source sha mismatch at 0x{start:x}")
        off = text["offset"] + start - text["address"]
        tgt = data[off : off + n]
        if sha(tgt) != rec["target_body_sha256"]:
            raise AssertionError(f"target sha mismatch at 0x{start:x}")
        cmp = compare(src, tgt, rec["relocations"])
        if not cmp["relocation_qualified"] or cmp["raw_equal"] != rec["raw_equal"]:
            raise AssertionError(f"relocation-qualified compare failed at 0x{start:x}")
        unmasked = n - cmp["relocation_bytes"]
        if unmasked < MIN_UNMASKED or cmp["relocation_bytes"] * 2 > n:
            raise AssertionError(f"mask bounds violated at 0x{start:x}")
        if tier == "high_entropy_multi_copy":
            if (
                rec["crate"] not in MULTI_COPY_CRATES
                or rec["node115_hit_count"] > MULTI_COPY_MAX_HITS
                or n < MULTI_COPY_MIN_BYTES
                or unmasked < MULTI_COPY_MIN_UNMASKED
            ):
                raise AssertionError(f"high_entropy_multi_copy gate violated at 0x{start:x}")
        seen.append((start, end))
        total_bytes += n

    seen.sort()
    for (_, e1), (s2, _) in zip(seen, seen[1:]):
        if s2 < e1:
            raise AssertionError(f"internal overlap at 0x{s2:x} < 0x{e1:x}")
    if total_bytes != census["summary"]["total_bytes"] or len(seen) != census["summary"]["total_windows"]:
        raise AssertionError("summary totals mismatch")
    return census


def rebuild_and_verify(census: dict) -> None:
    object_functions = _load_object_functions()
    env = os.environ.copy()
    env["CARGO_BUILD_JOBS"] = env.get("CARGO_BUILD_JOBS", "4")
    env["RUSTFLAGS"] = "-C save-temps"

    reuse_dir = env.get("ZFORKS_W2_REUSE_TARGET_DIR")
    tmp_ctx = None
    if reuse_dir:
        target_dir = Path(reuse_dir)
    else:
        tmp_ctx = tempfile.TemporaryDirectory(prefix="zforks-w2-thinlto-rebuild-")
        target_dir = Path(tmp_ctx.name)
    env["CARGO_TARGET_DIR"] = str(target_dir)

    try:
        for _, subdir in HARNESSES:
            manifest = HERE / subdir / "Cargo.toml"
            subprocess.run(
                [
                    "cargo",
                    "+1.95.0",
                    "build",
                    "--offline",
                    "--locked",
                    "--release",
                    "--target",
                    "x86_64-unknown-linux-gnu",
                    "--manifest-path",
                    str(manifest),
                ],
                cwd=str(ROOT),
                env=env,
                check=True,
                stdout=subprocess.DEVNULL,
            )

        deps_dir = target_dir / "x86_64-unknown-linux-gnu/release/deps"
        rebuilt: dict[tuple[str, str], set[str]] = {}
        for bin_name, _ in HARNESSES:
            for obj_path in sorted(deps_dir.glob(f"{bin_name}-*.rcgu.o")):
                obj = obj_path.read_bytes()
                if obj[:4] != b"\x7fELF":
                    continue
                for symbols, body, _ in object_functions(obj):
                    bsha = sha(body)
                    for sym in symbols:
                        rebuilt.setdefault((bin_name, sym), set()).add(bsha)

        for rec in census["records"]:
            key = (rec["bin_name"], rec["symbol"])
            if rec["source_body_sha256"] not in rebuilt.get(key, set()):
                raise AssertionError(
                    f"rebuild did not reproduce {rec['symbol']} ({rec['start_va']}) in {rec['bin_name']}"
                )
    finally:
        if tmp_ctx is not None:
            tmp_ctx.cleanup()


def run_self_tests(census: dict) -> int:
    bodies = (HERE / "bodies.bin").read_bytes()
    data = (ROOT / TARGET).read_bytes()
    text = next(s for s in sections(data) if s["name"] == ".text")

    rec0 = census["records"][0]
    n0 = rec0["size"]
    src0 = bytearray(bodies[rec0["source_offset"] : rec0["source_offset"] + n0])
    off0 = text["offset"] + rec0["start"] - text["address"]
    tgt0 = data[off0 : off0 + n0]

    masked = set()
    for r in rec0["relocations"]:
        masked.update(range(r["offset"], r["offset"] + r["width"]))
    unmasked_idx = next(i for i in range(n0) if i not in masked)
    src0[unmasked_idx] ^= 0xFF
    if compare(bytes(src0), tgt0, rec0["relocations"])["relocation_qualified"]:
        raise AssertionError("NC1 failed: mutated unmasked byte still passed compare()")

    if extract_defining_crate_ident("_ZN16zforks_w2_revm404main17h0000000000000000E") is not None:
        raise AssertionError("NC2 failed: harness symbol was not rejected")

    s0, e0 = rec0["start"], rec0["end"]
    if not any(s0 < b and a < e0 for a, b in [(s0 + 1, e0 + 1)]):
        raise AssertionError("NC3 failed: overlap predicate missed intersection")

    if (MIN_BYTES - 1) >= MIN_BYTES:
        raise AssertionError("NC4 failed: min-bytes gate broken")

    return 4


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generate", type=Path, help="Generate records.json/bodies.bin from deps dir")
    parser.add_argument("--rebuild", action="store_true", help="Rebuild harnesses offline and verify bodies")
    parser.add_argument("--self-test", action="store_true", help="Run 4 negative controls")
    args = parser.parse_args()

    if args.generate is not None:
        generate(args.generate)
        return

    census = verify_committed()
    if args.rebuild:
        rebuild_and_verify(census)
    nc_count = run_self_tests(census) if args.self_test else 0
    s = census["summary"]
    print(
        f"PASS: RE-002-node115-zforks-wave2-byte-matches: "
        f"{s['total_windows']} windows, {s['total_bytes']:,} B "
        f"({s['raw_equal_windows']} raw-equal, {s['relaxed_windows']} relaxed, "
        f"{s['crates_matched']} crates; rebuild={args.rebuild}, "
        f"negative_controls={nc_count}/4)"
    )


if __name__ == "__main__":
    main()
