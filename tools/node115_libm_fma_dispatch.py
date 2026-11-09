#!/usr/bin/env python3
"""Verify node #115's compiler_builtins libm FMA backend dispatch statically."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from elf_index import sections


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts/node/115/hl-node"
CENSUS = ROOT / "research/work-items/RE-002-node115-std-census/census.json"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_BYTES = 105_896_032

WINDOWS = {
    "full_availability_fma": (0x63F0210, 0x63F0221),
    "fma_fallback": (0x63F0230, 0x63F0679),
    "fma_initializer": (0x63F06A0, 0x63F0711),
    "load_x86_features": (0x63F0730, 0x63F08D9),
}
DISPATCH_SLOT = 0x64FFE00
INITIALIZED_FEATURE_BYTE = 0x6728920
FMA3_ENTRY = 0x63F0680
FMA4_ENTRY = 0x63F0690
FALLBACK_ENTRY = 0x63F0230


class EvidenceError(ValueError):
    pass


def _require(ok: bool, message: str) -> None:
    if not ok:
        raise EvidenceError(message)


def _read_va(data: bytes, address: int, size: int) -> bytes:
    matches = [s for s in sections(data)
               if s["type"] != 8 and s["address"] <= address
               and address + size <= s["address"] + s["size"]]
    _require(len(matches) == 1, f"VA {address:#x}+{size:#x} has no unique file mapping")
    s = matches[0]
    offset = s["offset"] + address - s["address"]
    return data[offset:offset + size]


def _rel32_target(data: bytes, address: int, opcode: bytes, length: int) -> int:
    ins = _read_va(data, address, length)
    _require(ins.startswith(opcode), f"unexpected opcode at {address:#x}")
    displacement = struct.unpack_from("<i", ins, length - 4)[0]
    return address + length + displacement


def _rel8_target(data: bytes, address: int, opcode: bytes) -> int:
    ins = _read_va(data, address, 2)
    _require(ins[:1] == opcode, f"unexpected short-branch opcode at {address:#x}")
    displacement = struct.unpack_from("<b", ins, 1)[0]
    return address + 2 + displacement


def _relocations(data: bytes) -> dict[int, tuple[int, int, int]]:
    sec = next((s for s in sections(data) if s["name"] == ".rela.dyn"), None)
    _require(sec is not None and sec["size"] % 24 == 0,
             "missing or malformed .rela.dyn")
    raw = data[sec["offset"]:sec["offset"] + sec["size"]]
    result: dict[int, tuple[int, int, int]] = {}
    for offset, info, addend in struct.iter_unpack("<QQq", raw):
        if offset in (0x64E0FD0, DISPATCH_SLOT):
            _require(offset not in result, f"duplicate relocation at {offset:#x}")
            result[offset] = (info >> 32, info & 0xFFFFFFFF, addend)
    return result


def _census_records() -> dict[str, dict]:
    records = json.loads(CENSUS.read_text(encoding="utf-8"))["records"]
    selected = {}
    for label, (start, end) in WINDOWS.items():
        hits = [r for r in records if r.get("start") == start and r.get("end") == end]
        _require(len(hits) == 1, f"std census does not uniquely bind {label}")
        selected[label] = hits[0]
    expected = {
        "full_availability_fma": "full_availability3fma",
        "fma_fallback": "fma12fma_fallback",
        "fma_initializer": "fma11initializer",
        "load_x86_features": "load_x86_features",
    }
    for label, needle in expected.items():
        _require(needle in selected[label]["symbol"],
                 f"std census symbol changed for {label}")
    return selected


def analyze(data: bytes) -> dict:
    _require(len(data) == TARGET_BYTES, f"wrong target size: {len(data)}")
    digest = hashlib.sha256(data).hexdigest()
    _require(digest == TARGET_SHA256, f"wrong target digest: {digest}")
    census = _census_records()
    bodies = {}
    for label, (start, end) in WINDOWS.items():
        body = _read_va(data, start, end - start)
        _require(hashlib.sha256(body).hexdigest() == census[label]["target_body_sha256"],
                 f"{label} bytes disagree with the pinned std census")
        bodies[label] = body

    table = _relocations(data)
    expected_relocations = {
        0x64E0FD0: (0, 8, 0x63F0210),
        DISPATCH_SLOT: (0, 8, 0x63F06A0),
    }
    _require(table == expected_relocations, "FMA dispatch relocations changed")

    wrapper_slot = _rel32_target(data, 0x63F0214, bytes.fromhex("488b05"), 7)
    initializer_cache = _rel32_target(data, 0x63F06A0, bytes.fromhex("8b05"), 6)
    _require(wrapper_slot == DISPATCH_SLOT, "FMA wrapper no longer loads dispatch slot")
    _require(initializer_cache == INITIALIZED_FEATURE_BYTE,
             "initializer no longer loads its feature byte")
    _require(_read_va(data, 0x63F021B, 2) == bytes.fromhex("ffd0"),
             "full_availability::fma no longer calls through the slot")

    cold_target = _rel8_target(data, 0x63F06A8, b"\x79")
    load_call = _rel32_target(data, 0x63F06EB, b"\xe8", 5)
    _require(cold_target == 0x63F06D4, "cold-cache branch changed")
    _require(load_call == WINDOWS["load_x86_features"][0],
             "initializer no longer calls load_x86_features")
    fma4_target = _rel32_target(data, 0x63F06B3, bytes.fromhex("488d15"), 7)
    fallback_target = _rel32_target(data, 0x63F06AC, bytes.fromhex("488d0d"), 7)
    fma3_target = _rel32_target(data, 0x63F06C0, bytes.fromhex("488d05"), 7)
    store_slot = _rel32_target(data, 0x63F06CB, bytes.fromhex("488905"), 7)
    _require((fma3_target, fma4_target, fallback_target, store_slot)
             == (FMA3_ENTRY, FMA4_ENTRY, FALLBACK_ENTRY, DISPATCH_SLOT),
             "initializer's selected implementation addresses changed")
    _require(_read_va(data, 0x63F06AA, 2) == bytes.fromhex("84c0"),
             "initializer's FMA4 feature-bit test changed")
    _require(_read_va(data, 0x63F06BE, 2) == bytes.fromhex("a840"),
             "initializer's FMA3 feature-bit test changed")
    _require(_read_va(data, 0x63F06BA, 4) == bytes.fromhex("480f49d1"),
             "FMA4/fallback conditional selection changed")
    _require(_read_va(data, 0x63F06C7, 4) == bytes.fromhex("480f44c2"),
             "FMA3 conditional selection changed")

    xgetbv_call = _rel32_target(data, 0x63F0839, b"\xe8", 5)
    _require(xgetbv_call == 0x63F0720, "feature loader's XGETBV helper call changed")
    _require(_read_va(data, 0x63F0722, 3) == bytes.fromhex("0f01d0"),
             "XCR0 helper no longer contains XGETBV")
    xsave_skip = _rel8_target(data, 0x63F082C, b"\x75")
    xcr0_skip = _rel8_target(data, 0x63F0845, b"\x75")
    _require((xsave_skip, xcr0_skip) == (0x63F0884, 0x63F087C),
             "XSAVE/XCR0 failure branches changed")
    _require(_read_va(data, 0x63F0824, 8) == bytes.fromhex("f7d1f7c10000000c"),
             "XSAVE/OSXSAVE presence gate changed")
    _require(_read_va(data, 0x63F0842, 3) == bytes.fromhex("f6c106"),
             "XCR0 XMM/YMM state mask changed")
    _require(_read_va(data, 0x63F0845, 2) == bytes.fromhex("7535"),
             "XCR0 XMM/YMM failure branch changed")
    _require(_read_va(data, 0x63F0849, 8) == bytes.fromhex("41c1ec064183e440"),
             "FMA3 output bit no longer derives from leaf 1 ECX bit 12")
    _require(_read_va(data, 0x63F07D5, 5) == bytes.fromhex("b801000080"),
             "extended feature query no longer selects leaf 0x80000001")
    _require(_read_va(data, 0x63F07E4, 10).startswith(bytes.fromhex("f7c10000010041")),
             "FMA4 feature test changed")
    _require(_read_va(data, 0x63F0894, 0x36) == bytes.fromhex(
        "4881f263414d444809ca741c4489f148ba4879676f6e47656e"
        "4831d34881f175696e654809d9750e89c181c9800000004584db0f44c1"),
             "vendor-gated FMA4 feature-bit write changed")

    fma3 = _read_va(data, FMA3_ENTRY, 6)
    fma4 = _read_va(data, FMA4_ENTRY, 7)
    _require(fma3 == bytes.fromhex("c4e2f1a9c2c3"), "FMA3 entry bytes changed")
    _require(fma4 == bytes.fromhex("c4e3f96bc210c3"), "FMA4 entry bytes changed")
    _require(bodies["fma_fallback"].startswith(bytes.fromhex("41574156")),
             "fallback FDE bytes changed")

    return {
        "schema_version": 1,
        "task": "RE-002",
        "target": {"path": "artifacts/node/115/hl-node", "bytes": len(data),
                   "sha256": TARGET_SHA256},
        "question": "How does node #115 choose its compiler_builtins libm fma backend?",
        "census": {
            label: {"range": f"{start:#x}..{end:#x}", "bytes": end - start,
                   "sha256": census[label]["target_body_sha256"],
                   "source_sha256": census[label]["source_body_sha256"],
                   "symbol": census[label]["symbol"]}
            for label, (start, end) in WINDOWS.items()
        },
        "dispatch": {
            "wrapper": "full_availability::fma loads and calls the function pointer at 0x64ffe00",
            "slot": f"{DISPATCH_SLOT:#x}",
            "slot_relocations": {f"{k:#x}": f"{v[2]:#x}" for k, v in table.items()},
            "cached_feature_byte": f"{INITIALIZED_FEATURE_BYTE:#x}",
            "initialized_marker": "bit 31",
            "features": {
                "fma3": {"bit": 6, "source": "CPUID leaf 1 ECX bit 12",
                         "xcr0_gate": "XSAVE and OSXSAVE bits 26/27; XCR0 bits 1/2",
                         "skip_targets": {"missing_xsave_or_osxsave": f"{xsave_skip:#x}",
                                          "missing_xmm_or_ymm_state": f"{xcr0_skip:#x}"}},
                "fma4": {"bit": 7, "source": "CPUID leaf 0x80000001 ECX bit 16",
                         "vendor_gate": ["AuthenticAMD", "HygonGenuine"],
                         "xcr0_gate": "none observed in this feature-byte path"},
            },
            "selected_entries": {
                "fma3": {"address": f"{FMA3_ENTRY:#x}", "bytes": fma3.hex(),
                         "instruction": "VFMADD213SD"},
                "fma4": {"address": f"{FMA4_ENTRY:#x}", "bytes": fma4.hex(),
                         "instruction": "VFMADDSD four-operand form"},
                "fallback": {"address": f"{FALLBACK_ENTRY:#x}",
                             "fde": "0x63f0230..0x63f0679"},
            },
            "priority": "FMA3 bit 6 selects first; otherwise FMA4 bit 7; otherwise fallback",
            "xcr0_implication": "This packet records the observed bit-7 path only; it does not assess OS-state safety or runtime consequences.",
        },
        "captured_code_executed": False,
        "component_gate_changed": False,
    }


def generate(output: Path | None = None) -> dict:
    report = analyze(TARGET.read_bytes())
    if output is not None:
        output.mkdir(parents=True, exist_ok=True)
        (output / "records.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    packet = ROOT / "research/work-items/RE-002-node115-libm-fma-dispatch"
    report = generate(packet if args.write else None)
    print(f"verified FMA3/FMA4 backend dispatch for #115 at {report['dispatch']['slot']}")
