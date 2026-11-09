#!/usr/bin/env python3
"""Bind const-hex's AVX2 decoder to the node #115 CPUID cache guard.

This is static evidence only. It authenticates the retained node capture,
checks the selected FDE identities against the dependency census, resolves the
cache/helper relocations, and proves the branch from A bit 15 to decode_avx2.
It does not execute the captured node or the reconstructed function.
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from elf_index import sections


ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts/node/115/hl-node"
VENDOR_CENSUS = ROOT / "research/work-items/RE-002-node115-vendor-census/census.json"
FIELD_MAP = ROOT / "research/work-items/RE-002-node115-cpuid-field-map/records.json"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_BYTES = 105_896_032

CALLER = (0x167A9C0, 0x167ABFB)
AVX2_BODY = (0x167AC00, 0x167AFCF)
CACHE_SLOT = 0x64DFA60
REFRESH_SLOT = 0x64DFA68
CACHE_WORD = 0x6500098
REFRESH_HELPER = 0x5CADD50
FEATURE_TEST = 0x167AAF7
FEATURE_BRANCH = 0x167AAFA
REFRESH_CALL = 0x167ABAD
POST_REFRESH_TEST = 0x167ABC3
POST_REFRESH_BRANCH = 0x167ABC6
AVX2_CALL = 0x167ABDB
AVX2_INSTRUCTION = 0x167AC11


class EvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def _read_va(data: bytes, address: int, size: int) -> bytes:
    matches = [
        section for section in sections(data)
        if section["type"] != 8
        and section["address"] <= address
        and address + size <= section["address"] + section["size"]
    ]
    _require(len(matches) == 1, f"VA {address:#x}+{size:#x} has no unique file mapping")
    section = matches[0]
    offset = section["offset"] + address - section["address"]
    return data[offset:offset + size]


def _relative_relocations(data: bytes) -> dict[int, int]:
    matches = [section for section in sections(data)
               if section["name"] == ".rela.dyn" and section["type"] == 4]
    _require(len(matches) == 1, "expected one .rela.dyn section")
    section = matches[0]
    _require(section["size"] % 24 == 0, ".rela.dyn has a partial ELF64 record")
    start = section["offset"]
    body = data[start:start + section["size"]]
    result: dict[int, int] = {}
    for offset, info, addend in struct.iter_unpack("<QQq", body):
        if offset not in (CACHE_SLOT, REFRESH_SLOT):
            continue
        _require(info >> 32 == 0 and (info & 0xFFFFFFFF) == 8,
                 f"unexpected relocation type at {offset:#x}")
        _require(offset not in result, f"duplicate relocation at {offset:#x}")
        result[offset] = addend
    _require(result == {CACHE_SLOT: CACHE_WORD, REFRESH_SLOT: REFRESH_HELPER},
             "cache/helper relative relocations changed")
    return result


def _rel32_target(data: bytes, site: int, opcode: bytes, length: int) -> int:
    instruction = _read_va(data, site, length)
    _require(instruction[:len(opcode)] == opcode,
             f"unexpected opcode at {site:#x}: {instruction.hex()}")
    displacement = struct.unpack_from("<i", instruction, len(opcode))[0]
    return site + length + displacement


def _packet_records() -> tuple[dict, dict]:
    census = json.loads(VENDOR_CENSUS.read_text(encoding="utf-8"))
    matching = [row for row in census["records"]
                if row.get("start") == AVX2_BODY[0]
                and row.get("end") == AVX2_BODY[1]
                and "decode_avx2" in row.get("symbol", "")]
    _require(len(matching) == 1, "vendor census no longer identifies the AVX2 FDE")
    caller = [row for row in census["records"]
              if row.get("start") == CALLER[0]
              and row.get("end") == CALLER[1]
              and row.get("crate") == "const-hex"]
    _require(len(caller) == 1, "vendor census no longer identifies the caller FDE")

    fields = json.loads(FIELD_MAP.read_text(encoding="utf-8"))
    a15 = [row for row in fields["field_map"]
           if row.get("word") == "A" and row.get("bit") == 15]
    _require(len(a15) == 1, "CPUID map must contain exactly one A bit 15 record")
    _require(a15[0].get("support") == ["cpuid leaf 7 subleaf 0 ebx bit 5"],
             "A bit 15 is no longer mapped to the expected CPUID support")
    _require("xcr0 bits 1,2" in a15[0].get("driver", ""),
             "A bit 15 no longer records the XCR0 gate")
    _require(fields.get("suffix", {}).get("cache_slot") == "0x64dfa60",
             "CPUID packet cache slot changed")
    _require("raw rax return = A" in fields.get("suffix", {}).get("equations", ""),
             "CPUID packet no longer binds the refresh result to word A")
    return matching[0], caller[0]


def analyze(data: bytes) -> dict:
    _require(len(data) == TARGET_BYTES, f"wrong target size: {len(data)}")
    target_hash = hashlib.sha256(data).hexdigest()
    _require(target_hash == TARGET_SHA256, f"wrong target digest: {target_hash}")

    vendor_avx2, vendor_caller = _packet_records()
    caller_bytes = _read_va(data, CALLER[0], CALLER[1] - CALLER[0])
    avx2_bytes = _read_va(data, AVX2_BODY[0], AVX2_BODY[1] - AVX2_BODY[0])
    _require(hashlib.sha256(caller_bytes).hexdigest() == vendor_caller["target_body_sha256"],
             "caller FDE bytes disagree with the dependency census")
    _require(hashlib.sha256(avx2_bytes).hexdigest() == vendor_avx2["target_body_sha256"],
             "AVX2 FDE bytes disagree with the dependency census")

    _relative_relocations(data)
    cache_load = _rel32_target(data, 0x167AAE4, bytes.fromhex("488b05"), 7)
    refresh_call = _rel32_target(data, REFRESH_CALL, bytes.fromhex("ff15"), 6)
    _require(cache_load == CACHE_SLOT, "caller no longer reads the mapped CPUID cache slot")
    _require(refresh_call == REFRESH_SLOT, "cache-miss path no longer calls the mapped helper slot")
    _require(_read_va(data, 0x167AAEB, 3) == bytes.fromhex("488b00"),
             "cache pointer is no longer dereferenced at the expected site")
    _require(_read_va(data, 0x167AAEE, 3) == bytes.fromhex("4885c0"),
             "cache-miss test changed")

    # TEST AX,AX sets SF to AX[15]. JS therefore reaches the AVX2 arm only
    # when the cached A word's bit 15 is set. The cold-cache path repeats the
    # same decision with JNS returning to the fallback when the bit is clear.
    _require(_read_va(data, FEATURE_TEST, 3) == bytes.fromhex("6685c0"),
             "A bit 15 test changed")
    js_target = _rel32_target(data, FEATURE_BRANCH, bytes.fromhex("0f88"), 6)
    _require(js_target == 0x167ABCC, "signed branch no longer reaches the AVX2 setup")
    _require(_read_va(data, POST_REFRESH_TEST, 3) == bytes.fromhex("6685c0"),
             "post-refresh A bit test changed")
    jns_target = _rel32_target(data, POST_REFRESH_BRANCH, bytes.fromhex("0f89"), 6)
    _require(jns_target == 0x167AB00, "clear-bit path no longer returns to the fallback")
    avx2_target = _rel32_target(data, AVX2_CALL, b"\xe8", 5)
    _require(avx2_target == AVX2_BODY[0], "gated direct call no longer targets decode_avx2")
    _require(_read_va(data, AVX2_INSTRUCTION, 9).startswith(bytes.fromhex("c4e27d7905")),
             "AVX2 FDE no longer starts with the pinned YMM broadcast")
    _require(bytes.fromhex("c5f877") in avx2_bytes,
             "AVX2 FDE no longer contains the retained VZEROUPPER sequence")

    return {
        "schema_version": 1,
        "target": {"path": "artifacts/node/115/hl-node", "bytes": TARGET_BYTES,
                   "sha256": TARGET_SHA256},
        "question": "Is the const-hex AVX2 decoder selected by the node #115 CPU-feature cache?",
        "caller_fde": {"range": f"{CALLER[0]:#x}..{CALLER[1]:#x}",
                        "bytes": len(caller_bytes),
                        "sha256": hashlib.sha256(caller_bytes).hexdigest(),
                        "vendor_census_symbol": vendor_caller["symbol"]},
        "avx2_fde": {"range": f"{AVX2_BODY[0]:#x}..{AVX2_BODY[1]:#x}",
                      "bytes": len(avx2_bytes),
                      "sha256": hashlib.sha256(avx2_bytes).hexdigest(),
                      "vendor_census_symbol": vendor_avx2["symbol"],
                      "crate": vendor_avx2["crate"],
                      "candidate_versions": vendor_avx2["candidate_versions"],
                      "candidate_source_body_sha256": vendor_avx2["source_body_sha256"]},
        "published_candidate": {
            "name": "const-hex", "version": "1.14.0",
            "archive_sha256": "4b0485bab839b018a8f1723fc5391819fea5f8f0f32288ef8a735fd096b6160c",
            "license": "MIT OR Apache-2.0",
            "source_behavior": "decode_unchecked checks has_avx2 and falls back to generic decode when false",
            "version_is_exact_for_target": False,
        },
        "cache": {"pointer_slot": f"{CACHE_SLOT:#x}", "word_address": f"{CACHE_WORD:#x}",
                  "refresh_pointer_slot": f"{REFRESH_SLOT:#x}",
                  "refresh_helper": f"{REFRESH_HELPER:#x}",
                  "relocations": {f"{CACHE_SLOT:#x}": f"{CACHE_WORD:#x}",
                                  f"{REFRESH_SLOT:#x}": f"{REFRESH_HELPER:#x}"}},
        "feature_path": {
            "cached_word": "A",
            "tested_bit": 15,
            "test_instruction": f"{FEATURE_TEST:#x}",
            "set_bit_branch": {"site": f"{FEATURE_BRANCH:#x}", "condition": "JS",
                               "target": f"{js_target:#x}"},
            "clear_bit_branch": {"site": f"{POST_REFRESH_BRANCH:#x}", "condition": "JNS",
                                 "target": f"{jns_target:#x}"},
            "gated_call": {"site": f"{AVX2_CALL:#x}", "target": f"{avx2_target:#x}"},
            "support": ["cpuid leaf 7 subleaf 0 ebx bit 5"],
            "xcr0_gate": "XCR0 bits 1 and 2, per the A bit 15 provenance record",
        },
        "claim": "The selected const-hex AVX2 decoder is reached only when cached A bit 15 is set; the mapped bit is CPUID leaf 7 subleaf 0 EBX bit 5 with the recorded XCR0 gate.",
        "global_target_cpu_features": "unresolved; this packet covers one dependency path, not every AVX/VEX/EVEX/BMI instruction",
        "captured_code_executed": False,
    }


def generate(target: Path = TARGET, output: Path | None = None) -> dict:
    report = analyze(target.read_bytes())
    if output is not None:
        output.mkdir(parents=True, exist_ok=True)
        (output / "records.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="regenerate records.json")
    args = parser.parse_args()
    out = ROOT / "research/work-items/RE-002-node115-const-hex-avx2-dispatch"
    report = generate(TARGET, out if args.write else None)
    print(f"verified {report['avx2_fde']['range']} AVX2 body behind A bit 15")
