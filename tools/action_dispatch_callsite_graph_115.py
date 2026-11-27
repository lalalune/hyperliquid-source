#!/usr/bin/env python3
"""Verify direct-call site relationships around the node #115 Action decoder/router."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402

TASK = ROOT / "research/work-items/action-dispatch-callsite-graph-115"
TARGET = ROOT / "artifacts/node/115/hl-node"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
FOCAL = {
    "action_decoder": 0x2B817D0,
    "action_router": 0x2BDA7C0,
    "action_envelope": 0x20F00B0,
    "nested_action_parser": 0x2109050,
}
EXPECTED = {
    0x2B817D0: (0x20F06D3, 0x20F0A29),
    0x2BDA7C0: (0x2704C0C, 0x2704C54, 0x2C69574, 0x2C69744, 0x2C719C3),
    0x20F00B0: (0x2109697, 0x2109E11),
    0x2109050: (0x2B83AF5, 0x2BD5A97),
}
CALLS_FILE = TASK / "call-sites.tsv"
SUMMARY_FILE = TASK / "summary.json"
FIELDS = (
    "target_name", "target_va", "call_site_va", "call_site_file_offset",
    "caller_fde_start", "caller_fde_end", "instruction_hex",
)


class EvidenceError(ValueError):
    pass


def direct_calls(binary: bytes) -> dict[int, list[tuple[int, bytes]]]:
    """Find E8 rel32 references to the focal addresses in the executable .text."""
    digest = hashlib.sha256(binary).hexdigest()
    if digest != DIGEST:
        raise EvidenceError(f"target digest mismatch: {digest}")
    text = next((section for section in sections(binary) if section["name"] == ".text"), None)
    if text is None:
        raise EvidenceError("missing .text section")
    data = binary[text["offset"]:text["offset"] + text["size"]]
    found: dict[int, list[tuple[int, bytes]]] = {address: [] for address in FOCAL.values()}
    for offset, opcode in enumerate(data[:-4]):
        if opcode != 0xE8:
            continue
        site = text["address"] + offset
        target = site + 5 + struct.unpack_from("<i", data, offset + 1)[0]
        if target in found:
            found[target].append((site, data[offset:offset + 5]))
    return found


def verify_direct_call(raw: bytes, site: int, expected_target: int) -> None:
    if len(raw) != 5 or raw[0] != 0xE8:
        raise EvidenceError(f"expected E8 rel32 at {site:#x}")
    actual = site + 5 + struct.unpack_from("<i", raw, 1)[0]
    if actual != expected_target:
        raise EvidenceError(f"call target mismatch at {site:#x}: {actual:#x} != {expected_target:#x}")


def build_rows(binary: bytes) -> tuple[list[dict[str, str]], dict[str, object]]:
    found = direct_calls(binary)
    _, fdes, _ = fde_extents(binary)
    # Site lookup uses indexed FDE ranges, not assumed function symbols.
    rows: list[dict[str, str]] = []
    sites_by_target: dict[int, list[int]] = {}
    fde_groups: dict[int, set[tuple[int, int]]] = {}
    text = next(section for section in sections(binary) if section["name"] == ".text")
    for name, target in FOCAL.items():
        actual = tuple(site for site, _ in found[target])
        if actual != EXPECTED[target]:
            raise EvidenceError(
                f"direct-call census changed for {name}: "
                f"{[hex(x) for x in actual]} != {[hex(x) for x in EXPECTED[target]]}"
            )
        sites_by_target[target] = list(actual)
        for site, raw in found[target]:
            fde = next((item for item in fdes if item["start"] <= site < item["end"]), None)
            if fde is None:
                raise EvidenceError(f"call site {site:#x} is outside an indexed FDE")
            # Confirm the byte-level target independently of the scan expression.
            verify_direct_call(raw, site, target)
            rows.append({
                "target_name": name,
                "target_va": f"0x{target:x}",
                "call_site_va": f"0x{site:x}",
                "call_site_file_offset": f"0x{text['offset'] + site - text['address']:x}",
                "caller_fde_start": f"0x{fde['start']:x}",
                "caller_fde_end": f"0x{fde['end']:x}",
                "instruction_hex": raw.hex(),
            })
            fde_groups.setdefault(target, set()).add((fde["start"], fde["end"]))
    rows.sort(key=lambda row: (int(row["target_va"], 16), int(row["call_site_va"], 16)))
    decoder_fdes = fde_groups[FOCAL["action_decoder"]]
    router_fdes = fde_groups[FOCAL["action_router"]]
    summary = {
        "target_sha256": DIGEST,
        "direct_call_encoding_scanned": "x86-64 E8 rel32 in .text",
        "direct_call_site_counts": {name: len(sites_by_target[target]) for name, target in FOCAL.items()},
        "direct_call_sites": {name: [f"0x{site:x}" for site in sites_by_target[target]] for name, target in FOCAL.items()},
        "decoder_caller_fdes": [f"0x{start:x}..0x{end:x}" for start, end in sorted(decoder_fdes)],
        "router_caller_fdes": [f"0x{start:x}..0x{end:x}" for start, end in sorted(router_fdes)],
        "decoder_router_shared_caller_fdes": [f"0x{start:x}..0x{end:x}" for start, end in sorted(decoder_fdes & router_fdes)],
        "statement_limit": "Direct-call/FDE crosswalk only; does not prove or disprove interprocedural object flow, indirect transfer, or runtime identity.",
    }
    return rows, summary


def write_outputs(binary: bytes, out_dir: Path = TASK) -> dict[str, object]:
    rows, summary = build_rows(binary)
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "call-sites.tsv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=TARGET)
    parser.add_argument("--out", type=Path, default=TASK)
    args = parser.parse_args()
    print(json.dumps(write_outputs(args.binary.read_bytes(), args.out), indent=2))


if __name__ == "__main__":
    main()
