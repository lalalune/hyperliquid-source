#!/usr/bin/env python3
"""Generate records.json for the RE-001-default-name-115 packet.

Run from the repository root:
    python3 research/work-items/RE-001-default-name-115/gen_records.py

Reads the node #115 binary (digest-bound) and the packet's own
callers.tsv, and writes semantic records only: the global object,
the initializer, the eleven consumer sites with the test each
applies and its outcome, the shared helpers, the literals, the
relocations, and the census counts. No per-instruction mnemonic
list is emitted anywhere in this packet: instruction-level detail
lives only in the verbatim excerpt text files.
"""

import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

sys.dont_write_bytecode = True
sys.path.insert(0, str(PACKET))
from export_excerpts import WINDOWS  # noqa: E402


def run(cmd, cwd=ROOT):
    return subprocess.run(cmd, capture_output=True, text=True,
                          check=True, cwd=cwd).stdout


def load_sections():
    sections = []
    for line in run(["readelf", "-S", "-W", str(BINARY)]).splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+"
                     r"([0-9a-f]+)\s+([0-9a-f]+)", line)
        if m:
            sections.append((m.group(1), int(m.group(2), 16),
                             int(m.group(3), 16), int(m.group(4), 16)))
    return sections


SECTIONS = load_sections()
_BINARY_DATA = BINARY.read_bytes()


def read_vaddr(addr, n):
    for _name, vaddr, off, size in SECTIONS:
        if vaddr <= addr < vaddr + size:
            start = off + (addr - vaddr)
            return _BINARY_DATA[start: start + n]
    raise ValueError("address %#x not in any section" % addr)


def read_cstr(addr):
    out = bytearray()
    cur = addr
    while True:
        b = read_vaddr(cur, 1)[0]
        if b == 0:
            return bytes(out)
        out.append(b)
        cur += 1


def reloc_at(addr):
    dyn = run(["readelf", "-r", "-W", str(BINARY)])
    for line in dyn.splitlines():
        m = re.match(r"\s*([0-9a-f]{16})\s+[0-9a-f]{16}\s+"
                     r"(R_X86_64_\S+)\s+(.*)$", line)
        if m and int(m.group(1), 16) == addr:
            return {"offset": "%#x" % addr, "type": m.group(2),
                    "symbol": m.group(3).strip()}
    return None


def main():
    assert hashlib.sha256(_BINARY_DATA).hexdigest() == DIGEST
    records = {
        "artifact": {
            "path": "artifacts/node/115/hl-node",
            "sha256": DIGEST,
        },
        "bounded_question": (
            "What is node #115's global default name, how is it "
            "constructed at startup, and what does every consumer "
            "site do with it: the static initializer 0x61d2970, the "
            "global std::string at 0x6508980, and all eleven sites "
            "that load it across the Find/create/release family?"),
        "global": {
            "address": "0x6508980",
            "section": ".bss",
            "type": "std::string (libstdc++ SSO, 32 bytes)",
            "text": "nullptr",
            "length": 7,
            "buffer_address": "0x6508990",
            "buffer": "nullptr\\0",
        },
        "initializer": {
            "address": "0x61d2970",
            "fde": "0x61d2970..0x61d29af",
            "bytes": 63,
            "init_array": {
                "base": "0x63f36c8",
                "entries": 168,
                "slot": 141,
                "slot_address": "0x63f3b30",
            },
            "stores": [
                {"offset": "+0x10", "value": "0x6c6c756e",
                 "note": "bytes 'null'"},
                {"offset": "+0x00", "value": "0x6508990",
                 "note": "_M_p = &local buffer"},
                {"offset": "+0x13", "value": "0x7274706c",
                 "note": "bytes 'lptr', overlapping the last 'l'"},
                {"offset": "+0x08", "value": "7",
                 "note": "_M_length"},
                {"offset": "+0x17", "value": "0",
                 "note": "NUL terminator"},
            ],
            "atexit": {
                "func_got": "0x64ed5d8",
                "func": "~basic_string@GLIBCXX_3.4.21",
                "arg": "0x6508980",
                "dso_handle": "0x64efa20",
            },
        },
        "routines": {},
        "consumer_sites": [
            {
                "site": "0x6077907",
                "routine": "create_host",
                "test": "default length (7) vs name length; memcmp",
                "match_outcome": "release the holder, Status 0",
                "nonmatch_outcome": "registry Find path",
                "note": "length 0 builds a fresh StatisticsImpl; "
                        "length 15 with bytes 'BasicStatistics' "
                        "also builds fresh",
            },
            {
                "site": "0x607e8e0",
                "routine": "resolver_host",
                "test": "delegate's first field is null",
                "match_outcome": "assign the default name, Status 0",
                "nonmatch_outcome": "resolver 0x60971c0 path",
                "note": "the +0x04 flag set instead clears the "
                        "output name",
            },
            {
                "site": "0x6086c84",
                "routine": "twin_a",
                "test": "record name length, then memcmp vs default",
                "match_outcome": "return 1, nothing assigned",
                "nonmatch_outcome": "assign the candidate name, "
                                    "return 0",
                "note": "kind-0x15/0x16 tail only; the record comes "
                        "from map_find_name",
            },
            {
                "site": "0x60a7534",
                "routine": "twin_b",
                "test": "record name length, then memcmp vs default",
                "match_outcome": "return 1, nothing assigned",
                "nonmatch_outcome": "assign the candidate name, "
                                    "return 0",
                "note": "byte-identical instantiation of twin_a",
            },
            {
                "site": "0x60bf710",
                "routine": "matcher_wrapper",
                "test": "string_equal(candidate, default)",
                "match_outcome": "return True",
                "nonmatch_outcome": "fall to the generic compare",
                "note": "kind 2 only",
            },
            {
                "site": "0x60bf730",
                "routine": "matcher_wrapper",
                "test": "default length vs candidate length, memcmp",
                "match_outcome": "return True",
                "nonmatch_outcome": "fall to the generic compare",
                "note": "kind 3 only",
            },
            {
                "site": "0x61372c8",
                "routine": "release_host",
                "test": "default length (7) vs name length; memcmp",
                "match_outcome": "clear the holder, Status 0",
                "nonmatch_outcome": "canonical-name check, then "
                                    "registry Find path",
                "note": "length 0 also clears; the canonical name "
                        "is 'rocksdb.BuiltinBloomFilter'",
            },
            {
                "site": "0x609e567",
                "routine": "find_entry",
                "test": "default length (7) vs name length; memcmp",
                "match_outcome": "clear the name string and the "
                                 "map, Status 0",
                "nonmatch_outcome": "normal Find path",
                "note": "length 0 clears without the memcmp",
            },
            {
                "site": "0x609a45e",
                "routine": "find_norm",
                "test": "default length (7) vs name length; memcmp",
                "match_outcome": "assign the fallback name",
                "nonmatch_outcome": "search the name for '='",
                "note": "length 0 also assigns the fallback",
            },
            {
                "site": "0x60bbc99",
                "routine": "matcher",
                "test": "record +0xb1 flag bit 0 set, or +0x04 "
                        "byte clear",
                "match_outcome": "assign the default name",
                "nonmatch_outcome": "the other branch",
                "note": "assigns the global itself as the source",
            },
        ],
        "helpers": {
            "string_equal": {
                "address": "0x5e4bcf0",
                "contract": "lengths equal and (length 0 or "
                            "memcmp equal)",
            },
            "map_find_name": {
                "address": "0x5d66e30",
                "linear_limit": 20,
                "hash_seed": "0xc70f6907",
                "contract": "unordered_map find by key: linear "
                            "walk at <= 20 entries, hash bucket "
                            "walk above",
            },
            "kind_validator": {
                "address": "0x60bf980",
                "jump_table": "0x978718",
                "kind_count": 25,
                "contract": "kind dispatch over the descriptor's "
                            "+0xac word; returns a boolean the "
                            "twins consume as a gate",
            },
            "canonical_name": {
                "address": "0x6130140",
                "literal": "0x44481b",
                "text": "rocksdb.BuiltinBloomFilter",
                "length": 26,
            },
        },
        "twins": {
            "entries": ["0x6086b70", "0x60a7420"],
            "identical": False,
            "holder_offsets": {"0x6086b70": "0x630",
                               "0x60a7420": "0x90"},
            "difference": "one template instantiated twice: the "
                          "instruction streams are identical except "
                          "the holder-map field offset (0x630 in A, "
                          "0x90 in B); verify.py checks the "
                          "normalized streams differ only in those "
                          "two loads",
            "vtable_slots": [
                {"slot": "0x64d3210", "vtable": "0x64d31b0",
                 "index": 12, "target": "0x6086b70"},
                {"slot": "0x64d3690", "vtable": "0x64d3630",
                 "index": 12, "target": "0x60a7420"},
                {"slot": "0x64d3710", "vtable": "0x64d36b0",
                 "index": 12, "target": "0x60a7420"},
            ],
            "note": "slot index 12 is offset 0x60, the virtual "
                    "call the kind validator makes at 0x60bfa2a; "
                    "both twins are reached by indirect dispatch, "
                    "with no direct call sites in the census",
        },
        "literals": {
            "0x4376fd": read_cstr(0x4376FD).decode("latin1"),
            "0x433f9f": read_cstr(0x433F9F).decode("latin1"),
            "0x44481b": read_cstr(0x44481B).decode("latin1"),
        },
        "constants": {
            "control_counts": "0x100000001",
            "basic_statistics": "BasicStatistics",
            "basic_statistics_len": 15,
            "reset_message_len": 20,
        },
        "relocations": {},
        "census": {"rows": 0, "counts": {}},
    }
    for name, start, stop in WINDOWS:
        records["routines"]["%#x" % start] = {
            "name": name[:-4],
            "fde": "%#x..%#x" % (start, stop),
            "bytes": stop - start,
        }
    for addr in (0x63F3B30, 0x64ED5D8, 0x64D3210, 0x64D3690, 0x64D3710,
                 0x64ED028, 0x64ED290, 0x64ED818, 0x64ED820, 0x64ED828,
                 0x64EFA20):
        records["relocations"]["%#x" % addr] = reloc_at(addr)
    rows = (PACKET / "callers.tsv").read_text().splitlines()[1:]
    records["census"]["rows"] = len(rows)
    counts = {}
    for line in rows:
        parts = line.split("\t")
        key = "%s:%s" % (parts[1], parts[3].strip())
        counts[key] = counts.get(key, 0) + 1
    records["census"]["counts"] = counts
    (PACKET / "records.json").write_text(
        json.dumps(records, indent=1) + "\n")
    print("wrote records.json (%d consumer sites, %d census rows)"
          % (len(records["consumer_sites"]), len(rows)))


if __name__ == "__main__":
    main()
