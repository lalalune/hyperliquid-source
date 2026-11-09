#!/usr/bin/env python3
"""Generate functions.tsv for this packet from the vendor census + the
binary, so no hash is hand-transcribed.

Body hashes are recomputed from work/hl-node-115.bin over the FDE
range; source hashes are recomputed by zeroing the census relocation
fields. The three 45-byte std::function managers have no census
record (like the forwarder stubs in the Bytewise/Reverse factories
packet #5950): only the body hash is recorded for them, with no
source hash claimed. The twelve kind-42 relocations of 0x61c1210
already carry opcode 0x8B in the target, so the gotpcrelx-mov-lea
opcode restoration is a no-op here (it is still applied
conditionally, only where the target byte is 0x8D).
"""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
BIN = ROOT / "artifacts" / "node" / "115" / "hl-node"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

# (start, end, name, slug, census-bound?)
FUNCS = [
    ("0x61c1210", "0x61c1a1a",
     "rocksdb::RegisterBuiltinComparators (call_once lambda)",
     "register_builtin_comparators115", True),
    ("0x61bd810", "0x61bd83d",
     "rocksdb::RegisterBuiltinComparators std::function manager (Bytewise)",
     "manager-bytewise115", False),
    ("0x61bd840", "0x61bd86d",
     "rocksdb::RegisterBuiltinComparators std::function manager (Reverse)",
     "manager-reverse115", False),
    ("0x61bd870", "0x61bd89d",
     "rocksdb::RegisterBuiltinComparators std::function manager (U64Ts)",
     "manager-u64ts115", False),
]


def va2off(va):
    out = subprocess.check_output(["readelf", "-lW", str(BIN)]).decode()
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            v, o, f = int(p[2], 16), int(p[1], 16), int(p[4], 16)
            if v <= va < v + f:
                return o + (va - v)
    raise ValueError(hex(va))


def main():
    data = open(BIN, "rb").read()
    assert hashlib.sha256(data).hexdigest() == DIGEST
    census = json.load(open(
        ROOT / "research" / "work-items" / "RE-002-node115-vendor-census"
        / "census.json"))["records"]
    by_start = {r["start"]: r for r in census}
    rows = []
    for start_s, end_s, name, slug, bound in FUNCS:
        start, end = int(start_s, 16), int(end_s, 16)
        body = data[va2off(start):va2off(end)]
        body_hash = hashlib.sha256(body).hexdigest()
        if bound:
            rec = by_start[start]
            assert body_hash == rec["target_body_sha256"], name
            zeroed = bytearray(body)
            for rel in rec["relocations"]:
                o, w = rel["offset"], rel["width"]
                zeroed[o:o + w] = b"\x00" * w
                if rel.get("relaxation") == "gotpcrelx-mov-lea":
                    assert zeroed[o - 2] == 0x8D
                    zeroed[o - 2] = 0x8B
            # The twelve kind-42 sites carry opcode 0x8B in the
            # target already, so no restoration applies to them.
            source_hash = hashlib.sha256(bytes(zeroed)).hexdigest()
            assert source_hash == rec["source_body_sha256"], name
            relocs = ";".join(
                f"{r['offset']}:kind{r['kind']}"
                + ("(mov-lea)" if r.get("relaxation") == "gotpcrelx-mov-lea"
                   else "")
                for r in rec["relocations"])
            rows.append({
                "name": name, "start": start_s, "end": end_s,
                "size": str(end - start), "body_sha256": body_hash,
                "source_sha256": source_hash,
                "raw_equal": str(rec["raw_equal"]),
                "relocations": relocs,
                "census_id": f"node115-vendor-{start_s[2:]}",
                "symbol": rec["symbol"], "excerpt": slug + ".objdump.txt",
                "hex": slug + ".hex",
            })
        else:
            # No census record: body hash only, no source hash claimed.
            assert by_start.get(start) is None, name
            rows.append({
                "name": name, "start": start_s, "end": end_s,
                "size": str(end - start), "body_sha256": body_hash,
                "source_sha256": "",
                "raw_equal": "n/a",
                "relocations": "0",
                "census_id": "none",
                "symbol": "", "excerpt": slug + ".objdump.txt",
                "hex": slug + ".hex",
            })
    with open(PACKET / "functions.tsv", "w") as fh:
        cols = ["name", "start", "end", "size", "body_sha256",
                "source_sha256", "raw_equal", "relocations", "census_id",
                "symbol", "excerpt", "hex"]
        fh.write("\t".join(cols) + "\n")
        for r in rows:
            fh.write("\t".join(r[c] for c in cols) + "\n")
    print(f"wrote functions.tsv ({len(rows)} functions, all hashes verified)")
    return rows


if __name__ == "__main__":
    main()
