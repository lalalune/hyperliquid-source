#!/usr/bin/env python3
"""Deterministic generator for RE-004 panic-tagged-length-94.

Verifies node #94 digest/size first, then checks every recorded
instruction byte, every message byte, the tagged-length arithmetic
(raw == 2*true + 1, raw odd), the unwrap tag transform
(lea rsi,[rsi*2+1]), the decoder branch (test al,1 / shr rax,1),
and every chain GOT relocation by .rela.dyn entry index.
Writes only to --out.
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NODE = ROOT / "artifacts" / "node" / "94" / "hl-node"
NODE_SIZE = 91774280
NODE_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
RELA_OFF = 0x6BC0
RELA_LEN = 24


def fail(msg):
    print(f"panic_tagged_length: FAIL {msg}", file=sys.stderr)
    sys.exit(1)


def read_at(data, va, length, region):
    if region == "text":
        off = va - 0x1000
    elif region == "rodata":
        off = va
    else:
        raise AssertionError(region)
    return data[off:off + length], off


def call_target(va, call_off, disp):
    # call instruction at va+call_off is 6 bytes (ff 15 disp32) or 5 (e8 disp32)
    return va + call_off + 6 + disp if call_off is not None else None


# (name, thunk_va, msg_va, raw_len, true_len, message, got_slot, got_idx, hex)
THUNKS = [
    ("div", 0x157B440, 0x25D230, 51, 25,
     "attempt to divide by zero", 0x576E1B8, 72929,
     "554889e54889fa488d3de21dcefebe33000000ff153f2c1f04"),
    ("rem", 0x157B460, 0x25D249, 115, 57,
     "attempt to calculate the remainder with a divisor of zero",
     0x576E528, 73036,
     "554889e54889fa488d3ddb1dcefebe73000000ff151f2c1f04"),
    ("add", 0x157B480, 0x252CF8, 57, 28,
     "attempt to add with overflow", 0x576E118, 72909,
     "554889e54889fa488d3d6a78cdfebe39000000ff15ff2b1f04"),
    ("mul", 0x157B4A0, 0x252D14, 67, 33,
     "attempt to multiply with overflow", 0x576E1B0, 72928,
     "554889e54889fa488d3d6678cdfebe43000000ff15df2b1f04"),
    ("neg", 0x157B4C0, 0x252D35, 63, 31,
     "attempt to negate with overflow", 0x576EB38, 73221,
     "554889e54889fa488d3d6778cdfebe3f000000ff15bf2b1f04"),
    ("shl", 0x157B4E0, 0x252D54, 71, 35,
     "attempt to shift left with overflow", 0x576E478, 73015,
     "554889e54889fa488d3d6678cdfebe47000000ff159f2b1f04"),
    ("shr", 0x157B500, 0x252D77, 73, 36,
     "attempt to shift right with overflow", 0x576F128, 73398,
     "554889e54889fa488d3d6978cdfebe49000000ff157f2b1f04"),
    ("sub", 0x157B520, 0x252D9B, 67, 33,
     "attempt to subtract with overflow", 0x576E150, 72916,
     "554889e54889fa488d3d6d78cdfebe43000000ff155f2b1f04"),
    ("async", 0x157B540, 0x25D282, 71, 35,
     "`async fn` resumed after completion", 0x576F040, 73370,
     "554889e54889fa488d3d341dcefebe47000000ff153f2b1f04"),
]

# (name, va, length, hex, got_slot, got_idx) for non-thunk code segments
CODE = [
    ("helper-unwrap", 0x157A9F0, 25,
     "554889e54889fa488d3d3abccdfebe2b000000ff15ff361f04",
     0x576E470, 73014),
    ("helper-bounds", 0x157A6F0, 200,
     "554889e54883ec304839d7763b48897df8488955f0488d45f8488945d0488b051c431f04488945d8488d55f0488955e0488945e8488d3da7e5c7fe488d75d04889caff1560391f044839d677404839f7763b48897df8488975f0488d45f8488945d0488b05d7421f04488945d8488d55f0488955e0488945e8488d3daa28c7fe488d75d04889caff151b391f04488975f8488955f0488d45f8488945d0488b059c421f04488945d8488d55f0488955e0488945e8488d3d16bfc7fe488d75d04889caff15e0381f04",
     0x576E2E0, 72965),
    ("helper-pair", 0x157A9B0, 52,
     "554889e54883ec2048897df0488975f8488d45f0488945e0488d052157ffff488945e8488d3d73fac6fe488d75e0ff15b4361f04",
     0x576E468, 73013),
    ("adapter-panic", 0x157B810, 44,
     "554889e54883ec3048897df0488975f8488d45f0488945d8488955e066c745e80100488d7dd8ff15a44e1f04",
     0x576E098, 72894),
    ("adapter-tag", 0x157B7F0, 18,
     "554889e5488d347501000000ff1596281f04",
     0x576E108, 72907),
    ("adapter-copy", 0x4ECDCF0, 29,
     "554889e54883ec200f10070f1145e848897df8488d7de8ff15db938a00",
     0x57706E0, 74070),
    ("adapter-thunk2", 0x4EE9AE0, 9,
     "554889e5e8a7580000",
     0x57770E8, 77399),
    ("decoder", 0x4EEF390, 173,
     "554889e5534883ec28488b0f488b4108a801753648897df048b80000000000000080488945d8488b5708488b47100fb64810440fb64011488d35e2348600488d7dd8ff15808188000f0b488b0948d1e848894dd8488945e0488b5708488b47100fb64810440fb64011488d3578348600488d7dd8ff154e818800488b75d8488d0c75000000004885c975084889c7e8ed0c7700488b7de031d24889c3ff15deeb87004889d84889c7e8d30c7700",
     None, None),
    ("adapter-caller2", 0x157B690, 53,
     "554889e54883ec3048897dd8488975e0488d45d8488945e848894df0c645f8008855f9488d7de8ff1523501f040f0bff15fb3a1f04",
     0x57706E0, 74070),
]

# (got_slot, got_idx, target) for every chain relocation
RELOCS = [
    (0x576E098, 72894, 0x157B810),
    (0x576E108, 72907, 0x157B7F0),
    (0x576E118, 72909, 0x157B480),
    (0x576E150, 72916, 0x157B520),
    (0x576E1B0, 72928, 0x157B4A0),
    (0x576E1B8, 72929, 0x157B440),
    (0x576E2E0, 72965, 0x157A6F0),
    (0x576E468, 73013, 0x157A9B0),
    (0x576E470, 73014, 0x157A9F0),
    (0x576E478, 73015, 0x157B4E0),
    (0x576E528, 73036, 0x157B460),
    (0x576EB38, 73221, 0x157B4C0),
    (0x576F040, 73370, 0x157B540),
    (0x576F128, 73398, 0x157B500),
    (0x57706E0, 74070, 0x4ECDCF0),
    (0x57770E8, 77399, 0x4EE9AE0),
    (0x5777558, 77450, 0x4EEF596),
]

# (got_slot, helper, thunk, site_count, entries) routing #179's 35 sites
ROUTES = [
    (0x576E118, "thunk-add", "add", 9, "2,19x3,21x3,23,25"),
    (0x576E150, "thunk-sub", "sub", 9, "11,18,20x3,22x4"),
    (0x576E1B0, "thunk-mul", "mul", 1, "1"),
    (0x576E2E0, "helper-bounds", "-", 2, "3,24"),
    (0x576E468, "helper-pair", "-", 1, "0"),
    (0x576E470, "helper-unwrap", "-", 13, "continuation 4-17"),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    data = NODE.read_bytes()
    if len(data) != NODE_SIZE:
        fail(f"node size {len(data)} != {NODE_SIZE}")
    if hashlib.sha256(data).hexdigest() != NODE_SHA256:
        fail("node digest mismatch")

    segments = []

    def add_segment(name, va, length, region):
        chunk, off = read_at(data, va, length, region)
        segments.append({
            "id": name, "start": va, "end": va + length, "length": length,
            "file_offset": off, "sha256": hashlib.sha256(chunk).hexdigest(),
            "kind": "claim",
        })
        return chunk

    # --- thunks: bytes + lea/msg + mov esi + call target + tagged arithmetic
    thunk_rows = []
    for name, va, msg_va, raw, true, msg, got, gidx, hx in THUNKS:
        chunk, _ = read_at(data, va, 25, "text")
        if chunk.hex() != hx:
            fail(f"thunk {name} bytes mismatch")
        lea_disp = struct.unpack("<i", chunk[10:14])[0]
        if va + 14 + lea_disp != msg_va:
            fail(f"thunk {name} lea does not resolve to msg")
        if chunk[14] != 0xBE or struct.unpack("<I", chunk[15:19])[0] != raw:
            fail(f"thunk {name} mov esi != raw")
        call_disp = struct.unpack("<i", chunk[21:25])[0]
        if va + 25 + call_disp != 0x576E098:
            fail(f"thunk {name} call does not target 0x576e098")
        if raw % 2 != 1 or (raw - 1) // 2 != true:
            fail(f"thunk {name} tagged arithmetic fails")
        mchunk, _ = read_at(data, msg_va, true, "rodata")
        if mchunk.decode() != msg:
            fail(f"thunk {name} message mismatch")
        add_segment(f"thunk-{name}", va, 25, "text")
        add_segment(f"msg-{name}", msg_va, true, "rodata")
        thunk_rows.append((name, va, msg_va, raw, true, msg, got, gidx))

    # --- helpers / adapters: bytes + key structural checks
    for name, va, length, hx, got, gidx in CODE:
        chunk, _ = read_at(data, va, length, "text")
        if chunk.hex() != hx:
            fail(f"{name} bytes mismatch")
        add_segment(name, va, length, "text")
    # unwrap message + raw length (tagged downstream by adapter-tag)
    mchunk, _ = read_at(data, 0x256638, 43, "rodata")
    if mchunk.decode() != "called `Option::unwrap()` on a `None` value":
        fail("unwrap message mismatch")
    add_segment("msg-unwrap", 0x256638, 43, "rodata")
    # unwrap helper structure: lea -> 0x256638, mov esi 43, call -> 0x576e108
    uw = read_at(data, 0x157A9F0, 25, "text")[0]
    if 0x157A9F0 + 14 + struct.unpack("<i", uw[10:14])[0] != 0x256638:
        fail("unwrap lea mismatch")
    if struct.unpack("<I", uw[15:19])[0] != 43:
        fail("unwrap mov esi != 43")
    if 0x157A9F0 + 25 + struct.unpack("<i", uw[21:25])[0] != 0x576E108:
        fail("unwrap call mismatch")
    # tagger: lea rsi,[rsi*2+1] then call -> 0x576e098
    tg = read_at(data, 0x157B7F0, 18, "text")[0]
    if tg[4:12] != bytes.fromhex("488d347501000000"):
        fail("tagger transform missing")
    if 0x157B7F0 + 18 + struct.unpack("<i", tg[14:18])[0] != 0x576E098:
        fail("tagger call mismatch")
    # panic adapter: WORD 1 at [rbp-0x18], call -> 0x57706e0
    pa = read_at(data, 0x157B810, 44, "text")[0]
    if "66c745e80100" not in pa.hex():
        fail("panic adapter WORD 1 missing")
    if 0x157B810 + 44 + struct.unpack("<i", pa[40:44])[0] != 0x57706E0:
        fail("panic adapter call mismatch")
    # copy adapter: call -> 0x57770e8
    cp = read_at(data, 0x4ECDCF0, 29, "text")[0]
    if 0x4ECDCF0 + 29 + struct.unpack("<i", cp[25:29])[0] != 0x57770E8:
        fail("copy adapter call mismatch")
    # thunk2: direct E8 call -> 0x4eef390
    t2 = read_at(data, 0x4EE9AE0, 9, "text")[0]
    if t2[4] != 0xE8 or 0x4EE9AE0 + 9 + struct.unpack("<i", t2[5:9])[0] != 0x4EEF390:
        fail("thunk2 call mismatch")
    # decoder: test al,1 at +0x10, shr rax,1 at +0x4d
    dc = read_at(data, 0x4EEF390, 173, "text")[0]
    if dc[0x10:0x12] != bytes.fromhex("a801"):
        fail("decoder test al,1 missing")
    if dc[0x4D:0x50] != bytes.fromhex("48d1e8"):
        fail("decoder shr rax,1 missing")
    # caller2: call -> 0x57706e0
    c2 = read_at(data, 0x157B690, 53, "text")[0]
    if 0x157B690 + 45 + struct.unpack("<i", c2[41:45])[0] != 0x57706E0:
        fail("caller2 call mismatch")

    # --- relocations by index
    for slot, idx, target in RELOCS:
        off_b, info, add = struct.unpack_from("<QQq", data, RELA_OFF + idx * RELA_LEN)
        if off_b != slot or (add & 0xFFFFFFFFFFFFFFFF) != target:
            fail(f"reloc idx {idx} slot/target mismatch")

    # --- routes sum
    if sum(r[3] for r in ROUTES) != 35:
        fail("route site count != 35")

    code_bytes = sum(s["length"] for s in segments if s["id"] not in
                      [f"msg-{n}" for n, *_ in THUNKS] and s["id"] != "msg-unwrap")
    msg_bytes = sum(s["length"] for s in segments if s["id"].startswith("msg-"))
    evidence = {
        "node": {"digest": NODE_SHA256, "size": NODE_SIZE, "id": 94},
        "thunks": [
            {"name": n, "thunk": hex(va), "msg": hex(mva), "raw": raw,
             "true": true, "message": msg, "got": hex(got), "got_idx": gidx}
            for n, va, mva, raw, true, msg, got, gidx in thunk_rows
        ],
        "chain": [
            {"hop": "thunk->panic", "via_got": "0x576e098", "idx": 72894,
             "to": "0x157b810"},
            {"hop": "unwrap->tag", "via_got": "0x576e108", "idx": 72907,
             "to": "0x157b7f0"},
            {"hop": "tag->panic", "via_got": "0x576e098", "idx": 72894,
             "to": "0x157b810"},
            {"hop": "bounds/pair->panic", "via_got": "0x576e098", "idx": 72894,
             "to": "0x157b810"},
            {"hop": "panic->copy", "via_got": "0x57706e0", "idx": 74070,
             "to": "0x4ecdcf0"},
            {"hop": "caller2->copy", "via_got": "0x57706e0", "idx": 74070,
             "to": "0x4ecdcf0"},
            {"hop": "copy->thunk2", "via_got": "0x57770e8", "idx": 77399,
             "to": "0x4ee9ae0"},
            {"hop": "thunk2->decoder", "via": "direct E8", "to": "0x4eef390"},
            {"hop": "decoder->next", "via_got": "0x5777558", "idx": 77450,
             "to": "0x4eef596"},
        ],
        "routes": [
            {"got": hex(g), "helper": h, "thunk": t, "sites": c, "entries": e}
            for g, h, t, c, e in ROUTES
        ],
        "decode": {
            "branch": "test al,1 at decoder+0x10; jne to decoder+0x4a",
            "odd_path": "shr rax,1 at decoder+0x4d; out.len = tagged>>1",
            "even_path": "sentinel 0x8000000000000000; different table 0x57528b0",
            "odd_table": "0x5752878",
        },
        "counts": {
            "thunks": 9, "helpers": 3, "adapters": 5, "decoder": 1,
            "segments": len(segments), "claim_bytes": code_bytes + msg_bytes,
            "code_bytes": code_bytes, "message_bytes": msg_bytes,
            "routes_sites": 35,
        },
    }
    (out / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    with open(out / "thunks.tsv", "w") as fh:
        fh.write("name\tthunk_va\tmsg_va\traw_len\ttrue_len\tmessage\tgot_slot\tgot_idx\n")
        for n, va, mva, raw, true, msg, got, gidx in thunk_rows:
            fh.write(f"{n}\t{hex(va)}\t{hex(mva)}\t{raw}\t{true}\t{msg}\t{hex(got)}\t{gidx}\n")
    with open(out / "chain.tsv", "w") as fh:
        fh.write("hop\tvia\tidx\tto\n")
        for row in evidence["chain"]:
            fh.write(f"{row['hop']}\t{row.get('via_got', row.get('via'))}\t"
                     f"{row.get('idx', '-')}\t{row['to']}\n")
    with open(out / "routes.tsv", "w") as fh:
        fh.write("got_slot\thelper\tthunk\tsites\tentries\n")
        for g, h, t, c, e in ROUTES:
            fh.write(f"{hex(g)}\t{h}\t{t}\t{c}\t{e}\n")
    with open(out / "segments.txt", "w") as fh:
        for s in segments:
            fh.write(f"{s['id']}\t{hex(s['start'])}\t{hex(s['end'])}\t"
                     f"{s['length']}\t{hex(s['file_offset'])}\t{s['sha256']}\t"
                     f"{s['kind']}\n")
    print(f"panic_tagged_length: OK ({len(segments)} segments)")


if __name__ == "__main__":
    main()
