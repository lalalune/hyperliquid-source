#!/usr/bin/env python3
"""Independent RE-012 verifier (no imports from tools/).

Re-derives hub→deser call bytes, FDE membership of pinned starts via a
fresh .eh_frame_hdr walk, and, for each JSON tag, every rodata occurrence
of its text that a RIP lea anchors (exactly or via a length byte) — then
requires the packet's (kind, occurrence, anchor) to be one of them. Only
lea targets count here; the tool also accepts RELATIVE relocation targets.
Verdict: PASS / FAIL / INCONCLUSIVE.
"""
from __future__ import annotations

import hashlib
import json
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "artifacts/node/94/hl-node"
JSON = HERE / "info-request-path.json"
BIN_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
OUT_SHA = "4edf26203f2a9f2ddd307b728d54aba77ac493a158462e40e331e4a494893baa"
HUB, DESER, SITE = 0x24AF210, 0x28C7C80, 0x24AFF82
GATE = 0x27E91D0
LEA_RE = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")


def verdict(status, evidence):
    print(status)
    for line in evidence:
        print(f"  {line}")
    return 0 if status == "PASS" else 1


def loads_and_sections(data):
    if data[:4] != b"\x7fELF":
        raise ValueError("not ELF")
    phoff = struct.unpack_from("<Q", data, 0x20)[0]
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from("<HHHHH", data, 0x36)
    loads = []
    for i in range(phnum):
        t, _, o, v, _, fs, _, _ = struct.unpack_from("<IIQQQQQQ", data, phoff + i * phentsize)
        if t == 1:
            loads.append((v, o, fs))
    secs_raw = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
    stro = secs_raw[shstrndx][4]
    secs = {}
    for s in secs_raw:
        name = data[stro + s[0]:data.index(b"\0", stro + s[0])].decode()
        secs[name] = (s[3], s[4], s[5])
    return loads, secs


def off(loads, va):
    for v, o, s in loads:
        if v <= va < v + s:
            return o + va - v
    return None


def fde_starts(data, loads, secs):
    addr, o, _ = secs[".eh_frame_hdr"]
    count = struct.unpack_from("<I", data, o + 8)[0]
    starts = []
    for i in range(count):
        pos = o + 12 + 8 * i
        pc = addr + struct.unpack_from("<i", data, pos)[0]
        starts.append(pc)
    return starts


def main():
    ev = []
    try:
        data = BIN.read_bytes()
        jbytes = JSON.read_bytes()
    except OSError as e:
        return verdict("INCONCLUSIVE", [f"read error: {e}"])
    if hashlib.sha256(data).hexdigest() != BIN_SHA:
        return verdict("FAIL", ["binary sha256 mismatch"])
    if hashlib.sha256(jbytes).hexdigest() != OUT_SHA:
        return verdict("FAIL", ["packet JSON sha256 mismatch"])
    d = json.loads(jbytes)
    loads, secs = loads_and_sections(data)
    starts = fde_starts(data, loads, secs)
    start_set = set(starts)
    ev.append(f"fde_count tool={d['fde_count']} indep={len(starts)}")
    if d["fde_count"] != len(starts):
        return verdict("FAIL", ev + ["fde_count diverge"])
    for pin, name in ((HUB, "hub"), (DESER, "deser"), (GATE, "gate")):
        ok = pin in start_set
        ev.append(f"{name} {pin:#x} is_fde_start={ok}")
        if not ok:
            return verdict("FAIL", ev)
    # hub call bytes
    o = off(loads, SITE)
    call = data[o:o + 5]
    dest = SITE + 5 + struct.unpack_from("<i", call, 1)[0]
    ev.append(f"call@{SITE:#x} bytes={call.hex()} dest={dest:#x}")
    if call != bytes.fromhex("e8f97c4100") or dest != DESER:
        return verdict("FAIL", ev + ["hub→deser call mismatch"])
    # tags: re-derive every .rodata occurrence of the text that a RIP lea
    # targets exactly, or through the length byte before it (len_prefix), and
    # require the packet's (kind, occurrence, anchor) to be one of them
    ro_va, ro_o, ro_sz = secs[".rodata"]
    ro = data[ro_o:ro_o + ro_sz]
    t_va, t_o, t_sz = secs[".text"]
    text = data[t_o:t_o + t_sz]
    lea_tgts = set()
    for m in LEA_RE.finditer(text):
        i = m.start()
        if i + 7 > len(text):
            continue
        lea_tgts.add(t_va + i + 7 + struct.unpack_from("<i", text, i + 3)[0])
    missing, mismatched = [], []
    for tag in d["tags"]:
        b = tag["text"].encode()
        found = set()
        for m in re.finditer(re.escape(b), ro):
            s = ro_va + m.start()
            if s in lea_tgts:
                found.add(("exact", s, s))
            elif m.start() > 0 and ro[m.start() - 1] == len(b) and s - 1 in lea_tgts:
                found.add(("len_prefix", s, s - 1))
        if not found:
            missing.append(tag["text"])
        elif (tag["kind"], int(tag["occurrence"], 16), int(tag["anchor"], 16)) not in found:
            mismatched.append(tag["text"])
    ev.append(f"tags_checked={len(d['tags'])} unanchored_indep={len(missing)} "
              f"packet_anchor_mismatch={len(mismatched)}")
    if missing:
        return verdict("FAIL", ev + [f"unanchored: {missing[:5]}"])
    if mismatched:
        return verdict("FAIL", ev + [f"packet anchor not re-derived: {mismatched[:5]}"])
    if d["tag_count"] != 56 or len(d["tags"]) != 56:
        return verdict("FAIL", ev + ["tag_count"])
    if d["hub"]["to_deserializer"]["to"] != "0x28c7c80":
        return verdict("FAIL", ev + ["json hub edge"])
    # snapshot template
    tpl = b"not writing snapshot to file because request was not from localhost"
    if ro.find(tpl) < 0:
        return verdict("FAIL", ev + ["template missing"])
    ev.append("snapshot template present in .rodata")
    if d["scoped_location_counts"] != {
        "info_server/src/abci_state_info_handler.rs": 17,
        "info_server/src/f_types/position.rs": 1,
        "info_server/src/handle_request.rs": 3,
        "info_server/src/handler.rs": 1,
        "info_server/src/request.rs": 2,
        "info_server/src/router.rs": 1,
        "info_server/src/user_ip.rs": 1,
    }:
        return verdict("FAIL", ev + ["scoped counts"])
    return verdict("PASS", ev)


if __name__ == "__main__":
    raise SystemExit(main())
