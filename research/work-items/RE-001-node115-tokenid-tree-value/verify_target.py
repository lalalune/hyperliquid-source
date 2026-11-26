#!/usr/bin/env python3
"""Digest-first static replay of the node115 token-id vacant-insert tree branch.

Traces what the tree branch of the vacant-insert function 0x3f19f10 stores
beside the key: the token index, in both tree sub-paths, with the value-address
function 0x3f1a750 as an independent cross-check. Never executes the target.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

PACKET = Path(__file__).resolve().parent
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _at(window, base, va, n):
    i = va - base
    require(0 <= i and i + n <= len(window), "instruction outside excerpt")
    return window[i:i + n]


def _call_dest(window, base, va):
    call = _at(window, base, va, 5)
    require(call[0] == 0xe8, "direct call opcode")
    return va + 5 + struct.unpack_from("<i", call, 1)[0]


def facts(excerpts):
    """Check only the listed instructions, not a general x86 decoder."""
    w = {e["name"]: (bytes.fromhex(e["raw_hex"]), int(e["start"], 16))
         for e in excerpts}

    insert, base = w["insert_dispatch"]
    require(_at(insert, base, 0x3f19f1c, 4) == bytes.fromhex("48833e00"),
            "insert dispatch comparison")
    require(_at(insert, base, 0x3f19f20, 2) == bytes.fromhex("7438"),
            "insert dispatch branch")
    require(_at(insert, base, 0x3f19f22, 3) == bytes.fromhex("0f1006")
            and _at(insert, base, 0x3f19f25, 4) == bytes.fromhex("0f104e10")
            and _at(insert, base, 0x3f19f29, 4) == bytes.fromhex("0f105620"),
            "tree path 48-byte copy")
    require(_at(insert, base, 0x3f19f3c, 3) == bytes.fromhex("4889e7")
            and _at(insert, base, 0x3f19f3f, 5) == bytes.fromhex("488d742420"),
            "tree path call arguments")
    require(_call_dest(insert, base, 0x3f19f44) == 0x3706900, "tree insert call")
    require(_at(insert, base, 0x3f19f5a, 4) == bytes.fromhex("4c8b7608")
            and _at(insert, base, 0x3f19f5e, 4) == bytes.fromhex("4c8b7e10"),
            "flat path header and position")
    require(_at(insert, base, 0x3f19f62, 4) == bytes.fromhex("0f104618")
            and _at(insert, base, 0x3f19f66, 4) == bytes.fromhex("0f290424"),
            "flat entry key from position struct +0x18")
    require(_at(insert, base, 0x3f19f6a, 5) == bytes.fromhex("4889542410"),
            "flat entry value is incoming rdx")
    require(_at(insert, base, 0x3f19f6f, 3) == bytes.fromhex("4889e2")
            and _at(insert, base, 0x3f19f72, 3) == bytes.fromhex("4c89f7")
            and _at(insert, base, 0x3f19f75, 3) == bytes.fromhex("4c89fe"),
            "flat insert call arguments")
    require(_call_dest(insert, base, 0x3f19f78) == 0x454caa0, "flat insert call")
    require(_at(insert, base, 0x3f19f7d, 5) == bytes.fromhex("66490f6ec7")
            and _at(insert, base, 0x3f19f82, 2) == bytes.fromhex("31c0"),
            "flat result first and third fields")
    require(_at(insert, base, 0x3f19f84, 3) == bytes.fromhex("488903")
            and _at(insert, base, 0x3f19f87, 4) == bytes.fromhex("4c897308")
            and _at(insert, base, 0x3f19f8b, 5) == bytes.fromhex("f30f7f4310"),
            "insert 24-byte result tail")

    tree, base = w["tree_insert_entry_alloc"]
    require(_at(tree, base, 0x370690b, 3) == bytes.fromhex("4989d7"),
            "tree insert saves index in r15")
    require(_at(tree, base, 0x370690e, 3) == bytes.fromhex("4989f6"),
            "tree insert saves position struct in r14")
    require(_at(tree, base, 0x3706914, 5) == bytes.fromhex("48837e1800")
            and _at(tree, base, 0x3706919, 2) == bytes.fromhex("7451"),
            "tree root null check")
    require(_at(tree, base, 0x370691b, 4) == bytes.fromhex("498d4618"),
            "recursive path node field address")
    require(_at(tree, base, 0x3706930, 5) == bytes.fromhex("410f104608"),
            "recursive path key from position struct +0x08")
    require(_at(tree, base, 0x370694d, 3) == bytes.fromhex("4c89f9"),
            "recursive path carries index in rcx")
    require(_call_dest(tree, base, 0x3706953) == 0x34f9d60, "recursive insert call")
    require(_at(tree, base, 0x370696c, 3) == bytes.fromhex("4d8b26"),
            "new node owner load")
    require(_at(tree, base, 0x370696f, 5) == bytes.fromhex("bf18010000"),
            "new node size 0x118")
    slot = _at(tree, base, 0x3706974, 6)
    require(slot[:2] == bytes.fromhex("ff15")
            and 0x370697a + struct.unpack_from("<i", slot, 2)[0] == 0x64df480,
            "new node allocation slot")
    require(_at(tree, base, 0x370697f, 11) == bytes.fromhex("48c780b000000000000000"),
            "new node +0xb0 cleared")
    require(_at(tree, base, 0x370698a, 9) == bytes.fromhex("66c780120100000000"),
            "new node count at +0x112 cleared")
    require(_at(tree, base, 0x37069a0, 7) == bytes.fromhex("0fb78812010000"),
            "new node count read")
    require(_at(tree, base, 0x37069a7, 4) == bytes.fromhex("4883f90b")
            and _at(tree, base, 0x37069ab, 2) == bytes.fromhex("7358"),
            "new node 11-slot bound")
    require(_at(tree, base, 0x37069ad, 3) == bytes.fromhex("8d5101")
            and _at(tree, base, 0x37069b0, 7) == bytes.fromhex("66899012010000"),
            "new node count at +0x112 incremented")
    require(_at(tree, base, 0x37069b7, 2) == bytes.fromhex("89ca")
            and _at(tree, base, 0x37069b9, 3) == bytes.fromhex("c1e204"),
            "new node key slot scaled by 16")
    require(_at(tree, base, 0x37069cd, 2) == bytes.fromhex("31d2"),
            "new node result high bits cleared")
    require(_at(tree, base, 0x37069bc, 5) == bytes.fromhex("410f104608")
            and _at(tree, base, 0x37069c1, 4) == bytes.fromhex("0f110410"),
            "new node key at slot*16 from position struct +0x08")
    require(_at(tree, base, 0x37069c5, 8) == bytes.fromhex("4c89bcc8b8000000"),
            "new node value at 0xb8+slot*8 is the index")
    require(_at(tree, base, 0x37069cf, 5) == bytes.fromhex("49ff442410"),
            "tree owner count incremented")

    entry, base = w["recursive_entry_slot"]
    require(_at(entry, base, 0x34f9d71, 3) == bytes.fromhex("4989fc"),
            "recursive insert output saved")
    require(_at(entry, base, 0x34f9d74, 3) == bytes.fromhex("4c8b2e"),
            "recursive insert node load")
    require(_at(entry, base, 0x34f9d77, 8) == bytes.fromhex("410fb79d12010000"),
            "recursive insert count at +0x112")
    require(_at(entry, base, 0x34f9d7f, 4) == bytes.fromhex("4883fb0b")
            and _at(entry, base, 0x34f9d83, 2) == bytes.fromhex("7323"),
            "recursive insert 11-slot bound")
    require(_at(entry, base, 0x34f9d85, 4) == bytes.fromhex("488b4610"),
            "recursive insert slot load")
    require(_at(entry, base, 0x34f9d89, 4) == bytes.fromhex("488d6801"),
            "recursive insert next slot")
    require(_at(entry, base, 0x34f9d97, 3) == bytes.fromhex("4839dd")
            and _at(entry, base, 0x34f9d9a, 2) == bytes.fromhex("7642"),
            "recursive insert append branch")
    require(_at(entry, base, 0x34f9d8d, 3) == bytes.fromhex("4989c6")
            and _at(entry, base, 0x34f9d90, 4) == bytes.fromhex("49c1e604")
            and _at(entry, base, 0x34f9d94, 3) == bytes.fromhex("4d01ee"),
            "recursive insert key slot address")
    require(_at(entry, base, 0x34f9d9c, 3) == bytes.fromhex("0f1002")
            and _at(entry, base, 0x34f9d9f, 4) == bytes.fromhex("410f1106"),
            "recursive insert key at slot*16")
    require(_at(entry, base, 0x34f9da3, 5) == bytes.fromhex("e9ac000000"),
            "recursive insert append jumps to common store")

    store, base = w["recursive_value_store"]
    require(_at(store, base, 0x34f9e43, 4) == bytes.fromhex("488b0c24"),
            "recursive insert index restored")
    require(_at(store, base, 0x34f9e47, 3) == bytes.fromhex("4c89e0"),
            "recursive insert slot restored")
    require(_at(store, base, 0x34f9e54, 2) == bytes.fromhex("ffc3"),
            "recursive insert count incremented")
    require(_at(store, base, 0x34f9e56, 8) == bytes.fromhex("49898cc5b8000000"),
            "recursive insert value at 0xb8+slot*8 is the index")
    require(_at(store, base, 0x34f9e5e, 8) == bytes.fromhex("6641899d12010000"),
            "recursive insert count stored")

    addr, base = w["value_address"]
    require(_at(addr, base, 0x3f1a750, 3) == bytes.fromhex("488b07")
            and _at(addr, base, 0x3f1a753, 3) == bytes.fromhex("4885c0")
            and _at(addr, base, 0x3f1a756, 2) == bytes.fromhex("740f"),
            "value address tree test")
    require(_at(addr, base, 0x3f1a758, 4) == bytes.fromhex("488b4f10")
            and _at(addr, base, 0x3f1a75c, 4) == bytes.fromhex("488d04c8")
            and _at(addr, base, 0x3f1a760, 6) == bytes.fromhex("4805b8000000"),
            "value address tree form is node+0xb8+slot*8")
    require(_at(addr, base, 0x3f1a767, 4) == bytes.fromhex("488b4f08")
            and _at(addr, base, 0x3f1a76b, 4) == bytes.fromhex("488b4710")
            and _at(addr, base, 0x3f1a76f, 4) == bytes.fromhex("483b4118")
            and _at(addr, base, 0x3f1a773, 2) == bytes.fromhex("7324"),
            "value address flat bounds check")
    require(_at(addr, base, 0x3f1a775, 4) == bytes.fromhex("48034110")
            and _at(addr, base, 0x3f1a779, 3) == bytes.fromhex("488b11")
            and _at(addr, base, 0x3f1a77c, 2) == bytes.fromhex("31f6")
            and _at(addr, base, 0x3f1a77e, 3) == bytes.fromhex("4839d0")
            and _at(addr, base, 0x3f1a781, 4) == bytes.fromhex("480f43f2")
            and _at(addr, base, 0x3f1a785, 4) == bytes.fromhex("488b4908")
            and _at(addr, base, 0x3f1a789, 3) == bytes.fromhex("4829f0"),
            "value address flat ring index")
    require(_at(addr, base, 0x3f1a78c, 4) == bytes.fromhex("488d0440")
            and _at(addr, base, 0x3f1a790, 4) == bytes.fromhex("488d04c1")
            and _at(addr, base, 0x3f1a794, 4) == bytes.fromhex("4883c010"),
            "value address flat form is entry+0x10")

    vacant, base = w["lookup_vacant_id"]
    require(_at(vacant, base, 0x3cd3d3f, 2) == bytes.fromhex("31c0")
            and _at(vacant, base, 0x3cd3d41, 3) == bytes.fromhex("4889f2"),
            "vacant lookup result registers")
    require(_at(vacant, base, 0x3cd3d44, 4) == bytes.fromhex("410f1006"),
            "vacant lookup key load")
    require(_at(vacant, base, 0x3cd3d48, 5) == bytes.fromhex("4c8b5c2408")
            and _at(vacant, base, 0x3cd3d4d, 4) == bytes.fromhex("49894b08"),
            "vacant lookup output pointer and node field")
    require(_at(vacant, base, 0x3cd3d51, 5) == bytes.fromhex("410f114310"),
            "vacant lookup id at position struct +0x10")
    require(_at(vacant, base, 0x3cd3d56, 5) == bytes.fromhex("bf30000000")
            and _at(vacant, base, 0x3cd3d5b, 6) == bytes.fromhex("41b928000000")
            and _at(vacant, base, 0x3cd3d61, 6) == bytes.fromhex("41ba20000000")
            and _at(vacant, base, 0x3cd3d67, 2) == bytes.fromhex("31f6")
            and _at(vacant, base, 0x3cd3d69, 3) == bytes.fromhex("4531c0"),
            "vacant lookup remaining fields")
    require(_at(vacant, base, 0x3cd3d6c, 4) == bytes.fromhex("4b890413")
            and _at(vacant, base, 0x3cd3d70, 4) == bytes.fromhex("4b89340b")
            and _at(vacant, base, 0x3cd3d74, 4) == bytes.fromhex("4989143b")
            and _at(vacant, base, 0x3cd3d78, 3) == bytes.fromhex("4d8903"),
            "vacant lookup field stores")

    convert, base = w["lookup_convert_id"]
    require(_at(convert, base, 0x3cd3b94, 3) == bytes.fromhex("49391f"),
            "convert lookup container check")
    require(_at(convert, base, 0x3cd3b97, 6) == bytes.fromhex("0f84be000000"),
            "convert lookup container branch")
    require(_at(convert, base, 0x3cd3b9d, 4) == bytes.fromhex("4883f801")
            and _at(convert, base, 0x3cd3ba1, 2) == bytes.fromhex("7542"),
            "convert lookup one-entry condition")
    require(_at(convert, base, 0x3cd3ba3, 4) == bytes.fromhex("410f1006"),
            "convert lookup key load")
    require(_at(convert, base, 0x3cd3ba7, 5) == bytes.fromhex("4c8b5c2408"),
            "convert lookup output pointer")
    require(_at(convert, base, 0x3cd3bac, 5) == bytes.fromhex("410f114320"),
            "convert lookup id at position struct +0x20")
    require(_at(convert, base, 0x3cd3bb1, 8) == bytes.fromhex("49c7430800000000"),
            "convert lookup flat dispatch zero")
    require(_at(convert, base, 0x3cd3bb9, 4) == bytes.fromhex("4d897b10"),
            "convert lookup container field")
    require(_at(convert, base, 0x3cd3bbd, 5) == bytes.fromhex("bf18000000")
            and _at(convert, base, 0x3cd3bc2, 3) == bytes.fromhex("4531c0"),
            "convert lookup remaining fields")
    return {"insert": "0x3f19f10", "tree_insert": "0x3706900",
            "tree_insert_recursive": "0x34f9d60", "value_address": "0x3f1a750",
            "lookup": "0x3cd39b0",
            "tree_value": "incoming index at node+0xb8+slot*8",
            "tree_key": "16-byte id at node+slot*16",
            "flat_value": "incoming rdx at entry+0x10"}


def _check_fde(data, pins, name):
    pin = pins["fdes"][name]
    shoff = struct.unpack_from("<Q", data, 40)[0]
    ents, count, names = struct.unpack_from("<HHH", data, 58)
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * ents)
                for i in range(count)]
    namesec = sections[names]
    strings = data[namesec[4]:namesec[4] + namesec[5]]
    byname = {strings[s[0]:].split(b"\0", 1)[0].decode(): s for s in sections}

    def off(va):
        for s in sections:
            if s[1] != 8 and s[3] <= va < s[3] + s[5]:
                return s[4] + va - s[3]
        raise ValueError("unmapped ELF VA")

    h = byname[".eh_frame_hdr"]
    require(data[h[4]:h[4] + 4] == bytes([1, 0x1b, 3, 0x3b]), "unwind index encoding")
    n = struct.unpack_from("<I", data, h[4] + 8)[0]
    entries = [(h[3] + a, h[3] + b)
               for a, b in struct.iter_unpack("<ii", data[h[4] + 12:h[4] + 12 + 8 * n])]
    starts = [a for a, b in entries]
    require(starts == sorted(starts), "unsorted unwind index")
    target = int(pin["start"], 16)
    start, fde = entries[bisect.bisect_right(starts, target) - 1]
    require(start == target and fde == int(pin["fde_va"], 16),
            "unwind index entry for " + name)
    fo = off(fde)
    length, cie_delta = struct.unpack_from("<II", data, fo)
    co = fo + 4 - cie_delta
    clen = struct.unpack_from("<I", data, co)[0]
    require(data[fo:fo + 4 + length].hex() == pin["fde_record_hex"],
            "FDE record for " + name)
    require(data[co:co + 4 + clen].hex() == pin["cie_record_hex"],
            "CIE record for " + name)
    require(data[co + 8] == 1 and data[co + 9:co + 10] == b"z",
            "CIE version and augmentation for " + name)
    initial = fde + 8 + struct.unpack_from("<i", data, fo + 8)[0]
    extent = struct.unpack_from("<i", data, fo + 12)[0]
    require(initial == start and start + extent == int(pin["end"], 16),
            "decoded FDE extent for " + name)
    body = data[off(start):off(start) + extent]
    require(hashlib.sha256(body).hexdigest() == pin["body_sha256"],
            "body hash for " + name)


def verify(data, pins, with_objdump=False, elf=None):
    require(hashlib.sha256(data).hexdigest() == DIGEST, "target digest")
    require(len(data) == 105896032 and data[:6] == b"\x7fELF\x02\x01",
            "target ELF identity")
    for name in pins["fdes"]:
        _check_fde(data, pins, name)
    excerpts = pins["excerpts"]
    for e in excerpts:
        a, z = int(e["start"], 16), int(e["end"], 16)
        shoff = struct.unpack_from("<Q", data, 40)[0]
        ents, count, names = struct.unpack_from("<HHH", data, 58)
        sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * ents)
                    for i in range(count)]
        namesec = sections[names]
        strings = data[namesec[4]:namesec[4] + namesec[5]]
        byname = {strings[s[0]:].split(b"\0", 1)[0].decode(): s for s in sections}

        def off(va):
            for s in sections:
                if s[1] != 8 and s[3] <= va < s[3] + s[5]:
                    return s[4] + va - s[3]
            raise ValueError("unmapped ELF VA")

        window = data[off(a):off(z)]
        require(z - a <= 512 and window.hex() == e["raw_hex"],
                "retained excerpt " + e["name"])
    observed = facts(excerpts)
    if with_objdump:
        require(elf is not None, "objdump needs target path")
        total = 0
        for e in excerpts:
            a, z = int(e["start"], 16), int(e["end"], 16)
            window = bytes.fromhex(e["raw_hex"])
            command = ["objdump", "-d", "-M", "intel", "--insn-width=16",
                       f"--start-address={a}", f"--stop-address={z}", str(elf)]
            result = subprocess.run(command, check=True, capture_output=True,
                                    text=True, timeout=20)
            decoded = []
            for line in result.stdout.splitlines():
                m = re.match(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*(.*)$", line)
                if m:
                    va, raw = int(m[1], 16), bytes.fromhex(m[2])
                    require(va == a + sum(len(x[1]) for x in decoded),
                            "instruction continuity in " + e["name"])
                    require(raw == window[va - a:va - a + len(raw)],
                            "decoded instruction bytes in " + e["name"])
                    decoded.append((va, raw, m[3]))
            require(sum(len(x[1]) for x in decoded) == len(window),
                    "decoded excerpt extent in " + e["name"])
            total += len(decoded)
        observed["decoded_instructions"] = total
    return observed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--elf", type=Path, default=Path("artifacts/node/115/hl-node"))
    parser.add_argument("--with-objdump", action="store_true")
    args = parser.parse_args()
    pins = json.loads((PACKET / "discovery.json").read_text())
    print(json.dumps(verify(args.elf.read_bytes(), pins, args.with_objdump, args.elf),
                     sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
