#!/usr/bin/env python3
"""Extract the node 94 archive-value serializer path from authenticated ELF bytes.

This is a bounded static analysis. It does not execute, emulate, or disassemble
native code. Instruction claims use fixed encodings at reviewed addresses.
"""

import argparse
import csv
import hashlib
import itertools
import json
import mmap
from pathlib import Path
import struct
import sys

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = TOOLS.parent
BINARY = ROOT / "artifacts/node/94/hl-node"
DIGEST = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

# Reviewed FDEs, with exact .eh_frame ends and unmodified body digests.
FUNCTIONS = {
    0x1e749e0: (0x1e74acb, "f2e7d12e5e600b55889e9f7df80ba35a60ea61a7d1d4c403f9fdf96ceccc9388"),
    0x459c550: (0x459c6aa, "9dc7a0ae9ca81c630c75aa3e13a705592a9b3732ee4577d83af576934632ad16"),
    0x45a1200: (0x45a151f, "afccf49688209fa2b2da29af322d1bf4208d2711722b08f7bf91b9c94aeee3b6"),
    0x45951c0: (0x45954b0, "066461ea8d2c7cc47af405bf243dd906b17dee92a82d7c25097b90baa6ae3177"),
    0x46bfbe0: (0x46c0028, "59c67bc84b09d57a22b0e6df4e79654d07660acb1e19e15cfce6d1aa58783b21"),
    0x441f360: (0x441f6b4, "177b66f1c436e314a731c8023416fd7d1060facac89c4ed154beee2ccbf01f05"),
    0x4428950: (0x4428ce4, "fe84dc149287324899b980a6ab2da5b1752ea4cf37811cf37e7c92c4fefd157b"),
    0x4405e60: (0x44060eb, "fee6ac38f37fd9cd72dacae95d519a43d7864ab2ee4815ec00c0d49955d978e1"),
    0x4595c30: (0x4595d5b, "31643cf672ea6dbd9f543661e2c9b7b35c68f09049e12b5e70da5ea6eff32637"),
    0x4596e80: (0x459718c, "46a41e5fd443b56aa49d1c31ca24418b33c7e133747f26bc47fdf930550ec06d"),
    0x4597190: (0x45972cc, "8c42ca8b246477e525af5181189c8906b987d1afd34a791b5df00e706e997ffa"),
    0x4595d60: (0x4595f0e, "6885994efa40cc4518a533c789326bca70b035cb3f7ec887ec5e8133f6ca0c49"),
    0x45c7600: (0x45c7947, "85d1983562abe472f52863befcf659d0d377b0e0f48fa31fce256dd8a4e937c0"),
    0x4aead00: (0x4aeae0c, "af72af02df6e7f8b60020230d2a6e3f7c911f8de62de529e4f2a67313ea7e0a7"),
    0x4aea820: (0x4aeab9e, "e80d5dabcc8fe4cdc68b4305ba648fb401a4d324f3a74301ce0057c11b42c177"),
    0x466e210: (0x466e3e8, "d69ca238ec7d0e94135d188eea948e22e5df69630b3df6bf6255339ca012a581"),
    0x466e540: (0x466e577, "8f63d483ddac8ae8e1dfda95e3b7b1dfc480942e65e3a0845719e769753c5f7a"),
    0x47aeb30: (0x47aeb8c, "95d1969ea9602519f4122ef155f952426c3884dbc3fd4f733788737003076048"),
    0x47ad870: (0x47ad8db, "8be5fe4a6cfe423087d880fdc3f2f3fddc52772e40e9c999506cd2a7e90880e8"),
    0x47ad6f0: (0x47ad75b, "1e71574cc34ef57d2f4fea36e638737f9a96749683876fe83d3c22c7fcfa4ee1"),
    0x47ad800: (0x47ad86b, "9d7a79dac7a36c66a9ee16e6000b410001b93ac18ba4c9841efaabbac07517f1"),
    0x47ae5b0: (0x47ae61b, "98951d7d1ae0024acc97dd1f128e4284e7073ca34f42c510ebfa43865b9c3b01"),
    0x47ae3f0: (0x47ae44c, "57f2d447834e5d74cb970aa30e3dbe7261131656faf54f09eddc21a3b8e5a5fd"),
    0x47ae450: (0x47ae4ac, "19b766e62d93fcf968297eb73764ac794aa83a55d0dd2284d637a65d2d0cf7b0"),
    0x47af6e0: (0x47af73c, "14ff30886e615cdd04602fd0386415dcde1ac34c8a10a2c3341e3f79b9e052c2"),
    0x47af880: (0x47af8dc, "0b3022d4946085e4d68673caf2c1d2402c4320ae960b2fd118e4e0962e2abef0"),
    0x47ae220: (0x47ae353, "10e5b03217935510ce8cfc5af199dd40d57540ebba0f320ea37d5ad2805798f0"),
    0x47afa90: (0x47afae6, "fe3e9b8ec55ed7797f791f83a0064b557a321ecb35557d321c54cf76a580d217"),
    0x47ae6c0: (0x47ae716, "3c62e0299b5dd29885818621a4c4c1fc7dfd56aa6a6593e110d740f5af04081f"),
    0x47af530: (0x47af643, "37c08af1e30f3f3dfbd503b3a2e7fb3c15555fbb385b9269e1f055eaff4be7aa"),
    0x486b570: (0x486b86e, "a4c68ac6a65bca0b428c3e0fcd7b2937764cde80407ffb1beb56636eeebbf7b3"),
    0x43cb4a0: (0x43cba70, "885eafb00b9769a0bc6e202e636a9a5a94d1b8549dee843a72358d857a0013e7"),
    0x45a0d20: (0x45a0f1e, "cc0e43201643b253400da7e8df3ae43ce8658871e7501c8574997c8dfaa88e6c"),
    0x4c064e0: (0x4c067d7, "4bc3317e7933396d02e2b0aae5ddb792d235afe66e276b6b6bda07d98822b07d"),
    0x4670350: (0x4670565, "223fa0660c9ab7481b2736504d54f29053b78d02a63756e4cc1a834bac4d0b65"),
}

# Conditions are part of the claim: checking only a destination would accept,
# for example, a corrupted JNE changed to JE with the same displacement.
BRANCH_OPCODES = {
    0x459c560:"73", 0x459c601:"75", 0x45a1225:"74", 0x45a1275:"75",
    0x45a128f:"0f85", 0x45a12b0:"0f85", 0x45a12ce:"0f85", 0x45a12ea:"0f85",
    0x45a12f5:"75", 0x45a130f:"0f85", 0x45a132b:"0f85", 0x45a1336:"75",
    0x45a1350:"0f85", 0x45a136c:"75", 0x45a1373:"74", 0x45a138d:"0f85",
    0x45a139d:"74", 0x45a1452:"74", 0x45a146a:"75", 0x45a1471:"74",
    0x45a148b:"0f85", 0x45a1499:"75", 0x45a14eb:"0f85", 0x45951e5:"74",
    0x45952dc:"0f85", 0x459531c:"0f85", 0x45953b5:"0f85", 0x45953fa:"0f85",
    0x459542c:"75", 0x4595496:"75", 0x46bfc2d:"74", 0x46bfcaa:"0f85",
    0x46bff0e:"0f85", 0x46bfefa:"74", 0x46bff1f:"75", 0x46bff4a:"74",
    0x46bff69:"74", 0x46bff8b:"75", 0x46bffb5:"75", 0x1e749eb:"0f87",
    0x466e298:"0f85", 0x466e2a2:"0f85", 0x466e2c6:"0f85", 0x466e2d0:"0f85",
    0x466e2f4:"0f85", 0x466e2fe:"75", 0x466e31e:"75", 0x466e335:"75",
    0x440605b:"0f85", 0x441f466:"0f85", 0x4428a66:"0f85", 0x43cb518:"0f85",
    0x43cb563:"0f85", 0x43cb5fa:"75",
    0x45a0d44:"74", 0x45a0db2:"75", 0x45a0db9:"74", 0x45a0dd3:"75",
    0x45a0ddf:"75", 0x45a0e42:"75", 0x4c064fb:"74", 0x4c0657a:"0f85",
    0x4c065e4:"0f85", 0x4c0660e:"0f85", 0x4c0667d:"75", 0x4c06698:"75",
    0x4c066b9:"75", 0x4c066df:"75",
    # Container headers and every selected header-field result.
    0x45a123f:"74", 0x45a126e:"75",
    0x45951ff:"74", 0x459522e:"75", 0x459524f:"0f85",
    0x4595274:"74", 0x4595298:"75", 0x45952b9:"0f85",
    0x4595301:"0f85", 0x4595341:"0f85", 0x4595370:"0f85",
    0x4595396:"0f85", 0x45953db:"0f85", 0x4595420:"75",
    0x46bfc42:"74", 0x46bfc70:"75", 0x46bfc91:"0f85",
    0x46bfccf:"0f85", 0x46bfd0d:"0f85", 0x46bfd4e:"0f85",
    0x46bfd8f:"0f85", 0x46bfce8:"0f85", 0x46bfd29:"0f85",
    0x46bfd6a:"0f85", 0x46bfdab:"0f85", 0x46bfdd3:"0f85",
    0x46bfdef:"0f85", 0x46bfe17:"0f85", 0x46bfe33:"0f85",
    0x46bfe4f:"0f85", 0x46bfe6b:"0f85", 0x46bfe87:"0f85",
    0x46bfeac:"0f85", 0x46bfed4:"0f85", 0x46bfef0:"0f85",
    0x46bff3c:"0f85", 0x46bff5b:"0f85", 0x46bff7a:"0f85",
    0x46bffa8:"75", 0x46bffd5:"75", 0x45a0d5e:"74", 0x45a0d8d:"75",
    0x4c06518:"74", 0x4c06554:"75",
    0x1e74a11:"0f85", 0x1e74a3b:"75", 0x1e74a53:"75",
    0x1e74a85:"75", 0x1e74ab7:"74",
}


def hx(value):
    return f"0x{value:x}"


class Image:
    def __init__(self, data, expected_digest=DIGEST):
        # Check identity before any ELF parsing.
        self.data = data
        if hashlib.sha256(data).hexdigest() != expected_digest:
            raise ValueError("node 94 SHA-256 mismatch")
        self.sections = sections(data)
        _, index = unwind_index(data)
        _, fdes = eh_frame_records(data, self.sections)
        self.index = {entry["start"]: entry for entry in index}
        self.fdes = {entry["start"]: entry for entry in fdes}
        if len(self.index) != len(index) or len(self.fdes) != len(fdes):
            raise ValueError("duplicate unwind start")

    def offset(self, va, size=1, executable=False):
        if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
            raise ValueError("invalid VA or length")
        candidates = [s for s in self.sections
                      if s["type"] != 8 and (not executable or s["flags"] & 4)
                      and s["address"] <= va and va + size <= s["address"] + s["size"]]
        if len(candidates) != 1:
            raise ValueError("VA range does not have one file-backed section")
        sec = candidates[0]
        off = sec["offset"] + va - sec["address"]
        if off + size > len(self.data):
            raise ValueError("VA range outside file")
        return off

    def read(self, va, size, executable=False):
        off = self.offset(va, size, executable)
        return bytes(self.data[off:off + size])

    def check_function(self, start):
        expected_end, expected_hash = FUNCTIONS[start]
        frame = self.fdes.get(start)
        index = self.index.get(start)
        if frame is None or index is None or frame["fde"] != index["fde"]:
            raise ValueError(f"unindexed or missing FDE at {start:#x}")
        if frame["end"] != expected_end:
            raise ValueError(f"unexpected FDE extent at {start:#x}")
        code = self.read(start, expected_end - start, executable=True)
        actual = hashlib.sha256(code).hexdigest()
        if actual != expected_hash:
            raise ValueError(f"body digest mismatch at {start:#x}")
        return {"start": hx(start), "end_exclusive": hx(expected_end),
                "file_offset": hx(self.offset(start, len(code), executable=True)),
                "fde": hx(frame["fde"]), "bytes": len(code), "sha256": actual}


class Extract:
    def __init__(self, image):
        self.image = image
        self.anchors = []
        self.edges = []
        self.branches = []

    def pin(self, va, expected, label):
        expected = bytes.fromhex(expected)
        got = self.image.read(va, len(expected))
        if got != expected:
            raise ValueError(f"unexpected {label} bytes at {va:#x}")
        self.anchors.append({"site": hx(va), "file_offset": hx(self.image.offset(va, len(got))),
                             "bytes": got.hex(), "label": label})
        return got

    def call(self, va, target, label, opcode=0xe8):
        raw = self.image.read(va, 5, executable=True)
        if raw[0] != opcode:
            raise ValueError(f"unexpected transfer at {va:#x}")
        actual = va + 5 + struct.unpack_from("<i", raw, 1)[0]
        if actual != target:
            raise ValueError(f"transfer target mismatch at {va:#x}")
        self.edges.append({"site": hx(va), "target": hx(actual), "opcode": raw[:1].hex(),
                           "file_offset": hx(self.image.offset(va, len(raw), executable=True)),
                           "bytes": raw.hex(), "label": label})
        return actual

    def branch(self, va, target, label):
        b = self.image.read(va, 2, executable=True)
        expected = bytes.fromhex(BRANCH_OPCODES[va])
        if not b.startswith(expected):
            raise ValueError(f"branch condition mismatch at {va:#x}")
        if 0x70 <= b[0] <= 0x7f:
            raw = b
            displacement = struct.unpack_from("<b", raw, 1)[0]
        elif b[0] == 0x0f and 0x80 <= b[1] <= 0x8f:
            raw = self.image.read(va, 6, executable=True)
            displacement = struct.unpack_from("<i", raw, 2)[0]
        else:
            raise ValueError(f"unsupported conditional branch at {va:#x}")
        dest = va + len(raw) + displacement
        if dest != target:
            raise ValueError(f"branch target mismatch at {va:#x}")
        self.branches.append({"site": hx(va), "destination": hx(dest),
                              "file_offset": hx(self.image.offset(va, len(raw), executable=True)),
                              "bytes": raw.hex(), "label": label})
        return dest

    def rip(self, va, prefixes):
        raw = self.image.read(va, 7, executable=True)
        if raw[:3] not in prefixes:
            raise ValueError(f"unexpected RIP-relative instruction at {va:#x}")
        return va + 7 + struct.unpack_from("<i", raw, 3)[0]

    def name(self, lea, length_site):
        target = self.rip(lea, (b"\x48\x8d\x35", b"\x48\x8d\x15"))
        mov = self.image.read(length_site, 5, executable=True)
        if mov[0] not in (0xb9, 0xba):
            raise ValueError(f"unexpected name length instruction at {length_site:#x}")
        count = struct.unpack_from("<I", mov, 1)[0]
        if not 1 <= count <= 32:
            raise ValueError("invalid field-name length")
        name = self.image.read(target, count).decode("ascii")
        return {"name": name, "name_va": hx(target), "name_file_offset": hx(self.image.offset(target, count)),
                "name_length": count, "name_lea": hx(lea),
                "name_lea_bytes": self.image.read(lea, 7, executable=True).hex(),
                "length_instruction": hx(length_site), "length_bytes": mov.hex()}

    def source(self, va):
        raw = self.image.read(va, 7, executable=True)
        # Only these reviewed address-formation encodings are accepted.
        if raw[:3] in (b"\x49\x8d\xb6", b"\x49\x8d\x96", b"\x4d\x8d\x86",
                        b"\x49\x81\xc6", b"\x49\x81\xc7", b"\x49\x8d\x97",
                        b"\x49\x8b\x8f", b"\x48\x8d\x8b", b"\x48\x81\xc3"):
            size, value = 7, struct.unpack_from("<i", raw, 3)[0]
        elif raw[:3] in (b"\x49\x8d\x76", b"\x49\x8d\x56", b"\x4d\x8d\x46"):
            size, value = 4, struct.unpack_from("<b", raw, 3)[0]
        elif raw[:3] == b"\x4c\x89\xf2":
            size, value = 3, 0
        else:
            raise ValueError(f"unexpected field offset instruction at {va:#x}")
        self.anchors.append({"site": hx(va), "file_offset": hx(self.image.offset(va, size, executable=True)),
                             "bytes": raw[:size].hex(), "label": "field source operand"})
        return value


def field(ex, name_site, length_site, source_site, call_site, call_target, *, gate="always"):
    row = ex.name(name_site, length_site)
    row.update({"source_offset": hx(ex.source(source_site)), "source_instruction": hx(source_site),
                "value_call": hx(call_site), "value_target": hx(ex.call(call_site, call_target, row["name"])),
                "gate": gate})
    return row


def selector(image, ex):
    range_code = ex.pin(0x1e749e3, "4883c2fb4883fa15", "field length range")
    ex.branch(0x1e749eb, 0x1e74ab9, "length outside selected jump table")
    base = ex.rip(0x1e749f1, (b"\x48\x8d\x0d",))
    ex.pin(0x1e749f8, "486314914801caffe2", "signed relative table dispatch")
    first_length = -struct.unpack("<b", range_code[3:4])[0]
    count = range_code[7] + 1
    raw = image.read(base, count * 4)
    entries = [base + v[0] for v in struct.iter_unpack("<i", raw)]
    expected = {5: 0x1e74a01, 8: 0x1e74a46, 10: 0x1e74a20,
                21: 0x1e74a5e, 26: 0x1e74a90}
    for length, dest in enumerate(entries, start=first_length):
        if dest != expected.get(length, 0x1e74ab9):
            raise ValueError("classifier table target changed")
    block = ex.pin(0x1e74a01, "b9626c6f63", "five-byte classifier prefix")[1:]
    block += ex.pin(0x1e74a0c, "83f26b", "five-byte classifier suffix")[-1:]
    receipts = ex.pin(0x1e74a46, "48b97265636569707473", "eight-byte classifier")[2:]
    system = ex.pin(0x1e74a20, "48b973797374656d5f74", "ten-byte classifier prefix")[2:]
    system += ex.pin(0x1e74a31, "4881f278730000", "ten-byte classifier suffix")[3:5]
    ex.pin(0x1e74a5e, "f30f6f06f30f6f4e05", "21-byte classifier loads")
    ex.pin(0x1e74a90, "f30f6f06f30f6f4e0a", "26-byte classifier loads")
    def simd_name(first_site, second_site, shift):
        def address(va):
            b = image.read(va, 8, executable=True)
            if b[:4] not in (b"\x66\x0f\x74\x05", b"\x66\x0f\x74\x0d"):
                raise ValueError("unexpected vector comparison")
            return va + 8 + struct.unpack_from("<i", b, 4)[0]
        first, second = image.read(address(first_site), 16), image.read(address(second_site), 16)
        if first[shift:] != second[:16-shift]:
            raise ValueError("overlapping classifier constants disagree")
        return first + second[16-shift:]
    read_calls = simd_name(0x1e74a6f, 0x1e74a67, 5)
    highest = simd_name(0x1e74aa1, 0x1e74a99, 10)
    for at, pin_bytes, label in [
        (0x1e74a06,"330e0fb6560483f26b09ca","five-byte equality operation"),
        (0x1e74a2a,"48330e0fb756084881f2787300004809ca","ten-byte equality operation"),
        (0x1e74a50,"48390e","eight-byte equality operation"),
        (0x1e74a77,"660fdbc1660fd7c881f9ffff0000","21-byte vector equality reduction"),
        (0x1e74aa9,"660fdbc1660fd7c881f9ffff0000","26-byte vector equality reduction"),
    ]:
        ex.pin(at,pin_bytes,label)
    for at, dest, label in [
        (0x1e74a11,0x1e74ab9,"five-byte name mismatch"),
        (0x1e74a3b,0x1e74ab9,"ten-byte name mismatch"),
        (0x1e74a53,0x1e74ab9,"eight-byte name mismatch"),
        (0x1e74a85,0x1e74ab9,"21-byte name mismatch"),
        (0x1e74ab7,0x1e74ac2,"26-byte name match"),
    ]:
        ex.branch(at,dest,label)
    # Return tags are pinned independently of the name data.
    tag0 = ex.pin(0x1e74a17, "31c9884801c60009c3", "return tag 0")
    tag1 = ex.pin(0x1e74a55, "b101884801c60009c3", "return tag 1")
    tag2 = ex.pin(0x1e74a3d, "b102884801c60009c3", "return tag 2")
    tag3 = ex.pin(0x1e74a87, "b103884801c60009c3", "return tag 3")
    tag4 = ex.pin(0x1e74ac2, "b104884801c60009c3", "return tag 4")
    other = ex.pin(0x1e74ab9, "b105884801c60009c3", "return tag 5 for other names")
    keys = [block, receipts, system, read_calls, highest]
    tags = [0, tag1[1], tag2[1], tag3[1], tag4[1]]  # xor ecx,ecx supplies the first tag.
    return {"table_va": hx(base), "table_file_offset": hx(image.offset(base, len(raw))),
            "table_bytes": raw.hex(), "length_dispatch": [
                {"length": first_length + n, "target": hx(dest)} for n, dest in enumerate(entries)],
            "fields": [{"tag": tag, "name": name.decode("ascii"), "length": len(name)}
                       for tag, name in zip(tags, keys)], "other_tag": other[1], "outer_tag": tag0[-2]}


def classify(selector_record, key):
    for row in selector_record["fields"]:
        if key == row["name"].encode("ascii"):
            return row["tag"]
    return selector_record["other_tag"]


def selector_mode(add_byte, bound, code):
    if not 0 <= code <= 255:
        raise ValueError("selector must be a byte")
    return ((code + add_byte) & 255) < bound


def header_count(bits, base):
    if len(bits) != 6 or any(type(b) is not int or b not in (0, 1) for b in bits):
        raise ValueError("header flags must be six zero-or-one integers")
    return base + sum(bits)


def outer_mode_plan(mode):
    """Observed key gates in the selected writer, including noncanonical bytes."""
    if not isinstance(mode, int) or not 0 <= mode <= 255:
        raise ValueError("mode must be a byte")
    return {"container": "array" if mode == 0 else "map",
            "name_emitted": [mode == 1] * 3 + [mode != 0] * 2}


def binary_frame(payload, encoding):
    """Static model of the selected binary-length marker and payload write."""
    length = len(payload)
    if length < encoding["length8_limit"]:
        return bytes([encoding["marker8"], length]) + payload
    if length < encoding["length16_limit"]:
        return bytes([encoding["marker16"]]) + struct.pack(">H", length) + payload
    if length <= 0xffffffff:
        return bytes([encoding["marker32"]]) + struct.pack(">I", length) + payload
    raise ValueError("payload exceeds the admitted 32-bit length")


def variant_name(rows, tag):
    # The native jump has no local bound check. This analysis only admits the
    # five explicitly checked table rows; refusal here is not native behavior.
    if type(tag) is not int or not 0 <= tag < len(rows):
        raise ValueError("variant is outside the admitted table rows")
    return rows[tag]["name"]


def receipt_boolean(value, marker_base):
    if type(value) is not int or value not in (0, 1):
        raise ValueError("receipt boolean model admits zero or one")
    return marker_base | value


def facts(image):
    ex = Extract(image)
    functions = [image.check_function(start) for start in sorted(FUNCTIONS)]
    gate = ex.pin(0x459c558, "4080c6e94080fe04", "selector arithmetic")
    ex.branch(0x459c560, 0x459c5ab, "selector chooses positional configuration")
    one = ex.pin(0x459c587, "c744242800040001", "named configuration")
    zero = ex.pin(0x459c5d0, "c744242800040000", "positional configuration")
    ex.pin(0x459c58f, "c644242c00", "named trailing configuration byte")
    ex.pin(0x459c5d8, "c644242c00", "positional trailing configuration byte")
    words = [struct.unpack_from("<I", x, 4)[0] for x in (zero, one)]
    ex.call(0x459c5a4, 0x45a1200, "named archive writer")
    ex.call(0x459c5ed, 0x45a1200, "positional archive writer")
    ex.pin(0x459c5f2, "48b80400000000000080", "success sentinel")
    ex.branch(0x459c601, 0x459c631, "writer result differs from success sentinel")
    ex.pin(0x459c65c, "48c7030000000048c743080100000048c7431000000000", "empty output triple after error")
    ex.call(0x459c678, 0x45be8d0, "error result cleanup")
    modes = [code for code in range(256) if selector_mode(gate[3], gate[7], code)]

    # Main writer and its distinct format visitor.
    ex.pin(0x45a1221, "807a0b00", "outer named-mode test")
    for at, raw, label in [
        (0x45a1270, "41807e0b01", "block key mode test"),
        (0x45a12f0, "41807e0b01", "receipts key mode test"),
        (0x45a1331, "41807e0b01", "system transaction key mode test"),
        (0x45a136e, "41807e0b00", "precompile key mode test"),
        (0x45a146c, "41807e0b00", "highest address key mode test"),
        (0x45a12d7, "4c89fe4c89f2", "block value and serializer arguments"),
    ]:
        ex.pin(at, raw, label)
    ex.branch(0x45a1225, 0x45a1256, "outer positional header")
    ex.pin(0x45a122d, "ba05000000", "outer named field count")
    ex.pin(0x45a125c, "ba05000000", "outer positional field count")
    ex.call(0x45a1232, 0x4ae9900, "five-entry named header")
    ex.call(0x45a1261, 0x4aea420, "five-entry positional header")
    outer = [
        ex.name(0x45a1277, 0x45a127e),
        field(ex, 0x45a12f7, 0x45a12fe, 0x45a1315, 0x45a1322, 0x441f360),
        field(ex, 0x45a1338, 0x45a133f, 0x45a1356, 0x45a1363, 0x4428950),
        ex.name(0x45a1375, 0x45a137c),
        ex.name(0x45a1473, 0x45a147a),
    ]
    outer[0].update({"source_offset": hx(0), "value_call": hx(0x45a12dd),
                     "value_target": hx(ex.call(0x45a12dd, 0x45951c0, "archive block value"))})
    outer[3].update({"source_offset": hx(ex.source(0x45a1393)),
                     "collection_call": hx(0x45a1435), "collection_target": hx(ex.call(0x45a1435, 0x486b570, "precompile row collection")),
                     "value_call": hx(0x45a1445), "value_target": hx(ex.call(0x45a1445, 0x4405e60, "precompile row sequence"))})
    option_test = ex.pin(0x45a1491, "4180bf8003000001", "optional address tag at input offset")
    outer[4].update({"source_offset": hx(ex.source(0x45a149b)), "tag_offset": hx(struct.unpack_from("<i", option_test, 3)[0]),
                     "present_call": hx(0x45a14ab), "present_target": hx(ex.call(0x45a14ab, 0x4596e80, "present address")),
                     "absent_call": hx(0x45a14e2), "absent_target": hx(ex.call(0x45a14e2, 0x44355d0, "absent address"))})
    variant = ex.name(0x45a12b6, 0x45a12bd)
    ex.pin(0x45a129d, "ba01000000", "variant envelope count")
    ex.call(0x45a12a2, 0x4ae9900, "single-entry variant map")
    for va, dest, label in [
        (0x45a123f, 0x45a1270, "outer named header success"),
        (0x45a126e, 0x45a1241, "outer positional header failure"),
        (0x45a1275, 0x45a1295, "block name is gated by equality to one"),
        (0x45a128f, 0x45a13df, "block name failure"),
        (0x45a12b0, 0x45a13da, "variant header failure"),
        (0x45a12ce, 0x45a13df, "variant name failure"),
        (0x45a12ea, 0x45a13ed, "block child failure"),
        (0x45a12f5, 0x45a1315, "receipts name is gated by equality to one"),
        (0x45a130f, 0x45a13df, "receipts name failure"),
        (0x45a132b, 0x45a13ed, "receipts child failure"),
        (0x45a1336, 0x45a1356, "system transaction name is gated by equality to one"),
        (0x45a1350, 0x45a13df, "system transaction name failure"),
        (0x45a136c, 0x45a13ed, "system transaction child failure"),
        (0x45a1373, 0x45a1393, "precompile name is gated by nonzero"),
        (0x45a138d, 0x45a14b2, "precompile name failure"),
        (0x45a139d, 0x45a1418, "empty precompile collection"),
        (0x45a1452, 0x45a1465, "skip freeing empty temporary"),
        (0x45a146a, 0x45a14c1, "precompile child failure"),
        (0x45a1471, 0x45a1491, "highest address name is gated by nonzero"),
        (0x45a148b, 0x45a13df, "highest address name failure"),
        (0x45a1499, 0x45a14dc, "address tag differs from one"),
        (0x45a14eb, 0x45a13ed, "highest address child failure"),
    ]:
        ex.branch(va, dest, label)

    # Block value: a two-field header and a three-field body. The value's
    # inner child serializers are identified by their fixed direct calls.
    nested = [ex.name(0x4595237, 0x459523e),
              field(ex, 0x45952a1, 0x45952a8, 0x45952bf, 0x45952cc, 0x4595c30),
              ex.name(0x45952e9, 0x45952f0),
              ex.name(0x4595329, 0x4595330),
              field(ex, 0x459537e, 0x4595385, 0x459539c, 0x45953a9, 0x4416e00),
              field(ex, 0x45953c3, 0x45953ca, 0x45953e1, 0x45953ee, 0x4409e70),
              ex.name(0x4595408, 0x459540f)]
    nested[2].update({"source_offset": hx(0), "value_call": hx(0x4595310),
                      "value_target": hx(ex.call(0x4595310, 0x46bfbe0, "nested block header"))})
    nested[6].update({"source_offset": hx(ex.source(0x4595422)), "gate": "sentinel chooses absent or present child"})
    body_type = ex.name(0x4595347, 0x4595351)
    for site, target, label in [
        (0x45951f2,0x4ae9900,"block named container"),
        (0x4595221,0x4aea420,"block positional container"),
        (0x4595267,0x4ae9900,"block header named container"),
        (0x459528b,0x4aea420,"block header positional container"),
    ]:
        ex.call(site,target,label)
    ex.pin(0x4595356, "41b803000000", "block body field count")
    ex.call(0x459535f, 0x44359b0, "three-field body header")
    ex.call(0x4595434, 0x44355d0, "absent withdrawals")
    ex.call(0x459548a, 0x44365d0, "present withdrawals")
    for va, dest, label in [
        (0x45951e5, 0x4595216, "nested block positional header"),
        (0x45951ff, 0x4595230, "nested block named container success"),
        (0x459522e, 0x4595201, "nested block positional container failure"),
        (0x459524f, 0x4595448, "nested header name failure"),
        (0x4595274, 0x459529a, "block header named container success"),
        (0x4595298, 0x4595276, "block header positional container failure"),
        (0x45952b9, 0x4595448, "block hash name failure"),
        (0x45952dc, 0x459543b, "block hash child failure"),
        (0x4595301, 0x4595448, "block header field name failure"),
        (0x459531c, 0x459543b, "header child failure"),
        (0x4595341, 0x4595465, "body name failure"),
        (0x4595370, 0x45954a2, "body container failure"),
        (0x4595396, 0x459546d, "transactions name failure"),
        (0x45953b5, 0x459549d, "transactions child failure"),
        (0x45953db, 0x459546d, "ommers name failure"),
        (0x45953fa, 0x459549d, "ommers child failure"),
        (0x4595420, 0x459546d, "withdrawals name failure"),
        (0x459542c, 0x4595475, "withdrawals sentinel present"),
        (0x4595496, 0x459549d, "withdrawals child failure"),
    ]:
        ex.branch(va, dest, label)

    # Each tuple names the source of the actual field name and its source
    # operand and call in the parent. Some names are passed in registers to
    # shared field helpers, while others are loaded inside those helpers.
    specs = [
        (0x46bfc79,0x46bfc80,0x46bfc97,0x46bfca1,0x4595c30,"always"),
        (0x46bfcb7,0x46bfcbe,0x46bfcd5,0x46bfcdf,0x4595c30,"always"),
        (0x46bfcf5,0x46bfcfc,0x46bfd13,0x46bfd20,0x4596e80,"always"),
        (0x46bfd36,0x46bfd3d,0x46bfd54,0x46bfd61,0x4595c30,"always"),
        (0x46bfd77,0x46bfd7e,0x46bfd95,0x46bfda2,0x4595c30,"always"),
        (0x46bfdb8,0x46bfdc2,0x46bfdb1,0x46bfdca,0x47afa90,"always"),
        (0x47aeb41,0x47aeb48,0x46bfdd9,0x46bfde6,0x47aeb30,"always"),
        (0x46bfdfc,0x46bfe06,0x46bfdf5,0x46bfe0e,0x47ae6c0,"always"),
        (0x47ad885,0x47ad88c,0x46bfe1d,0x46bfe2a,0x47ad870,"always"),
        (0x47ad705,0x47ad70c,0x46bfe39,0x46bfe46,0x47ad6f0,"always"),
        (0x47ad815,0x47ad81c,0x46bfe55,0x46bfe62,0x47ad800,"always"),
        (0x47ae5c5,0x47ae5cc,0x46bfe71,0x46bfe7e,0x47ae5b0,"always"),
        (0x46bfe91,0x46bfe9b,0x46bfe8d,0x46bfea3,0x47af530,"always"),
        (0x46bfeb9,0x46bfec3,0x46bfeb2,0x46bfecb,0x47afa90,"always"),
        (0x47ae401,0x47ae408,0x46bfeda,0x46bfee7,0x47ae3f0,"always"),
        (0x47ae461,0x47ae468,0x46bff02,0x46bff05,0x47ae450,"qword at +0x0 nonzero"),
        (0x46bff21,0x46bff2b,0x46bff14,0x46bff33,0x47ae220,"byte at +0x26c equals 1"),
        (0x47af6f1,0x47af6f8,0x46bff42,0x46bff52,0x47af6e0,"qword at +0x10 nonzero"),
        (0x47af891,0x47af898,0x46bff61,0x46bff71,0x47af880,"qword at +0x20 nonzero"),
        (0x46bff8d,0x46bff97,0x46bff80,0x46bff9f,0x47ae220,"byte at +0x28d equals 1"),
        (0x46bffb7,0x46bffc1,0x46bffaa,0x46bffcc,0x47ae220,"byte at +0x2ae equals 1"),
    ]
    header = [field(ex, *r[:5], gate=r[5]) for r in specs]
    ex.call(0x46bfc35,0x4ae9900,"header named container")
    ex.call(0x46bfc63,0x4aea420,"header positional container")
    header_code = ex.pin(0x46bfbfe, "0fb6866c02000048833e0183d8000346100346200fb68e8d02000001c10fb686ae0200008d140883c210", "header field count calculation")
    count_base = header_code[-1] - 1
    for at, raw, label in [
        (0x46bfef6,"49833e00","base fee option test"),
        (0x46bff1b,"41803801","withdrawals root option test"),
        (0x46bff46,"48833a00","blob gas option test"),
        (0x46bff65,"48833a00","excess blob gas option test"),
        (0x46bff87,"41803801","parent beacon root option test"),
        (0x46bffb1,"41803e01","requests hash option test"),
    ]:
        ex.pin(at,raw,label)
    for va, dest, label in [
        (0x46bfc2d,0x46bfc5d,"header named or positional container"),
        (0x46bfc42,0x46bfc72,"header named container success"),
        (0x46bfc70,0x46bfc44,"header positional container failure"),
        (0x46bfc91,0x46bffdc,"parentHash name failure"),
        (0x46bfcaa,0x46bffee,"parent hash child failure"),
        (0x46bfccf,0x46bffdc,"sha3Uncles name failure"),
        (0x46bfce8,0x46bffee,"sha3Uncles child failure"),
        (0x46bfd0d,0x46bffdc,"miner name failure"),
        (0x46bfd29,0x46bffee,"miner child failure"),
        (0x46bfd4e,0x46bffdc,"stateRoot name failure"),
        (0x46bfd6a,0x46bffee,"stateRoot child failure"),
        (0x46bfd8f,0x46bffdc,"transactionsRoot name failure"),
        (0x46bfdab,0x46bffee,"transactionsRoot child failure"),
        (0x46bfdd3,0x46c0016,"receiptsRoot child failure"),
        (0x46bfdef,0x46c0016,"logsBloom child failure"),
        (0x46bfe17,0x46c0016,"difficulty child failure"),
        (0x46bfe33,0x46c0016,"number child failure"),
        (0x46bfe4f,0x46c0016,"gasLimit child failure"),
        (0x46bfe6b,0x46c0016,"gasUsed child failure"),
        (0x46bfe87,0x46c0016,"timestamp child failure"),
        (0x46bfeac,0x46c0016,"extraData child failure"),
        (0x46bfed4,0x46c0016,"mixHash child failure"),
        (0x46bfef0,0x46c0016,"nonce child failure"),
        (0x46bff0e,0x46c0016,"base fee child failure"),
        (0x46bfefa,0x46bff14,"omit absent base fee"),
        (0x46bff1f,0x46bff42,"omit absent withdrawals root"),
        (0x46bff3c,0x46c0016,"withdrawalsRoot child failure"),
        (0x46bff4a,0x46bff61,"omit absent blob gas used"),
        (0x46bff5b,0x46c0016,"blobGasUsed child failure"),
        (0x46bff69,0x46bff80,"omit absent excess blob gas"),
        (0x46bff7a,0x46c0016,"excessBlobGas child failure"),
        (0x46bff8b,0x46bffaa,"omit absent parent beacon root"),
        (0x46bffa8,0x46c0016,"parentBeaconBlockRoot child failure"),
        (0x46bffb5,0x46bffd7,"omit absent requests hash"),
        (0x46bffd5,0x46c0016,"requestsHash child failure"),
    ]:
        ex.branch(va,dest,label)

    # Three selected collections use distinct in-memory strides. The last
    # collection's row writer begins with a two-element sequence; the two
    # element writers remain opaque. These are strides in memory, not fixed
    # serialized lengths.
    ex.pin(0x486b579,"4c8b7e404d89fe49c1e604","precompile collection allocation scale")
    pre_scale = ex.pin(0x4406013,"49c1e604","precompile row end scale")
    ex.pin(0x4406040,"488b5500488b4d08","precompile row argument loads")
    pre_stride = ex.pin(0x4406061,"4883c510","precompile row stride")
    receipt_scale = ex.pin(0x441f381,"488d04d500000000488d2c80","receipt end scale")
    receipt_stride = ex.pin(0x441f46c,"4983c428","receipt row stride")
    system_scale = ex.pin(0x4428971,"4869da10010000","system transaction end scale")
    system_stride = ex.pin(0x4428a6c,"4981c410010000","system transaction row stride")
    ex.call(0x440604e,0x43cb4a0,"precompile row pair writer")
    ex.call(0x441f459,0x4c064e0,"receipt row writer")
    ex.call(0x4428a59,0x45a0d20,"system transaction row writer")
    ex.call(0x4405ec7,0x4aea420,"precompile sequence header")
    pair_count = ex.pin(0x43cb505,"ba02000000","precompile row element count")
    pair_marker = ex.pin(0x43cb5b0,"c6040192","precompile row direct header byte")
    ex.call(0x43cb50a,0x4aea420,"precompile row alternate header")
    ex.call(0x43cb5ec,0x43f4a40,"first precompile row child")
    ex.call(0x43cb61c,0x460a940,"second precompile row child")
    for at, dest, label in [
        (0x440605b,0x4405f40,"precompile row failure"),
        (0x441f466,0x441f62f,"receipt row failure"),
        (0x4428a66,0x4428c25,"system transaction row failure"),
        (0x43cb518,0x43cb684,"precompile pair header failure"),
        (0x43cb563,0x43cb65b,"first alternate pair child failure"),
        (0x43cb5fa,0x43cb634,"first pair child failure"),
    ]:
        ex.branch(at,dest,label)
    sequences = [
        {"field": outer[1]["name"], "row_stride": receipt_stride[-1], "writer": hx(0x441f360)},
        {"field": outer[2]["name"], "row_stride": struct.unpack_from("<I",system_stride,3)[0], "writer": hx(0x4428950)},
        {"field": outer[3]["name"], "row_stride": pre_stride[-1], "writer": hx(0x4405e60),
         "row_element_count": struct.unpack_from("<I",pair_count,1)[0], "direct_header_byte": pair_marker[-1]},
    ]
    if (1 << pre_scale[-1] != pre_stride[-1] or receipt_stride[-1] != 8 * (1 + 4) or
            struct.unpack_from("<I",system_scale,3)[0] != sequences[1]["row_stride"]):
        raise ValueError("collection stride checks disagree")

    # A system transaction row writes a tagged transaction followed by an
    # optional receipt. The direct receipt collection calls the same writer.
    sys_tx = ex.name(0x45a0d8f,0x45a0d99)
    sys_receipt = ex.name(0x45a0dbb,0x45a0dc2)
    ex.pin(0x45a0d4c,"ba02000000","system row named field count")
    ex.pin(0x45a0d7b,"ba02000000","system row positional field count")
    ex.call(0x45a0d51,0x4ae9900,"system row named container")
    ex.call(0x45a0d80,0x4aea420,"system row positional container")
    ex.pin(0x45a0da1,"4d89f8","system transaction source argument")
    sys_tx.update({"source_offset": hx(0), "value_call": hx(0x45a0da4),
                   "value_target": hx(ex.call(0x45a0da4,0x4670350,"system transaction variant"))})
    sys_receipt.update({"source_offset": hx(ex.source(0x45a0dd5)),
                        "present_call": hx(0x45a0e35),
                        "present_target": hx(ex.call(0x45a0e35,0x4c064e0,"present system receipt"))})
    ex.pin(0x45a0ddc,"4d3927","system receipt sentinel comparison")
    ex.pin(0x45a0e01,"c60430c0","absent system receipt null marker")
    for at,dest,label in [
        (0x45a0d44,0x45a0d75,"system row positional header"),
        (0x45a0d5e,0x45a0d8f,"system row named container success"),
        (0x45a0d8d,0x45a0d60,"system row positional container failure"),
        (0x45a0db2,0x45a0e18,"system transaction value failure"),
        (0x45a0db9,0x45a0dd5,"system receipt name gate"),
        (0x45a0dd3,0x45a0e49,"system receipt name failure"),
        (0x45a0ddf,0x45a0e2a,"present system receipt"),
        (0x45a0e42,0x45a0e58,"system receipt child failure"),
    ]:
        ex.branch(at,dest,label)

    # Each chosen table has five inspected signed-relative entries. The native
    # dispatches index without a local range check; indices outside these rows
    # are deliberately excluded, not described as an error from the target.
    tx_table = ex.rip(0x4670387,(b"\x48\x8d\x0d",))
    receipt_table = ex.rip(0x4c06582,(b"\x48\x8d\x0d",))
    ex.pin(0x4670380,"498b074983c710","system transaction variant discriminant and payload")
    ex.pin(0x4c06556,"410fb66e21","receipt variant discriminant")
    tx_spec = [
        (0x4670397,0x46703b5,0x46703bc,0x46703e5,0x46be9c0),
        (0x46704df,0x46704f9,0x4670500,0x4670525,0x49d5d10),
        (0x467043d,0x467045b,0x4670462,0x467048b,0x49d49d0),
        (0x4670490,0x46704ae,0x46704b5,0x46704da,0x49d6960),
        (0x46703ea,0x4670408,0x467040f,0x4670438,0x49d79f0),
    ]
    receipt_spec = [
        (0x4c06592,0x4c06592,0x4c06599),
        (0x4c065cc,0x4c065cc,0x4c065d3),
        (0x4c065ba,0x4c065ba,0x4c065d3),
        (0x4c065c3,0x4c065c3,0x4c065d3),
        (0x4c065b1,0x4c065b1,0x4c065d3),
    ]
    def entries(table, specs, owner, *, tail):
        raw = image.read(table, len(specs)*4)
        rows = []
        for index, (spec, value) in enumerate(zip(specs,struct.iter_unpack("<i",raw))):
            dest = table + value[0]
            if dest != spec[0]:
                raise ValueError("variant jump table target changed")
            name = ex.name(spec[1],spec[2])
            name.update({"table_index":index,"table_entry_va":hx(table + index*4),
                         "table_entry_bytes": raw[index*4:index*4+4].hex(), "table_target":hx(dest)})
            if tail:
                name.update({"child_transfer":hx(spec[3]),
                             "child_target":hx(ex.call(spec[3],spec[4],"transaction variant child",opcode=0xe9))})
            rows.append(name)
        next_word = image.read(table+len(specs)*4,4)
        next_target = table + struct.unpack("<i", next_word)[0]
        owner_frame = image.fdes[owner]
        if owner_frame["start"] <= next_target < owner_frame["end"]:
            raise ValueError("following table word unexpectedly enters selected FDE")
        boundary = {"table_va":hx(table), "admitted_entries":len(specs),
                    "following_word_va":hx(table+len(specs)*4), "following_word_bytes":next_word.hex(),
                    "following_word_as_relative_target":hx(next_target),
                    "following_target_in_selected_fde":False}
        return rows,boundary
    tx_variants,tx_boundary = entries(tx_table,tx_spec,0x4670350,tail=True)
    receipt_variants,receipt_boundary = entries(receipt_table,receipt_spec,0x4c064e0,tail=False)
    if [r["name"] for r in tx_variants] != [r["name"] for r in receipt_variants]:
        raise ValueError("transaction and receipt variant names differ")
    receipt_names = [ex.name(0x4c06562,0x4c06569), ex.name(0x4c065f6,0x4c065fd),
                     ex.name(0x4c06665,0x4c0666c), ex.name(0x4c066a1,0x4c066a8)]
    type_load = ex.pin(0x4c06556,"410fb66e21","receipt type byte")
    success_load = ex.pin(0x4c065ea,"450fb66e20","receipt success byte")
    gas_load = ex.pin(0x4c0665a,"4d8b6618","receipt gas qword")
    bool_marker = ex.pin(0x4c0662e,"4180cdc2","receipt boolean marker base")
    ex.call(0x4c06636,0x4aed5a0,"receipt boolean marker")
    ex.call(0x4c0668a,0x4aeca50,"receipt cumulative gas writer")
    ex.call(0x4c066d0,0x441dd20,"receipt logs writer")
    for row,offset in zip(receipt_names,(type_load[-1],success_load[-1],gas_load[-1],0)):
        row["source_offset"] = hx(offset)
    ex.pin(0x4c06505,"ba04000000","receipt named field count")
    ex.pin(0x4c06541,"ba04000000","receipt positional field count")
    ex.call(0x4c0650a,0x4ae9900,"receipt named container")
    ex.call(0x4c06546,0x4aea420,"receipt positional container")
    for at,dest,label in [
        (0x4c064fb,0x4c06539,"receipt positional header"),
        (0x4c06518,0x4c06556,"receipt named container success"),
        (0x4c06554,0x4c0651a,"receipt positional container failure"),
        (0x4c0657a,0x4c066ef,"receipt type name failure"),
        (0x4c065e4,0x4c066ef,"receipt variant name failure"),
        (0x4c0660e,0x4c066ef,"receipt success name failure"),
        (0x4c0667d,0x4c066ef,"receipt gas name failure"),
        (0x4c06698,0x4c066ea,"receipt gas value failure"),
        (0x4c066b9,0x4c06716,"receipt logs name failure"),
        (0x4c066df,0x4c0672f,"receipt logs value failure"),
    ]:
        ex.branch(at,dest,label)

    # Selected binary-mode primitive inputs. The source width is the immediate
    # passed to the fixed-byte helper, not an inferred on-disk struct offset.
    fixed = []
    for va, width, call_site, label in [
        (0x4595ce7,32,0x4595cef,"hash"),
        (0x4597118,20,0x4597120,"address"),
        (0x459725b,256,0x4597263,"bloom"),
        (0x4595e9a,8,0x4595ea2,"nonce"),
        (0x45c7650,8,0x45c765b,"unsigned scalar"),
    ]:
        mov = image.read(va,5,executable=True)
        if mov[0] != 0xba or struct.unpack_from("<I",mov,1)[0] != width:
            raise ValueError("unexpected fixed-width value")
        ex.call(call_site,0x4aead00,label + " binary writer")
        fixed.append({"kind": label,"width": struct.unpack_from("<I",mov,1)[0],
                      "width_instruction": hx(va),"call": hx(call_site)})
    ex.pin(0x45c764a,"480fcb488918","u64 byte swap before binary write")
    for at in (0x47ad8b5, 0x47ad735, 0x47ad845, 0x47ae5f5):
        ex.call(at,0x45c7600,"header unsigned scalar field")
    ex.call(0x47aeb6c,0x4597190,"header bloom field",opcode=0xe9)
    ex.call(0x47ae42c,0x4595d60,"header nonce field",opcode=0xe9)
    ex.call(0x47afac6,0x4595c30,"header fixed hash field",opcode=0xe9)
    ex.pin(0x47ae24e,"41803f01","optional root present tag")
    ex.call(0x47ae26b,0x4595c30,"present optional root hash",opcode=0xe9)
    ex.call(0x4aead1e,0x4aea820,"binary length header")
    marker_high = ex.pin(0x4aea82e,"81fa00000100b0c61c0089542404","binary 16/32-bit marker selection")
    marker_low = ex.pin(0x4aea83c,"81fa000100000fb6c0bdc40000000f43e8","binary 8-bit marker selection")
    ex.pin(0x4aea925,"8b4c2404880c30","one-byte binary length write")
    ex.pin(0x4aeaa02,"8b4c240466c1c108498b460866890c30","two-byte big-endian binary length write")
    ex.pin(0x4aeaadb,"8b4c24040fc9498b4608890c30","four-byte big-endian binary length write")
    ex.pin(0x4aeadd4,"49015f10b802000000","binary copy length and success")
    encoding = {"length8_limit": struct.unpack_from("<I",marker_low,2)[0],
                "length16_limit": struct.unpack_from("<I",marker_high,2)[0],
                "marker8": marker_low[10], "marker16": marker_high[7]-1,
                "marker32": marker_high[7]}

    classifier = selector(image,ex)
    if [x["name"] for x in classifier["fields"]] != [x["name"] for x in outer]:
        raise ValueError("writer names and field classifier disagree")
    json_names = [ex.name(0x466e27e,0x466e288),
                  field(ex,0x466e2af,0x466e2b9,0x466e2a8,0x466e2be,0x4a95c20),
                  field(ex,0x466e2dd,0x466e2e7,0x466e2d6,0x466e2ec,0x4aa0960),
                  field(ex,0x466e307,0x466e311,0x466e300,0x466e316,0x4a7ebc0),
                  ex.name(0x466e548,0x466e54f)]
    if [x["name"] for x in json_names] != [x["name"] for x in outer]:
        raise ValueError("other writer's names disagree")
    ex.call(0x466e32d,0x466e540,"final field helper in JSON-shaped writer")
    ex.pin(0x466e28d,"4889d9","JSON-shaped block input argument")
    json_names[0]["source_offset"] = hx(0)
    json_names[4]["source_offset"] = hx(ex.source(0x466e320))
    for at, dest, label in [
        (0x466e298,0x466e37b,"JSON-shaped block failure"),
        (0x466e2a2,0x466e363,"JSON-shaped state failure after block"),
        (0x466e2c6,0x466e37b,"JSON-shaped receipts failure"),
        (0x466e2d0,0x466e363,"JSON-shaped state failure after receipts"),
        (0x466e2f4,0x466e37b,"JSON-shaped system transaction failure"),
        (0x466e2fe,0x466e363,"JSON-shaped state failure after system transactions"),
        (0x466e31e,0x466e37b,"JSON-shaped precompile failure"),
        (0x466e335,0x466e37b,"JSON-shaped highest address failure"),
    ]:
        ex.branch(at,dest,label)
    descriptor = b"struct EvmArchiveBlock with 5 elements"
    observed_descriptor = ex.pin(0x3b1380,descriptor.hex(),"archive type diagnostic")

    schema = {"schema": "node94-evm-archive-wire/v1", "binary_sha256": DIGEST,
              "coordinate_system": "ELF link-time virtual addresses; FDE ends exclusive",
              "selector": {"add_byte": gate[3], "exclusive_bound": gate[7],
                           "named_codes": modes, "positional_count": 256-len(modes),
                           "config_words_by_mode": [hx(w) for w in words],
                           "human_readable_bytes": [(w >> 16) & 255 for w in words],
                           "field_name_bytes": [(w >> 24) & 255 for w in words]},
              "outer_fields": outer, "variant": variant, "nested_fields": nested,
              "body_type": body_type, "header_fields": header, "header_required_count": count_base,
              "header_count_formula": {
                  "base_immediate": header_code[-1],
                  "subtract_if_first_word_below": header_code[10],
                  "dword_offsets": [hx(header_code[16]), hx(header_code[19])],
                  "byte_offsets": [hx(struct.unpack_from("<I",header_code,offset)[0])
                                   for offset in (3,23,32)],
                  "rule": "base minus comparison borrow plus the five raw values, modulo u32"},
              "fixed_binary": fixed, "binary_length_encoding": encoding, "sequences": sequences,
              "system_row": [sys_tx,sys_receipt],
              "transaction_variants": tx_variants, "receipt_variants": receipt_variants,
              "variant_table_boundaries": [tx_boundary,receipt_boundary],
              "receipt_fields": receipt_names, "receipt_boolean_marker_base": bool_marker[-1],
              "field_classifier": classifier, "json_shaped_fields": json_names,
              "type_diagnostic": {"va": hx(0x3b1380), "bytes": observed_descriptor.hex(),
                                  "text": observed_descriptor.decode("ascii")},
              "limitations": ["selected static path only", "child element schemas and runtime reachability unresolved",
                              "header flag examples require valid zero-or-one discriminants"]}
    header_cases = []
    for bits in itertools.product((0,1),repeat=6):
        header_cases.append({"flags": "".join(str(b) for b in bits),
                             "field_count": header_count(bits, count_base),
                             "included_optional": [header[15+i]["name"] for i,b in enumerate(bits) if b]})
    return schema, functions, ex.anchors, ex.edges, ex.branches, header_cases


def write_tsv(path, fields, rows):
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter="\t", lineterminator="\n")
        w.writeheader()
        for row in rows:
            w.writerow({key: row[key] for key in fields})


def generate(out, binary=BINARY):
    with binary.open("rb") as handle:
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            schema, funcs, anchors, calls, branches, cases = facts(Image(data))
    out.mkdir(parents=True, exist_ok=True)
    (out / "schema.json").write_text(json.dumps(schema, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    (out / "header-cases.json").write_text(json.dumps(cases, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    write_tsv(out / "functions.tsv", ["start","end_exclusive","file_offset","fde","bytes","sha256"], funcs)
    write_tsv(out / "anchors.tsv", ["site","file_offset","bytes","label"], anchors)
    write_tsv(out / "calls.tsv", ["site","file_offset","target","opcode","bytes","label"], calls)
    write_tsv(out / "branches.tsv", ["site","file_offset","destination","bytes","label"], branches)
    return schema


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    generate(args.out)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, struct.error) as error:
        print(f"evm_archive_wire94: {error}", file=sys.stderr)
        raise SystemExit(1)
