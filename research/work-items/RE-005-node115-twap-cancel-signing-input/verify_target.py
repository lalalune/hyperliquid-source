#!/usr/bin/env python3
"""Static target verification for RE-005 node #115 twapCancel signing input.

Reads the pinned ELF and `pins.json`; never executes or emulates the target and
never modifies the packet. All results go to a NEW directory given by --outdir
(required; refused if it exists or lies inside the packet).

  verify_target.py --elf ELF --outdir NEW_DIR              verify the pins
  verify_target.py --elf ELF --outdir NEW_DIR --selftest   baseline + corruption controls
  verify_target.py --elf ELF --emit-pins NEW_FILE          (authoring) write pins.json

Exit status: 0 all checks passed; 1 any mismatch/missing/surviving corruption;
2 usage error; 3 environment error (objdump, unreadable ELF); 4 outdir refused.

Requires GNU objdump (binutils); instruction text is whatever that decoder
prints, whitespace-collapsed. Pins record the same decoder's output, so the
facts are anchored to bytes (exact), instruction starts (linear decode from each
FDE start) and decoder text; they are not an independent decoder comparison.
"""
import argparse
import hashlib
import json
import mmap
import os
import re
import struct
import subprocess
import sys

PACKET = os.path.dirname(os.path.abspath(__file__))
ELF_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
ELF_SIZE = 105896032

WINDOWS = {
    "serializer": 0x36AA9A0, "dispatcher": 0x36B1600, "cancel_writer": 0x46ABEC0,
    "other_writer": 0x46AC020, "other_dispatcher": 0x36B3F80, "map_header": 0x3D4F6D0,
    "uint_writer": 0x3D517E0, "uint16": 0x3D51D10, "uint32": 0x3D51F40, "uint64": 0x3D520D0,
    "str_writer": 0x41C6110, "marker": 0x3D52310, "other_uint": 0x3D51450, "other_str": 0x41C6610,
    "sponge_update": 0x5CDA910, "sponge_finalize": 0x5CDAD40, "permutation": 0x5CDA380,
}

# (window, va, decoder text, claim). Text is whitespace-collapsed, comments dropped.
FACTS = [
    ("serializer", 0x36AA9AF, "mov r15,rcx", "suffix record pointer kept in r15"),
    ("serializer", 0x36AA9B2, "mov ebp,edx", "chain selector kept in ebp"),
    ("serializer", 0x36AA9DC, "mov DWORD PTR [rsp+0x28],0x1000400", "writer spec dword; byte +0xb = 1 selects struct-map mode"),
    ("serializer", 0x36AA9F6, "call 0x36b1600", "action dispatcher call"),
    ("serializer", 0x36AA9FB, "movabs rax,0x8000000000000004", "Ok discriminant compared after the dispatcher"),
    ("serializer", 0x36AAA0D, "jne 0x36aad04", "any other result goes to the unwrap panic"),
    ("serializer", 0x36AAA26, "mov r12,QWORD PTR [r15+0x10]", "nonce read from record +0x10"),
    ("serializer", 0x36AAA3E, "bswap r12", "nonce stored big-endian"),
    ("serializer", 0x36AAA53, "cmp BYTE PTR [r15+0x18],0x1", "vault present iff byte +0x18 == 1"),
    ("serializer", 0x36AAA58, "jne 0x36aaab7", "absent vault branch"),
    ("serializer", 0x36AAA6D, "mov BYTE PTR [rcx+r14*1+0x8],0x1", "vault marker 1"),
    ("serializer", 0x36AAA8D, "lea rax,[r15+0x19]", "vault bytes read from record +0x19"),
    ("serializer", 0x36AAAA6, "add r14,0x14", "20 vault bytes appended"),
    ("serializer", 0x36AAAAF, "cmp DWORD PTR [r15],0x1", "expiry present iff dword +0 == 1 (vault present path)"),
    ("serializer", 0x36AAACA, "mov BYTE PTR [rcx+r14*1+0x8],0x0", "vault marker 0 when absent"),
    ("serializer", 0x36AAAD9, "cmp DWORD PTR [r15],0x1", "expiry present iff dword +0 == 1 (vault absent path)"),
    ("serializer", 0x36AAAF3, "mov BYTE PTR [rax+r14*1],0x0", "zero marker before expiry"),
    ("serializer", 0x36AAB00, "mov r15,QWORD PTR [r15+0x8]", "expiry read from record +0x8"),
    ("serializer", 0x36AAB15, "bswap r15", "expiry stored big-endian"),
    ("serializer", 0x36AAB9C, "mov QWORD PTR [rsp+0x110],0x88", "sponge rate 136"),
    ("serializer", 0x36AABA8, "mov WORD PTR [rsp+0x118],0x1", "domain byte 1 (Keccak), unsqueezed flag 0"),
    ("serializer", 0x36AABBD, "call QWORD PTR [rip+0x2e35585]", "update via slot 0x64e0148"),
    ("serializer", 0x36AABE3, "mov edx,0x20", "32 output bytes"),
    ("serializer", 0x36AABEB, "call QWORD PTR [rip+0x2e3555f]", "finalize via slot 0x64e0150"),
    ("serializer", 0x36AAC32, "cmp bpl,0x3", "tag test looks only at the selector low byte"),
    ("serializer", 0x36AAC36, "sete cl", "equal flag"),
    ("serializer", 0x36AAC39, "mov dl,0x62", "base tag 0x62"),
    ("serializer", 0x36AAC3B, "sub dl,cl", "0x61 when equal"),
    ("serializer", 0x36AAC4E, "mov QWORD PTR [rbx],0x1", "record word 0 = 1"),
    ("serializer", 0x36AAC59, "mov QWORD PTR [rbx+0x10],0x1", "record word 2 = 1"),
    ("serializer", 0x36AAC71, "movups XMMWORD PTR [rbx+0x18],xmm0", "digest bytes 0..15 at +0x18"),
    ("serializer", 0x36AAC75, "movups XMMWORD PTR [rbx+0x28],xmm1", "digest bytes 16..31 at +0x28"),
    ("serializer", 0x36AAC79, "mov QWORD PTR [rbx+0x38],0x539", "constant 1337 at +0x38"),
    ("serializer", 0x36AAC42, "movups XMMWORD PTR [rbx+0x40],xmm0", "zero words +0x40..+0x50"),
    ("serializer", 0x36AAC46, "mov QWORD PTR [rbx+0x50],0x0", "zero word +0x50"),
    ("dispatcher", 0x36B1605, "mov rax,QWORD PTR [rsi]", "action tag qword"),
    ("dispatcher", 0x36B1608, "sub rax,0x86", "table index = tag - 0x86"),
    ("dispatcher", 0x36B161A, "lea rax,[rip+0xfffffffffd0e893b]", "jump table base 0x799f5c"),
    ("dispatcher", 0x36B1621, "movsxd rcx,DWORD PTR [rax+rcx*4]", "signed 32-bit table entry"),
    ("dispatcher", 0x36B1E3C, "add rsi,0x8", "payload pointer = action + 8"),
    ("dispatcher", 0x36B1E55, "lea rax,[rip+0xfffffffffd0eb8b8]", "variant name TwapCancel at 0x79d714"),
    ("dispatcher", 0x36B1E61, "mov QWORD PTR [rsp+0x20],0xa", "variant name length 10"),
    ("dispatcher", 0x36B1E6A, "lea rax,[rip+0xfffffffffcda82d3]", "key text at 0x45a144"),
    ("dispatcher", 0x36B1E76, "mov QWORD PTR [rsp+0x30],0x4", "key length 4"),
    ("dispatcher", 0x36B1E7F, "lea rax,[rip+0xfffffffffd0eaa02]", "action name at 0x79c888"),
    ("dispatcher", 0x36B1E8B, "mov QWORD PTR [rsp+0x40],0xa", "action name length 10"),
    ("dispatcher", 0x36B1E94, "mov QWORD PTR [rsp+0x48],rdx", "writer pointer passed on"),
    ("dispatcher", 0x36B1EA1, "call 0x46abec0", "twapCancel arm calls the cancel writer"),
    ("cancel_writer", 0x46ABEE1, "mov r14,QWORD PTR [rdx+0x40]", "writer from descriptor +0x40"),
    ("cancel_writer", 0x46ABEE5, "cmp BYTE PTR [r14+0xb],0x0", "map/array mode byte"),
    ("cancel_writer", 0x46ABEF2, "mov edx,0x3", "map length 3 (map branch)"),
    ("cancel_writer", 0x46ABEF7, "call 0x3d4f6d0", "map header writer"),
    ("cancel_writer", 0x46ABF11, "mov edx,0x3", "array branch length 3"),
    ("cancel_writer", 0x46ABF16, "call 0x3d50270", "array header writer (not selected: spec byte is 1)"),
    ("cancel_writer", 0x46ABF38, "cmp BYTE PTR [r14+0xb],0x1", "key written only in map mode"),
    ("cancel_writer", 0x46ABF3F, "mov rsi,QWORD PTR [r12+0x20]", "type key text"),
    ("cancel_writer", 0x46ABF4C, "call 0x41c6110", "string writer: type key"),
    ("cancel_writer", 0x46ABF5E, "mov rsi,r13", "action name text"),
    ("cancel_writer", 0x46ABF64, "call 0x41c6110", "string writer: twapCancel"),
    ("cancel_writer", 0x46ABF7A, "lea rsi,[rip+0xfffffffffc12e018]", "key a at 0x7d9f99"),
    ("cancel_writer", 0x46ABF89, "call 0x41c6110", "string writer: key a"),
    ("cancel_writer", 0x46ABF99, "mov edx,DWORD PTR [r12+0x8]", "a is the u32 at payload +8"),
    ("cancel_writer", 0x46ABFA4, "call 0x3d517e0", "uint writer: a"),
    ("cancel_writer", 0x46ABFBA, "lea rsi,[rip+0xfffffffffc12dfc7]", "key t at 0x7d9f88"),
    ("cancel_writer", 0x46ABFC9, "call 0x41c6110", "string writer: key t"),
    ("cancel_writer", 0x46ABFD4, "mov rdx,QWORD PTR [r12]", "t is the u64 at payload +0"),
    ("cancel_writer", 0x46ABFDE, "call 0x3d517e0", "uint writer: t"),
    ("cancel_writer", 0x46ABFED, "add r15,0x4", "Ok discriminant 0x8000000000000004"),
    ("map_header", 0x3D4F6E9, "cmp edx,0x10", "fixmap for length < 16"),
    ("map_header", 0x3D4F6EF, "mov ebp,0x80", "fixmap base 0x80"),
    ("map_header", 0x3D4F71D, "call 0x3d52310", "marker byte helper"),
    ("map_header", 0x3D4F731, "mov BYTE PTR [rax+r12*1],bl", "marker byte stored"),
    ("marker", 0x3D52348, "and sil,0xf", "fixmap/fixarray length mask"),
    ("marker", 0x3D5234C, "or sil,0x80", "fixmap = 0x80 | len"),
    ("marker", 0x3D52339, "and sil,0x1f", "fixstr length mask"),
    ("marker", 0x3D5233D, "or sil,0xa0", "fixstr = 0xa0 | len"),
    ("uint_writer", 0x3D517F0, "cmp rdx,0x100", "8-bit boundary"),
    ("uint_writer", 0x3D51810, "test dl,dl", "bit 7 set means 128..255"),
    ("uint_writer", 0x3D51812, "js 0x3d51918", "128..255 takes the 0xcc arm"),
    ("uint_writer", 0x3D51825, "mov BYTE PTR [rax+rsi*1],dl", "positive fixint byte"),
    ("uint_writer", 0x3D51925, "mov BYTE PTR [rax+rsi*1],0xcc", "uint8 marker"),
    ("uint_writer", 0x3D5183C, "cmp rdx,0x10000", "16-bit boundary"),
    ("uint_writer", 0x3D5184A, "call 0x3d51d10", "u16 data helper"),
    ("uint_writer", 0x3D51855, "mov BYTE PTR [rbx+0x8],0xcd", "uint16 marker returned"),
    ("uint_writer", 0x3D5185E, "shr rax,0x20", "32-bit boundary"),
    ("uint_writer", 0x3D51869, "call 0x3d51f40", "u32 data helper"),
    ("uint_writer", 0x3D51874, "mov BYTE PTR [rbx+0x8],0xce", "uint32 marker returned"),
    ("uint_writer", 0x3D51880, "call 0x3d520d0", "u64 data helper"),
    ("uint_writer", 0x3D5188B, "mov BYTE PTR [rbx+0x8],0xcf", "uint64 marker returned"),
    ("uint16", 0x3D51D37, "mov BYTE PTR [rcx+rax*1],0xcd", "marker byte 0xcd written"),
    ("uint16", 0x3D51DC9, "rol si,0x8", "16-bit value big-endian"),
    ("uint32", 0x3D51F67, "mov BYTE PTR [rcx+rax*1],0xce", "marker byte 0xce written"),
    ("uint32", 0x3D51FF9, "bswap esi", "32-bit value big-endian"),
    ("uint64", 0x3D520F8, "mov BYTE PTR [rcx+rax*1],0xcf", "marker byte 0xcf written"),
    ("uint64", 0x3D5218C, "bswap rsi", "64-bit value big-endian"),
    ("str_writer", 0x41C6126, "cmp r14d,0x20", "fixstr for length < 32"),
    ("str_writer", 0x41C612C, "mov bl,0xa0", "fixstr base 0xa0"),
    ("str_writer", 0x41C6230, "call 0x3d52310", "marker byte helper"),
    ("str_writer", 0x41C6429, "test r14,r14", "copy skipped for empty strings"),
    ("str_writer", 0x41C643A, "call QWORD PTR [rip+0x23190c8]", "memcpy slot 0x64df508 copies the text"),
    ("other_writer", 0x46AC038, "movzx r12d,BYTE PTR [r14+0x1b]", "other writer: mode byte at +0x1b (not +0xb)"),
    ("other_writer", 0x46AC041, "xor r12b,0x1", "other writer: header derived from mode"),
    ("other_writer", 0x46AC045, "shl r12b,0x4", "other writer: header derived from mode"),
    ("other_writer", 0x46AC049, "or r12b,0x83", "other writer: map 0x83 / array 0x93"),
    ("other_writer", 0x46AC089, "call 0x41c6610", "other writer: its own string helper"),
    ("other_writer", 0x46AC0CB, "mov BYTE PTR [rcx+rsi*1],0xa1", "other writer: inline fixstr-1 marker for key a"),
    ("other_writer", 0x46AC0DF, "mov BYTE PTR [rcx+rsi*1],0x61", "other writer: key a"),
    ("other_writer", 0x46AC0EA, "mov edx,DWORD PTR [r15+0x8]", "other writer: a is the u32 at +8"),
    ("other_writer", 0x46AC0F6, "call 0x3d51450", "other writer: its own uint helper"),
    ("other_writer", 0x46AC135, "mov BYTE PTR [rcx+rsi*1],0x74", "other writer: key t"),
    ("other_writer", 0x46AC140, "mov rdx,QWORD PTR [r15]", "other writer: t is the u64 at +0"),
    ("other_uint", 0x3D51458, "cmp rdx,0x100", "other copy: 8-bit boundary"),
    ("other_uint", 0x3D5148F, "cmp rdx,0x10000", "other copy: 16-bit boundary"),
    ("other_uint", 0x3D514AC, "mov BYTE PTR [rdi+r9*1],0xcd", "other copy: uint16 marker"),
    ("other_uint", 0x3D514EA, "shr rcx,0x20", "other copy: 32-bit boundary"),
    ("other_uint", 0x3D51508, "mov BYTE PTR [rdi+r9*1],0xce", "other copy: uint32 marker"),
    ("other_uint", 0x3D51554, "mov BYTE PTR [rcx+r9*1],0xcc", "other copy: uint8 marker"),
    ("other_str", 0x41C6627, "cmp ebx,0x20", "other copy: fixstr boundary"),
    ("other_str", 0x41C662C, "mov bpl,0xa0", "other copy: fixstr base"),
    ("other_str", 0x41C6645, "call 0x3d52310", "other copy: same marker helper"),
    ("sponge_update", 0x5CDA924, "cmp BYTE PTR [rdi+0xd9],0x0", "unsqueezed flag"),
    ("sponge_update", 0x5CDA95A, "mov rdi,QWORD PTR [rbx+0xc8]", "absorbed length"),
    ("sponge_update", 0x5CDA961, "mov r13,QWORD PTR [rbx+0xd0]", "rate"),
    ("sponge_update", 0x5CDA971, "cmp r12,r13", "input length against remaining rate"),
    ("sponge_update", 0x5CDA974, "jae 0x5cda9c5", "only inputs >= rate - cursor take the permutation path"),
    ("sponge_update", 0x5CDAC84, "xor DWORD PTR [rcx+r8*1],r9d", "word XOR into the state"),
    ("sponge_update", 0x5CDACA5, "xor BYTE PTR [rdx+rax*1],r8b", "byte XOR into the state"),
    ("sponge_update", 0x5CDACB4, "mov QWORD PTR [rbx+0xc8],r15", "cursor = absorbed length"),
    ("sponge_finalize", 0x5CDAD6B, "cmp BYTE PTR [rsp+0xe1],0x1", "squeezed flag test"),
    ("sponge_finalize", 0x5CDADDF, "movzx ecx,BYTE PTR [rsp+0xe0]", "domain byte"),
    ("sponge_finalize", 0x5CDADE7, "xor BYTE PTR [rsp+rax*1+0x8],cl", "domain byte XORed at the absorbed length"),
    ("sponge_finalize", 0x5CDADF4, "dec rdi", "rate - 1"),
    ("sponge_finalize", 0x5CDAE0A, "xor BYTE PTR [rsp+rdi*1+0x8],0x80", "0x80 at rate - 1"),
    ("sponge_finalize", 0x5CDAE14, "call QWORD PTR [rip+0x811d56]", "permutation via slot 0x64ecb70"),
]

# direct calls (E8/E9 rel32) expected inside a window: (window, target, how many)
CALL_FACTS = [
    ("serializer", 0x36B1600, "action dispatcher"),
    ("dispatcher", 0x46ABEC0, "cancel writer"),
    ("other_dispatcher", 0x46AC020, "other writer copy"),
    ("cancel_writer", 0x3D4F6D0, "map header"),
    ("cancel_writer", 0x41C6110, "string writer"),
    ("cancel_writer", 0x3D517E0, "uint writer"),
]
RELOC_SLOTS = [0x64E0148, 0x64E0150, 0x64ECB70]
CALLER_TARGETS = [0x46ABEC0, 0x36AA9A0, 0x36B1600]
DATA_FACTS = [
    (0x79D5A6, 6, "Action"), (0x79D714, 10, "TwapCancel"), (0x45A144, 4, "type"),
    (0x79C888, 10, "twapCancel"), (0x7D9F99, 1, "a"), (0x7D9F88, 1, "t"),
]
TABLE_BASE = 0x799F5C
TABLE_INDEX = 0xA9 - 0x86
ARM_VA = 0x36B1E3C


class Env(Exception):
    pass


LOG = []


def say(msg):
    """Print a selftest line and keep it for selftest.txt in the outdir."""
    print(msg)
    LOG.append(msg)


class Image:
    """Read-only mmap of the ELF with an optional in-memory byte patch overlay."""

    def __init__(self, path):
        try:
            self.fh = open(path, "rb")
            self.mm = mmap.mmap(self.fh.fileno(), 0, access=mmap.ACCESS_READ)
        except OSError as exc:
            raise Env("cannot read ELF: %s" % exc)
        self.size = len(self.mm)
        self.patch = {}
        if self.mm[:4] != b"\x7fELF":
            raise Env("not an ELF file")
        phoff, shoff = struct.unpack_from("<QQ", self.mm, 0x20)
        phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from("<HHHHH", self.mm, 0x36)
        self.loads = []
        for i in range(phnum):
            p_type, _fl, off, vaddr, _pa, filesz, _ms, _al = struct.unpack_from("<IIQQQQQQ", self.mm, phoff + i * phentsize)
            if p_type == 1:
                self.loads.append((vaddr, off, filesz))
        secs = []
        for i in range(shnum):
            secs.append(struct.unpack_from("<IIQQQQIIQQ", self.mm, shoff + i * shentsize))
        strtab = secs[shstrndx]
        self.sections = {}
        for s in secs:
            name_off = strtab[4] + s[0]
            end = self.mm.find(b"\0", name_off)
            self.sections[self.mm[name_off:end].decode()] = {"addr": s[3], "off": s[4], "size": s[5], "link": s[6]}

    def va_to_off(self, va):
        for vaddr, off, filesz in self.loads:
            if vaddr <= va < vaddr + filesz:
                return off + (va - vaddr)
        raise Env("address 0x%x is not file backed" % va)

    def read_va(self, va, n):
        off = self.va_to_off(va)
        data = bytearray(self.mm[off:off + n])
        for i in range(n):
            if off + i in self.patch:
                data[i] = self.patch[off + i]
        return bytes(data)

    def patched(self, va, new_bytes):
        clone = object.__new__(Image)
        clone.__dict__.update(self.__dict__)
        clone.patch = dict(self.patch)
        off = self.va_to_off(va)
        for i, b in enumerate(new_bytes):
            clone.patch[off + i] = b
        return clone

    def file_sha256(self):
        h = hashlib.sha256()
        for i in range(0, self.size, 1 << 24):
            h.update(self.mm[i:i + (1 << 24)])
        return h.hexdigest()

    def fde_table(self):
        """{start_va: (start, end)} for the pinned windows, from .eh_frame_hdr and the FDEs it points to."""
        if self.__dict__.get("_fdes") is not None:
            return self._fdes
        sec = self.sections[".eh_frame_hdr"]
        base_off, base_va = sec["off"], sec["addr"]
        version, ptr_enc, count_enc, table_enc = struct.unpack_from("<BBBB", self.mm, base_off)
        if (version, ptr_enc, count_enc, table_enc) != (1, 0x1B, 0x03, 0x3B):
            raise Env("unexpected eh_frame_hdr encoding")
        count = struct.unpack_from("<I", self.mm, base_off + 8)[0]
        out = {}
        eh_off, eh_va = self.sections[".eh_frame"]["off"], self.sections[".eh_frame"]["addr"]
        entries = struct.iter_unpack("<ii", self.mm[base_off + 12:base_off + 12 + 8 * count])
        want = set(WINDOWS.values())
        cie_cache = {}
        for loc_rel, fde_rel in entries:
            start = base_va + loc_rel
            if start not in want:
                continue
            fde_va = base_va + fde_rel
            fde_off = eh_off + (fde_va - eh_va)
            length, cie_ptr = struct.unpack_from("<II", self.mm, fde_off)
            cie_off = fde_off + 4 - cie_ptr
            if cie_off not in cie_cache:
                cie_cache[cie_off] = self._fde_encoding(cie_off)
            enc = cie_cache[cie_off]
            if enc != 0x1B:
                raise Env("unexpected FDE pointer encoding 0x%x" % enc)
            pc_rel = struct.unpack_from("<i", self.mm, fde_off + 8)[0]
            pc_begin = fde_va + 8 + pc_rel
            pc_range = struct.unpack_from("<i", self.mm, fde_off + 12)[0]
            if pc_begin != start:
                raise Env("FDE start disagrees with the search table")
            out[start] = (pc_begin, pc_begin + pc_range)
        self._fdes = out
        return out

    def _fde_encoding(self, cie_off):
        length = struct.unpack_from("<I", self.mm, cie_off)[0]
        p = cie_off + 9  # length, id, version
        end = self.mm.find(b"\0", p)
        aug = self.mm[p:end].decode()
        p = end + 1

        def uleb(p):
            v, shift = 0, 0
            while True:
                b = self.mm[p]
                p += 1
                v |= (b & 0x7F) << shift
                if not b & 0x80:
                    return v, p
                shift += 7

        _, p = uleb(p)
        _, p = uleb(p)
        p += 1  # return address register (version 1)
        if not aug.startswith("z"):
            raise Env("unexpected CIE augmentation")
        _, p = uleb(p)
        enc = 0
        for ch in aug[1:]:
            if ch == "R":
                enc = self.mm[p]
                p += 1
            elif ch == "L":
                p += 1
            elif ch == "P":
                penc = self.mm[p]
                p += 1 + {0x00: 8, 0x03: 4, 0x0B: 4, 0x04: 8, 0x0C: 8, 0x02: 2, 0x0A: 2}.get(penc & 0x0F, 8)
        return enc

    def relocations(self, wanted_slots, wanted_addends):
        """RELATIVE addends at `wanted_slots` and every slot whose addend is in `wanted_addends`."""
        sec = self.sections[".rela.dyn"]
        slots, refs, other = {}, {t: [] for t in wanted_addends}, {}
        dynsym, dynstr = self.sections[".dynsym"], self.sections[".dynstr"]
        for off, info, addend in struct.iter_unpack("<QQq", self.mm[sec["off"]:sec["off"] + sec["size"]]):
            rtype, sym = info & 0xFFFFFFFF, info >> 32
            if off in wanted_slots:
                slots[off] = (rtype, addend)
            if rtype == 8 and addend in refs:
                refs[addend].append(off)
        return slots, refs

    def slot_symbol(self, slot):
        """Dynamic symbol name for a GLOB_DAT/JUMP_SLOT at `slot` (.rela.dyn or .rela.plt)."""
        dynsym, dynstr = self.sections[".dynsym"], self.sections[".dynstr"]
        for secname in (".rela.dyn", ".rela.plt"):
            sec = self.sections[secname]
            for off, info, _ in struct.iter_unpack("<QQq", self.mm[sec["off"]:sec["off"] + sec["size"]]):
                if off == slot and (info & 0xFFFFFFFF) in (6, 7):
                    so = dynsym["off"] + 24 * (info >> 32)
                    name_off = struct.unpack_from("<I", self.mm, so)[0]
                    p = dynstr["off"] + name_off
                    return self.mm[p:self.mm.find(b"\0", p)].decode()
        return None

    def text_range(self):
        t = self.sections[".text"]
        return t["addr"], t["off"], t["size"]


LINE = re.compile(r"^\s*([0-9a-f]+):\t(.*)$")


def norm(text):
    return re.sub(r"\s+", " ", text.split("#")[0]).strip()


def decode_window(data, va, workdir, name):
    os.makedirs(workdir, exist_ok=True)
    path = os.path.join(workdir, name + ".bin")
    with open(path, "wb") as fh:
        fh.write(data)
    try:
        res = subprocess.run(
            ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64", "-M", "intel", "--no-show-raw-insn",
             "--adjust-vma=0x%x" % va, path], capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        raise Env("objdump failed: %s" % exc)
    if res.returncode != 0:
        raise Env("objdump exit %d: %s" % (res.returncode, res.stderr.strip()[:200]))
    ins = []
    for line in res.stdout.splitlines():
        m = LINE.match(line)
        if m:
            ins.append((int(m.group(1), 16), norm(m.group(2))))
    return ins


class Findings:
    def __init__(self):
        self.items = []

    def add(self, code, ident, detail):
        self.items.append((code, ident, detail))

    def codes(self):
        return {(c, i) for c, i, _ in self.items}


def fact_id(window, va):
    return "%s@%x" % (window, va)


def emit_pins(image, path):
    if os.path.exists(path):
        raise SystemExit("refusing to overwrite %s" % path)
    fdes = image.fde_table()
    pins = {"elf_sha256": ELF_SHA, "elf_size": ELF_SIZE, "windows": {}, "facts": [], "calls": [],
            "relocs": {}, "callers": {}, "data": {}, "table": {}}
    decoded = {}
    for key, start in WINDOWS.items():
        if start not in fdes:
            raise SystemExit("no FDE for %s at 0x%x" % (key, start))
        s, e = fdes[start]
        body = image.read_va(s, e - s)
        pins["windows"][key] = {"start": s, "end": e, "sha256": hashlib.sha256(body).hexdigest()}
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        for key, start in WINDOWS.items():
            s, e = fdes[start]
            decoded[key] = decode_window(image.read_va(s, e - s), s, tmp, key)
        for window, va, text, claim in FACTS:
            ins = decoded[window]
            idx = [i for i, (a, _) in enumerate(ins) if a == va]
            if not idx:
                raise SystemExit("fact %s is not an instruction start" % fact_id(window, va))
            i = idx[0]
            if ins[i][1] != text:
                raise SystemExit("fact %s decodes as %r, expected %r" % (fact_id(window, va), ins[i][1], text))
            nxt = ins[i + 1][0] if i + 1 < len(ins) else pins["windows"][window]["end"]
            pins["facts"].append({"window": window, "va": va, "len": nxt - va, "text": text,
                                  "bytes": image.read_va(va, nxt - va).hex(), "claim": claim})
        for window, target, claim in CALL_FACTS:
            vas = [a for a, t in decoded[window] if t.split(" ")[0] in ("call", "jmp") and t.endswith("0x%x" % target)]
            pins["calls"].append({"window": window, "target": target, "sites": vas, "claim": claim})
    slots, refs = image.relocations(set(RELOC_SLOTS), set(CALLER_TARGETS))
    pins["relocs"] = {"0x%x" % k: {"type": v[0], "addend": v[1]} for k, v in slots.items()}
    pins["reloc_refs"] = {"0x%x" % k: v for k, v in refs.items()}
    pins["slot_symbol"] = {"0x64df508": image.slot_symbol(0x64DF508)}
    found = callers_of(image, CALLER_TARGETS)
    pins["callers"] = {"0x%x" % t: found[t] for t in CALLER_TARGETS}
    for va, n, text in DATA_FACTS:
        pins["data"]["0x%x" % va] = image.read_va(va, n).hex()
    pins["table"] = table_info(image)
    with open(path, "w", newline="\n") as fh:
        json.dump(pins, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print("wrote %s (%d facts, %d windows)" % (os.path.basename(path), len(pins["facts"]), len(pins["windows"])))


def callers_of(image, targets):
    """{target: [sites]}: every E8/E9 rel32 in .text landing on a target.

    A byte scan, so a site is a candidate until decoded; it cannot miss a real
    direct call or jump, but it does not see calls through registers or data.
    """
    va0, off0, size = image.text_range()
    data = image.mm[off0:off0 + size]
    want = set(targets)
    hits = {t: [] for t in targets}
    for m in re.finditer(rb"[\xe8\xe9]", data):
        i = m.start()
        if i + 5 > size:
            continue
        dest = va0 + i + 5 + struct.unpack_from("<i", data, i + 1)[0]
        if dest in want:
            hits[dest].append(va0 + i)
    return hits


def table_info(image):
    dispatcher_end = image.fde_table()[WINDOWS["dispatcher"]][1]
    matches, entries = [], 0
    while True:
        raw = image.read_va(TABLE_BASE + 4 * entries, 4)
        target = TABLE_BASE + struct.unpack("<i", raw)[0]
        if not WINDOWS["dispatcher"] <= target < dispatcher_end:
            break
        if target == ARM_VA:
            matches.append(entries)
        entries += 1
    return {"entries_inside_dispatcher": entries, "indices_to_arm": matches,
            "entry_0xa9": TABLE_BASE + struct.unpack("<i", image.read_va(TABLE_BASE + 4 * TABLE_INDEX, 4))[0]}


def check(image, pins, workdir, findings, deep_callers=True, sha=True):
    """Run all pin checks; returns table rows for the result files."""
    rows = []
    if sha and image.file_sha256() != pins["elf_sha256"]:
        findings.add("E_ELF_SHA", "elf", "SHA-256 differs from the pin")
    if image.size != pins["elf_size"]:
        findings.add("E_ELF_SIZE", "elf", "size %d differs from the pin %d" % (image.size, pins["elf_size"]))
    fdes = image.fde_table()
    decoded, bodies = {}, {}
    for key, w in sorted(pins["windows"].items()):
        got = fdes.get(WINDOWS[key])
        if got is None:
            findings.add("E_FDE_MISSING", key, "no FDE starts at 0x%x" % WINDOWS[key])
            continue
        if got != (w["start"], w["end"]):
            findings.add("E_FDE_RANGE", key, "FDE 0x%x..0x%x, pinned 0x%x..0x%x" % (got + (w["start"], w["end"])))
        rows.append(("fde", key, "0x%x..0x%x" % got))
        body = image.read_va(w["start"], w["end"] - w["start"])
        bodies[key] = body
        if hashlib.sha256(body).hexdigest() != w["sha256"]:
            findings.add("E_BODY_HASH", key, "FDE body bytes differ from the pinned SHA-256")
        decoded[key] = decode_window(body, w["start"], workdir, key)
    for f in pins["facts"]:
        ident = fact_id(f["window"], f["va"])
        ins = decoded.get(f["window"])
        if ins is None:
            findings.add("E_FACT_MISSING", ident, "window missing")
            continue
        here = [t for a, t in ins if a == f["va"]]
        if not here:
            findings.add("E_FACT_START", ident, "not a decoded instruction start")
        elif here[0] != f["text"]:
            findings.add("E_FACT_TEXT", ident, "decodes as %r, pinned %r" % (here[0], f["text"]))
        raw = image.read_va(f["va"], f["len"]).hex()
        if raw != f["bytes"]:
            findings.add("E_FACT_BYTES", ident, "bytes %s, pinned %s" % (raw, f["bytes"]))
        rows.append(("fact", ident, "ok" if (here and here[0] == f["text"] and raw == f["bytes"]) else "FAIL"))
    for c in pins["calls"]:
        ins = decoded.get(c["window"], [])
        got = [a for a, t in ins if t.split(" ")[0] in ("call", "jmp") and t.endswith("0x%x" % c["target"])]
        ident = "%s->0x%x" % (c["window"], c["target"])
        if got != c["sites"] or not got:
            findings.add("E_CALLS", ident, "sites %s, pinned %s" % ([hex(x) for x in got], [hex(x) for x in c["sites"]]))
        rows.append(("call", ident, ",".join(hex(x) for x in got)))
    slots, refs = image.relocations(set(RELOC_SLOTS), set(CALLER_TARGETS))
    for slot, want in pins["relocs"].items():
        got = slots.get(int(slot, 16))
        if got is None or got != (want["type"], want["addend"]):
            findings.add("E_RELOC", slot, "got %s, pinned %s" % (got, want))
        rows.append(("reloc", slot, "type %s addend 0x%x" % got if got else "missing"))
    for tgt, want in pins["reloc_refs"].items():
        if refs.get(int(tgt, 16)) != want:
            findings.add("E_RELOC", "refs:" + tgt, "RELATIVE references differ")
    if image.slot_symbol(0x64DF508) != pins["slot_symbol"]["0x64df508"]:
        findings.add("E_RELOC", "0x64df508", "import symbol differs")
    for va, n, text in DATA_FACTS:
        want = pins["data"]["0x%x" % va]
        if image.read_va(va, n).hex() != want or bytes.fromhex(want).decode() != text:
            findings.add("E_DATA", "0x%x" % va, "bytes differ from pin or from %r" % text)
        rows.append(("data", "0x%x" % va, text))
    if table_info(image) != pins["table"] or pins["table"]["indices_to_arm"] != [TABLE_INDEX]:
        findings.add("E_TABLE", "0x%x" % TABLE_BASE, "dispatcher table differs from the pin")
    rows.append(("table", "0x%x" % TABLE_BASE, json.dumps(pins["table"], sort_keys=True)))
    if deep_callers:
        found = callers_of(image, [int(t, 16) for t in pins["callers"]])
        for tgt, want in pins["callers"].items():
            got = found[int(tgt, 16)]
            if got != want:
                findings.add("E_CALLERS", tgt, "direct call/jmp sites %s, pinned %s" % ([hex(x) for x in got], [hex(x) for x in want]))
            rows.append(("callers", tgt, ",".join(hex(x) for x in got)))
    return rows, decoded


def bitflip_run(image, pins, workdir):
    """Flip every bit of every pinned instruction byte; each flip must be caught."""
    by_window = {}
    for f in pins["facts"]:
        by_window.setdefault(f["window"], []).append(f)
    summary, undetected = [], []
    totals = {"flips": 0, "bytes_layer": 0, "text_layer": 0, "hash_layer": 0, "undetected": 0}
    for key, facts in sorted(by_window.items()):
        w = pins["windows"][key]
        body = bytearray(image.read_va(w["start"], w["end"] - w["start"]))
        n = t = hsh = flips = 0
        for f in facts:
            for k in range(f["len"]):
                for bit in range(8):
                    pos = f["va"] - w["start"] + k
                    body[pos] ^= 1 << bit
                    flips += 1
                    mutated = bytes(body)
                    ins = decode_window(mutated, w["start"], workdir, "flip")
                    starts = dict(ins)
                    byte_hit = any(mutated[g["va"] - w["start"]:g["va"] - w["start"] + g["len"]].hex() != g["bytes"] for g in facts)
                    text_hit = any(starts.get(g["va"]) != g["text"] for g in facts)
                    hash_hit = hashlib.sha256(mutated).hexdigest() != w["sha256"]
                    n += byte_hit
                    t += text_hit
                    hsh += hash_hit
                    if not (byte_hit or text_hit or hash_hit):
                        undetected.append("%s+0x%x bit %d" % (key, pos, bit))
                    body[pos] ^= 1 << bit
        summary.append((key, len(facts), flips, n, t, hsh))
        totals["flips"] += flips
        totals["bytes_layer"] += n
        totals["text_layer"] += t
        totals["hash_layer"] += hsh
    totals["undetected"] = len(undetected)
    return summary, totals, undetected


def refuse_outdir(outdir):
    real = os.path.realpath(outdir)
    if os.path.exists(real):
        return "--outdir already exists; give a new directory"
    pk = os.path.realpath(PACKET)
    if real == pk or real.startswith(pk + os.sep):
        return "--outdir lies inside the packet"
    return None


def write_tsv(path, header, rows):
    with open(path, "w", newline="\n") as fh:
        fh.write("\t".join(header) + "\n")
        for r in rows:
            fh.write("\t".join(str(c) for c in r) + "\n")


def run_verify(image, pins, outdir, flips=True):
    findings = Findings()
    rows, decoded = check(image, pins, os.path.join(outdir, "windows"), findings)
    os.makedirs(os.path.join(outdir, "decoded"))
    for key, ins in sorted(decoded.items()):
        with open(os.path.join(outdir, "decoded", key + ".txt"), "w", newline="\n") as fh:
            fh.write("".join("%x\t%s\n" % (a, t) for a, t in ins))
    summary, totals, undetected = bitflip_run(image, pins, os.path.join(outdir, "flip")) if flips else ([], {"flips": 0}, [])
    for u in undetected:
        findings.add("E_BITFLIP", u, "bit flip not caught by any layer")
    write_tsv(os.path.join(outdir, "target-checks.tsv"), ["kind", "id", "result"], rows)
    write_tsv(os.path.join(outdir, "bitflips.tsv"),
              ["window", "facts", "flips", "bytes_layer_caught", "text_layer_caught", "hash_layer_caught"], summary)
    write_tsv(os.path.join(outdir, "findings.tsv"), ["code", "id", "detail"], findings.items)
    result = {"facts": len(pins["facts"]), "windows": len(pins["windows"]), "findings": len(findings.items),
              "bitflips": totals}
    with open(os.path.join(outdir, "summary.json"), "w", newline="\n") as fh:
        json.dump(result, fh, indent=1, sort_keys=True)
        fh.write("\n")
    return findings, result


def selftest(image, pins, outdir, flips=True, meta=True):
    os.makedirs(outdir)
    base_findings, base = run_verify(image, pins, os.path.join(outdir, "baseline"), flips=flips)
    if base_findings.items:
        say("selftest: BASELINE NOT CLEAN (%d findings); variants not evaluated" % len(base_findings.items))
        for f in base_findings.items[:10]:
            say("   %s" % (f,))
        return 1
    say("selftest: baseline clean (%d facts, %d bit flips caught: %s)" % (base["facts"], base["bitflips"]["flips"], base["bitflips"]))

    def variant(name, expect, img=None, pn=None, deep=False):
        fnd = Findings()
        check(img or image, pn if pn is not None else pins, os.path.join(outdir, "v-" + name), fnd, deep_callers=deep)
        ok = all(e in fnd.codes() for e in expect)
        say("selftest: %-28s %s (%d findings)" % (name, "rejected as expected" if ok else "NOT REJECTED CORRECTLY", len(fnd.items)))
        return ok

    def clone():
        return json.loads(json.dumps(pins))

    results = []
    p = clone(); p["elf_sha256"] = "0" * 64
    results.append(variant("elf-sha-pin", [("E_ELF_SHA", "elf")], pn=p))
    p = clone(); p["windows"]["cancel_writer"]["end"] += 1
    results.append(variant("fde-range-pin", [("E_FDE_RANGE", "cancel_writer")], pn=p))
    p = clone(); p["windows"]["serializer"]["sha256"] = "1" * 64
    results.append(variant("body-hash-pin", [("E_BODY_HASH", "serializer")], pn=p))
    f = next(x for x in pins["facts"] if x["window"] == "serializer" and x["va"] == 0x36AAC32)
    img = image.patched(f["va"] + 3, bytes([4]))  # cmp bpl,0x3 -> cmp bpl,0x4
    results.append(variant("cmp-bpl-3-to-4", [("E_FACT_TEXT", fact_id("serializer", 0x36AAC32)), ("E_FACT_BYTES", fact_id("serializer", 0x36AAC32)), ("E_BODY_HASH", "serializer")], img=img))
    f = next(x for x in pins["facts"] if x["window"] == "cancel_writer" and x["va"] == 0x46ABEE5)
    img = image.patched(f["va"] + 3, bytes([image.read_va(f["va"] + 3, 1)[0] ^ 0x01]))  # [r14+0xb] -> [r14+0xa]
    results.append(variant("mode-byte-offset",[("E_FACT_TEXT", fact_id("cancel_writer", 0x46ABEE5)), ("E_BODY_HASH", "cancel_writer")], img=img))
    p = clone(); p["facts"][5]["text"] = "jne 0x36aad05"
    results.append(variant("fact-text-pin", [("E_FACT_TEXT", fact_id(p["facts"][5]["window"], p["facts"][5]["va"]))], pn=p))
    p = clone(); p["facts"][6]["bytes"] = "00" * p["facts"][6]["len"]
    results.append(variant("fact-bytes-pin", [("E_FACT_BYTES", fact_id(p["facts"][6]["window"], p["facts"][6]["va"]))], pn=p))
    p = clone(); p["relocs"]["0x64e0148"]["addend"] += 16
    results.append(variant("reloc-addend-pin", [("E_RELOC", "0x64e0148")], pn=p))
    img = image.patched(TABLE_BASE + 4 * TABLE_INDEX, struct.pack("<i", 0x2F17EE4))
    results.append(variant("jump-table-entry", [("E_TABLE", "0x%x" % TABLE_BASE)], img=img))
    img = image.patched(0x79C888, b"X")
    results.append(variant("action-name-byte", [("E_DATA", "0x79c888")], img=img))
    p = clone(); p["calls"][1]["sites"] = [0x36B1EA2]
    results.append(variant("call-site-pin", [("E_CALLS", "dispatcher->0x46abec0")], pn=p))
    results.append(variant("finalize-pad-0x80",[("E_FACT_TEXT", fact_id("sponge_finalize", 0x5CDAE0A))],
                           img=image.patched(0x5CDAE0A + 4, bytes([0x81]))))
    p = clone(); p["callers"]["0x46abec0"] = p["callers"]["0x46abec0"] + [0x36B1EA2]
    results.append(variant("callers-pin", [("E_CALLERS", "0x46abec0")], pn=p, deep=True))
    # CLI guards
    me = os.path.abspath(__file__)
    for name, extra, want in [("no-outdir", [], 2), ("existing-outdir", ["--outdir", outdir], 4),
                              ("outdir-in-packet", ["--outdir", os.path.join(PACKET, "new-out")], 4)]:
        r = subprocess.run([sys.executable, "-I", me, "--elf", image.path_for_selftest] + extra, capture_output=True, text=True)
        ok = r.returncode == want
        say("selftest: cli %-23s exit %d %s" % (name, r.returncode, "as expected" if ok else "UNEXPECTED (want %d)" % want))
        results.append(ok)
    if meta:
        # the selftest itself must fail on a broken baseline instead of counting rejections
        broken = clone()
        broken["facts"][0]["text"] = "nop"
        say("selftest: meta control, running the selftest on a broken baseline")
        ok = selftest(image, broken, os.path.join(outdir, "meta-broken-baseline"), flips=False, meta=False) == 1
        say("selftest: meta control %s" % ("failed the broken baseline as expected" if ok else "DID NOT FAIL"))
        results.append(ok)
    passed = sum(1 for r in results if r)
    say("selftest: %d/%d controls behaved as expected" % (passed, len(results)))
    return 0 if passed == len(results) else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--elf", required=True)
    ap.add_argument("--outdir")
    ap.add_argument("--pins", default=os.path.join(PACKET, "pins.json"))
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--emit-pins", metavar="NEW_FILE")
    args = ap.parse_args()
    try:
        image = Image(args.elf)
        image.path_for_selftest = args.elf
        image.fde_table()  # cached so patched clones reuse it
        if args.emit_pins:
            emit_pins(image, args.emit_pins)
            return 0
        if not args.outdir:
            ap.error("--outdir is required")
        why = refuse_outdir(args.outdir)
        if why:
            print("verify_target: " + why, file=sys.stderr)
            return 4
        if not os.path.exists(args.pins):
            raise Env("pins file missing")
        with open(args.pins) as fh:
            pins = json.load(fh)
        if args.selftest:
            rc = selftest(image, pins, args.outdir)
            with open(os.path.join(args.outdir, "selftest.txt"), "w", newline="\n") as fh:
                fh.write("\n".join(LOG) + "\n")
            return rc
        os.makedirs(args.outdir)
        findings, result = run_verify(image, pins, args.outdir)
    except Env as exc:
        print("verify_target: environment error: %s" % exc, file=sys.stderr)
        return 3
    print("verify_target: %d facts, %d windows, bit flips %s" % (result["facts"], result["windows"], result["bitflips"]))
    for code, ident, detail in findings.items:
        print("FINDING %s %s: %s" % (code, ident, detail))
    if findings.items:
        print("verify_target: FAILED with %d findings" % len(findings.items))
        return 1
    print("verify_target: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
