#!/usr/bin/env python3
"""RE-001: node #94 level-stats report builder (function 0x514c580).

The target function appends a header and one formatted line per level
to an output string.  Each level is a pointer span: its (begin, end)
pair of 8-byte pointers lives in a 0x18-byte array element, and the
level's size comes from a sum function reached through a trampoline.

    span fields (array element, stride 0x18):
        +0x00  begin pointer (first 8-byte pointer of the span)
        +0x08  end pointer (one past the last 8-byte pointer)
        +0x10  third field, read only by the sum function

File count for a level is (end - begin) / 8, computed directly in
the main function.  Size for a level is the sum function: it adds the
+0x10 field of each pointer in the leading run of non-null pointers
in the span and stops at the first null pointer; an empty span
(begin == end) sums to 0.  The sum, an int64, is converted to a
double as an *unsigned* value and multiplied by 2**-20, so the size
column is MiB.  Lines are formatted with ``%3d %8d %8.0f\\n`` as
(index, file count, MiB).

Every append is guarded: with remaining = 0x3fffffffffffffff -
current length, an append whose text is longer than remaining throws
length_error("basic_string::append") instead of appending.  The
function returns 1 on success; the observable output is the text
appended to the output string.

The model takes spans as objects, not raw pointers: a span's pointer
array is a list whose entries are None (a null pointer, which ends
the sum) or the entry's +0x10 field value.  A span presupposes
end >= begin, as the binary's empty-span arm presupposes begin ==
end for zero; negative-count spans are a corrupt-input edge and are
not modelled.

Stdlib only.  ``check_packet`` verifies a packet directory against a
node #94 binary; it returns a list of error strings (empty = pass).
"""

import hashlib
import json
import os
import struct
import sys

TARGET_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
TARGET_SIZE = 91774280
FUNC_START = 0x514C580
FUNC_END = 0x514C74E
CLEANUP_START = 0x514C74E
CLEANUP_END = 0x514C774
TRAMPOLINE_START = 0x51CBCD0
TRAMPOLINE_END = 0x51CBCEB
SUM_START = 0x50047B0
SUM_END = 0x50047EE

HEADER = "Level Files Size(MB)\n--------------------\n"
LINE_FORMAT = "%3d %8d %8.0f\n"
MAX_APPEND = 0x3FFFFFFFFFFFFFFF
MIB_SCALE = 2.0 ** -20
ELEMENT_STRIDE = 0x18


class AppendLengthError(Exception):
    """The binary's length_error("basic_string::append")."""


class Span:
    """One level's pointer span: a list of entries, None = null pointer.

    ``entries[i]`` is the +0x10 field of the i-th pointer in the span,
    or None when that pointer is null.  ``len(entries)`` is the file
    count, (end - begin) / 8 in the binary's terms.
    """

    def __init__(self, entries):
        self.entries = list(entries)

    def file_count(self):
        return len(self.entries)

    def size_bytes(self):
        """The sum function: leading non-null run, empty span is 0."""
        total = 0
        for entry in self.entries:
            if entry is None:
                break
            total += entry
        return total

    def size_mib(self):
        """Unsigned int64 -> double, scaled by 2**-20, as the binary does."""
        total = self.size_bytes() & 0xFFFFFFFFFFFFFFFF
        return float(total) * MIB_SCALE


def level_line(index, span):
    """One formatted line: "%3d %8d %8.0f\\n" % (index, files, MiB)."""
    return LINE_FORMAT % (index, span.file_count(), span.size_mib())


def append_guarded(out, text, max_append=MAX_APPEND):
    """Append with the binary's length guard; raises on overflow."""
    if max_append - len(out) < len(text):
        raise AppendLengthError("basic_string::append")
    return out + text


def build_report(count, spans, max_append=MAX_APPEND):
    """Append the header plus ``count`` level lines; returns the text.

    ``spans`` supplies at least ``count`` spans; extra spans are
    ignored, matching the binary's count-driven loop.  Returns the
    appended text (the binary returns 1 and appends to its string
    argument; the text is the observable output).
    """
    out = append_guarded("", HEADER, max_append)
    for index in range(count):
        out = append_guarded(out, level_line(index, spans[index]),
                             max_append)
    return out


class _Elf:
    """Minimal ELF64 reader: PT_LOAD mapping only."""

    def __init__(self, data):
        self.data = data
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise ValueError("not a 64-bit little-endian ELF file")
        (self.e_phoff,) = struct.unpack_from("<Q", data, 0x20)
        (self.e_phentsize, self.e_phnum) = struct.unpack_from("<HH", data, 0x36)
        self.loads = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            (p_type, _flags, p_offset, p_vaddr, _paddr,
             p_filesz, _memsz, _align) = struct.unpack_from(
                "<IIQQQQQQ", data, off)
            if p_type == 1:
                self.loads.append((p_vaddr, p_offset, p_filesz))

    def read(self, va, size):
        for vaddr, offset, filesz in self.loads:
            if vaddr <= va < vaddr + filesz:
                return self.data[offset + (va - vaddr):
                                 offset + (va - vaddr) + size]
        raise ValueError("VA %#x not in any PT_LOAD segment" % va)


def strip_objdump_header(text):
    """Drop objdump's filename header lines, which embed the binary path.

    Every objdump run starts with a "<path>: file format ..." line;
    plt.objdump.txt concatenates several runs, so all such lines are
    removed. The disassembly lines that follow are the evidence; the
    header lines differ only in how the binary path was spelled on
    the command line. Accepts str or bytes and returns the same type.
    """
    if isinstance(text, bytes):
        sep, needle = b"\n", b"file format elf"
    else:
        sep, needle = "\n", "file format elf"
    lines = text.split(sep)
    kept = [line for line in lines if needle not in line]
    return sep.join(kept)


def _rel_target(elf, site, length):
    raw = elf.read(site, length)
    if length == 2:
        (disp,) = struct.unpack_from("<b", raw, 1)
    elif length == 5:
        (disp,) = struct.unpack_from("<i", raw, 1)
    elif length == 6:
        (disp,) = struct.unpack_from("<i", raw, 2)
    else:
        raise ValueError("unsupported branch length %d" % length)
    return site + length + disp


def check_packet(packet_dir, binary_path):
    """Verify the packet against a node #94 binary; [] means pass."""
    errors = []
    records_path = os.path.join(packet_dir, "records.json")
    try:
        with open(records_path) as f:
            rec = json.load(f)
    except (OSError, ValueError) as exc:
        return ["cannot read records.json: %s" % exc]
    try:
        with open(binary_path, "rb") as f:
            data = f.read()
    except OSError as exc:
        return ["cannot read binary: %s" % exc]
    if hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        errors.append("target digest mismatch")
    if len(data) != TARGET_SIZE:
        errors.append("target size mismatch")
    elf = _Elf(data)
    parts = (("function", FUNC_START, FUNC_END, 0),
             ("cleanup", CLEANUP_START, CLEANUP_END, 12),
             ("trampoline", TRAMPOLINE_START, TRAMPOLINE_END, 5),
             ("sum", SUM_START, SUM_END, 2))
    for key, start, end, padding in parts:
        part = rec[key]
        blob = elf.read(start, end - start)
        if hashlib.sha256(blob).hexdigest() != part["sha256"]:
            errors.append("%s SHA mismatch" % key)
        if elf.read(end, padding) != b"\xcc" * padding:
            errors.append("%s padding is not int3" % key)
    for call in rec["calls"]:
        if _rel_target(elf, int(call["site"], 16), 5) != \
                int(call["target"], 16):
            errors.append("call %s target mismatch" % call["site"])
    for branch in rec["branches"]:
        if _rel_target(elf, int(branch["site"], 16),
                       branch["length"]) != int(branch["target"], 16):
            errors.append("branch %s target mismatch" % branch["site"])
    for entry in rec["plt"]:
        sva = int(entry["stub_va"], 16)
        raw = elf.read(sva, 6)
        (disp,) = struct.unpack_from("<i", raw, 2)
        if raw[0] != 0xFF or raw[1] != 0x25 or \
                sva + 6 + disp != int(entry["got_va"], 16):
            errors.append("PLT stub %s GOT mismatch" % entry["stub_va"])
    # Excerpt bytes: each shipped excerpt must match a fresh objdump
    # range for its function, so the packet's raw disassembly is
    # byte-identical to the binary's own disassembly. The range stop
    # is the next FDE start, so each excerpt includes its int3
    # padding, exactly as export_excerpts.py generates it.
    try:
        import subprocess
        ranges = (("window.objdump.txt", FUNC_START, 0x514C74E),
                  ("cleanup.objdump.txt", CLEANUP_START, 0x514C780),
                  ("trampoline.objdump.txt", TRAMPOLINE_START, 0x51CBCF0),
                  ("sum.objdump.txt", SUM_START, 0x50047F0))
        for name, start, end in ranges:
            result = subprocess.run(
                ["objdump", "-d",
                 "--start-address=%#x" % start,
                 "--stop-address=%#x" % end, binary_path],
                capture_output=True, text=True)
            with open(os.path.join(packet_dir, name)) as f:
                if strip_objdump_header(result.stdout) != \
                        strip_objdump_header(f.read()):
                    errors.append("excerpt %s mismatch" % name)
    except OSError as exc:
        errors.append("excerpt check failed: %s" % exc)
    try:
        with open(os.path.join(packet_dir, "MANIFEST.sha256")) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                digest, name = line.split(None, 1)
                with open(os.path.join(packet_dir, name.strip()),
                          "rb") as pf:
                    if hashlib.sha256(pf.read()).hexdigest() != digest:
                        errors.append("MANIFEST mismatch for %s" % name)
    except OSError as exc:
        errors.append("cannot verify MANIFEST: %s" % exc)
    return errors
