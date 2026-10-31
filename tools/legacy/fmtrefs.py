"""Decode Rust 1.95 compact fmt templates passed to alloc::fmt::format.

Scans an llvm-objdump (intel) listing for `lea rsi, [rip ...] # 0xADDR`
followed within a few lines by a call through FORMAT_GOT, then decodes the
template bytes at ADDR (rodata file offset == vaddr): 0x00 ends, 0x01-0x7f
prefixes a literal of that length, 0xc0 is a `{}` argument, any other byte
>= 0x80 is printed as `{?xx}`.

usage: python3 -I fmtrefs.py BINARY DISASM FORMAT_GOT LO HI
"""
import re
import sys

binary, disasm, got = sys.argv[1], sys.argv[2], sys.argv[3].lower()
lo, hi = int(sys.argv[4], 16), int(sys.argv[5], 16)
data = open(binary, "rb").read()


def decode(addr, limit=400):
    if not 0 <= addr < len(data):
        return "{?out-of-range}"
    out, i = [], addr
    while i < addr + limit and i < len(data):
        b = data[i]
        if b == 0:
            break
        if b < 0x80:
            out.append(data[i + 1:i + 1 + b].decode("utf-8", "replace"))
            i += 1 + b
        elif b == 0xC0:
            out.append("{}")
            i += 1
        else:
            out.append(f"{{?{b:02x}}}")
            i += 1
    return "".join(out)


lines = open(disasm).read().splitlines()
lea = re.compile(r"^\s*([0-9a-f]+):\s+lea\s+rsi, \[rip [+-] 0x[0-9a-f]+\]\s+# 0x([0-9a-f]+)")
for n, line in enumerate(lines):
    m = lea.match(line)
    if not m:
        continue
    at, target = int(m.group(1), 16), int(m.group(2), 16)
    if not (lo <= at < hi):
        continue
    if any(f"# 0x{got}" in l and "call" in l for l in lines[n + 1:n + 4]):
        print(f"0x{at:x}  tmpl@0x{target:x}  {decode(target)!r}")
