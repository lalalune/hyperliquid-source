"""Find R_X86_64_RELATIVE relocations that point into given string addresses.

For each hit, print the slot address and the neighbouring slots as (ptr, len)
pairs resolved to strings, which is how Rust lays out &str tables.

usage: python3 -I elfrel.py FILE VADDR [VADDR ...]
"""
import struct
import sys

path = sys.argv[1]
targets = [int(a, 16) for a in sys.argv[2:]]
data = open(path, "rb").read()

shoff, = struct.unpack_from("<Q", data, 0x28)
shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
secs = []
for i in range(shnum):
    name, typ, flags, addr, off, size = struct.unpack_from("<IIQQQQ", data, shoff + i * shentsize)
    secs.append([name, typ, addr, off, size])
strtab_off = secs[shstrndx][3]
strtab_size = secs[shstrndx][4]
strtab = data[strtab_off:strtab_off + strtab_size]
for s in secs:
    if s[0] >= len(strtab):
        raise SystemExit(f"{path}: section name offset {s[0]} outside .shstrtab")
    end = strtab.find(b"\0", s[0])
    if end < 0:
        raise SystemExit(f"{path}: unterminated section name at offset {s[0]}")
    s[0] = strtab[s[0]:end].decode()
by_name = {s[0]: s for s in secs}


def v2o(vaddr):
    for name, typ, addr, off, size in secs:
        if addr and addr <= vaddr < addr + size and typ != 8:  # skip NOBITS
            return off + (vaddr - addr)
    return None


relative = {}
_, _, _, off, size = by_name[".rela.dyn"]
for i in range(0, size, 24):
    r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off + i)
    if r_info & 0xFFFFFFFF == 8:  # R_X86_64_RELATIVE
        relative[r_offset] = r_addend


def text_at(vaddr, n):
    o = v2o(vaddr)
    if o is None:
        return "?"
    return "".join(chr(b) if 32 <= b < 127 else "·" for b in data[o:o + n])


def word(vaddr):
    o = v2o(vaddr)
    return struct.unpack_from("<Q", data, o)[0] if o is not None else None


for t in targets:
    slots = sorted(s for s, a in relative.items() if a == t)
    print(f"=== target 0x{t:x} {text_at(t, 48)!r}: {len(slots)} slot(s)")
    for slot in slots[:8]:
        print(f"--- slot 0x{slot:x}")
        for k in range(-6, 8):
            sv = slot + 16 * k
            ptr = relative.get(sv)
            ln = word(sv + 8)
            if ptr is None:
                print(f"  0x{sv:x}: (no reloc) word=0x{(word(sv) or 0):x}")
                continue
            shown = text_at(ptr, min(ln or 0, 80)) if ln and ln < 4096 else text_at(ptr, 40) + " …"
            print(f"  0x{sv:x}: ptr=0x{ptr:x} len={ln} {shown!r}")
