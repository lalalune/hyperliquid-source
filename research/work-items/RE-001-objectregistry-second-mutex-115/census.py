"""Census for RE-001-objectregistry-second-mutex-115.

Whole-binary census of every pthread-mutex operation and every access
to the ObjectRegistry +0x70..0x98 region, answering #4015's open
unknown: what lives at registry +0x70..0x98.

Method (same family as the RE-001-registrar-map-115 packet):
  * FDE ranges from `objdump --dwarf=frames` (objdump has no function
    boundaries in this stripped binary).
  * One streaming `objdump -d` pass over the whole binary records:
      - every call to the pthread_mutex_* PLT stubs (lock, unlock,
        trylock, init, destroy) with enclosing FDE and the instruction
        that sets %rdi (the mutex address): lea displacement when
        direct, else the register source;
      - every call to the std::mutex-destructor helper 0x60d5170
        (the binary's only pthread_mutex_destroy call site lives
        inside it) with enclosing FDE and %rdi source;
      - every instruction with a memory displacement in [0x70, 0x98)
        inside an FDE that carries a registry marker (a call to a
        registry routine, or a lea of a registry global).
  * `readelf -r` records for the mutex PLT/GOT slots and the
    ObjectRegistry control-block vtable RELATIVE region (re-shipped
    from #4015 for the vtable part).

Writes lock-sites.tsv, destroy-sites.tsv, disp-hits.tsv,
marked-fdes.txt, callers.tsv and relocations.txt into this packet
directory.

Run from the repository root:
    python3 research/work-items/RE-001-objectregistry-second-mutex-115/census.py
"""

import bisect
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = os.path.join(ROOT, "work", "hl-node-115.bin")
BIN_REL = "work/hl-node-115.bin"

PLT = {
    0x63F0B60: "pthread_mutex_lock",
    0x63F0B70: "pthread_mutex_unlock",
    0x63F14B0: "pthread_mutex_init",
    0x63F17A0: "pthread_mutex_destroy",
    0x63F17B0: "pthread_mutex_trylock",
}
DESTROY_HELPER = 0x60D5170

# Registry routines (direct call targets) and globals (lea targets).
REG_CALLS = {
    0x61F91B0,  # ctor
    0x61F92B0,  # getter
    0x61F9400,  # clone (NewInstance)
    0x61F8DC0,  # AddLibrary
    0x62069F0,  # TTL register
    0x5FF88C0,  # big registry method (encryption host, #4028)
    0x60BB890,  # NewInstance wrapper (per #4108)
    0x61F8760,  # control-block _M_dispose
    0x61F8B60,  # ObjectLibrary::Default (getter init path)
}
REG_GLOBALS = {0x6509540, 0x6509100, 0x65090F8, 0x64D8EF0, 0x64D8F00}

# Registry field offsets (object base).
REGISTRY_SIZE = 0xC0
OBJECTS_MUTEX = 0x70
LIBRARY_MUTEX = 0x98
MUTEX_SIZE = 0x28

GETTER = 0x61F92B0


def fde_map():
    out = subprocess.run(["objdump", "--dwarf=frames", BIN_REL],
                         cwd=ROOT, capture_output=True, text=True,
                         check=True).stdout
    fdes = []
    for m in re.finditer(r"FDE cie=\S+ pc=([0-9a-f]+)\.\.([0-9a-f]+)", out):
        fdes.append((int(m.group(1), 16), int(m.group(2), 16)))
    fdes.sort()
    return fdes


INSN_RE = re.compile(r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*\t(.*)$")
LEA_RDI_RE = re.compile(r"lea\s+0x([0-9a-f]+)\(%([a-z0-9]+)\),%rdi$")
LEA_REG_RE = re.compile(r"lea\s+0x([0-9a-f]+)\(%([a-z0-9]+)\),%([a-z0-9]+)$")
MOV_RDI_RE = re.compile(r"mov\s+%([a-z0-9]+),%rdi$")
CALL_RE = re.compile(r"\bcall\s+([0-9a-f]+)\s+<")
DISP_RE = re.compile(r"0x([0-9a-f]+)\(%([a-z0-9]+)\)")


def rdi_source(window):
    """Walk backwards over the recent instructions; find what set %rdi."""
    for addr, text in reversed(window):
        m = LEA_RDI_RE.search(text)
        if m:
            return ("lea_rdi", int(m.group(1), 16), m.group(2), addr)
        m = MOV_RDI_RE.search(text)
        if m:
            src = m.group(1)
            for addr2, text2 in reversed(window):
                m2 = LEA_REG_RE.search(text2)
                if m2 and m2.group(3) == src:
                    return ("lea_then_mov", int(m2.group(1), 16),
                            m2.group(2), addr2)
            return ("mov_rdi", None, src, addr)
        if re.search(r"\bmov\s+0x[0-9a-f]+\(%[a-z0-9]+\),%rdi", text):
            return ("load_rdi", None, text, addr)
    return ("unknown", None, "", None)


def is_registry_marked(insns):
    for _addr, text in insns:
        m = CALL_RE.search(text)
        if m and int(m.group(1), 16) in REG_CALLS:
            return True
        if "lea" in text and "#" in text:
            tgt = text.rsplit("#", 1)[1].strip().split()[0]
            try:
                if int(tgt, 16) in REG_GLOBALS:
                    return True
            except ValueError:
                pass
    return False


def scan():
    fdes = fde_map()
    starts = [s for s, _ in fdes]

    def fde_of(addr):
        i = bisect.bisect_right(starts, addr) - 1
        if i < 0:
            return None
        s, e = fdes[i]
        return s if addr < e else None

    lock_sites = []      # (addr, fde, call, rdi_kind, rdi_disp, rdi_base)
    destroy_sites = []   # (addr, fde, rdi_kind, rdi_disp, rdi_base)
    marked_fdes = set()
    disp_hits = []       # (addr, fde, text)
    getter_calls = []    # (addr, fde)
    cur_fde_insns = []
    cur_fde = None
    window = []

    def flush():
        nonlocal cur_fde_insns
        if cur_fde is None or not cur_fde_insns:
            cur_fde_insns = []
            return
        if is_registry_marked(cur_fde_insns):
            marked_fdes.add(cur_fde)
            for addr, text in cur_fde_insns:
                for dm in DISP_RE.finditer(text):
                    if OBJECTS_MUTEX <= int(dm.group(1), 16) < LIBRARY_MUTEX:
                        disp_hits.append((addr, cur_fde, text))
        cur_fde_insns = []

    proc = subprocess.Popen(["objdump", "-d", BIN_REL], cwd=ROOT,
                            stdout=subprocess.PIPE, text=True,
                            bufsize=1 << 20)
    for line in proc.stdout:
        im = INSN_RE.match(line.rstrip("\n"))
        if not im:
            continue
        addr = int(im.group(1), 16)
        text = im.group(3)
        fde = fde_of(addr)
        if fde != cur_fde:
            flush()
            cur_fde = fde
            window = []
        cur_fde_insns.append((addr, text))
        window.append((addr, text))
        if len(window) > 40:
            window.pop(0)
        cm = CALL_RE.search(text)
        if cm:
            tgt = int(cm.group(1), 16)
            kind, disp, base, _at = rdi_source(window[:-1])
            if tgt in PLT:
                lock_sites.append((addr, fde, PLT[tgt], kind, disp, base))
            if tgt == DESTROY_HELPER:
                destroy_sites.append((addr, fde, kind, disp, base))
            if tgt == GETTER:
                getter_calls.append((addr, fde))
    flush()
    proc.wait()
    return lock_sites, destroy_sites, marked_fdes, disp_hits, getter_calls


def relocations():
    out = subprocess.run(["readelf", "-rW", BIN], capture_output=True,
                         text=True, check=True).stdout
    rows = []
    want_offsets = {
        0x64E2300, 0x64E2308,  # pthread_mutex_lock/unlock GLOB_DAT
        0x64EE200, 0x64EE208,  # pthread_mutex_lock/unlock JUMP_SLOT
        0x64EE6A8, 0x64EE820, 0x64EE828,  # init/destroy/trylock JUMP_SLOT
    }
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-f]+)\s+[0-9a-f]+\s+(R_X86_64_\S+)\s+([0-9a-f]+)(?:\s+(.*))?$", line)
        if not m:
            continue
        off = int(m.group(1), 16)
        if off in want_offsets or 0x64D8E80 <= off <= 0x64D8F40 or off == 0x64ECDC8:
            rows.append((off, m.group(2), m.group(3),
                         (m.group(4) or "").strip()))
    rows.sort()
    return rows


def main():
    lock_sites, destroy_sites, marked_fdes, disp_hits, getter_calls = scan()
    relocs = relocations()
    from collections import Counter
    print("mutex PLT call sites: %d %s" % (
        len(lock_sites), dict(Counter(s[2] for s in lock_sites))))
    print("destroy-helper call sites: %d" % len(destroy_sites))
    print("registry-marked FDEs: %d" % len(marked_fdes))
    print("disp 0x70..0x97 hits in marked FDEs: %d" % len(disp_hits))
    print("getter calls: %s" % [hex(a) for a, _ in getter_calls])

    def w(name, header, rows):
        with open(os.path.join(HERE, name), "w") as fh:
            fh.write(header + "\n")
            for r in rows:
                fh.write("\t".join("" if v is None else str(v) for v in r) + "\n")

    w("lock-sites.tsv",
      "site\tcontaining_fde\tcall\trdi_kind\trdi_disp\trdi_base",
      [(hex(a), hex(f) if f else "", c, k,
        hex(d) if d is not None else "", b)
       for a, f, c, k, d, b in lock_sites])
    w("destroy-sites.tsv",
      "site\tcontaining_fde\trdi_kind\trdi_disp\trdi_base",
      [(hex(a), hex(f) if f else "", k,
        hex(d) if d is not None else "", b)
       for a, f, k, d, b in destroy_sites])
    w("disp-hits.tsv", "site\tcontaining_fde\tinstruction",
      [(hex(a), hex(f), t) for a, f, t in disp_hits])
    with open(os.path.join(HERE, "marked-fdes.txt"), "w") as fh:
        for f in sorted(marked_fdes):
            fh.write("%#x\n" % f)

    # callers.tsv: the sites this packet's claims rest on.
    rows = []
    for a, f, c, k, d, b in lock_sites:
        if d in (OBJECTS_MUTEX, LIBRARY_MUTEX):
            rows.append((hex(a), c, hex(f) if f else "",
                         "mutex@+%#x" % d))
    for a, f, k, d, b in destroy_sites:
        rows.append((hex(a), "destroy-helper-call", hex(f) if f else "",
                     "rdi %s%s" % (k, ("+%#x" % d) if d is not None else "")))
    for a, f in getter_calls:
        rows.append((hex(a), "call-getter", hex(f) if f else "", ""))
    rows.sort(key=lambda r: int(r[0], 16))
    w("callers.tsv", "site\tkind\tcontaining_fde\tnote", rows)

    with open(os.path.join(HERE, "relocations.txt"), "w") as fh:
        fh.write("offset\ttype\taddend\tsymbol\n")
        for off, typ, addend, sym in relocs:
            fh.write("%#x\t%s\t%s\t%s\n" % (off, typ, addend, sym))
    print("wrote lock-sites.tsv (%d), destroy-sites.tsv (%d), "
          "disp-hits.tsv (%d), callers.tsv (%d), relocations.txt (%d)"
          % (len(lock_sites), len(destroy_sites), len(disp_hits),
             len(rows), len(relocs)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
