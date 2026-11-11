#!/usr/bin/env python3
"""Reproducible caller census for RE-001-delegate-vtable-115 (node #115).

One streaming objdump pass over the whole binary counts every direct
call/jump and every lea that references one of the packet's routines
(the delegate-interface slot implementations) or one of the packet's
vtable bases (the construction/install sites), and records the
enclosing FDE for each site. The objdump output is consumed as a
stream, never written to disk whole. Run from the repository root:

    python3 research/work-items/RE-001-delegate-vtable-115/census.py

Writes callers.tsv next to this script (sorted by site address) and
prints the per-target counts to stdout. verify.py re-runs this script
and requires callers.tsv to come out byte-identical.
"""

import bisect
import collections
import re
import subprocess
import sys
from pathlib import Path

BINARY = Path(__file__).resolve().parents[3] / "work" / "hl-node-115.bin"

# Delegate-interface slot implementations (call/jump/lea targets).
ROUTINES = {
    0x609D760: "slot10_get",
    0x609DC40: "slot18_configure",
    0x5D32560: "slot20_init",
    0x6095E70: "slot28_shared",
    0x6096790: "slot30_shared",
    0x5D2E090: "slot38_shared",
    0x60956F0: "slot40_status_stub",
    0x609D0E0: "slot48_host_a",
    0x60986B0: "slot50_shared",
    0x6095710: "slot58_shared",
    0x609DE80: "slot60_shared",
    0x609D980: "slot68_shared",
    0x5FCC0D0: "slot70_name_env",
    0x5D32A30: "slot78_name_string",
    0x5D2E770: "slot80_isinstance",
    0x5D2CA00: "slot88_false",
    0x5D2CA10: "slot90_nickname_env",
    0x5FCC0E0: "slot98_status_stub_env",
    0x5D4D490: "slot98_unwrap",
    0x606FA20: "stats_name",
    0x606FA30: "stats_slot88",
    0x5FD6240: "mockenv_slot80",
    0x5FD4E60: "compenvwrap_name",
    0x5FE0FE0: "posixclock_name",
    0x5FE0FF0: "posixclock_nickname",
    0x5FE1000: "posixenv_name",
    0x5FE1010: "posixenv_nickname",
    0x6025790: "mockenv_name",
    0x60257A0: "emulatedclock_name",
    0x5FCF590: "scw_slot28",
    0x5FCDAE0: "scw_slot60",
    0x5FD5A00: "slot98_shared",
    0x5FD7560: "mockenv_slot28",
    0x5FD5E00: "mockenv_slot60",
    0x5FD4E70: "mockenv_slot88",
    0x5FCC3F0: "scw_slot88",
    0x5FCC100: "zero_stub_copy",
    0x6099030: "conf_slot10",
    0x60996A0: "conf_slot18",
    0x607DD50: "conf_slot38",
    0x607E420: "conf_slot48_mut",
    0x60A2470: "conf_slot48_db",
    0x6086B70: "twin_a",
    0x60A7420: "twin_b",
    0x60985E0: "conf_slot60",
    0x6095A60: "conf_slot68",
    0x5FCC410: "logger_slot10",
    0x6025980: "testmem_slot30",
    0x5FCC480: "testmem_slot50",
    0x6097110: "delegate_impl",
}

# Vtable bases (lea targets only: the construction/install sites).
VTABLES = {
    0x64CDA68: "vtable_envlogger",
    0x64CDAD0: "vtable_env",
    0x64CDD88: "vtable_systemclockwrapper",
    0x64CE2D8: "vtable_compositeenv",
    0x64CE590: "vtable_compositeenvwrapper",
    0x64CE930: "vtable_posixclock",
    0x64CEA10: "vtable_posixenv",
    0x64D1398: "vtable_mockenv",
    0x64D1650: "vtable_emulatedclock",
    0x64D1940: "vtable_mockenvdirectory",
    0x64D1980: "vtable_mockenvfilelock",
    0x64D19A0: "vtable_testmemlogger",
    0x64D1F00: "vtable_autorolllogger",
    0x64D3138: "vtable_conf_mutablecfoptions",
    0x64D31B8: "vtable_conf_cfoptions",
    0x64D3430: "vtable_configurable",
    0x64D3638: "vtable_mutabledbconfigurable",
    0x64D36B8: "vtable_dboptionsconfigurable",
    0x64D2D88: "vtable_statisticsimpl",
    0x64CF008: "vtable_filesystem",
    0x64D02E0: "vtable_posixfilesystem",
    0x64D1A08: "vtable_mockfilesystem",
}

TARGETS = dict(ROUTINES)
TARGETS.update(VTABLES)


def load_fdes(binary):
    out = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", str(binary)],
        capture_output=True, text=True, check=True).stdout
    fdes = []
    for m in re.finditer(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", out):
        fdes.append((int(m.group(1), 16), int(m.group(2), 16)))
    fdes.sort()
    return fdes


def main():
    fdes = load_fdes(BINARY)
    starts = [s for s, _ in fdes]

    def enclosing(addr):
        i = bisect.bisect_right(starts, addr) - 1
        if i < 0:
            return None
        s, e = fdes[i]
        return (s, e) if s <= addr < e else None

    proc = subprocess.Popen(
        ["objdump", "-d", "--no-show-raw-insn", str(BINARY)],
        stdout=subprocess.PIPE, text=True)
    rows = []
    counts = collections.Counter()
    line_re = re.compile(r"\s+([0-9a-f]+):\t(.*)")
    call_re = re.compile(r"\b(call|jmp)\s+([0-9a-f]+)\s")
    lea_re = re.compile(r"\blea\b.*#\s+([0-9a-f]+)")
    for line in proc.stdout:
        m = line_re.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        insn = m.group(2).strip()
        mm = call_re.search(insn)
        if mm:
            t = int(mm.group(2), 16)
            if t in ROUTINES:
                enc = enclosing(addr)
                rows.append((addr, t, ROUTINES[t],
                             "%#x..%#x" % enc if enc else "?",
                             mm.group(1)))
                counts[(ROUTINES[t], mm.group(1))] += 1
        lm = lea_re.search(insn)
        if lm:
            t = int(lm.group(1), 16)
            if t in TARGETS:
                enc = enclosing(addr)
                rows.append((addr, t, TARGETS[t],
                             "%#x..%#x" % enc if enc else "?",
                             "lea"))
                counts[(TARGETS[t], "lea")] += 1
    proc.wait()
    if proc.returncode != 0:
        print("objdump failed", file=sys.stderr)
        sys.exit(1)
    rows.sort()
    out_path = Path(__file__).resolve().parent / "callers.tsv"
    with open(out_path, "w") as f:
        f.write("site\ttarget\tcaller\tkind\n")
        for addr, t, name, enc, kind in rows:
            f.write("%#x\t%#x\t%s\t%s\n" % (addr, t, enc, kind))
    for (name, kind), n in sorted(counts.items()):
        print("%-32s %-4s %d" % (name, kind, n))
    print("rows: %d" % len(rows))


if __name__ == "__main__":
    main()
