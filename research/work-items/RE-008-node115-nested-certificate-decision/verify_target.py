#!/usr/bin/env python3
"""Static byte checks for the node #115 nested certificate flow (nothing is executed).

Usage:
  python3 -I verify_target.py <hl-node> <packet dir> --outdir NEW_DIR [--pins FILE] [--no-flips]
  python3 -I verify_target.py <hl-node> <packet dir> --outdir NEW_DIR --record     (writes functions.tsv there)
  python3 -I verify_target.py <hl-node> <packet dir> --outdir NEW_DIR --selftest   (negative controls)

--outdir is required and must not exist yet or be an empty directory outside the packet; every file this tool
writes goes there and the packet is never written (a snapshot of all packet files is compared at the end and
a difference is itself a failure). Exit status 0 only if every check below passes; any failure prints FAIL
lines and exits 1; the report.txt written to --outdir has the same lines.

 1. SHA-256 of the artifact.
 2. Every function in functions.tsv starts and ends exactly at its .eh_frame FDE, and the bytes
    hash to the recorded SHA-256.
 3. Each function is disassembled twice with GNU objdump (raw bytes as a binary blob, and from the
    ELF). The address sets and every decoded text must agree both ways (no row may exist on one
    side only).
 4. Every row of pins.tsv (function, address, decoded text) must be an instruction of that
    function with exactly that text, in both decodes.
 5. Every trace item ("address decoded text") in the `trace` column of relations*.tsv is a pin as well,
    checked exactly like the rows of pins.tsv.
 6. Every constant in data-pins.tsv (address, hex bytes) must match the file bytes.
 7. Every row of reloc-pins.tsv (slot, addend) must be an R_X86_64_RELATIVE entry of .rela.dyn with that addend.
 8. A one-bit flip in every byte of every pinned instruction (in a copy of the function bytes)
    must break at least one pin. A flip that leaves every decoded text of the function unchanged (an
    encoding no-op such as the REX.B bit of a RIP-relative instruction) cannot be seen by a text pin; it is
    counted separately (only the function hash of check 2 sees it). Any other undetected flip fails the run.
--selftest first runs checks 1-7 on the unmodified inputs and exits 1 if that baseline has any failure (so a
broken input can never be "rejected 10 of 10"). It then damages the inputs one way at a time (wrong pin text, pin
at a non-instruction address, pin outside every function, unknown function, relation item with wrong text or
without an address, wrong function hash, wrong FDE end, wrong data constant, wrong relocation addend, a bit
flipped in the artifact copy) and requires, for each damage, a FAIL line of the kind that damage causes; exit 1
unless every damage is rejected for its own reason.
"""
import argparse
import hashlib
import os
import re
import struct
import subprocess
import sys
import tempfile

SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def read_tsv(path):
    with open(path, encoding="utf-8") as f:
        rows = [l.rstrip("\n").split("\t") for l in f if l.strip()]
    return rows[0], rows[1:]


class Elf:
    def __init__(self, data):
        self.data = data
        shoff, = struct.unpack_from("<Q", data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
        secs = []
        for i in range(shnum):
            name, typ, flags, addr, off, size = struct.unpack_from("<IIQQQQ", data, shoff + i * shentsize)
            secs.append((name, addr, off, size))
        stroff = secs[shstrndx][2]
        self.sec = {}
        for name, addr, off, size in secs:
            end = data.index(b"\0", stroff + name)
            self.sec[data[stroff + name:end].decode()] = (addr, off, size)
        self._rela = None

    def va_to_off(self, va):
        for name in (".text", ".plt", ".rodata", ".init", ".plt.sec"):
            if name in self.sec:
                a, o, s = self.sec[name]
                if a <= va < a + s:
                    return o + (va - a)
        raise KeyError(hex(va))

    def rela(self):
        """.rela.dyn as {r_offset: (type, addend)}."""
        if self._rela is None:
            _, off, size = self.sec[".rela.dyn"]
            self._rela = {}
            for i in range(size // 24):
                r_off, r_info, r_add = struct.unpack_from("<QQq", self.data, off + i * 24)
                self._rela[r_off] = (r_info & 0xFFFFFFFF, r_add)
        return self._rela

    def fde_for(self, va):
        """Return (pc_begin, pc_end) of the FDE whose table entry is the last one <= va."""
        hdr_a, hdr_o, _ = self.sec[".eh_frame_hdr"]
        d = self.data
        ver, ptr_enc, cnt_enc, tab_enc = d[hdr_o:hdr_o + 4]
        if (ver, cnt_enc, tab_enc) != (1, 0x03, 0x3B):
            raise ValueError("unexpected .eh_frame_hdr encoding")
        count, = struct.unpack_from("<I", d, hdr_o + 8)
        tab = hdr_o + 12
        lo, hi = 0, count
        while lo < hi:
            mid = (lo + hi) // 2
            init, = struct.unpack_from("<i", d, tab + mid * 8)
            if hdr_a + init <= va:
                lo = mid + 1
            else:
                hi = mid
        if lo == 0:
            raise KeyError(hex(va))
        init, fde = struct.unpack_from("<ii", d, tab + (lo - 1) * 8)
        fde_off = hdr_o + fde
        length, cie_ptr = struct.unpack_from("<II", d, fde_off)
        cie_off = fde_off + 4 - cie_ptr
        aug_end = d.index(b"\0", cie_off + 9)
        aug = d[cie_off + 9:aug_end]
        if not aug.startswith(b"z"):
            raise ValueError("unexpected CIE augmentation %r" % aug)
        pos = aug_end + 1

        def uleb(p):
            v = s = 0
            while True:
                b = d[p]
                p += 1
                v |= (b & 0x7F) << s
                s += 7
                if not b & 0x80:
                    return v, p

        _, pos = uleb(pos)        # code alignment
        while d[pos] & 0x80:      # data alignment (signed LEB128)
            pos += 1
        pos += 1
        pos += 1                  # return address register (CIE version 1)
        _, pos = uleb(pos)        # augmentation data length
        sizes = {0x0: 8, 0x2: 2, 0x3: 4, 0x4: 8, 0xA: 2, 0xB: 4, 0xC: 8}
        fde_enc = None
        for ch in aug[1:]:
            if ch == ord("P"):
                enc = d[pos]
                pos += 1 + sizes[enc & 0x0F]
            elif ch == ord("L"):
                pos += 1
            elif ch == ord("R"):
                fde_enc = d[pos]
                pos += 1
            else:
                raise ValueError("unexpected CIE augmentation %r" % aug)
        if fde_enc != 0x1B:
            raise ValueError("unexpected FDE pointer encoding %r" % fde_enc)
        begin_field_va = hdr_a + (fde_off + 8 - hdr_o)
        begin_rel, rng = struct.unpack_from("<ii", d, fde_off + 8)
        begin = begin_field_va + begin_rel
        if begin != hdr_a + init:
            raise ValueError("FDE and table disagree")
        return begin, begin + rng


def disasm(path, cwd, extra, raw):
    flag = "-D" if raw else "-d"
    r = subprocess.run(["objdump", flag, "--no-show-raw-insn"] + extra + [path], cwd=cwd,
                       capture_output=True, text=True, check=True)
    rows = {}
    for line in r.stdout.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\t(.*)$", line)
        if m:
            text = re.sub(r"\s+#.*$", "", m.group(2))
            text = re.sub(r"\s*<[^>]*>", "", text)
            text = re.sub(r"^(j\w+|call) 0x([0-9a-f]+)$", r"\1 \2", re.sub(r"\s+", " ", text).strip())
            rows[int(m.group(1), 16)] = text
    return r.stdout, rows


def decode_raw(code, start, tmp):
    name = os.path.join(tmp, "slice.bin")
    with open(name, "wb") as f:
        f.write(code)
    return disasm("slice.bin", tmp, ["-b", "binary", "-m", "i386:x86-64", "--adjust-vma=0x%x" % start], True)


class Packet:
    def __init__(self, target, packet, pins_file=None):
        self.target, self.packet = target, packet
        _, frows = read_tsv(os.path.join(packet, "functions.tsv"))
        self.funcs = {r[0]: (int(r[1], 16), int(r[2], 16), r[3]) for r in frows}
        _, prows = read_tsv(pins_file or os.path.join(packet, "pins.tsv"))
        self.pins = [(r[0], int(r[1], 16), r[2]) for r in prows]
        # Every trace item of relations*.tsv ("address decoded text", separated by " ; ") is a pin too.
        self.relations = []
        for name in sorted(os.listdir(packet)):
            if name.startswith("relations") and name.endswith(".tsv"):
                _, rrows = read_tsv(os.path.join(packet, name))
                self.relations += [(r[0], r[1], r[-1]) for r in rrows]
        _, drows = read_tsv(os.path.join(packet, "data-pins.tsv"))
        self.data_pins = [(int(r[0], 16), r[1]) for r in drows]
        _, rrows = read_tsv(os.path.join(packet, "reloc-pins.tsv"))
        self.reloc_pins = [(int(r[0], 16), int(r[1], 16)) for r in rrows]


def check(elf, pk, errors, record=False, outdir=None, flips=True):
    """Run every check, appending FAIL strings to errors. Returns the summary dict."""
    summary = {}
    code = {}
    base_rows = {}
    elf_rows = {}
    elf_text = []
    with tempfile.TemporaryDirectory() as tmp:
        for name, (start, end, sha) in pk.funcs.items():
            try:
                b, e = elf.fde_for(start)
                if (b, e) != (start, end):
                    errors.append("FAIL fde %s: FDE is 0x%x..0x%x, packet says 0x%x..0x%x" % (name, b, e, start, end))
            except (KeyError, ValueError, struct.error) as ex:
                errors.append("FAIL fde %s: %r" % (name, ex))
            off = elf.va_to_off(start)
            code[name] = elf.data[off:off + (end - start)]
            got = hashlib.sha256(code[name]).hexdigest()
            if not record and got != sha:
                errors.append("FAIL sha %s: %s != %s" % (name, got, sha))
            _, base_rows[name] = decode_raw(code[name], start, tmp)
            text, elf_rows[name] = disasm(os.path.abspath(pk.target), tmp,
                                          ["--start-address=0x%x" % start, "--stop-address=0x%x" % end], False)
            elf_text.append(text.replace(os.path.abspath(pk.target), "hl-node", 1))
            only = sorted(set(base_rows[name]) ^ set(elf_rows[name]))
            diff = [a for a in base_rows[name] if a in elf_rows[name] and base_rows[name][a] != elf_rows[name][a]]
            if only or diff:
                errors.append("FAIL decode %s: %d address(es) on one side only, %d text differences"
                              % (name, len(only), len(diff)))
            summary["rows_" + name] = len(base_rows[name])
        if record:
            return summary, code, elf_text

        all_pins = list(pk.pins)
        cited = 0
        for fn, path, trace in pk.relations:
            for item in [t.strip() for t in trace.split(" ; ") if t.strip()]:
                m = re.match(r"^([0-9a-f]{6,8}) (.+)$", item)
                if not m:
                    errors.append("FAIL relation %s %s: malformed trace item %r" % (fn, path, item))
                    continue
                cited += 1
                all_pins.append((fn, int(m.group(1), 16), m.group(2)))
        summary["relation_trace_items"] = cited

        by_fn = {}
        for fn, addr, text in all_pins:
            if fn not in pk.funcs:
                errors.append("FAIL pin 0x%x: unknown function %s" % (addr, fn))
                continue
            if (addr, text) not in by_fn.setdefault(fn, []):
                by_fn[fn].append((addr, text))
            start, end, _ = pk.funcs[fn]
            if not start <= addr < end:
                errors.append("FAIL pin 0x%x outside %s" % (addr, fn))
            for side, rows in (("raw", base_rows[fn]), ("elf", elf_rows[fn])):
                if rows.get(addr) != text:
                    errors.append("FAIL pin %s 0x%x: %s decode is %r, pin says %r"
                                  % (fn, addr, side, rows.get(addr), text))
        summary["pins_tsv_rows"] = len(pk.pins)
        summary["distinct_pinned_instructions"] = len({(fn, a) for fn, a, _ in all_pins if fn in pk.funcs})

        for addr, hexbytes in pk.data_pins:
            off = elf.va_to_off(addr)
            have = elf.data[off:off + len(hexbytes) // 2].hex()
            if have != hexbytes:
                errors.append("FAIL data 0x%x: %s != %s" % (addr, have, hexbytes))
        summary["data_pins"] = len(pk.data_pins)

        rela = elf.rela()
        for slot, addend in pk.reloc_pins:
            have = rela.get(slot)
            if have != (8, addend):
                errors.append("FAIL reloc 0x%x: .rela.dyn has %r, pin says RELATIVE addend 0x%x" % (slot, have, addend))
        summary["reloc_pins"] = len(pk.reloc_pins)

        if outdir:
            lines = ["fn\taddress\tlength\tbytes\ttext"]
            for fn, plist in by_fn.items():
                start, end, _ = pk.funcs[fn]
                addrs = sorted(base_rows[fn])
                lens = {a: (addrs[i + 1] if i + 1 < len(addrs) else end) - a for i, a in enumerate(addrs)}
                for a, t in sorted(plist):
                    n = lens.get(a, 0)
                    lines.append("%s\t0x%x\t%d\t%s\t%s" % (fn, a, n, code[fn][a - start:a - start + n].hex(), t))
            with open(os.path.join(outdir, "pin-bytes.tsv"), "w", newline="\n") as f:
                f.write("\n".join(lines) + "\n")

        total = detected = equivalent = 0
        if flips:
            for fn, plist in by_fn.items():
                start, end, _ = pk.funcs[fn]
                addrs = sorted(base_rows[fn])
                lens = {a: (addrs[i + 1] if i + 1 < len(addrs) else end) - a for i, a in enumerate(addrs)}
                for a, _t in plist:
                    for k in range(lens.get(a, 0)):
                        pos = a - start + k
                        mut = bytearray(code[fn])
                        mut[pos] ^= 0x01
                        _, rows = decode_raw(bytes(mut), start, tmp)
                        total += 1
                        if any(rows.get(pa) != pt for pa, pt in plist):
                            detected += 1
                        elif rows == base_rows[fn]:
                            # the flip changed no decoded text anywhere (for example the REX.B bit of an
                            # instruction whose only register operand is %rip): no pin can see it, the
                            # function hash of check 2 does
                            equivalent += 1
                        else:
                            errors.append("FAIL flip %s 0x%x+%d not detected" % (fn, a, k))
        summary["bit_flips_tried"] = total
        summary["bit_flips_detected_by_pin_text"] = detected
        summary["bit_flips_text_equivalent_hash_only"] = equivalent
    if outdir:
        with open(os.path.join(outdir, "function.asm"), "w", newline="\n") as f:
            f.write("".join(elf_text))
    return summary, code, elf_text


# (name, regex that one of the FAIL lines must match)
CONTROLS = [
    ("wrong pin text", r"^FAIL pin .*decode is"),
    ("pin at a non-instruction address", r"^FAIL pin .*decode is None"),
    ("pin outside every function", r"^FAIL pin 0x400000 outside"),
    ("pin for an unknown function", r"^FAIL pin .*unknown function nope"),
    ("relation trace item with wrong text", r"^FAIL pin .*decode is"),
    ("relation trace item without address", r"^FAIL relation .*malformed trace item"),
    ("wrong function hash", r"^FAIL sha "),
    ("wrong function end", r"^FAIL fde "),
    ("wrong data constant", r"^FAIL data 0x"),
    ("wrong relocation addend", r"^FAIL reloc 0x"),
    ("flipped byte in a pinned instruction", r"^FAIL (pin|sha|decode) "),
]


def selftest(elf, pk, packet, pins_file):
    """Returns (baseline errors, [(name, rejected for its own reason, first matching or first line)])."""
    base_errors = []
    check(elf, Packet(pk.target, packet, pins_file), base_errors, flips=False)
    if base_errors:
        return base_errors, []
    results = []
    pattern = dict(CONTROLS)

    def run(name, mutate):
        p = Packet(pk.target, packet, pins_file)
        mutate(p)
        errs = []
        check(elf, p, errs, flips=False)
        hit = [e for e in errs if re.search(pattern[name], e)]
        results.append((name, bool(hit), (hit or errs or ["no FAIL line"])[0]))

    fn0, a0, t0 = pk.pins[0]
    run("wrong pin text", lambda p: p.pins.__setitem__(0, (fn0, a0, t0 + " x")))
    run("pin at a non-instruction address", lambda p: p.pins.__setitem__(0, (fn0, a0 + 1, t0)))
    run("pin outside every function", lambda p: p.pins.__setitem__(0, (fn0, 0x400000, t0)))
    run("pin for an unknown function", lambda p: p.pins.__setitem__(0, ("nope", a0, t0)))
    run("relation trace item with wrong text", lambda p: p.relations.append((fn0, "X", "%x nop" % a0)))
    run("relation trace item without address", lambda p: p.relations.append((fn0, "X", "no address here")))
    first = next(iter(pk.funcs))
    run("wrong function hash", lambda p: p.funcs.__setitem__(first, p.funcs[first][:2] + ("0" * 64,)))
    run("wrong function end", lambda p: p.funcs.__setitem__(first, (p.funcs[first][0], p.funcs[first][1] + 1, p.funcs[first][2])))
    run("wrong data constant", lambda p: p.data_pins.__setitem__(0, (p.data_pins[0][0], "00" * (len(p.data_pins[0][1]) // 2))))
    run("wrong relocation addend", lambda p: p.reloc_pins.__setitem__(0, (p.reloc_pins[0][0], p.reloc_pins[0][1] + 8)))
    # A bit flipped in the in-memory copy of the artifact while the file on disk is untouched: the raw
    # decode (from the flipped copy) and the ELF decode (from disk) then disagree, and the hash fails.
    flipped = bytearray(elf.data)
    flipped[elf.va_to_off(a0)] ^= 0x01
    errs = []
    check(Elf(bytes(flipped)), Packet(pk.target, packet, pins_file), errs, flips=False)
    name = "flipped byte in a pinned instruction"
    hit = [e for e in errs if re.search(dict(CONTROLS)[name], e)]
    results.append((name, bool(hit), (hit or errs or ["no FAIL line"])[0]))
    return base_errors, results


def snapshot(packet):
    state = {}
    for root, dirs, files in os.walk(packet):
        dirs.sort()
        for name in sorted(files):
            path = os.path.join(root, name)
            with open(path, "rb") as f:
                state[os.path.relpath(path, packet)] = hashlib.sha256(f.read()).hexdigest()
    return state


def prepare_outdir(outdir, packet):
    if not outdir:
        sys.exit("--outdir is required: results are written only to a new directory, never into the packet")
    out, pk = os.path.realpath(outdir), os.path.realpath(packet)
    if out == pk or out.startswith(pk + os.sep) or pk.startswith(out + os.sep):
        sys.exit("--outdir must not be the packet directory or inside it (or contain it): " + outdir)
    if os.path.exists(out) and (not os.path.isdir(out) or os.listdir(out)):
        sys.exit("--outdir must not exist yet or be an empty directory: " + outdir)
    os.makedirs(out, exist_ok=True)
    return out


def emit(out, lines):
    text = "\n".join(lines) + "\n"
    with open(os.path.join(out, "report.txt"), "w", newline="\n") as f:
        f.write(text)
    sys.stdout.write(text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("packet")
    ap.add_argument("--pins")
    ap.add_argument("--outdir")
    ap.add_argument("--record", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--no-flips", action="store_true", help="skip check 8 (development only)")
    args = ap.parse_args()
    out = prepare_outdir(args.outdir, args.packet)
    before = snapshot(args.packet)
    data = open(args.target, "rb").read()
    if hashlib.sha256(data).hexdigest() != SHA:
        sys.exit("artifact SHA-256 mismatch")
    elf = Elf(data)
    pk = Packet(args.target, args.packet, args.pins)

    def packet_untouched(lines):
        if snapshot(args.packet) != before:
            lines.append("FAIL the packet directory changed while this tool ran")
            return False
        return True

    if args.record:
        errs = []
        _, code, elf_text = check(elf, pk, errs, record=True)
        lines = ["name\tstart\tend\tsha256"]
        for name, (s, e, _old) in pk.funcs.items():
            lines.append("%s\t0x%x\t0x%x\t%s" % (name, s, e, hashlib.sha256(code[name]).hexdigest()))
        with open(os.path.join(out, "functions.tsv"), "w", newline="\n") as f:
            f.write("\n".join(lines) + "\n")
        ok = packet_untouched(errs)
        emit(out, errs + lines)
        sys.exit(0 if ok and not errs else 1)

    if args.selftest:
        base_errors, results = selftest(elf, pk, args.packet, args.pins)
        lines = []
        if base_errors:
            lines.append("baseline control FAILED: the unmodified inputs do not pass, so no damage can be judged")
            lines += base_errors[:20]
            ok = False
        else:
            lines.append("baseline control: unmodified inputs pass checks 1-7")
            bad = 0
            for name, rejected, first in results:
                lines.append("%s\t%s\t%s" % ("rejected" if rejected else "NOT REJECTED FOR ITS OWN REASON", name, first))
                bad += 0 if rejected else 1
            lines.append("damages rejected for their own reason: %d/%d" % (len(results) - bad, len(results)))
            ok = bad == 0 and len(results) == len(CONTROLS)
        ok = packet_untouched(lines) and ok
        emit(out, lines)
        sys.exit(0 if ok else 1)

    errors = []
    summary, code, _ = check(elf, pk, errors, outdir=out, flips=not args.no_flips)
    with open(os.path.join(out, "function.hex"), "w", newline="\n") as f:
        for name, (s, e, _h) in pk.funcs.items():
            f.write("# %s 0x%x..0x%x sha256 %s\n" % (name, s, e, hashlib.sha256(code[name]).hexdigest()))
            for i in range(0, len(code[name]), 16):
                f.write("0x%x %s\n" % (s + i, code[name][i:i + 16].hex()))
    lines = ["functions\t%d" % len(pk.funcs)]
    lines += ["%s\t%s" % (k, v) for k, v in sorted(summary.items())]
    lines.append("failures\t%d" % len(errors))
    with open(os.path.join(out, "target-checks.tsv"), "w", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    ok = packet_untouched(errors)
    emit(out, errors + lines)
    sys.exit(0 if ok and not errors else 1)


if __name__ == "__main__":
    main()
