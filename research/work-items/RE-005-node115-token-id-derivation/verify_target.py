#!/usr/bin/env python3
"""Static byte evidence for the node #115 token-id derivation (RE-005 token-id packet).

Reads the ELF read-only; writes ONLY into a new --outdir (refused if it exists or lies inside this
packet or the crate). It never executes or emulates the ELF.

  verify_target.py --elf ELF --outdir NEW                    check pins.json against the ELF
  verify_target.py --elf ELF --outdir NEW --with-objdump     ... and cross-check with GNU objdump
  verify_target.py --elf ELF --outdir NEW --regen-pins SPEC  decode pin_spec.json into a new pins.json
  verify_target.py --elf ELF --outdir NEW --selftest         baseline first, then corruption controls

Decoder 1 is Capstone (in process); decoder 2, only with --with-objdump, is GNU objdump (a separate
implementation, so a decoding slip in one shows up as a disagreement). Matching bytes and text only
shows the pinned windows are what the packet says they are; what they mean is the README's argument.
Exit codes: 0 all checks pass, 1 a check failed, 2 environment or usage error.
"""
import argparse
import copy
import hashlib
import json
import mmap
import os
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.realpath(os.path.join(HERE, '..', '..', '..'))
CRATE = os.path.join(ROOT, 'src', 'node115-token-id')
ELF_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'


def env_error(msg):
    print('error: ' + msg, file=sys.stderr)
    sys.exit(2)


def new_outdir(path):
    out = os.path.realpath(path)
    for guarded in (HERE, CRATE):
        if out == guarded or out.startswith(guarded + os.sep):
            env_error('refusing --outdir inside the packet or the crate: ' + out)
    if os.path.lexists(path):
        env_error('refusing existing --outdir: ' + out)
    os.makedirs(out)
    return out


def write_new(path, text):
    with open(path, 'x', newline='\n') as fh:
        fh.write(text)


try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_OP_MEM, X86_REG_RIP
except ImportError:  # pragma: no cover
    Cs = None


# ------------------------------------------------------------------ ELF access (read only)
class Elf:
    def __init__(self, path):
        try:
            self.fh = open(path, 'rb')
            self.mm = mmap.mmap(self.fh.fileno(), 0, access=mmap.ACCESS_READ)
        except (OSError, ValueError) as exc:
            env_error('cannot map ELF %s: %s' % (path, exc))
        if self.mm[:4] != b'\x7fELF':
            env_error('not an ELF file: ' + path)
        self._xrefs = {}
        phoff, shoff = struct.unpack_from('<QQ', self.mm, 0x20)[0], struct.unpack_from('<Q', self.mm, 0x28)[0]
        phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from('<HHHHH', self.mm, 0x36)
        self.loads = []
        for i in range(phnum):
            ptype, _fl, off, va, _pa, fsz, _msz, _al = struct.unpack_from('<IIQQQQQQ', self.mm, phoff + i * phentsize)
            if ptype == 1:
                self.loads.append((va, off, fsz))
        raw = [struct.unpack_from('<IIQQQQIIQQ', self.mm, shoff + i * shentsize) for i in range(shnum)]
        names = raw[shstrndx]
        self.sections = {}
        for name, typ, _fl, addr, off, size, _lk, _inf, _al, _es in raw:
            end = self.mm.find(b'\0', names[4] + name)
            self.sections[self.mm[names[4] + name:end].decode()] = (typ, addr, off, size)

    def sha256(self):
        return hashlib.sha256(self.mm).hexdigest()

    def read(self, va, n):
        for lva, off, fsz in self.loads:
            if lva <= va and va + n <= lva + fsz:
                return bytes(self.mm[off + va - lva: off + va - lva + n])
        raise KeyError('unmapped VA 0x%x+%d' % (va, n))

    def relative_target(self, slot):
        typ, _addr, off, size = self.sections['.rela.dyn']
        for r_off, r_info, addend in struct.iter_unpack('<QQq', self.mm[off:off + size]):
            if r_off == slot:
                return addend if (r_info & 0xffffffff) == 8 else None
        return None

    def xrefs(self, targets):
        """Direct `call`/`jmp rel32` sites in .text and RELATIVE relocation slots that point at each
        target. A byte-pattern scan, not a disassembly: stray E8/E9 bytes inside other instructions and
        indirect calls through computed addresses are not excluded."""
        key = tuple(sorted(targets))
        if key not in self._xrefs:
            _t, addr, off, size = self.sections['.text']
            data = self.mm[off:off + size]
            sites = {t: [] for t in key}
            for opcode in (b'\xe8', b'\xe9'):
                p = data.find(opcode)
                while p != -1 and p + 5 <= len(data):
                    target = addr + p + 5 + struct.unpack_from('<i', data, p + 1)[0]
                    if target in sites:
                        sites[target].append(addr + p)
                    p = data.find(opcode, p + 1)
            slots = {t: [] for t in key}
            _t, _a, roff, rsize = self.sections['.rela.dyn']
            for r_off, r_info, addend in struct.iter_unpack('<QQq', self.mm[roff:roff + rsize]):
                if (r_info & 0xffffffff) == 8 and addend in slots:
                    slots[addend].append(r_off)
            self._xrefs[key] = {t: (sorted(sites[t]), sorted(slots[t])) for t in key}
        return self._xrefs[key]

    def fde_range(self, va):
        """Range of the FDE whose initial location is `va`, via .eh_frame_hdr and the FDE itself."""
        _t, hdr_va, off, size = self.sections['.eh_frame_hdr']
        d = self.mm[off:off + size]
        if tuple(d[:4]) != (1, 0x1b, 0x03, 0x3b):
            env_error('unexpected .eh_frame_hdr encoding')
        count = struct.unpack_from('<I', d, 8)[0]
        lo, hi = 0, count
        while lo < hi:
            mid = (lo + hi) // 2
            start, fde = struct.unpack_from('<ii', d, 12 + 8 * mid)
            if hdr_va + start < va:
                lo = mid + 1
            else:
                hi = mid
        if lo == count or hdr_va + struct.unpack_from('<i', d, 12 + 8 * lo)[0] != va:
            return None
        fde_va = hdr_va + struct.unpack_from('<i', d, 12 + 8 * lo + 4)[0]
        length, cie_back = struct.unpack('<II', self.read(fde_va, 8))
        cie_va = fde_va + 4 - cie_back
        cie = self.read(cie_va, 64)
        assert cie[8] == 1, 'unexpected CIE version'
        end = cie.index(b'\0', 9)
        augmentation = cie[9:end].decode()
        assert augmentation.startswith('z') and 'R' in augmentation, augmentation
        pos = end + 1
        for _ in range(2):          # code and data alignment (single-byte LEB128 here)
            assert cie[pos] < 0x80
            pos += 1
        pos += 1                    # return address register (version 1)
        pos += 1                    # augmentation data length (single byte here)
        fde_enc = None
        for ch in augmentation[1:]:
            if ch == 'R':
                fde_enc = cie[pos]
                pos += 1
            elif ch == 'L':
                pos += 1
            elif ch == 'P':
                pos += 1 + {0x03: 4, 0x0b: 4, 0x04: 8, 0x0c: 8, 0x00: 8}[cie[pos] & 0x0f]
            else:
                raise AssertionError('unexpected CIE augmentation ' + augmentation)
        assert fde_enc == 0x1b, 'FDE pointer encoding is not pcrel|sdata4'
        begin_field = fde_va + 8
        begin = begin_field + struct.unpack('<i', self.read(begin_field, 4))[0]
        rng = struct.unpack('<i', self.read(begin_field + 4, 4))[0]
        return begin, begin + rng


# ------------------------------------------------------------------ canonical instruction text
NUM = re.compile(r'(?<![a-z0-9_])(0x[0-9a-f]+|\d+)(?![a-z0-9_])')


def canon(mnemonic, operands, rip_target=None):
    ops = operands.lower()
    ops = re.sub(r'\bptr\b', '', ops).replace(' ', '').replace('*1', '')
    if rip_target is not None:
        ops = re.sub(r'\[rip[^\]]*\]', '[rip->0x%x]' % rip_target, ops)
    if mnemonic.startswith(('j', 'call')) and re.fullmatch(r'[0-9a-f]+', ops):
        ops = '0x' + ops
    ops = NUM.sub(lambda m: hex(int(m.group(1), 0)), ops)
    ops = ', '.join(ops.split(','))
    return (mnemonic.lower() + ' ' + ops).strip()


def decode(code, va, count):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    out = []
    for insn in md.disasm(code, va):
        target = None
        for op in insn.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                target = insn.address + insn.size + op.mem.disp
        out.append((insn.address, bytes(insn.bytes), canon(insn.mnemonic, insn.op_str, target)))
        if len(out) == count:
            break
    return out


def objdump_text(elf_path, va, length):
    run = subprocess.run(['objdump', '-d', '--no-show-raw-insn', '-M', 'intel', '--start-address=0x%x' % va,
                          '--stop-address=0x%x' % (va + length), elf_path], capture_output=True, text=True)
    if run.returncode != 0:
        env_error('objdump failed: ' + run.stderr.strip())
    out = []
    for line in run.stdout.splitlines():
        m = re.match(r'\s*([0-9a-f]+):\t(.*)$', line)
        if not m:
            continue
        body, _, comment = m.group(2).partition('#')
        body = re.sub(r'<[^>]*>', '', body).strip()
        mnemonic, _, operands = body.partition(' ')
        target = int(comment.split()[0], 16) if comment.strip() else None
        out.append((int(m.group(1), 16), canon(mnemonic, operands.strip(), target if 'rip' in operands else None)))
    return out


# ------------------------------------------------------------------ pins
def regen(elf, spec):
    pins = {'target_sha256': ELF_SHA256, 'fde': [], 'relocations': [], 'data': [], 'xrefs': [], 'windows': []}
    found = elf.xrefs([int(t, 16) for _n, t in spec['xrefs']])
    for name, target in spec['xrefs']:
        direct, slots = found[int(target, 16)]
        pins['xrefs'].append({'name': name, 'target': target, 'direct_sites': [hex(s) for s in direct],
                              'relative_slots': [hex(s) for s in slots]})
    for name, start, end in spec['fde']:
        s, e = int(start, 16), int(end, 16)
        pins['fde'].append({'name': name, 'start': start, 'end': end,
                            'bytes': e - s, 'sha256': hashlib.sha256(elf.read(s, e - s)).hexdigest()})
    for name, slot, target in spec['relocations']:
        pins['relocations'].append({'name': name, 'slot': slot, 'target': target})
    for name, va, ascii_, ref in spec['data']:
        raw = elf.read(int(va, 16), len(ascii_))
        pins['data'].append({'name': name, 'va': va, 'ascii': raw.decode(), 'referenced_by': ref})
    for name, va, n, claim in spec['windows']:
        insns = decode(elf.read(int(va, 16), 15 * n), int(va, 16), n)
        if len(insns) != n:
            env_error('window %s decoded %d of %d instructions' % (name, len(insns), n))
        pins['windows'].append({'name': name, 'va': va, 'n': n, 'claim': claim,
                                'hex': b''.join(i[1] for i in insns).hex(), 'asm': [i[2] for i in insns]})
    return pins


def check_window(elf, w):
    va, raw = int(w['va'], 16), bytes.fromhex(w['hex'])
    try:
        got = elf.read(va, len(raw))
    except KeyError as exc:
        return str(exc)
    if got != raw:
        return 'bytes differ at 0x%x' % va
    insns = decode(raw, va, w['n'])
    if len(insns) != w['n'] or sum(len(i[1]) for i in insns) != len(raw):
        return 'decode does not cover the pinned bytes with %d instructions' % w['n']
    if [i[2] for i in insns] != w['asm']:
        return 'decoded text differs'
    return None


def check_data(elf, d):
    va = int(d['va'], 16)
    try:
        if elf.read(va, len(d['ascii'])) != d['ascii'].encode():
            return 'string bytes differ'
        ref = int(d['referenced_by'], 16)
        code = elf.read(ref, 15)
    except KeyError as exc:
        return str(exc)
    insn = decode(code, ref, 1)
    if not insn or '[rip->0x%x]' % va not in insn[0][2]:
        return 'instruction at 0x%x does not reference 0x%x (%s)' % (ref, va, insn[0][2] if insn else '?')
    return None


def check_fde(elf, f):
    start, end = int(f['start'], 16), int(f['end'], 16)
    if elf.fde_range(start) != (start, end):
        return 'FDE range differs: %s' % (elf.fde_range(start),)
    if hashlib.sha256(elf.read(start, end - start)).hexdigest() != f['sha256']:
        return 'body hash differs'
    return None


def check_reloc(elf, r):
    got = elf.relative_target(int(r['slot'], 16))
    return None if got == int(r['target'], 16) else 'RELATIVE target %s' % (hex(got) if got is not None else None)


def check_xrefs(elf, pins):
    found = elf.xrefs([int(x['target'], 16) for x in pins['xrefs']])
    bad = []
    for x in pins['xrefs']:
        direct, slots = found[int(x['target'], 16)]
        if [hex(s) for s in direct] != x['direct_sites'] or [hex(s) for s in slots] != x['relative_slots']:
            bad.append(('xrefs:' + x['name'], 'sites %s slots %s' % ([hex(s) for s in direct], [hex(s) for s in slots])))
    return bad


def run_checks(elf, pins, elf_path=None, with_objdump=False):
    results = {'target_sha256': elf.sha256()}
    failures = []
    if results['target_sha256'] != pins['target_sha256']:
        failures.append(('target', 'sha256 %s' % results['target_sha256']))
    for kind, fn in (('fde', check_fde), ('relocations', check_reloc), ('data', check_data), ('windows', check_window)):
        for item in pins[kind]:
            msg = fn(elf, item)
            if msg:
                failures.append((kind + ':' + item['name'], msg))
    failures.extend(check_xrefs(elf, pins))
    results['counts'] = {k: len(pins[k]) for k in ('fde', 'relocations', 'data', 'xrefs', 'windows')}
    results['instructions'] = sum(w['n'] for w in pins['windows'])
    if with_objdump:
        mismatch = []
        for w in pins['windows']:
            va = int(w['va'], 16)
            theirs = objdump_text(elf_path, va, len(w['hex']) // 2)
            if [t[1] for t in theirs] != w['asm']:
                mismatch.append(w['name'])
        results['objdump_mismatch'] = mismatch
        failures.extend(('objdump:' + n, 'GNU objdump text differs') for n in mismatch)
    results['failures'] = failures
    return results


# ------------------------------------------------------------------ corruption controls
class FlippedBit:
    """Read-only overlay: the wrapped ELF with one bit of one byte flipped."""

    def __init__(self, elf, va, bit):
        self.elf, self.va, self.bit = elf, va, bit

    def read(self, va, n):
        data = bytearray(self.elf.read(va, n))
        if va <= self.va < va + n:
            data[self.va - va] ^= 1 << self.bit
        return bytes(data)


def selftest(elf, pins, outdir):
    base = run_checks(elf, pins)
    if base['failures']:
        env_error('baseline does not pass, controls would be meaningless: %s' % base['failures'][:3])
    report = {'baseline': 'pass', 'controls': {}}

    flips = text_changed = missed = 0
    for w in pins['windows']:
        va = int(w['va'], 16)
        for off in range(len(w['hex']) // 2):
            for bit in range(8):
                flips += 1
                if check_window(FlippedBit(elf, va + off, bit), w) is None:
                    missed += 1
                # informational: does the flipped byte also change the decoded text? (the hex compare
                # already rejects every flip, so this is not what makes the control pass)
                data = bytearray(bytes.fromhex(w['hex']))
                data[off] ^= 1 << bit
                after = [i[2] for i in decode(bytes(data), va, w['n'])]
                text_changed += after != w['asm']
    report['controls']['bit_flips'] = {'flipped': flips, 'accepted_by_checker': missed,
                                       'of_which_decoded_text_also_changes': text_changed}
    assert missed == 0

    def must_fail(label, mutate):
        bad = copy.deepcopy(pins)
        mutate(bad)
        got = run_checks(elf, bad)
        assert got['failures'], label + ' was not rejected'
        report['controls'][label] = 'rejected: ' + got['failures'][0][0]

    must_fail('pin_hex_changed', lambda p: p['windows'][0].__setitem__(
        'hex', p['windows'][0]['hex'][:-2] + '%02x' % (int(p['windows'][0]['hex'][-2:], 16) ^ 0xff)))
    must_fail('pin_text_changed', lambda p: p['windows'][3]['asm'].__setitem__(0, 'nop'))
    must_fail('pin_address_shifted', lambda p: p['windows'][5].__setitem__('va', hex(int(p['windows'][5]['va'], 16) + 1)))
    must_fail('fde_end_off_by_one', lambda p: p['fde'][1].__setitem__('end', hex(int(p['fde'][1]['end'], 16) + 1)))
    must_fail('fde_hash_changed', lambda p: p['fde'][2].__setitem__('sha256', '0' * 64))
    must_fail('relocation_target_changed', lambda p: p['relocations'][0].__setitem__('target', '0x5cda911'))
    must_fail('relocation_slot_missing', lambda p: p['relocations'][0].__setitem__('slot', '0x64e0149'))
    must_fail('xref_site_changed', lambda p: p['xrefs'][0].__setitem__('direct_sites', ['0x3c48f92']))
    must_fail('xref_extra_slot', lambda p: p['xrefs'][1].__setitem__('relative_slots', ['0x64e7d08']))
    must_fail('string_changed', lambda p: p['data'][0].__setitem__('ascii', 'nome'))
    must_fail('string_reference_wrong', lambda p: p['data'][0].__setitem__('referenced_by', p['data'][1]['referenced_by']))
    must_fail('target_sha_changed', lambda p: p.__setitem__('target_sha256', '0' * 64))

    exe = os.path.realpath(__file__)
    probes = {
        'missing_elf': [sys.executable, '-I', exe, '--elf', os.path.join(outdir, 'no-such.elf'), '--outdir', os.path.join(outdir, 'x1')],
        'outdir_exists': [sys.executable, '-I', exe, '--elf', elf.path, '--outdir', outdir],
        'outdir_in_packet': [sys.executable, '-I', exe, '--elf', elf.path, '--outdir', os.path.join(HERE, 'x2')],
        'outdir_in_crate': [sys.executable, '-I', exe, '--elf', elf.path, '--outdir', os.path.join(CRATE, 'x3')],
    }
    for label, cmd in probes.items():
        run = subprocess.run(cmd, capture_output=True, text=True)
        assert run.returncode == 2, (label, run.returncode, run.stderr)
        report['controls'][label] = 'exit 2: ' + run.stderr.strip().splitlines()[-1][:80]
    assert not os.path.exists(os.path.join(HERE, 'x2')) and not os.path.exists(os.path.join(CRATE, 'x3'))
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--elf', default=os.path.join(ROOT, 'artifacts', 'node', '115', 'hl-node'))
    ap.add_argument('--outdir', required=True)
    ap.add_argument('--pins', default=os.path.join(HERE, 'pins.json'))
    ap.add_argument('--regen-pins')
    ap.add_argument('--with-objdump', action='store_true')
    ap.add_argument('--selftest', action='store_true')
    args = ap.parse_args()
    if Cs is None:
        env_error('python capstone is required (tested with 4.0.2)')
    if not os.path.isfile(args.elf):
        env_error('ELF not found: ' + args.elf)
    out = new_outdir(args.outdir)
    elf = Elf(args.elf)
    elf.path = args.elf
    if elf.sha256() != ELF_SHA256:
        print('target mismatch: sha256 %s' % elf.sha256(), file=sys.stderr)
        return 1
    if args.regen_pins:
        write_new(os.path.join(out, 'pins.json'), json.dumps(regen(elf, json.load(open(args.regen_pins))), indent=1) + '\n')
        print('wrote pins.json')
        return 0
    pins = json.load(open(args.pins))
    if args.selftest:
        report = selftest(elf, pins, out)
        write_new(os.path.join(out, 'selftest.json'), json.dumps(report, indent=1) + '\n')
        print(json.dumps(report['controls'], indent=1))
        return 0
    res = run_checks(elf, pins, args.elf, args.with_objdump)
    write_new(os.path.join(out, 'verification.json'), json.dumps(res, indent=1) + '\n')
    write_new(os.path.join(out, 'fde-table.tsv'), 'name\tstart\tend\tbytes\tsha256\n' + ''.join(
        '%s\t%s\t%s\t%d\t%s\n' % (f['name'], f['start'], f['end'], f['bytes'], f['sha256']) for f in pins['fde']))
    print('target sha256 ok; %s; %d instructions in windows; failures: %d' % (res['counts'], res['instructions'], len(res['failures'])))
    for name, msg in res['failures']:
        print('FAIL %s: %s' % (name, msg), file=sys.stderr)
    return 1 if res['failures'] else 0


if __name__ == '__main__':
    sys.exit(main())
