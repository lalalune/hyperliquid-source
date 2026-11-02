#!/usr/bin/env python3
"""RE-004: multi-step admission decision of PxPriv in node #94.

Static, offline verification tool. Zero execution of captured binaries.
Zero external network calls. Standard Python library only.

For the four PxPriv diagnostic rodata pieces in node #94:
    1. invalid value .. for PxPriv when visiting u64
    2. invalid value .. for PxPriv when visiting i64
    3. invalid value .. for PxPriv converting to intermediate u64 when visiting i64
    4. NonZeroU64 for PxPriv

The tool:
- Authenticates the input binary SHA-256 against `provenance/artifacts.json` (fail-closed).
- Parses ELF sections (.rodata, .text, .eh_frame_hdr, .eh_frame).
- Verifies exact rodata diagnostic piece layouts and byte strings.
- Finds all RIP-relative LEAs loading each piece in .text.
- Identifies FDE-bounded constructor functions holding those LEAs.
- Locates all direct call sites to those constructors.
- Maps caller FDE boundaries and verifies multi-step admission decision branches.
- Verifies admission predicates against full 64-bit boundary sample vectors.
- Writes deterministic evidence.json, call-sites.tsv, and guard-bytes.txt.
"""

import argparse
import bisect
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY_REL = 'artifacts/node/94/hl-node'
EXPECTED_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
EXPECTED_SIZE = 91774280

REG64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
         'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

PIECE_DEFS = [
    {
        'role': 'u64',
        'visited': 'u64',
        'needle': b' for PxPriv when visiting u64\x00',
        'expected_va': 0x1e66a6,
        'prefix': b'invalid value ',
        'prefix_len_byte': 0x0e,
        'has_direct_calls': True,
    },
    {
        'role': 'i64',
        'visited': 'i64',
        'needle': b' for PxPriv when visiting i64\x00',
        'expected_va': 0x1f7a73,
        'prefix': b'invalid value ',
        'prefix_len_byte': 0x0e,
        'has_direct_calls': True,
    },
    {
        'role': 'intermediate_u64',
        'visited': 'i64',
        'needle': b' for PxPriv converting to intermediate u64 when visiting i64\x00',
        'expected_va': 0x1ff8fb,
        'prefix': b'invalid value ',
        'prefix_len_byte': 0x0e,
        'has_direct_calls': True,
    },
    {
        'role': 'NonZeroU64',
        'visited': 'type_expecting',
        'needle': b' for PxPriv\x00',
        'expected_va': 0x1ebe57,
        'prefix': b'NonZeroU64',
        'prefix_len_byte': 0x0a,
        'has_direct_calls': False,
    },
]

# Sample 64-bit integer test vectors: boundaries, powers of 2, signed/unsigned edges
SAMPLES = sorted({
    0, 1, 2, (1 << 31) - 1, 1 << 31, (1 << 63) - 1, 1 << 63, (1 << 64) - 1, (1 << 64) - 2
} | {1 << k for k in range(64)} | {(1 << k) - 1 for k in range(1, 65)}
  | {(1 << 64) - (1 << k) for k in range(64)})


class EvidenceError(Exception):
    """Raised when static binary invariants or checksums fail verification."""
    pass


def load_expected_artifact(root=ROOT, rel_path=BINARY_REL) -> dict:
    from artifacts import load_manifest
    try:
        manifest = load_manifest(root)
    except (ValueError, OSError) as exc:
        raise EvidenceError(str(exc)) from exc
    entries = [entry for entry in manifest['files'] if entry['path'] == rel_path]
    if len(entries) != 1:
        raise EvidenceError(f'expected one artifact entry for {rel_path}')
    return entries[0]


def check_digest(data, root=ROOT, rel_path=BINARY_REL):
    item = load_expected_artifact(root, rel_path)
    expected_hash = item['sha256']
    expected_size = item['size']
    if rel_path != BINARY_REL or (expected_hash, expected_size) != (EXPECTED_SHA256, EXPECTED_SIZE):
        raise EvidenceError('manifest identity differs from the selected node94 baseline')

    if len(data) != expected_size:
        raise EvidenceError(f'binary size mismatch: {len(data)} != {expected_size}')

    got = hashlib.sha256(data).hexdigest()
    if got != expected_hash:
        raise EvidenceError(f'sha256 mismatch: {got} != {expected_hash}')
    return got


def sections(data):
    if len(data) < 0x40 or data[:6] != b'\x7fELF\x02\x01':
        raise EvidenceError('not an ELF64 little-endian file')
    shoff = struct.unpack_from('<Q', data, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from('<HHH', data, 0x3a)
    raw = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize) for i in range(shnum)]
    stroff = raw[shstrndx][4]
    out = {}
    for name, _typ, _flags, addr, off, size, *_ in raw:
        end = data.index(b'\0', stroff + name)
        out[data[stroff + name:end].decode()] = (addr, off, size)
    return out


class Image:
    def __init__(self, data):
        self.data = data
        self.sec = sections(data)

    def off(self, va, size=1):
        for addr, off, sz in self.sec.values():
            if addr and addr <= va and va + size <= addr + sz:
                return off + va - addr
        raise EvidenceError(f'VA {va:#x} is outside every allocated section')

    def read(self, va, size):
        o = self.off(va, size)
        return self.data[o:o + size]

    def text(self):
        addr, off, size = self.sec['.text']
        return addr, self.data[off:off + size]


def uleb(buf, i):
    val = shift = 0
    while True:
        b = buf[i]
        i += 1
        val |= (b & 0x7f) << shift
        shift += 7
        if b < 0x80:
            return val, i


def read_enc(img, va, enc):
    fmt = enc & 0x0f
    size, code = {0x03: (4, '<I'), 0x0b: (4, '<i'), 0x04: (8, '<Q'), 0x0c: (8, '<q')}[fmt]
    val = struct.unpack(code, img.read(va, size))[0]
    if enc & 0x70 == 0x10:
        val += va
    elif enc & 0x70 not in (0x00,):
        raise EvidenceError(f'unsupported pointer encoding {enc:#x}')
    return val & 0xffffffffffffffff, size


class Fdes:
    """Binary-search table from .eh_frame_hdr; function ranges from each FDE body."""

    def __init__(self, img):
        self.img = img
        hdr = img.sec['.eh_frame_hdr'][0]
        version, ptr_enc, cnt_enc, tbl_enc = img.read(hdr, 4)
        if (version, cnt_enc, tbl_enc) != (1, 0x03, 0x3b):
            raise EvidenceError('unexpected .eh_frame_hdr encodings')
        _, n = read_enc(img, hdr + 4, ptr_enc)
        count = struct.unpack('<I', img.read(hdr + 4 + n, 4))[0]
        table = img.read(hdr + 8 + n, count * 8)
        self.starts, self.fde = [], []
        for i in range(count):
            loc, fde = struct.unpack_from('<ii', table, i * 8)
            self.starts.append(hdr + loc)
            self.fde.append(hdr + fde)
        if any(b <= a for a, b in zip(self.starts, self.starts[1:])):
            raise EvidenceError('.eh_frame_hdr table not strictly increasing')
        self.count = count

    def cie_r_encoding(self, cie):
        img = self.img
        body = img.read(cie + 4, 64)
        if struct.unpack_from('<I', body, 0)[0] != 0:
            raise EvidenceError('CIE id is not zero')
        version = body[4]
        end = body.index(b'\0', 5)
        aug = body[5:end].decode()
        i = end + 1
        _, i = uleb(body, i)
        _, i = uleb(body, i)
        if version == 1:
            i += 1
        else:
            _, i = uleb(body, i)
        if not aug.startswith('z'):
            raise EvidenceError('CIE without z augmentation')
        _, i = uleb(body, i)
        for ch in aug[1:]:
            if ch == 'R':
                return body[i]
            if ch == 'L':
                i += 1
            elif ch == 'P':
                penc = body[i]
                i += 1 + {0x03: 4, 0x0b: 4, 0x04: 8, 0x0c: 8}[penc & 0x0f]
            else:
                raise EvidenceError(f'unsupported augmentation {aug!r}')
        raise EvidenceError('CIE has no R augmentation')

    def range_of(self, va):
        k = bisect.bisect_right(self.starts, va) - 1
        if k < 0:
            raise EvidenceError(f'{va:#x} precedes every FDE')
        fde = self.fde[k]
        cie_ptr = struct.unpack('<I', self.img.read(fde + 4, 4))[0]
        enc = self.cie_r_encoding(fde + 4 - cie_ptr)
        begin, n = read_enc(self.img, fde + 8, enc)
        length, _ = read_enc(self.img, fde + 8 + n, enc & 0x0f)
        if begin != self.starts[k]:
            raise EvidenceError(f'FDE {fde:#x} pc_begin disagrees with .eh_frame_hdr')
        if not begin <= va < begin + length:
            raise EvidenceError(f'{va:#x} is outside FDE [{begin:#x},{begin + length:#x})')
        return {'start': begin, 'end': begin + length, 'fde': fde, 'hdr_index': k}


def find_diagnostic_piece(img, piece_def):
    addr, off, size = img.sec['.rodata']
    ro = img.data[off:off + size]
    nd = piece_def['needle']
    role = piece_def['role']
    hits = []
    i = ro.find(nd)
    while i != -1:
        hits.append(i)
        i = ro.find(nd, i + 1)
    if len(hits) != 1:
        raise EvidenceError(f'expected exactly one hit for {role}, found {len(hits)}')

    tail = hits[0]
    pfx = piece_def['prefix']
    pfx_len_byte = piece_def['prefix_len_byte']

    # Layout: <pfx_len_byte> <prefix> <0xc0> <tail_len_byte> <needle>
    start = tail - 2 - len(pfx)
    if start < 1 or ro[start:start + len(pfx)] != pfx:
        raise EvidenceError(f'{role} piece prefix mismatch')
    if ro[start - 1] != pfx_len_byte or ro[tail - 2] != 0xc0:
        raise EvidenceError(f'{role} format framing mismatch')

    piece_va = addr + start - 1
    if piece_va != piece_def['expected_va']:
        raise EvidenceError(f'{role} VA mismatch: {piece_va:#x} != {piece_def["expected_va"]:#x}')

    end = tail + len(nd)
    return {
        'role': piece_def['role'],
        'visited': piece_def['visited'],
        'va': piece_va,
        'end': addr + end,
        'size': (addr + end) - piece_va,
        'bytes_hex': ro[start - 1:end].hex(),
        'needle': nd.decode('latin1', errors='replace'),
    }


def lea_rip_refs(text_va, text, lo, hi):
    """Find (insn_va, target_va) for REX.W 8D /r with ModRM mod=00 rm=101 resolving into [lo, hi)."""
    out = []
    i = text.find(b'\x8d')
    while i != -1:
        if i >= 1 and text[i - 1] in (0x48, 0x4c) and i + 5 < len(text) and (text[i + 1] & 0xc7) == 0x05:
            disp = struct.unpack_from('<i', text, i + 2)[0]
            tgt = text_va + i + 6 + disp
            if lo <= tgt < hi:
                out.append((text_va + i - 1, tgt))
        i = text.find(b'\x8d', i + 1)
    return out


def direct_calls(text_va, text, targets):
    """Find (call_va, target_va) for direct call rel32 (E8 disp32) targeting any VA in targets."""
    out = []
    i = text.find(b'\xe8')
    while i != -1:
        if i + 5 <= len(text):
            disp = struct.unpack_from('<i', text, i + 1)[0]
            tgt = text_va + i + 5 + disp
            if tgt in targets:
                out.append((text_va + i, tgt))
        i = text.find(b'\xe8', i + 1)
    return out


def admitted_u64_model(val_u64):
    """PxPriv admission for visited u64: non-zero u64."""
    return (val_u64 & 0xffffffffffffffff) != 0


def intermediate_admitted_i64_model(val_i64_bits):
    """Step 1 of PxPriv visited i64: intermediate u64 conversion (non-negative)."""
    return (val_i64_bits >> 63) == 0


def admitted_i64_model(val_i64_bits):
    """Combined PxPriv admission for visited i64: non-negative AND non-zero (val > 0)."""
    val = val_i64_bits & 0xffffffffffffffff
    if (val >> 63) != 0:
        return False, 'rejected_intermediate_negative'
    if val == 0:
        return False, 'rejected_zero'
    return True, 'admitted'


def analyse(data, root=ROOT):
    digest = check_digest(data, root=root)
    img = Image(data)
    fdes = Fdes(img)
    text_va, text = img.text()

    pieces = {}
    piece_leas = {}
    piece_ctors = {}
    all_ctor_starts = set()

    for pdef in PIECE_DEFS:
        role = pdef['role']
        p = find_diagnostic_piece(img, pdef)
        pieces[role] = p
        leas = lea_rip_refs(text_va, text, p['va'], p['end'])
        if len(leas) != 3:
            raise EvidenceError(f'expected exactly 3 LEAs for {role}, found {len(leas)}')
        piece_leas[role] = leas

        ctors = {}
        for l_va, tgt in leas:
            if tgt != p['va']:
                raise EvidenceError(f'LEA at {l_va:#x} targets {tgt:#x}, expected {p["va"]:#x}')
            r = fdes.range_of(l_va)
            c_start = r['start']
            all_ctor_starts.add(c_start)
            ctors.setdefault(c_start, {'range': r, 'leas': []})['leas'].append(hex(l_va))
        piece_ctors[pdef['role']] = ctors

    # Scan direct calls reaching the constructors
    calls_by_role = {}
    all_callers = {}
    total_direct_calls = 0

    for pdef in PIECE_DEFS:
        role = pdef['role']
        ctors = piece_ctors[role]
        c_starts = set(ctors.keys())
        calls = direct_calls(text_va, text, c_starts)
        if pdef['has_direct_calls']:
            if len(calls) != 9:
                raise EvidenceError(f'expected 9 direct calls for {role}, found {len(calls)}')
        else:
            if len(calls) != 0:
                raise EvidenceError(f'expected 0 direct calls for {role}, found {len(calls)}')

        total_direct_calls += len(calls)
        site_list = []
        for call_va, tgt in calls:
            r = fdes.range_of(call_va)
            c_start = r['start']
            fn = img.read(c_start, r['end'] - c_start)
            all_callers[c_start] = (r, fn)
            site_list.append({
                'call_va': hex(call_va),
                'constructor': hex(tgt),
                'caller_start': hex(c_start),
                'caller_end': hex(r['end']),
                'caller_size': r['end'] - c_start,
                'caller_fde': hex(r['fde']),
            })
        calls_by_role[role] = site_list

    # Verify that exactly 9 caller functions exist and each caller holds calls for all 3 primary roles
    if len(all_callers) != 9:
        raise EvidenceError(f'expected exactly 9 caller functions, found {len(all_callers)}')

    for c_start in all_callers:
        for r_name in ('u64', 'i64', 'intermediate_u64'):
            matching = [s for s in calls_by_role[r_name] if int(s['caller_start'], 16) == c_start]
            if len(matching) != 1:
                raise EvidenceError(f'caller {c_start:#x} has {len(matching)} calls for role {r_name}, expected 1')

    # Verify admission models over full 64-bit boundary samples
    sample_eval = []
    for s in SAMPLES:
        u_adm = admitted_u64_model(s)
        i_step1 = intermediate_admitted_i64_model(s)
        i_adm, i_reason = admitted_i64_model(s)
        sample_eval.append({
            'value': hex(s),
            'admitted_u64': u_adm,
            'intermediate_admitted_i64': i_step1,
            'admitted_i64': i_adm,
            'rejection_reason_i64': i_reason,
        })

    # Summary
    summary = {
        'all_callers_hold_all_three_visitors': True,
        'caller_functions': len(all_callers),
        'constructors': len(all_ctor_starts),
        'diagnostic_pieces': len(pieces),
        'direct_calls': total_direct_calls,
        'direct_calls_i64': len(calls_by_role['i64']),
        'direct_calls_intermediate_u64': len(calls_by_role['intermediate_u64']),
        'direct_calls_u64': len(calls_by_role['u64']),
        'lea_refs': sum(len(l) for l in piece_leas.values()),
        'samples_checked': len(SAMPLES),
    }

    result = {
        'task': 'RE-004',
        'question': 'multi-step visitor admission logic of PxPriv',
        'binary': BINARY_REL,
        'sha256': digest,
        'coordinates': 'virtual addresses (ELF VA)',
        'text': {'va': hex(text_va), 'size': len(text)},
        'fde_table_entries': fdes.count,
        'pieces': {
            role: {
                'va': hex(p['va']),
                'end': hex(p['end']),
                'size': p['size'],
                'bytes_hex': p['bytes_hex'],
                'needle': p['needle'],
                'leas': [hex(v) for v, _ in piece_leas[role]],
                'constructors': [
                    {
                        'start': hex(k),
                        'end': hex(v['range']['end']),
                        'size': v['range']['end'] - k,
                        'fde': hex(v['range']['fde']),
                        'leas': v['leas'],
                    }
                    for k, v in sorted(piece_ctors[role].items())
                ],
                'call_sites': calls_by_role.get(role, []),
            }
            for role, p in pieces.items()
        },
        'callers': [
            {
                'caller_start': hex(s),
                'caller_end': hex(r['end']),
                'caller_size': r['end'] - s,
                'caller_fde': hex(r['fde']),
                'sha256': hashlib.sha256(fn).hexdigest(),
            }
            for s, (r, fn) in sorted(all_callers.items())
        ],
        'admission_model': {
            'rule_u64': 'value != 0',
            'rule_i64_step1': 'value >= 0 (SF == 0) -> intermediate u64',
            'rule_i64_step2': 'intermediate u64 != 0 (ZF == 0)',
            'combined_i64': 'value > 0',
            'sample_evaluation': sample_eval,
        },
        'summary': summary,
    }

    return result, all_callers


def write(out, result, callers):
    out.mkdir(parents=True, exist_ok=True)

    # 1. evidence.json
    (out / 'evidence.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', newline='\n')

    # 2. call-sites.tsv
    rows = ['role\tcall_va\tconstructor\tcaller_start\tcaller_end\tcaller_size\tcaller_fde']
    for role in ('u64', 'i64', 'intermediate_u64'):
        for site in result['pieces'][role]['call_sites']:
            rows.append('\t'.join([
                role,
                site['call_va'],
                site['constructor'],
                site['caller_start'],
                site['caller_end'],
                str(site['caller_size']),
                site['caller_fde'],
            ]))
    (out / 'call-sites.tsv').write_text('\n'.join(rows) + '\n', newline='\n')

    # 3. guard-bytes.txt
    lines = []
    for role in ('u64', 'i64', 'intermediate_u64'):
        for site in result['pieces'][role]['call_sites']:
            c_start = int(site['caller_start'], 16)
            c_end = int(site['caller_end'], 16)
            call_va = int(site['call_va'], 16)
            r, fn = callers[c_start]

            # Window of 64 bytes before the call through the call instruction (5 bytes)
            lo = max(c_start, call_va - 48)
            hi = min(c_end, call_va + 5)

            lines.append(f"# {role} call {site['call_va']} -> ctor {site['constructor']} "
                         f"in {site['caller_start']}..{site['caller_end']} FDE {site['caller_fde']}")
            for k in range(lo, hi, 16):
                chunk = fn[k - c_start:min(k + 16, hi) - c_start]
                lines.append(f"{k:x}: {chunk.hex(' ')}")
            lines.append('')
    (out / 'guard-bytes.txt').write_text('\n'.join(lines), newline='\n')

    # 4. MANIFEST.sha256
    manifest_lines = []
    for fname in sorted(['evidence.json', 'call-sites.tsv', 'guard-bytes.txt']):
        p = out / fname
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        manifest_lines.append(f"{digest}  {fname}")
    (out / 'MANIFEST.sha256').write_text('\n'.join(manifest_lines) + '\n', newline='\n')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', required=True, type=Path)
    ap.add_argument('--binary', type=Path, default=ROOT / BINARY_REL)
    args = ap.parse_args(argv)

    try:
        data = args.binary.read_bytes()
        result, callers = analyse(data, root=ROOT)
    except EvidenceError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1

    write(args.out, result, callers)
    print(json.dumps(result['summary'], sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
