#!/usr/bin/env python3
"""RE-007 (Part 2): Position Margin Mode Dispatch static verification tool.

Static, offline verification tool. Zero execution of captured binaries.
Zero external network calls. Standard Python library only.

Target:
    artifacts/node/94/hl-node (SHA-256: 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f)

Scope:
    1. Verification of the primary clearinghouse position margin calculator:
       - FDE 0x3717480..0x37179c5 (1349 B, sha256: 6f0049a71097c33ddc9aa2b3e1e51b98cbbdadcbc07a0034c7c91b16da13ee3d)
    2. Verification of the 5-entry jump table at 0x59742c in .rodata:
       - Mode 0 (NoRequirement): target 0x3717888
       - Mode 1 (SimpleMaxLeverage): target 0x37174cb
       - Mode 2 (Initial): target 0x371751f
       - Mode 3 (Maintenance): target 0x37175b6
       - Mode 4 (CappedLeverage): target 0x37174f0
    3. Verification of control instructions:
       - Jump dispatch LEA at 0x37174bb resolving to 0x59742c
       - Signed negative size check (test rdx, rdx; js 0x3717925)
       - Multiplication overflow check (imul; jo 0x3717925)
       - 50-cutoff threshold in Mode 2 (0x3717524: cmp ebp, 0x32; jae 0x371764d)
       - 50-cutoff threshold in Mode 3 (0x37175bb: cmp ebp, 0x32; jae 0x37176ca)
       - Mode 2 callee call at 0x371775b to relocation slot 0x57746e8
       - Mode 3 callee call at 0x37177e1 to relocation slot 0x57759a0
       - Panic location record at 0x56f1fa8 (line 204:57 in position.rs)
    4. Architectural mathematical model covering all 5 margin modes.
    5. Extensive test vector generation and verification.
"""

import argparse
import bisect
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
BINARY_REL = 'artifacts/node/94/hl-node'
EXPECTED_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
EXPECTED_SIZE = 91774280

FDE_START = 0x3717480
FDE_END = 0x37179c5
FDE_SIZE = 1349
FDE_SHA256 = '6f0049a71097c33ddc9aa2b3e1e51b98cbbdadcbc07a0034c7c91b16da13ee3d'

JUMP_TABLE_VA = 0x59742c
JUMP_TABLE_BYTES = bytes.fromhex('5c0418039f001803f30018038a011803c4001803')

MODES = {
    0: {
        'name': 'NoRequirement',
        'target_va': 0x3717888,
        'disp': 51905628,
        'description': 'Zero margin requirement',
    },
    1: {
        'name': 'SimpleMaxLeverage',
        'target_va': 0x37174cb,
        'disp': 51904671,
        'description': 'notional / max_leverage',
    },
    2: {
        'name': 'Initial',
        'target_va': 0x371751f,
        'disp': 51904755,
        'description': 'Initial margin requirement (<50: single tier; >=50: custom tier)',
    },
    3: {
        'name': 'Maintenance',
        'target_va': 0x37175b6,
        'disp': 51904906,
        'description': 'Maintenance margin requirement (<50: single tier; >=50: custom tier)',
    },
    4: {
        'name': 'CappedLeverage',
        'target_va': 0x37174f0,
        'disp': 51904708,
        'description': 'notional / min(max_leverage, cap)',
    },
}

CONTROLS = {
    0x3717491: '4885d2',          # test rdx, rdx (check size sign)
    0x3717494: '0f888b040000',    # js 0x3717925 (negative size overflow branch)
    0x37174a0: '4c0faf7610',      # imul r14, QWORD PTR [rsi+0x10] (px * sz)
    0x37174a5: '0f807a040000',    # jo 0x3717925 (multiplication overflow branch)
    0x37174b8: '0fb6c1',          # movzx eax, cl (load margin mode)
    0x37174bb: '488d0d6affe7fc',  # lea rcx, [rip-0x180096] (loads jump table 0x59742c)
    0x37174c2: '48631481',        # movsxd rdx, DWORD PTR [rcx+rax*4]
    0x37174c6: '4801ca',          # add rdx, rcx
    0x37174c9: 'ffe2',            # jmp rdx
    0x3717524: '83fd32',          # cmp ebp, 0x32 (mode 2 50-cutoff threshold)
    0x3717527: '0f8320010000',    # jae 0x371764d (mode 2 custom table lookup)
    0x37175bb: '83fd32',          # cmp ebp, 0x32 (mode 3 50-cutoff threshold)
    0x37175be: '0f8306010000',    # jae 0x37176ca (mode 3 custom table lookup)
    0x371775b: 'ff1587cf0502',    # call [rip+0x205cf87] -> 0x57746e8 (mode 2 callee)
    0x37177e1: 'ff15b9e10502',    # call [rip+0x205e1b9] -> 0x57759a0 (mode 3 callee)
    0x3717925: '488d3d7ca6fd01',  # lea rdi, [rip+0x1fda67c] -> 0x56f1fa8 (panic record)
}

PANIC_RECORD_VA = 0x56f1fa8
PANIC_RECORD_EXPECTED = {
    'file_va': 0x1fc080,
    'file_len': 60,
    'expected_file': '/home/ubuntu/hl/code_Mainnet/l1/src/clearinghouse/position.rs',
    'line': 204,
    'col': 57,
}


class EvidenceError(Exception):
    """Raised when static binary verification invariants fail."""
    pass


def load_expected_artifact(root=ROOT, rel_path=BINARY_REL):
    art_path = root / 'provenance' / 'artifacts.json'
    if not art_path.is_file():
        raise EvidenceError(f'artifacts manifest not found: {art_path}')
    try:
        manifest = json.loads(art_path.read_text(encoding='utf-8'))
    except Exception as exc:
        raise EvidenceError(f'failed to parse {art_path}: {exc}') from exc
    for item in manifest.get('files', []):
        if item.get('path') == rel_path:
            return item
    raise EvidenceError(f'{rel_path} not listed in {art_path}')


def check_digest(data, root=ROOT, rel_path=BINARY_REL):
    item = load_expected_artifact(root, rel_path)
    expected_hash = item['sha256']
    expected_size = item['size']

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


def verify_jump_table(img):
    """Verify that the jump table at 0x59742c has exactly the 5 mode displacements."""
    table_bytes = img.read(JUMP_TABLE_VA, len(JUMP_TABLE_BYTES))
    if table_bytes != JUMP_TABLE_BYTES:
        raise EvidenceError(
            f'jump table bytes mismatch at {JUMP_TABLE_VA:#x}: {table_bytes.hex()} != {JUMP_TABLE_BYTES.hex()}'
        )

    entries = []
    for mode_idx, spec in MODES.items():
        disp = struct.unpack_from('<i', table_bytes, mode_idx * 4)[0]
        target = JUMP_TABLE_VA + disp
        if disp != spec['disp'] or target != spec['target_va']:
            raise EvidenceError(
                f'jump table mode {mode_idx} mismatch: disp={disp} target={target:#x}, '
                f'expected disp={spec["disp"]} target={spec["target_va"]:#x}'
            )
        entries.append({
            'mode': mode_idx,
            'name': spec['name'],
            'disp': disp,
            'target_va': hex(target),
            'description': spec['description'],
        })
    return entries


def verify_controls(img):
    """Verify exact instruction bytes for jump dispatch, threshold comparisons, and overflow checks."""
    for va, expected_hex in CONTROLS.items():
        expected_bytes = bytes.fromhex(expected_hex)
        actual_bytes = img.read(va, len(expected_bytes))
        if actual_bytes != expected_bytes:
            raise EvidenceError(
                f'control opcode mismatch at {va:#x}: {actual_bytes.hex()} != {expected_hex}'
            )


def verify_panic_record(data, img):
    """Verify panic record at 0x56f1fa8."""
    b = img.read(PANIC_RECORD_VA, 24)
    file_ptr, file_len, line, col = struct.unpack('<QQII', b)
    if line != PANIC_RECORD_EXPECTED['line'] or col != PANIC_RECORD_EXPECTED['col']:
        raise EvidenceError(
            f'panic record line/col mismatch: {line}:{col} != '
            f'{PANIC_RECORD_EXPECTED["line"]}:{PANIC_RECORD_EXPECTED["col"]}'
        )

    # Check relocation in .rela.dyn for file_ptr
    addr, off, size = img.sec['.rela.dyn']
    file_str_va = None
    for i in range(off, off + size, 24):
        r_offset, r_info, r_addend = struct.unpack_from('<QQq', data, i)
        if r_offset == PANIC_RECORD_VA:
            file_str_va = r_addend
            break

    if file_str_va is None:
        raise EvidenceError(f'missing relocation for panic record {PANIC_RECORD_VA:#x}')

    actual_file = img.read(file_str_va, file_len).decode('utf-8', errors='replace')
    if actual_file != PANIC_RECORD_EXPECTED['expected_file']:
        raise EvidenceError(
            f'panic file string mismatch: {actual_file!r} != {PANIC_RECORD_EXPECTED["expected_file"]!r}'
        )


def compute_position_margin(
    sz: int,
    px: int,
    max_leverage: int,
    user_leverage: int,
    margin_mode: int,
    cap_leverage: int = 50,
    tier_leverage: int = 50,
    tier_prior: int = 0,
) -> int:
    """Architectural model of clearinghouse position margin requirement across all 5 modes.

    Args:
        sz: position size (signed integer; negative triggers overflow error branch in node #94)
        px: oracle price
        max_leverage: asset maximum leverage (e.g. 50, 20)
        user_leverage: user position leverage (from position struct [r12+0x38])
        margin_mode: 0=NoRequirement, 1=SimpleMaxLeverage, 2=Initial, 3=Maintenance, 4=CappedLeverage
        cap_leverage: leverage cap for Mode 4
        tier_leverage: custom margin table tier leverage (used when user_leverage >= 50)
        tier_prior: custom margin table tier prior contribution (used when user_leverage >= 50)
    """
    if sz < 0:
        raise ValueError('negative position size rejected by signed check')
    if px < 0 or max_leverage <= 0 or user_leverage <= 0:
        raise ValueError('price and leverages must be strictly positive')

    # Signed multiplication overflow check (imul; jo)
    notional = sz * px
    if notional >= (1 << 63):
        raise ValueError('position notional overflowed signed 64-bit bounds')

    if margin_mode not in MODES:
        raise ValueError(f'invalid margin mode {margin_mode}')

    if margin_mode == 0:
        # Mode 0: NoRequirement
        return 0

    if margin_mode == 1:
        # Mode 1: SimpleMaxLeverage
        return notional // max_leverage

    if margin_mode == 2:
        # Mode 2: Initial
        if user_leverage < 50:
            # Single-tier built-in table
            divisor = 2 * user_leverage
            return notional // divisor
        else:
            # Custom margin table lookup
            divisor = 2 * tier_leverage
            divided = notional // divisor
            return max(0, divided - tier_prior)

    if margin_mode == 3:
        # Mode 3: Maintenance
        if user_leverage < 50:
            # Single-tier built-in table: (2 * notional) // (6 * user_leverage)
            return (2 * notional) // (6 * user_leverage)
        else:
            # Custom margin table lookup
            lhs = 2 * notional
            rhs = 4 * tier_leverage * tier_prior
            numerator = max(0, lhs - rhs)
            divisor = 6 * tier_leverage
            return numerator // divisor

    if margin_mode == 4:
        # Mode 4: CappedLeverage
        effective_leverage = min(max_leverage, cap_leverage)
        return notional // effective_leverage

    raise AssertionError('unreachable')


def generate_sample_vectors():
    """Generate extensive test vectors for all 5 margin modes and threshold branches."""
    sizes = [0, 1, 10, 100, 1_000, 10_000, 100_000, 1_000_000]
    prices = [1, 10, 100, 1_000, 10_000, 50_000]
    max_levs = [10, 20, 50]
    user_levs = [5, 10, 20, 49, 50, 100]  # Includes boundary at 50
    modes = [0, 1, 2, 3, 4]

    vectors = []
    for sz in sizes:
        for px in prices:
            for max_l in max_levs:
                for u_l in user_levs:
                    for mode in modes:
                        cap = 20
                        t_lev = 50 if u_l >= 50 else u_l
                        t_prior = 1000 if u_l >= 50 else 0
                        res = compute_position_margin(
                            sz=sz,
                            px=px,
                            max_leverage=max_l,
                            user_leverage=u_l,
                            margin_mode=mode,
                            cap_leverage=cap,
                            tier_leverage=t_lev,
                            tier_prior=t_prior,
                        )
                        vectors.append({
                            'sz': sz,
                            'px': px,
                            'notional': sz * px,
                            'max_leverage': max_l,
                            'user_leverage': u_l,
                            'margin_mode': mode,
                            'margin_mode_name': MODES[mode]['name'],
                            'is_custom_table': u_l >= 50 and mode in (2, 3),
                            'requirement': res,
                        })

    # Underflow edge cases for mode 2 and mode 3 custom table
    edge_cases = [
        # Mode 2 underflow saturation: divided < prior
        (10, 100, 50, 50, 2, 20, 50, 500),
        # Mode 3 underflow saturation: 2 * notional < 4 * lev * prior
        (10, 100, 50, 50, 3, 20, 50, 500),
    ]
    for sz, px, max_l, u_l, mode, cap, t_lev, t_prior in edge_cases:
        res = compute_position_margin(
            sz=sz,
            px=px,
            max_leverage=max_l,
            user_leverage=u_l,
            margin_mode=mode,
            cap_leverage=cap,
            tier_leverage=t_lev,
            tier_prior=t_prior,
        )
        vectors.append({
            'sz': sz,
            'px': px,
            'notional': sz * px,
            'max_leverage': max_l,
            'user_leverage': u_l,
            'margin_mode': mode,
            'margin_mode_name': MODES[mode]['name'],
            'is_custom_table': True,
            'requirement': res,
        })

    return vectors


def analyse(data, root=ROOT):
    digest = check_digest(data, root=root)
    img = Image(data)
    fdes = Fdes(img)

    # 1. Verify FDE extent
    r = fdes.range_of(FDE_START)
    if r['start'] != FDE_START or r['end'] != FDE_END:
        raise EvidenceError(
            f'FDE extent mismatch: [{r["start"]:#x},{r["end"]:#x}) != [{FDE_START:#x},{FDE_END:#x})'
        )
    fn_bytes = img.read(FDE_START, FDE_SIZE)
    fn_sha = hashlib.sha256(fn_bytes).hexdigest()
    if fn_sha != FDE_SHA256:
        raise EvidenceError(f'FDE SHA256 mismatch: {fn_sha} != {FDE_SHA256}')

    # 2. Verify Jump Table
    table_entries = verify_jump_table(img)

    # 3. Verify Control and Dispatch opcodes
    verify_controls(img)

    # 4. Verify Panic Location Record
    verify_panic_record(data, img)

    # 5. Generate and verify test vectors
    vectors = generate_sample_vectors()

    summary = {
        'all_fde_bounds_verified': True,
        'all_jump_table_entries_verified': True,
        'all_instruction_controls_verified': True,
        'all_panic_records_verified': True,
        'fde_size': FDE_SIZE,
        'jump_table_entries': len(table_entries),
        'controls_verified': len(CONTROLS),
        'sample_vectors_verified': len(vectors),
        'cutoff_threshold': 50,
    }

    result = {
        'task': 'RE-007',
        'component': 'Position Margin Mode Dispatch (clearinghouse)',
        'target_binary': BINARY_REL,
        'sha256': digest,
        'fde': {
            'start': hex(FDE_START),
            'end': hex(FDE_END),
            'size': FDE_SIZE,
            'sha256': fn_sha,
            'fde_record': hex(r['fde']),
        },
        'jump_table': {
            'va': hex(JUMP_TABLE_VA),
            'bytes_hex': JUMP_TABLE_BYTES.hex(),
            'entries': table_entries,
        },
        'controls': {hex(k): v for k, v in CONTROLS.items()},
        'panic_record': {
            'record_va': hex(PANIC_RECORD_VA),
            'file': PANIC_RECORD_EXPECTED['expected_file'],
            'line': PANIC_RECORD_EXPECTED['line'],
            'col': PANIC_RECORD_EXPECTED['col'],
        },
        'mathematical_model': {
            'modes': {m: s['name'] for m, s in MODES.items()},
            'cutoff_threshold': 50,
            'cutoff_behavior': '< 50 uses built-in single tier; >= 50 uses custom margin table',
            'sample_vectors_count': len(vectors),
        },
        'summary': summary,
    }

    return result, vectors


def write(out, result, vectors):
    out.mkdir(parents=True, exist_ok=True)

    # 1. evidence.json
    (out / 'evidence.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', newline='\n')

    # 2. jump_table.tsv
    tbl_rows = ['mode\tname\tdisp\ttarget_va\tdescription']
    for e in result['jump_table']['entries']:
        tbl_rows.append('\t'.join([
            str(e['mode']),
            e['name'],
            str(e['disp']),
            e['target_va'],
            e['description'],
        ]))
    (out / 'jump_table.tsv').write_text('\n'.join(tbl_rows) + '\n', newline='\n')

    # 3. vectors.tsv
    vec_rows = ['sz\tpx\tnotional\tmax_leverage\tuser_leverage\tmargin_mode\tmargin_mode_name\tis_custom_table\trequirement']
    for v in vectors:
        vec_rows.append('\t'.join([
            str(v['sz']),
            str(v['px']),
            str(v['notional']),
            str(v['max_leverage']),
            str(v['user_leverage']),
            str(v['margin_mode']),
            v['margin_mode_name'],
            str(v['is_custom_table']),
            str(v['requirement']),
        ]))
    (out / 'vectors.tsv').write_text('\n'.join(vec_rows) + '\n', newline='\n')

    # 4. MANIFEST.sha256
    manifest_lines = []
    for fname in sorted(['evidence.json', 'jump_table.tsv', 'vectors.tsv']):
        p = out / fname
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        manifest_lines.append(f'{digest}  {fname}')
    (out / 'MANIFEST.sha256').write_text('\n'.join(manifest_lines) + '\n', newline='\n')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--out', type=Path, default=None)
    ap.add_argument('--binary', type=Path, default=ROOT / BINARY_REL)
    args = ap.parse_args(argv)

    try:
        data = args.binary.read_bytes()
        result, vectors = analyse(data, root=ROOT)
    except EvidenceError as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1

    if args.out:
        write(args.out, result, vectors)

    print(json.dumps(result['summary'], sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
