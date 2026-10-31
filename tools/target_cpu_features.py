#!/usr/bin/env python3
"""RE-002: census AVX/BMI encodings and same-function CPUID in captured targets.

Build-provenance question (docs/TASKS.md, RE-002 row `target_cpu_features`):
does each target contain unconditional AVX or BMI use outside runtime-dispatched
paths? A same-function CPUID is the only dispatch signal this tool claims; a
callee-side dispatch stub is explicitly out of scope.

The tool reads digest-authenticated ELF bytes and never executes them. An
x86-64 linear sweep classifies every decoded instruction in each FDE-bounded
function. Unknown opcodes are counted and the sweep resynchronises on the next
byte, so a decode gap cannot invent a hit. Standard library only.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import check
from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    '94': 'artifacts/node/94/hl-node',
    '115': 'artifacts/node/115/hl-node',
    'visor': 'artifacts/visor/captured/hl-visor',
}
LIMITATIONS = (
    'A linear sweep is not a full control-flow recovery: jump targets, jump tables, '
    'overlapping encodings and data-in-.text can desynchronise the cursor. Unknown '
    'opcodes advance one byte and are counted separately. Same-function CPUID is the '
    'only dispatch signal; a dispatcher that calls a leaf holding AVX/BMI is not '
    'detected here. FDE extents are unwind-described ranges, not validated function '
    'boundaries. No equivalence with reconstructed Rust is established.'
)

# Legacy prefixes. REX (0x40-0x4F) is handled separately because it must sit
# immediately before the opcode.
LEGACY_PREFIXES = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3}

# One-byte opcodes that take ModRM. Anything not listed is treated as no-ModRM
# unless it is in an immediate-bearing class below.
HAS_MODRM = set(range(0x00, 0x40)) - {0x06, 0x07, 0x0E, 0x16, 0x17, 0x1E, 0x1F, 0x27, 0x2F, 0x37, 0x3F}
HAS_MODRM.update({
    0x62, 0x63, 0x69, 0x6B,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0xC0, 0xC1, 0xC6, 0xC7, 0xD0, 0xD1, 0xD2, 0xD3,
    0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    0xF6, 0xF7, 0xFE, 0xFF,
})
# Two-byte (0F xx) opcodes that take ModRM. Default is ModRM for the 0F map.
TWO_BYTE_NO_MODRM = {
    0x05, 0x07, 0x0B, 0x0D, 0x18, 0x19, 0x1E, 0x1F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x37,
    0x77, 0xA0, 0xA1, 0xA2, 0xA8, 0xA9, 0xAA, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
}

# Immediate size in bytes for one-byte opcodes (after ModRM/SIB/disp).
ONE_BYTE_IMM = {
    0x04: 1, 0x0C: 1, 0x14: 1, 0x1C: 1, 0x24: 1, 0x2C: 1, 0x34: 1, 0x3C: 1,
    0x05: 4, 0x0D: 4, 0x15: 4, 0x1D: 4, 0x25: 4, 0x2D: 4, 0x35: 4, 0x3D: 4,
    0x68: 4, 0x6A: 1, 0x69: 4, 0x6B: 1,
    0x70: 1, 0x71: 1, 0x72: 1, 0x73: 1, 0x74: 1, 0x75: 1, 0x76: 1, 0x77: 1,
    0x78: 1, 0x79: 1, 0x7A: 1, 0x7B: 1, 0x7C: 1, 0x7D: 1, 0x7E: 1, 0x7F: 1,
    0x80: 1, 0x81: 4, 0x82: 1, 0x83: 1,
    0x90: 0,  # nop / xchg
    0xA0: 8, 0xA1: 8, 0xA2: 8, 0xA3: 8,
    0xA8: 1, 0xA9: 4,
    0xB0: 1, 0xB1: 1, 0xB2: 1, 0xB3: 1, 0xB4: 1, 0xB5: 1, 0xB6: 1, 0xB7: 1,
    0xB8: 4, 0xB9: 4, 0xBA: 4, 0xBB: 4, 0xBC: 4, 0xBD: 4, 0xBE: 4, 0xBF: 4,
    0xC0: 1, 0xC1: 1, 0xC2: 2, 0xC6: 1, 0xC7: 4,
    0xCD: 1,
    0xD0: 0, 0xD1: 0, 0xD2: 0, 0xD3: 0,
    0xE4: 1, 0xE5: 1, 0xE6: 1, 0xE7: 1,
    0xE8: 4, 0xE9: 4, 0xEA: 6, 0xEB: 1,
    0xEC: 0, 0xED: 0, 0xEE: 0, 0xEF: 0,
    0xF6: 0,  # group3: imm only for /0 /1, handled below
    0xF7: 0,
    0xFE: 0, 0xFF: 0,
}

# Non-VEX instruction classes we report.
# key: (map, opcode, pp)  map: 0=one-byte, 1=0F, 2=0F38, 3=0F3A
# pp: 0=none, 1=66, 2=F3, 3=F2
CLASS_TABLE = {
    (1, 0xA2, 0): 'cpuid',  # 0F A2
    # F3 0F BC/BD are the REP-BSF/REP-BSR aliases: they execute as BSF/BSR on
    # pre-BMI CPUs and do not by themselves require BMI1/ABM.
    (1, 0xBC, 2): 'tzcnt_lzcnt',
    (1, 0xBD, 2): 'tzcnt_lzcnt',
}
# VEX-only rows. A legacy F3 0F38 F6 is ADOX (ADX), not MULX: the VEX bit must
# be set before these opcodes are credited as BMI.
VEX_CLASS_TABLE = {
    (2, 0xF2, 0): 'bmi1',  # VEX.0F38 andn
    (2, 0xF3, 0): 'bmi1',  # VEX.0F38 blsr / blsmsk / blsi
    (2, 0xF5, 0): 'bmi2',  # VEX.0F38 bzhi
    (2, 0xF5, 2): 'bmi2',  # VEX.F3.0F38 pext
    (2, 0xF5, 3): 'bmi2',  # VEX.F2.0F38 pdep
    (2, 0xF6, 2): 'bmi2',  # VEX.F3.0F38 mulx
    (2, 0xF6, 3): 'bmi2',  # VEX.F2.0F38 mulx (W1 form seen in the captured nodes)
    (2, 0xF7, 1): 'bmi2',  # VEX.66.0F38 shlx
    (2, 0xF7, 2): 'bmi2',  # VEX.F3.0F38 shrx
    (2, 0xF7, 3): 'bmi2',  # VEX.F2.0F38 sarx
    (3, 0xF0, 3): 'bmi2',  # VEX.F2.0F3A rorx
}
# VEX map 0F opcodes that really are SIMD/AVX (Intel SDM Vol. 2 C5/C4 forms).
# Anything else on a VEX prefix is recorded as vex_other, not as AVX: a lone C4/C5
# byte in a desynchronised stream must not inflate the AVX count.
AVX_OPCODES_0F = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE,
    # 0xFF is group-5 in the one-byte map and has no VEX SIMD form.
}


def _vex_class(map_id, opcode, pp):
    """Classify a VEX/EVEX instruction. BMI hits win over the AVX default."""
    hit = VEX_CLASS_TABLE.get((map_id, opcode, pp))
    if hit:
        return hit
    if map_id == 1 and opcode in AVX_OPCODES_0F:
        return 'avx'
    if map_id in (2, 3):
        return 'avx'
    return 'vex_other'


def _modrm_len(data, i, end, addr32=False):
    """Return (total_len_of_modrm_sib_disp, ok)."""
    if i >= end:
        return 0, False
    modrm = data[i]
    mod, rm = modrm >> 6, modrm & 7
    length = 1
    if addr32 and mod == 0 and rm == 6:
        return 1 + 4, True
    if mod != 3 and rm == 4:  # SIB
        if i + 1 >= end:
            return 0, False
        sib = data[i + 1]
        length += 1
        base = sib & 7
        if mod == 0 and base == 5:
            length += 4
    if mod == 0 and rm == 5:
        length += 4
    elif mod == 1:
        length += 1
    elif mod == 2:
        length += 4
    return length, True


def _group3_imm(opcode, modrm):
    """F6/F7: imm8 for /0 /1 (test), imm16/32 for /7 (idiv) — only test has imm."""
    if opcode == 0xF6 and (modrm >> 3) & 7 in (0, 1):
        return 1
    if opcode == 0xF7 and (modrm >> 3) & 7 in (0, 1):
        return 4
    return 0


def decode_one(data, i, end):
    """Decode one instruction starting at i.

    Returns (length, cls, map_id, opcode, pp) or (None, 'undecoded', None, None, None).
    cls is one of: cpuid, bmi1, bmi2, avx, avx512, other, undecoded.
    map_id: 0=one-byte, 1=0F, 2=0F38, 3=0F3A. pp: 0=none, 1=66, 2=F3, 3=F2.
    """
    if i >= end:
        return None, 'undecoded', None, None, None
    start = i
    rex = 0
    legacy_pp = 0
    operand16 = False
    # Legacy prefixes (REX handled separately: it sits immediately before opcode).
    while i < end and data[i] in LEGACY_PREFIXES:
        b = data[i]
        if b == 0x66:
            operand16 = True
            legacy_pp = 1
        elif b == 0xF3:
            legacy_pp = 2
        elif b == 0xF2:
            legacy_pp = 3
        i += 1
        if i - start > 15:
            return None, 'undecoded', None, None, None
    if i < end and 0x40 <= data[i] <= 0x4F:
        rex = data[i]
        i += 1
    if i >= end:
        return None, 'undecoded', None, None, None

    def finish_vex(map_id, pp, opcode_i):
        if opcode_i >= end:
            return None, 'undecoded', None, None, None
        opcode = data[opcode_i]
        ml, ok = _modrm_len(data, opcode_i + 1, end)
        if not ok:
            return None, 'undecoded', None, None, None
        cls = _vex_class(map_id, opcode, pp)
        length = (opcode_i + 1 + ml) - start
        return length, cls, map_id, opcode, pp

    # EVEX (62 in 64-bit mode; P0 bits 3:2 are 00).
    if data[i] == 0x62 and i + 3 < end and (data[i + 1] & 0x0C) == 0:
        map_id = data[i + 1] & 0x07
        pp = data[i + 2] & 3
        length, cls, map_id, opcode, pp = finish_vex(map_id, pp, i + 4)
        if length is None:
            return None, 'undecoded', None, None, None
        if cls in ('avx', 'vex_other') and map_id in (1, 2, 3):
            cls = 'avx512' if cls == 'avx' else 'vex_other'
        return length, cls, map_id, opcode, pp

    # VEX3 (C4) and VEX2 (C5): in 64-bit mode these encodings are always VEX
    # (LES/LDS do not exist here). The captured targets are x86-64 only.
    if data[i] == 0xC4 and i + 2 < end:
        return finish_vex(data[i + 1] & 0x1F, data[i + 2] & 3, i + 3)
    if data[i] == 0xC5 and i + 1 < end:
        return finish_vex(1, data[i + 1] & 3, i + 2)

    # Non-VEX: 0F escape, optional 0F38/0F3A map.
    if data[i] == 0x0F:
        if i + 1 >= end:
            return None, 'undecoded', None, None, None
        b1 = data[i + 1]
        if b1 in (0x38, 0x3A):
            if i + 2 >= end:
                return None, 'undecoded', None, None, None
            map_id = 2 if b1 == 0x38 else 3
            opcode = data[i + 2]
            ml, ok = _modrm_len(data, i + 3, end)
            if not ok:
                return None, 'undecoded', None, None, None
            imm = 1 if map_id == 3 else 0
            cls = CLASS_TABLE.get((map_id, opcode, legacy_pp), 'other')
            length = (i + 3 + ml + imm) - start
            return length, cls, map_id, opcode, legacy_pp
        map_id, opcode, opcode_i = 1, b1, i + 1
    else:
        map_id, opcode, opcode_i = 0, data[i], i

    if map_id == 1:
        if opcode in TWO_BYTE_NO_MODRM:
            ml, imm = 0, 0
        else:
            ml, ok = _modrm_len(data, opcode_i + 1, end)
            if not ok:
                return None, 'undecoded', None, None, None
            imm = 0
            if opcode in (0x71, 0x72, 0x73, 0xA4, 0xAC, 0xBA):
                imm = 1
        length = (opcode_i + 1 + ml + imm) - start
        cls = CLASS_TABLE.get((map_id, opcode, legacy_pp), 'other')
        return length, cls, map_id, opcode, legacy_pp

    # One-byte map.
    ml = 0
    if opcode in HAS_MODRM:
        ml, ok = _modrm_len(data, opcode_i + 1, end)
        if not ok:
            return None, 'undecoded', None, None, None
    imm = ONE_BYTE_IMM.get(opcode, 0)
    if opcode in (0xF6, 0xF7) and opcode_i + 1 < end:
        imm = _group3_imm(opcode, data[opcode_i + 1])
    if opcode in (0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF) and rex & 8:
        imm = 8
    if operand16 and opcode in (0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D, 0xA9, 0x81, 0xC7):
        imm = 2
    length = (opcode_i + 1 + ml + imm) - start
    if length <= 0 or length > 15:
        return None, 'undecoded', None, None, None
    cls = CLASS_TABLE.get((map_id, opcode, legacy_pp), 'other')
    return length, cls, map_id, opcode, legacy_pp


def scan_text(data, fdes, secs):
    """Sweep each FDE-bounded function from its entry (an instruction boundary)."""
    executable = [s for s in secs if s['flags'] & 4 and s['size'] and s['type'] != 8]
    by_name = {s['name']: s for s in executable}
    fn_hits = {}
    section_stats = {}
    undecoded = 0
    decoded = 0
    for f in fdes:
        sec = by_name.get(f['section'])
        if sec is None:
            continue
        base_va, off, size = sec['address'], sec['offset'], sec['size']
        lo = max(f['start'], base_va)
        hi = min(f['end'], base_va + size)
        if hi <= lo:
            continue
        i0 = off + (lo - base_va)
        blob = data[i0:off + (hi - base_va)]
        i = 0
        while i < len(blob):
            length, cls, map_id, opcode, pp = decode_one(blob, i, len(blob))
            if length is None:
                undecoded += 1
                i += 1
                continue
            decoded += 1
            if cls in ALL_REPORTED:
                va = lo + i
                slot = fn_hits.setdefault((f['start'], f['end']),
                                          {'classes': collections.Counter(), 'sites': []})
                slot['classes'][cls] += 1
                slot['sites'].append({'va': va, 'offset': i0 + i, 'cls': cls,
                                      'map': map_id, 'opcode': opcode, 'pp': pp, 'len': length})
            i += length
    # Flatten sites into per-section stats for the TSV.
    for (start, end), slot in fn_hits.items():
        sec = next((s for s in executable if s['address'] <= start < s['address'] + s['size']), None)
        name = sec['name'] if sec else ''
        section_stats.setdefault(name, {'hits': []})
        for site in slot['sites']:
            site['fn_start'], site['fn_end'] = start, end
            section_stats[name]['hits'].append(site)
    section_stats.setdefault('', {'hits': []})
    for name, stats in section_stats.items():
        stats['hit_count'] = len(stats['hits'])
        stats['decoded_instructions'] = decoded
        stats['bytes'] = sum(s['size'] for s in executable if s['name'] == name)
    return fn_hits, section_stats, undecoded


ISA_CLASSES = ('bmi1', 'bmi2', 'avx', 'avx512')
SOFT_CLASSES = ('tzcnt_lzcnt',)
ALL_REPORTED = ('cpuid',) + ISA_CLASSES + SOFT_CLASSES + ('vex_other',)


def classify_functions(fn_hits):
    rows = []
    dispatchers = []
    soft_rows = []
    for (start, end), slot in sorted(fn_hits.items(), key=lambda kv: (kv[0][0] is None, kv[0][0] or 0)):
        classes = slot['classes']
        has_cpuid = classes.get('cpuid', 0) > 0
        isa = {k: classes[k] for k in ISA_CLASSES if classes.get(k)}
        soft = {k: classes[k] for k in SOFT_CLASSES if classes.get(k)}
        base = {
            'fn_start': hex(start) if start is not None else None,
            'fn_end': hex(end) if end is not None else None,
            'size': (end - start) if start is not None else None,
            'counts': dict(classes),
        }
        if isa:
            rows.append(dict(base, isa_classes=sorted(isa),
                             soft_classes=sorted(soft),
                             disposition='same_function_cpuid' if has_cpuid else 'no_same_function_cpuid'))
        elif soft:
            soft_rows.append(dict(base, soft_classes=sorted(soft),
                                  disposition='same_function_cpuid' if has_cpuid else 'no_same_function_cpuid'))
        elif has_cpuid:
            dispatchers.append(dict(base, disposition='cpuid_only'))
    return rows, dispatchers, soft_rows


def analyse(path):
    data = Path(path).read_bytes()
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    executable = [s for s in secs if s['flags'] & 4 and s['size'] and s['type'] != 8]
    for f in fdes:
        sec = next((s for s in executable if s['address'] <= f['start'] < s['address'] + s['size']), None)
        if sec is None:
            raise ValueError(f"FDE start outside executable sections: {f['start']:#x}")
        f['section'] = sec['name']
    fn_hits, section_stats, undecoded = scan_text(data, fdes, secs)
    rows, dispatchers, soft_rows = classify_functions(fn_hits)
    counts = collections.Counter()
    for slot in fn_hits.values():
        counts.update(slot['classes'])
    dispositions = collections.Counter(r['disposition'] for r in rows)
    summary = {
        'binary_sha256': hashlib.sha256(data).hexdigest(),
        'binary_size': len(data),
        'fde_records': len(fdes),
        'instruction_sites_by_class': {k: counts.get(k, 0) for k in ALL_REPORTED},
        'functions_with_isa_extension': len(rows),
        'function_dispositions': dict(dispositions),
        'functions_with_only_tzcnt_lzcnt': len(soft_rows),
        'cpuid_only_functions': len(dispatchers),
        'undecoded_bytes_skipped': undecoded,
        'limitations': LIMITATIONS,
    }
    return summary, rows, dispatchers, soft_rows, section_stats


def generate(rel, out_dir):
    item = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files'] if i['path'] == rel)
    check(ROOT / rel, item)
    summary, rows, dispatchers, soft_rows, section_stats = analyse(ROOT / rel)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / 'census.json').write_text(json.dumps(summary, indent=2) + '\n')
    (out_dir / 'functions.json').write_text(json.dumps(rows, indent=2) + '\n')
    (out_dir / 'dispatchers.json').write_text(json.dumps(dispatchers, indent=2) + '\n')
    (out_dir / 'tzcnt-lzcnt.json').write_text(json.dumps(soft_rows, indent=2) + '\n')
    by_start = {r['fn_start']: r for r in rows}
    soft_by_start = {r['fn_start']: r for r in soft_rows}
    lines = ['va\tfile_offset\tclass\tfn_start\tdisposition\topcode\tmap\tpp']
    for sec_name, stats in section_stats.items():
        for hit in stats['hits']:
            key = hex(hit['fn_start']) if hit['fn_start'] is not None else None
            owner = by_start.get(key) or soft_by_start.get(key)
            lines.append('\t'.join([
                hex(hit['va']), hex(hit['offset']), hit['cls'],
                key or '',
                owner['disposition'] if owner else '',
                f"0x{hit['opcode']:02x}", str(hit['map']), str(hit['pp']),
            ]))
    (out_dir / 'sites.tsv').write_text('\n'.join(lines) + '\n')
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--release', choices=sorted(TARGETS), required=True)
    p.add_argument('--out', type=Path, default=None)
    args = p.parse_args()
    rel = TARGETS[args.release]
    out = args.out or (ROOT / f'work/target-cpu-features/{args.release}')
    summary = generate(rel, out)
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
