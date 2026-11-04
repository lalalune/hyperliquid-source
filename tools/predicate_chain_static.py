"""Static evidence for the RE-005 predicate-chain packet.

Answers, for the authenticated hl-node 115 artifact only
(open edge 1 of RE-005-node115-gate-checkers, PR #2613):
which callee in checker_a's predicate post-check chain
overwrites the -1 sentinel the predicate stores at S+0x38,
and what the builder's S+0x60/S+0x68 inputs become.

1.  Conversion body 0x5cead40 (called by predicate
    0x5cf2d30 at 0x5cf2e46) and slot-0x64e0518 callee
    0x5ce91b0 (called by the predicate at 0x5cf2e94, after
    the conversion returns): full argument contracts, every
    store through their arguments, callees, returns.
2.  Exact attribution of the sentinel overwrite: body,
    store site, condition - or the actual writer if neither
    candidate writes it.
3.  Builder 0x5cf2150's S+0x60/S+0x68 values: provenance
    (base-value body 0x5c842e0, accessor 0x5cf2b50 via slot
    0x64e0848, descriptor static 0x644dc28) and how the
    conversion body consumes the pair.
4.  The testable condition under which checker_a returns
    nonzero through this path.

Method: all twelve bodies are exported in full.  Store
censuses are taken over the disassembly of the argument
registers of the conversion body, its tail callee (the
setter 0x5cea7c0), the post-call body, the builder, the
normalise body 0x5cf1d70 and the predicate itself; the
setter census stops at the instruction that rebinds its
rcx register to a different object (0x5cea8d5).  Strings
and tables resolve through the section table (.rodata is
identity-mapped; .text resolves at VA-0x1000; .data.rel.ro
at VA-0x2000); GOT slots are resolved from .rela.dyn
addends, and the one GLOB_DAT slot from .dynsym.
"""

import hashlib
import json
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifacts import ROOT  # noqa: E402
from elf_index import sections  # noqa: E402

TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
TARGET_SIZE = 105896032
TARGET_SHA256 = ('a6e2897cd051213d004802deca416e8eca62b7a8278'
                 'fa39f249e98c3867b5301')
WORK_ITEM = 'RE-005-node115-predicate-chain'
OUT = ROOT / 'research' / 'work-items' / WORK_ITEM
SNAPSHOT = '<authenticated-node115>'

OWNERS = {
    'checker_a': (0x2C7F360, 0x2C7F71B),
    'builder': (0x5CF2150, 0x5CF22E9),
    'predicate': (0x5CF2D30, 0x5CF2FEF),
    'normalise': (0x5CF1D70, 0x5CF1DF8),
    'accessor': (0x5CF2B50, 0x5CF2C34),
    'basevalue': (0x5C842E0, 0x5C843A9),
    'desccall': (0x5C84210, 0x5C842D6),
    'conversion': (0x5CEAD40, 0x5CEAE75),
    'setter': (0x5CEA7C0, 0x5CEAA17),
    'postcall': (0x5CE91B0, 0x5CE94B1),
    'insert': (0x5CF6880, 0x5CF69BF),
    'bucket': (0x5CE29A0, 0x5CE2A76),
}
EXPORTED = list(OWNERS)

OWNER_SHA256 = {
    'checker_a': 'ff59e02e9d3e078985ba6e3b58d8f64f3a6ed5171f2120'
                 'd314cbb5a3c744daed',
    'builder': '63364fa5c7e4158629d264ba1afefeb9e1353840a2bfae7'
               'd34266cc38d7dcade',
    'predicate': 'fb3fb193f0b14f251e01da509c670d299323482419d1e'
                 'def4170d948604cbbb2',
    'normalise': 'df16d24db15a077c7d624c4820f6ad7206588967bd076'
                 'bcb903f2ea172364d2f',
    'accessor': 'e367d0fd93829f39d7bf17c0645ea453b07f47e6dc71a91'
                '72bac94e70d47d05e',
    'basevalue': '3efe331bdc612bff27ad3c487fbff92d57a2e097820c3'
                 '8f87506703794918f30',
    'desccall': 'f9d8d8a41505bf8c9552d4a34ac4e190a6d0665c245595b'
                'e11f2848e1a333a4a',
    'conversion': 'a6069a107a631c0f5efdb0f22e5b4a623ad077389b6b'
                  '09225b8a5ca31de923dd',
    'setter': '5fbfddaf7831cf129e1dc6734e16b7aa37d5e51b3355c96a'
              '8da582d905f4d8e2',
    'postcall': 'f5d6c7cb996b0e42213f37df8337c7685b48103a5f856983'
                '884cc56d8f34c16d',
    'insert': '9b9b96ad18568130435d9442cbc897deef1bd531a6b2bab7'
              '1e050997e87ef6ef',
    'bucket': '7f1bf0ac13bf0df1287b21da22e231bf1b29ea287ea2182'
              'aa5b8433b1fef89d8',
}

# GOT / descriptor slots: va -> expected resolution.  The
# clock slot is a GLOB_DAT entry naming a libc symbol; all
# others are R_X86_64_RELATIVE addends.
SLOT_TARGETS = {
    0x64E13A0: 0x5CF2150,   # builder (predicate's build call)
    0x64E0858: 0x5CF2D30,   # predicate (checker_a's call)
    0x64E0848: 0x5CF2B50,   # accessor (builder + predicate)
    0x64E0518: 0x5CE91B0,   # postcall (predicate, after conv.)
    0x64DF770: 0x1680BD0,   # assert-fail callee
    0x64DF6A0: 0x1680C30,   # panic-format callee (basevalue)
    0x64DFE40: 0x5CEAFD0,   # normalise drop callee
    0x64E01F8: 0x5BB59D0,   # setter contention wait
    0x64E0F38: 0x5BB5650,   # setter / postcall release fn
    0x644DC28: 0x4326C1,    # descriptor static -> "base/src/lu.rs"
    0x64C6A48: 0x446310,    # wheel Location static -> path string
}
CLOCK_SLOT = 0x64E1248
CLOCK_SYMBOL = 'clock_gettime'

STRINGS = {
    'timers_disabled': (0x94CA6B, 115,
                        'A Tokio 1.x context was found, but timers '
                        'are disabled. Call `enable_time` on the '
                        'runtime builder to enable timers.'),
    'result_unwrap': (0x949294, 43,
                      'called `Result::unwrap()` on an `Err` value'),
    'duration_overflow': (0x949272, 25, 'overflow in Duration::new'),
    'add_duration_overflow': (0x94A2C1, 40,
                              'overflow when adding duration to '
                              'instant'),
    'lu_rs': (0x4326C1, 14, 'base/src/lu.rs'),
    'wheel_path': (0x446310, 73,
                   '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/'
                   'src/runtime/time/wheel/mod.rs'),
}

# Descriptor static 0x644dc28 (builder's rcx argument, a pair
# of panic Location statics) and the wheel Location static
# 0x64c6a48, as raw file qwords (first qword is relocated).
DESCRIPTOR_QWORDS = [0x0, 0xE, 0x50000004B, 0x0, 0xE, 0x390000004A]
WHEEL_LOCATION_QWORDS = [0x0, 0x49, 0x1100000082]

CONSTANTS = {
    'nsec_per_sec': 1000000000,
    'conversion_threshold': 999000001,
    'conversion_adjust_down': -999000001,
    'conversion_adjust_up': 999999,
    'millis_magic_multiplier': 1125899907,
    'millis_magic_shift': 50,
    'value_saturation': '0xfffffffffffffffd',
    'builder_fallback_add': 946080000,
    'selector_offsets': ['0x160', '0x240'],
    'wheel_bucket_stride': 1040,
}

# Frozen instruction-byte pins: site -> bytes (hex).
PINS = {
    0x5CF2E1E: '49c74638ffffffff',          # predicate sentinel store
    0x5CF2E46: 'e8f57effff',                # predicate -> conversion
    0x5CF2E94: 'ff157ed67e00',              # predicate -> postcall slot
    0x5CEA8C1: '4d896618',                  # setter VALUE store [r14+0x18]
    0x5CEA8C5: '4d896610',                  # setter value store [r14+0x10]
    0x5CEA897: '41c6463801',                # setter flag byte [r14+0x38]=1
    0x5CEA89C: '49c74618ffffffff',          # setter sentinel restore
    0x5CEA7D8: 'f00fb00f',                  # setter wheel lock cmpxchg
    0x5CEA881: '0fb64330',                  # setter flag test byte [rbx+0x30]
    0x5CEAE3E: 'e97df9ffff',                # conversion tail jmp -> setter
    0x5CEADB8: 'e85394f9ff',                # conversion -> desccall
    0x5CF2261: '4c897b60',                  # builder [S+0x60] store
    0x5CF2265: '896b68',                    # builder [S+0x68] store
    0x5CF216F: 'e86c21f9ff',                # builder -> basevalue (1st)
    0x5CE91C5: 'f0480fb14f10',              # postcall state cmpxchg [rdi+0x10]
    0x5C842ED: 'ff1555cf8500',              # basevalue -> clock slot call
    0x5CEAD70: '81fac1878b3b',              # conversion threshold cmp
    0x5CEADF3: '4869c983de1b43',            # conversion millis magic imul
}

STORE_MNEMS = {'mov', 'movq', 'movl', 'movw', 'movb', 'movups',
               'movaps', 'movsd', 'cmpxchg', 'xchg', 'xadd',
               'decq', 'incq'}


def check(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(va, data, size=None):
    for section in sections(data):
        start = section['address']
        if start <= va < start + section['size']:
            off = section['offset'] + (va - start)
            if size is None:
                return data[off:section['offset'] + section['size']]
            check(off + size <= section['offset'] + section['size'],
                  f'read overruns section at {va:#x}')
            return data[off:off + size]
    raise ValueError(f'no section holds {va:#x}')


def owners(data):
    lines = frame_lines(data)
    needles = {ln.split('pc=')[1].split()[0] for ln in lines
               if 'pc=' in ln}
    extents = set()
    for needle in needles:
        lo, hi = needle.split('..')
        extents.add((int(lo, 16), int(hi, 16)))
    records = {}
    for role, (start, end) in OWNERS.items():
        check((start, end) in extents, f'no FDE for {role}')
        raw = read(start, data, end - start)
        digest = sha(raw)
        check(digest == OWNER_SHA256[role], f'digest drift {role}')
        for section in sections(data):
            if section['address'] <= start < (section['address']
                                              + section['size']):
                offset = section['offset'] + (start
                                              - section['address'])
        records[role] = {
            'start': hex(start), 'end': hex(end),
            'file_offset': hex(offset), 'bytes': end - start,
            'sha256': digest}
    return records


def frame_lines(data):
    with tempfile.NamedTemporaryFile(suffix='.bin',
                                     delete=False) as tmp:
        tmp.write(data)
        name = tmp.name
    try:
        text = subprocess.run(['readelf', '-wf', name],
                              check=True, capture_output=True,
                              text=True).stdout
    finally:
        Path(name).unlink()
    wanted = []
    for start, end in OWNERS.values():
        needle = f'pc={start:016x}..{end:016x}'
        wanted += [ln for ln in text.splitlines() if needle in ln]
    check(len(wanted) == len(OWNERS), 'owner frame lines missing')
    return [line + '\n' for line in wanted]


def exports(data, role):
    start, end = OWNERS[role]
    text = subprocess.run(
        ['objdump', '-d', '-M', 'intel', '--no-show-raw-insn',
         '--start-address', hex(start), '--stop-address', hex(end),
         str(TARGET)],
        check=True, capture_output=True, text=True).stdout
    return text.replace(str(TARGET), SNAPSHOT, 1)


def disasm_rows(data, start, end):
    with tempfile.NamedTemporaryFile(suffix='.bin',
                                     delete=False) as tmp:
        tmp.write(data)
        name = tmp.name
    try:
        text = subprocess.run(
            ['objdump', '-d', '--start-address', hex(start),
             '--stop-address', hex(end), name],
            check=True, capture_output=True, text=True).stdout
    finally:
        Path(name).unlink()
    rows = []
    pat = re.compile(r'^\s+([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*'
                     r'\t(.*)$')
    for line in text.splitlines():
        m = pat.match(line)
        if m:
            rows.append((int(m.group(1), 16), m.group(3).strip()))
    return rows


def store_census(data, start, end, bases=None):
    """All memory-writing instructions in [start, end).

    Returns [{'site', 'base', 'disp'}] in address order.  The
    destination operand of an AT&T store is its last operand;
    a destination is a memory operand iff it contains '(' or
    starts with '%fs:'.
    """
    found = []
    for va, ins in disasm_rows(data, start, end):
        text = ins.split('#')[0].strip()
        if not text:
            continue
        parts = text.split(None, 1)
        mnem = parts[0]
        if mnem == 'lock':
            sub = parts[1].split(None, 1)
            mnem = sub[0]
            rest = sub[1] if len(sub) > 1 else ''
        else:
            rest = parts[1] if len(parts) > 1 else ''
        if mnem not in STORE_MNEMS or not rest:
            continue
        operands = [o.strip() for o in rest.split(',')]
        dst = operands[-1]
        if '(' not in dst and not dst.startswith('%fs:'):
            continue
        if dst.startswith('%fs:'):
            base, disp = 'fs', None
        else:
            m = re.match(r'^(.*)\(%(\w+)', dst)
            check(m is not None, f'unparsed store dst {dst}')
            raw_disp, base = m.group(1), m.group(2)
            if raw_disp in ('', '+'):
                disp = 0
            else:
                disp = int(raw_disp, 0)
        if bases is not None and base not in bases:
            continue
        found.append({'site': hex(va), 'base': base, 'disp': disp})
    return found


def expect(found, wanted, label):
    got = [(e['site'], e['base'], e['disp']) for e in found]
    check(got == wanted, f'{label} census drift: {got}')
    return found


def store_censuses(data):
    conv_all = store_census(data, *OWNERS['conversion'])
    expect(conv_all,
           [('0x5cead97', 'rsp', 8), ('0x5cead9c', 'rsp', 16),
            ('0x5ceada0', 'rsp', 24), ('0x5ceada5', 'rsp', 32)],
           'conversion')
    conv_arg = [e for e in conv_all if e['base'] in ('rdi', 'rbx')]
    check(conv_arg == [], 'conversion writes through its argument')

    post_main = store_census(data, 0x5CE91B0, 0x5CE9286,
                             bases={'rdi', 'rbx', 'rcx'})
    expect(post_main,
           [('0x5ce91c5', 'rdi', 16), ('0x5ce91ed', 'rbx', 0),
            ('0x5ce91f0', 'rbx', 8), ('0x5ce91fb', 'rbx', 16),
            ('0x5ce9235', 'rcx', 0), ('0x5ce923e', 'rcx', 16)],
           'postcall main')
    post_eh_rdi = store_census(data, 0x5CE9286, OWNERS['postcall'][1],
                               bases={'rdi'})
    check(post_eh_rdi == [], 'postcall EH pads write via rdi')
    post_eh_rbx = store_census(data, 0x5CE9286, OWNERS['postcall'][1],
                               bases={'rbx'})
    expect(post_eh_rbx, [('0x5ce9489', 'rbx', 16)], 'postcall EH rbx')
    post_eh_rcx = store_census(data, 0x5CE9286, OWNERS['postcall'][1],
                               bases={'rcx', 'rax'})
    expect(post_eh_rcx,
           [('0x5ce9296', 'rcx', 0), ('0x5ce9350', 'rcx', 0),
            ('0x5ce946b', 'rax', 0)], 'postcall EH globals')

    setter_q = store_census(data, 0x5CEA7C0, 0x5CEA8D5, bases={'r14'})
    expect(setter_q,
           [('0x5cea85e', 'r14', 0), ('0x5cea897', 'r14', 56),
            ('0x5cea89c', 'r14', 24), ('0x5cea8b7', 'r14', 48),
            ('0x5cea8c1', 'r14', 24), ('0x5cea8c5', 'r14', 16)],
           'setter q')
    setter_other = store_census(data, 0x5CEA7C0, 0x5CEA8D5,
                                bases={'rcx', 'rax', 'rbx'})
    expect(setter_other,
           [('0x5cea84c', 'rcx', 8), ('0x5cea858', 'rax', 0),
            ('0x5cea86e', 'rbx', 24)],
           'setter other')

    builder_s = store_census(data, *OWNERS['builder'], bases={'rbx'})
    expect(builder_s,
           [('0x5cf2261', 'rbx', 96), ('0x5cf2265', 'rbx', 104),
            ('0x5cf2268', 'rbx', 0), ('0x5cf226b', 'rbx', 8),
            ('0x5cf226f', 'rbx', 16)],
           'builder')

    predicate_s = store_census(data, *OWNERS['predicate'],
                               bases={'r14'})
    expect(predicate_s,
           [('0x5cf2e06', 'r14', 16), ('0x5cf2e0a', 'r14', 24),
            ('0x5cf2e11', 'r14', 32), ('0x5cf2e16', 'r14', 48),
            ('0x5cf2e1e', 'r14', 56), ('0x5cf2e26', 'r14', 64),
            ('0x5cf2e2e', 'r14', 80), ('0x5cf2e36', 'r14', 88),
            ('0x5cf2f99', 'r14', 16), ('0x5cf2f9d', 'r14', 24),
            ('0x5cf2fa4', 'r14', 32), ('0x5cf2fa9', 'r14', 48),
            ('0x5cf2fb1', 'r14', 56), ('0x5cf2fb9', 'r14', 64),
            ('0x5cf2fc1', 'r14', 80), ('0x5cf2fc9', 'r14', 88)],
           'predicate')

    norm_handle = store_census(data, *OWNERS['normalise'],
                               bases={'rax'})
    expect(norm_handle,
           [('0x5cf1d8e', 'rax', 0), ('0x5cf1d9f', 'rax', 0)],
           'normalise handle')
    norm_arg = store_census(data, *OWNERS['normalise'],
                            bases={'rdi', 'rbx'})
    check(norm_arg == [], 'normalise writes through its argument')

    return {
        'conversion_all_stores': conv_all,
        'conversion_through_argument': conv_arg,
        'postcall_argument_stores': post_main,
        'postcall_eh_rdi_stores': post_eh_rdi,
        'postcall_eh_rbx_stores': post_eh_rbx,
        'postcall_eh_global_stores': post_eh_rcx,
        'setter_q_stores_pre_rebind': setter_q,
        'setter_other_stores_pre_rebind': setter_other,
        'builder_s_stores': builder_s,
        'predicate_s_stores': predicate_s,
        'normalise_handle_stores': norm_handle,
        'normalise_through_argument': norm_arg,
    }


def rela_entries(data):
    entries = {}
    for section in sections(data):
        if section['name'] != '.rela.dyn':
            continue
        blob = data[section['offset']:
                    section['offset'] + section['size']]
        for i in range(0, len(blob) - 23, 24):
            off, info, addend = struct.unpack_from('<QQq', blob, i)
            entries[off] = (info & 0xFFFFFFFF, info >> 32, addend)
    return entries


def dynsym_name(data, index):
    dynsym = next(s for s in sections(data) if s['name'] == '.dynsym')
    dynstr = next(s for s in sections(data) if s['name'] == '.dynstr')
    off = dynsym['offset'] + index * 24
    name_off = struct.unpack_from('<I', data, off)[0]
    start = dynstr['offset'] + name_off
    end = data.index(b'\x00', start)
    return data[start:end].decode()


def slots_census(data):
    entries = rela_entries(data)
    records = {}
    for slot, target in SLOT_TARGETS.items():
        check(slot in entries, f'slot {slot:#x} has no relocation')
        typ, _, addend = entries[slot]
        check(typ == 8, f'slot {slot:#x} is not RELATIVE')
        check(addend == target,
              f'slot {slot:#x} resolves to {addend:#x}')
        records[hex(slot)] = hex(target)
    typ, sym, _ = entries[CLOCK_SLOT]
    check(typ == 6, 'clock slot is not GLOB_DAT')
    name = dynsym_name(data, sym)
    check(name == CLOCK_SYMBOL, f'clock slot names {name}')
    records[hex(CLOCK_SLOT)] = f'{CLOCK_SYMBOL}@GLOB_DAT'
    return records


def strings_census(data):
    records = {}
    for role, (va, size, text) in STRINGS.items():
        raw = read(va, data, size)
        check(raw.decode() == text, f'string drift {role}')
        records[role] = {'va': hex(va), 'bytes': size, 'text': text}
    return records


def statics_census(data):
    desc = list(struct.unpack_from('<6Q', read(0x644DC28, data, 48), 0))
    check(desc == DESCRIPTOR_QWORDS, f'descriptor drift {desc}')
    wheel = list(struct.unpack_from('<3Q', read(0x64C6A48, data, 24), 0))
    check(wheel == WHEEL_LOCATION_QWORDS,
          f'wheel location drift {wheel}')
    return {
        'descriptor_0x644dc28': {
            'qwords': [hex(q) for q in desc],
            'note': 'two panic Location statics {ptr relocated to '
                    '0x4326c1, len 14, packed line/col}: '
                    '0x50000004b = line 75 col 5, '
                    '0x390000004a = line 74 col 57'},
        'wheel_location_0x64c6a48': {
            'qwords': [hex(q) for q in wheel],
            'note': 'panic Location static {ptr relocated to '
                    '0x446310, len 73, packed 0x1100000082 = '
                    'line 130 col 17}'},
    }


def pins_census(data):
    records = {}
    for site, want in PINS.items():
        raw = read(site, data, len(bytes.fromhex(want)))
        check(raw.hex() == want, f'pin drift at {site:#x}')
        records[hex(site)] = want
    return records



FINDINGS = {
    'attribution': (
        'The -1 sentinel at S+0x38 is overwritten by the '
        'conversion chain, not by the slot-0x64e0518 callee. '
        'The conversion body 0x5cead40 makes no store through '
        'its argument at all (its only stores are four stack '
        'slots); it tail-jumps at 0x5ceae3e to the setter body '
        '0x5cea7c0 with rcx = &[S+0x20], rdx = the converted '
        'value and rdi = the wheel object at handle+sel+0x50. '
        'The setter stores the value at 0x5cea8c1 '
        '(mov [r14+0x18], r12 with r14 = &[S+0x20], i.e. '
        'S+0x38) and at 0x5cea8c5 ([r14+0x10], i.e. S+0x30).'),
    'postcall_negative': (
        'Body 0x5ce91b0 (slot 0x64e0518), called by the '
        'predicate on &[S+0x40] after the conversion returns, '
        'cannot reach the sentinel: relative to its argument '
        'the sentinel sits at -0x8, and the body\'s complete '
        'argument-store census is offsets {0x0, 0x8, 0x10} '
        'only (a once-cell state cmpxchg at +0x10, a pair '
        'store at +0x0/+0x8, a contention steal at +0x0 and '
        'an xchg at +0x10). Its exception-handling pads add '
        'exactly one further argument store - a lock cmpxchg '
        'at 0x5ce9489 on the same +0x10 state word, on a '
        'cleanup path that jumps back into the main '
        'contention flow - and three lock decq stores '
        'through the global counter pointer loaded from '
        'slot 0x64dfe90 (0x5ce9296, 0x5ce9350, 0x5ce946b). '
        'No store anywhere in the body uses a negative '
        'displacement from the argument.'),
    'normalise_negative': (
        'Body 0x5cf1d70 is called by the predicate at '
        '0x5cf2e01, before the sentinel store at 0x5cf2e1e, '
        'and on the [S+0x10] == 2 path it returns immediately '
        '(its first check is dword [rdi] == 2). In general it '
        'writes only through the handle it drops (two lock '
        'decq stores) and never through its argument struct, '
        'so it cannot be the writer either.'),
    'conversion_contract': (
        '0x5cead40(rdi = &[S+0x10], rsi = [S+0x60] seconds, '
        'edx = dword [S+0x68] nanoseconds). It reads the '
        'handle [S+0x18], selects the table offset from byte '
        '[S+0x10] (nonzero -> 0x160, zero -> 0x240), and '
        'traps through the assert-fail callee behind slot '
        '0x64df770 if dword [handle+sel+0x90] == 1000000000 - '
        'the 115-byte message at 0x94ca6b (timers disabled) - '
        'at 0x5cead6a and again at 0x5ceaddd after the '
        'difference call. The (sec, nsec) pair is adjusted: '
        'nsec >= 999000001 -> sec += 1 (overflow trap at '
        '0x5ceae5c, "overflow when adding duration to '
        'instant"), nsec -= 999000001; else nsec += 999999. '
        'It then calls the difference body 0x5c84210 with a '
        'stack descriptor {sec, nsec, [handle+sel+0x88], '
        '[handle+sel+0x90]} whose tail doubles as the second '
        'operand, computing (sec, nsec) - (handle sec, '
        'handle nsec) into {sign, diff sec, diff nsec} '
        '(body 0x5c84210, swap-recursive on A < B, panic '
        '"overflow in Duration::new"). The converted value '
        'is diff_sec * 1000 + (diff_nsec * 1125899907 >> 50) '
        '+ carry (a millisecond-shaped count), forced to 0 '
        'when the difference sign qword is nonzero, and '
        'saturated at 0xfffffffffffffffd. Return is the tail '
        'jump into the setter.'),
    'setter_contract': (
        '0x5cea7c0(rdi = wheel object at handle+sel+0x50, '
        'rsi = adjusted seconds, rdx = converted value, '
        'rcx = &[S+0x20] entry). Entry byte-locks the wheel '
        '(lock cmpxchg [rdi], 1 at 0x5cea7d8); on contention '
        'it waits via slot 0x64e01f8 -> 0x5bb59d0 with a '
        '1000000000 timeout and re-reads the entry. Before '
        'the flag test it unlinks or bucket-inserts an entry '
        'whose value slot is already set: level index from '
        'bsr((value xor [wheel+0x10]) | 0x3f) clamped to '
        '0xffffffffe, bucket = [wheel+0x8] + level * 0x410, '
        'insert body 0x5ce29a0; an out-of-range level traps '
        'at the wheel Location static 0x64c6a48 (path string '
        'at 0x446310, line 130 col 17). The decision is the '
        'byte at [wheel+0x30], loaded at 0x5cea881 - see the '
        'decision table. After a direct store it calls the '
        'insert body 0x5cf6880 (rdi = &[wheel+0x8], rsi = '
        'entry), which links the entry and returns a '
        '(rax, rdx) pair; the setter then rebinds r14 to the '
        'rdx object at 0x5cea8d5 and processes that returned '
        'entry (its own flag byte and value slot, a callback '
        'through [rdx+0x8]) - stores after 0x5cea8d5 are on '
        'that other object, not on S.'),
    'builder_inputs': (
        'Builder 0x5cf2150(rdi = S, rsi = duration seconds, '
        'edx = duration nanoseconds, rcx = descriptor static '
        '0x644dc28). It calls the base-value body 0x5c842e0 '
        'with edi = 1 (sites 0x5cf216f and, on the overflow '
        'fallback, 0x5cf21b6; the fallback adds 946080000 to '
        'the re-read seconds). 0x5c842e0 forwards that 1 '
        'untouched as the clock id of the GLOB_DAT slot '
        '0x64e1248 (clock_gettime) and returns its '
        '(sec, nsec) pair, unwrap-trapping on error (message '
        'at 0x949294) and trapping if nsec >= 1000000000. '
        'The builder forms deadline sec = clock sec + '
        'duration sec (checked; on overflow the fallback '
        'path runs) and deadline nsec = clock nsec + '
        'duration nsec normalised into [0, 1e9) with carry '
        'into the seconds. It calls the accessor behind '
        'slot 0x64e0848 (0x5cf2b50) with the descriptor: the '
        'accessor returns rax in {0, 1} (strong/weak flag) '
        'and rdx = the calling thread\'s current handle '
        'pointer (read from the TLS cell at fs:-0x1130+0x10) '
        'after a lock xadd refcount increment on it, and the '
        'builder asserts [handle+sel+0x90] != 1000000000 '
        '(sel from rax bit 0) through the same timers-'
        'disabled trap. Stores (0x5cf2261..0x5cf226f): '
        '[S+0x60] = deadline sec (qword), [S+0x68] = '
        'deadline nsec (dword), [S+0x0] = accessor flag, '
        '[S+0x8] = handle, [S+0x10] = 2. The conversion '
        'body consumes exactly the pair: [S+0x60] as an '
        'integer seconds count (incremented on the nsec '
        'carry arm, never dereferenced) and dword [S+0x68] '
        'as its nanosecond part - a (sec, nsec) deadline, '
        'differenced against the handle\'s stored (sec, '
        'nsec) at [handle+sel+0x88]/[handle+sel+0x90].'),
    'predicate_flow': (
        'Predicate 0x5cf2d30 on the non-TLS, [S+0x10] == 2 '
        'path: refcount-increments [S+0x8], calls 0x5cf1d70 '
        'on &[S+0x10] (no-op for tag 2), then stores the '
        'entry fields itself - [S+0x10] = derived flag, '
        '[S+0x18] = handle, [S+0x20..0x30] = 0, [S+0x30] = '
        '0, [S+0x38] = -1 at 0x5cf2e1e, [S+0x40] = 0, '
        '[S+0x50] = 0, byte [S+0x58] = 0 - calls the '
        'conversion, re-checks the handle fields, calls '
        '0x5ce91b0 on &[S+0x40], and only then reads '
        '[S+0x38] for its return rule (1 iff != -1; 0 iff '
        '== -1 and byte [S+0x58] == 0; -1 with byte '
        '[S+0x58] != 0 takes the timer-error unwind). The '
        'same eight field stores repeat in the timer-error '
        'landing pad at 0x5cf2f99 (the sentinel re-stored '
        'at 0x5cf2fb1) before the pad drops the entry '
        'through 0x5cf1d10 and resumes the unwind - a '
        'cleanup re-initialisation, not a second decision '
        'path.'),
}

DECISION_TABLE = {
    'scope': 'predicate non-TLS path, [S+0x10] == 2, entry '
             'slot [S+0x38] freshly stored as -1 and flag '
             'byte [S+0x58] freshly zeroed by the predicate',
    'rows': [
        {'wheel_byte_+0x30': '== 0',
         'setter_outcome': 'direct store: [S+0x38] := '
                           'converted value at 0x5cea8c1, '
                           '[S+0x30] := converted value at '
                           '0x5cea8c5, entry inserted via '
                           '0x5cf6880',
         'predicate_result': 'returns 1 (nonzero)'},
        {'wheel_byte_+0x30': '!= 0, entry value slot still '
                              '-1 at the flag test',
         'setter_outcome': 'no store, flag byte untouched',
         'predicate_result': 'returns 0'},
        {'wheel_byte_+0x30': '!= 0, entry value slot != -1 '
                              'at the flag test',
         'setter_outcome': 'flag store: byte [S+0x58] := 1 '
                           'at 0x5cea897, [S+0x38] := -1 '
                           'restored at 0x5cea89c, entry '
                           'state [S+0x50] |= 2 via cmpxchg '
                           'at 0x5cea8b7',
         'predicate_result': 'timer-error unwind (no return)'},
    ],
    'preconditions': 'the conversion assert must not trap '
                     '([handle+sel+0x90] != 1000000000 at '
                     '0x5cead6a and 0x5ceaddd) and the '
                     'setter wheel byte-lock must be '
                     'acquired (directly, or after the '
                     'contention wait via slot 0x64e01f8)',
    'testable_statement': (
        'Through this path checker_a returns nonzero iff '
        'byte [wheel+0x30] == 0 at the setter\'s flag test '
        '(0x5cea881), where wheel = [S+0x18] + sel + 0x50 '
        'and sel = byte [S+0x10] != 0 ? 0x160 : 0x240; the '
        'converted value\'s magnitude never influences the '
        'predicate\'s return beyond being stored.'),
}

OPEN_EDGES = [
    'The source identity of the wheel byte at [wheel+0x30] '
    '(the flag the setter tests at 0x5cea881): which writer '
    'sets it, and on what event, is not traced in this '
    'packet; only its three-way effect on the entry is '
    'pinned.',
    'The runtime contents of the handle fields '
    '[handle+sel+0x88]/[handle+sel+0x90] (the stored (sec, '
    'nsec) the deadline is differenced against) and of the '
    'globals behind the TLS accessor cell - runtime data, '
    'not statically decidable from the artifact.',
    'The insert body 0x5cf6880\'s returned (rax, rdx) '
    'object semantics beyond the setter\'s use of it '
    '(an already-due entry handed back for immediate '
    'processing); its internals are exported but its '
    'producer conditions are not censused here.',
    'Who re-invokes the gates to reach checker state 3 and '
    'the provenance of [record+0x1d8] before its first '
    'checker_a call (open edge 4 of #2613) remain open.',
]


def derive(data):
    check(len(data) == TARGET_SIZE, 'artifact size mismatch')
    check(sha(data) == TARGET_SHA256, 'artifact sha256 mismatch')
    return {
        'artifact': {'size': len(data), 'sha256': sha(data)},
        'work_item': WORK_ITEM,
        'owners': owners(data),
        'exported_bodies': EXPORTED,
        'slots': slots_census(data),
        'strings': strings_census(data),
        'statics': statics_census(data),
        'constants': CONSTANTS,
        'store_censuses': store_censuses(data),
        'pins': pins_census(data),
        'findings': FINDINGS,
        'decision_table': DECISION_TABLE,
        'open_edges': OPEN_EDGES,
    }


def analyze(data):
    return derive(data)


def generate(data):
    OUT.mkdir(parents=True, exist_ok=True)
    records = analyze(data)
    (OUT / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    (OUT / 'frames.txt').write_text(''.join(frame_lines(data)))
    for role in EXPORTED:
        (OUT / f'{role}.objdump.txt').write_text(
            exports(data, role))


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--generate', action='store_true')
    args = parser.parse_args()
    data = TARGET.read_bytes()
    if args.generate:
        generate(data)
        return
    records = analyze(data)
    expected = json.loads((OUT / 'records.json').read_text())
    check(records == expected, 'records.json is stale')
    for role in EXPORTED:
        check((OUT / f'{role}.objdump.txt').read_text() ==
              exports(data, role), f'{role}.objdump.txt is stale')
    check((OUT / 'frames.txt').read_text() ==
          ''.join(frame_lines(data)), 'frames.txt is stale')
    print(json.dumps({'packet': WORK_ITEM, 'matches': True},
                     sort_keys=True))


if __name__ == '__main__':
    main()
