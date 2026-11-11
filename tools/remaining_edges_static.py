"""Static evidence for the RE-005 remaining-edges packet.

Answers the three open edges the insert-return packet
(PR #2651) carried over from the predicate-chain packet
(PR #2617) and the gate-checkers packet (PR #2613), for
the authenticated hl-node 115 artifact only:

1.  Edge 1 (#2617): who writes the wheel flag byte at
    [wheel+0x30] the setter tests at 0x5cea881, and the
    horizon field at [wheel+0x28].  The flag writer is
    the body 0x5ce08e0: on the 0->1 transition only it
    xchg-stores 1 at [base+0x80] (= [wheel+0x30] for
    wheel = base+0x50) and immediately calls the wheel
    advance body 0x5ceaa20 with target u64::MAX, firing
    every pending entry.  It has exactly two direct
    callers.  The horizon's only writer in the traced
    set is the advance body itself (store at 0x5ceabc4).
2.  Edge 2 (#2617): the runtime contents of the handle
    fields [handle+sel+0x88]/[handle+sel+0x90] and of
    the TLS accessor cell.  Closed as a bounded
    negative: in every traced body the pair is only
    loaded, never stored; the TLS cell's file template
    is {counter 0, tag 2, handle 0, state byte 0}, the
    accessor only reads/increments it, and its only
    other traced writer is its registered destructor
    0x5cdf410.  A live handle is installed by runtime
    context entry outside the traced chain.
3.  Edge 4 (#2613): who re-invokes the gates so checker
    state 3 is reached, and the provenance of
    [record+0x1d8] before its first checker_a call.
    The gates are re-invoked only by two driver bodies
    under one dispatcher; but through every fully
    traced call path the checker state byte is zeroed
    immediately before the call, so state 3 is an
    output the callers test after the call, never a
    resumed input.  [record+0x1d8] is never read before
    checker_a writes it on the first call.

Method: four bodies are exported in full (flag writer,
advance, accessor, TLS destructor); every other body is
extent/digest pinned.  Direct callers are censused by a
whole-.text scan for relative call/jump sites and a
.rela.dyn RELATIVE census; store/access censuses are
taken over the disassembly; strings and tables resolve
through the section table (.rodata identity, .text
VA-0x1000, .data.rel.ro VA-0x2000); GOT slots resolve
from .rela.dyn addends; the TLS facts come from the
PT_TLS program header and the .tdata template bytes.
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
WORK_ITEM = 'RE-005-node115-remaining-edges'
OUT = ROOT / 'research' / 'work-items' / WORK_ITEM
SNAPSHOT = '<authenticated-node115>'

OWNERS = {
    'flag_writer': (0x5CE08E0, 0x5CE0998),
    'advance': (0x5CEAA20, 0x5CEAD37),
    'accessor': (0x5CF2B50, 0x5CF2C34),
    'tls_dtor': (0x5CDF410, 0x5CDF457),
}
EXPORTED = list(OWNERS)

OWNER_SHA256 = {
    'flag_writer': '9fa7b5de24e9817753cf9f25131869c1a866d55bf'
                   'da45a9ea3eeb5c1e22214ac',
    'advance': '3e07106e25d72afaf2baf4307e7d4efefce68c56b04'
               'd2a8db9ee1ea67b38b8af',
    'accessor': 'e367d0fd93829f39d7bf17c0645ea453b07f47e6dc71'
                'a9172bac94e70d47d05e',
    'tls_dtor': '83808b635c9c4571afcf4b915c2803f2707f64b0'
                'a4fc4c43fd5cbe88465c302c',
}

# Extent/digest pins only; none of these is exported.
PINNED_BODIES = {
    'setter': (0x5CEA7C0, 0x5CEAA17,
               '5fbfddaf7831cf129e1dc6734e16b7aa37d5e51b3355c'
               '96a8da582d905f4d8e2'),
    'conversion': (0x5CEAD40, 0x5CEAE75,
                   'a6069a107a631c0f5efdb0f22e5b4a623ad077389b6'
                   'b09225b8a5ca31de923dd'),
    'conv_twin': (0x5CEAE80, 0x5CEAFC8,
                  '0498488dbd7b217f33b3871fdc08e2fa762056c8b7'
                  'cc3771a53878ba8a2d9f14'),
    'poll': (0x5CEAFD0, 0x5CEB1A4,
             '5b1addcef08123e292e9e2110d74cdf9516ac713d91a'
             '19fb6a988b9bee7c52a3'),
    'flag_caller_1': (0x5CEB330, 0x5CEB52A,
                      '40a140f7bfbdb9681add88cc8beb66765c6ca3d8'
                      '4820569d584c6a0a737f4ab2'),
    'flag_caller_2': (0x5CFBFD0, 0x5CFC29E,
                      '00b892b1338b7e9e86719ad234b0f62b3e7ae849'
                      '0d707201dadcab3dcf2a612c'),
    'next_expiry': (0x5CF6510, 0x5CF6876,
                    'b7480df660b1983837d9b7b52af3a5359c9d4b51e'
                    '6667f7f1d272eebafec7649'),
    'next_deadline': (0x5CF6390, 0x5CF647D,
                      '7f576d12868e201a625c9ff780d4816c77d80f50'
                      'd55c1666485a8f5c957bd1ac'),
    'driver_poll': (0x5CFDD00, 0x5CFE0E9,
                    '2d8ea94341d17a31bd755de9d3226f6911a337d3a'
                    '6c97134ed1721c6a097c647'),
    'gate_c': (0x2CB6500, 0x2CBBBDF,
               '62835f8a447ea034c30a4fa0663abad7422644481788'
               '2c469f883d7d92e4a8d0'),
    'gate_a': (0x2AEAEF0, 0x2AF0654,
               'd1b4e3ecb40fb4027b69240f48eacf2de2cf5f7e8c3'
               'ae5c0e6910a784fdcce29'),
    'checker_a': (0x2C7F360, 0x2C7F71B,
                  'ff59e02e9d3e078985ba6e3b58d8f64f3a6ed5171f2'
                  '120d314cbb5a3c744daed'),
    'checker_b': (0x2C7FA40, 0x2C7FD80,
                  'c2dd071311e360249b28d2cacda998b6727b2e1d57a'
                  '74ebde965c96325b6c6fa'),
    'driver_c': (0x2CDE430, 0x2CE0DD1,
                 '99c49a3e20f63cf199f2a160ba9560e439acb2b49a6'
                 '6968623aa9607acfa417b'),
    'driver_a': (0x2AE41E0, 0x2AE6D66,
                 '90ae09003ca680bd4b5f32fec22ee1f7146cc1f67b'
                 '758f8e2f2ac880545b730b'),
    'dispatcher': (0x2AE1690, 0x2AE27B2,
                   '6ca0595c13836bca0cb0173bd591a09d6da6791532e'
                   '23a5a71c63715380727d9'),
    'thunk': (0x2CD8370, 0x2CD83AF,
              'ed23bc89640a43b1a5f373d5cb18929d79ce5b47923e'
              '58ba0565f592ba2b60d6'),
    'driver_a_caller_2': (0x2B404B0, 0x2B40666,
                          '05ef87dc8cdf209d34d246b129dfe209764f'
                          'e409efda8ee0ad73ceebb54fedac'),
    'lock_body': (0x5CF47F0, 0x5CF50F2,
                  '172b33905a2455009ebec2e18ec7a98537b5acf34175'
                  '5ed237f76b0446a8249e'),
    'builder': (0x5CF2150, 0x5CF22E9,
                '63364fa5c7e4158629d264ba1afefeb9e1353840a2b'
                'fae7d34266cc38d7dcade'),
    'predicate': (0x5CF2D30, 0x5CF2FEF,
                  'fb3fb193f0b14f251e01da509c670d299323482419d'
                  '1edef4170d948604cbbb2'),
}

SLOT_TARGETS = {
    0x64DF770: 0x1680BD0,   # shared assert-fail callee
    0x64DFE40: 0x5CEAFD0,   # poll body (data-held only)
    0x64E0510: 0x5CA0D20,   # TLS guard registrar
    0x64E0518: 0x5CE91B0,   # predicate post-call body
}

STRINGS = {
    'timers_disabled_msg': (
        0x94CA6B, 0x73,
        'A Tokio 1.x context was found, but timers are '
        'disabled. Call `enable_time` on the runtime '
        'builder to enable timers.'),
    'time_mod_path': (
        0x43E4FE, 0x43,
        '/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/'
        'runtime/time/mod.rs'),
}

LOCATIONS = {
    # flag writer's timers-disabled assert Location
    0x64C6FA8: (0x43E4FE, 0x43, 190, 32),
}

PINS = {
    0x5CE0926: '0fb68e80000000',      # flag_writer: movzx ecx,[rsi+0x80]
    0x5CE093D: '868e80000000',        # flag_writer: xchg [rsi+0x80],cl
    0x5CE0934: '488d4650',            # flag_writer: lea rax,[rsi+0x50]
    0x5CE0950: 'e8cba00000',          # flag_writer: call advance
    0x5CE091A: '81be9000000000ca9a3b',  # flag_writer: cmp [rsi+0x90],1e9
    0x5CEA881: '0fb64330',            # setter: movzx eax,[rbx+0x30]
    0x5CEABC4: '48894328',            # advance: mov [rbx+0x28],rax
    0x5CEAA76: 'e895ba0000',          # advance: call next_expiry
    0x5CEB468: 'f0410fb04f50',        # caller_1: lock cmpxchg [r15+0x50],cl
    0x5CEB47E: 'e85d54ffff',          # caller_1: call flag_writer
    0x5CFC20D: 'e8ce46feff',          # caller_2: call flag_writer
    0x5CF2B5A: '49c7c6d0eeffff',      # accessor: mov r14,-0x1130
    0x5CF2B61: '64410fb64e48',        # accessor: movzx ecx,fs:[r14+0x48]
    0x5CF2BE7: '64498b5610',          # accessor: mov rdx,fs:[r14+0x10]
    0x5CF2BF6: 'f0480fc132',          # accessor: lock xadd [rdx],rsi
    0x5CDF411: 'c6474802',            # tls_dtor: mov BYTE [rdi+0x48],2
    0x5CEAE9D: '8b8c3890000000',      # conv_twin: mov ecx,[rax+rdi+0x90]
    0x5CEAECF: '488b843888000000',    # conv_twin: mov rax,[rax+rdi+0x88]
    0x2CBB701: 'c683e001000000',      # gate_c: mov BYTE [rbx+0x1e0],0
    0x2CB9914: 'c6836801000000',      # gate_c: mov BYTE [rbx+0x168],0
    0x2CBB476: '41c686c801000000',    # gate_c: mov BYTE [r14+0x1c8],0
    0x2CBB724: '80bbe001000003',      # gate_c: cmp BYTE [rbx+0x1e0],3
    0x2CBB717: 'e8443cfcff',          # gate_c: call checker_a
    0x2CBB490: 'e8ab45fcff',          # gate_c: call checker_b
    0x2CDE6F4: 'e8077efdff',          # driver_c: call gate_c (mode 2)
    0x2CDF58B: 'e8706ffdff',          # driver_c: call gate_c (mode 1)
    0x2CDFE4F: 'e80cf5f9ff',          # driver_c: call checker_a
    0x2CDFE3A: '41c685c802000000',    # driver_c: mov BYTE [r13+0x2c8],0
    0x2CDF724: '498995f8030000',      # driver_c: mov [r13+0x3f8],rdx
    0x2AE4627: 'e8c4680000',          # driver_a: call gate_a (mode 2)
    0x2AE548C: 'e85f5a0000',          # driver_a: call gate_a (mode 1)
    0x2AE1A47: 'e894270000',          # dispatcher: call driver_a
    0x2AE1EEB: 'e840c51f00',          # dispatcher: call driver_c
    0x2CD83A2: 'e8e992e0ff',          # thunk: call dispatcher
    0x2CC0592: 'c6838801000000',      # caller: mov BYTE [rbx+0x188],0
    0x2CC6C9E: '41c687a801000000',    # caller: mov BYTE [r15+0x1a8],0
    0x2B90B12: '80bb8001000003',      # caller: cmp BYTE [rbx+0x180],3
}

STORE_MNEMS = {'mov', 'movq', 'movl', 'movw', 'movb', 'movups',
               'movaps', 'movsd', 'cmpxchg', 'xchg', 'xadd',
               'decq', 'incq', 'or'}


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


def fde_extents(data):
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
    extents = set()
    for line in text.splitlines():
        if 'pc=' not in line:
            continue
        needle = line.split('pc=')[1].split()[0]
        lo, hi = needle.split('..')
        extents.add((int(lo, 16), int(hi, 16)))
    return extents


def body_record(data, start, end, want_sha, extents):
    check((start, end) in extents,
          f'no FDE for body {start:#x}')
    raw = read(start, data, end - start)
    digest = sha(raw)
    check(digest == want_sha, f'digest drift {start:#x}')
    offset = None
    for section in sections(data):
        if section['address'] <= start < (section['address']
                                          + section['size']):
            offset = section['offset'] + (start
                                           - section['address'])
    return {'start': hex(start), 'end': hex(end),
            'file_offset': hex(offset), 'bytes': end - start,
            'sha256': digest}


def owners(data):
    extents = fde_extents(data)
    records = {}
    for role, (start, end) in OWNERS.items():
        records[role] = body_record(data, start, end,
                                    OWNER_SHA256[role], extents)
    return records


def pinned_bodies(data):
    extents = fde_extents(data)
    records = {}
    for role, (start, end, want) in PINNED_BODIES.items():
        rec = body_record(data, start, end, want, extents)
        rec['note'] = 'extent/digest only; not exported'
        records[role] = rec
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
    spans = list(OWNERS.values())
    spans += [(s, e) for s, e, _ in PINNED_BODIES.values()]
    for start, end in spans:
        needle = f'pc={start:016x}..{end:016x}'
        wanted += [ln for ln in text.splitlines() if needle in ln]
    check(len(wanted) == len(spans), 'frame lines missing')
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

    AT&T form: the destination of a store is its last
    operand; it is a memory operand iff it contains '('
    or starts with '%fs:'.
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


def access_census(data, start, end, disps, bases=None):
    """Every instruction (load or store) whose memory
    operand uses one of `disps` from one of `bases`.
    A store is an instruction whose mnemonic writes
    memory and whose matched operand is its last
    (destination) operand in AT&T order."""
    found = []
    for va, ins in disasm_rows(data, start, end):
        text = ins.split('#')[0].strip()
        if not text:
            continue
        parts = text.split(None, 1)
        mnem = parts[0]
        rest = parts[1] if len(parts) > 1 else ''
        if mnem == 'lock':
            sub = rest.split(None, 1)
            mnem = sub[0]
            rest = sub[1] if len(sub) > 1 else ''
        operands = [o.strip() for o in rest.split(',')] if rest \
            else []
        for m in re.finditer(r'([+-]?0x[0-9a-f]+)?\((%\w+)',
                             text):
            raw_disp, base = m.group(1), m.group(2)[1:]
            disp = int(raw_disp, 0) if raw_disp else 0
            if disp not in disps:
                continue
            if bases is not None and base not in bases:
                continue
            op_text = m.group(0) + ')'
            is_store = (mnem in STORE_MNEMS and bool(operands)
                        and operands[-1].endswith(op_text))
            found.append({'site': hex(va), 'base': base,
                          'disp': disp, 'mnem': mnem,
                          'store': is_store})
    return found


BYTE_REGS = {'al', 'bl', 'cl', 'dl', 'ah', 'bh', 'ch', 'dh',
             'sil', 'dil', 'spl', 'bpl'} | {f'r{i}b'
                                            for i in range(8, 16)}


def byte_store_census(data, start, end):
    """Byte-sized memory stores in [start, end): the
    AT&T mnemonic carries a 'b' suffix for immediate
    forms, otherwise the source register is a byte
    register."""
    found = []
    for va, ins in disasm_rows(data, start, end):
        text = ins.split('#')[0].strip()
        if not text:
            continue
        parts = text.split(None, 1)
        mnem = parts[0]
        rest = parts[1] if len(parts) > 1 else ''
        if mnem == 'lock':
            sub = rest.split(None, 1)
            mnem = sub[0]
            rest = sub[1] if len(sub) > 1 else ''
        base_mnem = mnem.rstrip('bwlq')
        if base_mnem not in STORE_MNEMS or not rest:
            continue
        operands = [o.strip() for o in rest.split(',')]
        dst = operands[-1]
        if '(' not in dst and not dst.startswith('%fs:'):
            continue
        is_byte = mnem.endswith('b')
        if not is_byte and operands[0].startswith('%'):
            is_byte = operands[0][1:] in BYTE_REGS
        if not is_byte:
            continue
        if dst.startswith('%fs:'):
            base, disp = 'fs', None
        else:
            m = re.match(r'^(.*)\(%(\w+)', dst)
            check(m is not None, f'unparsed store dst {dst}')
            raw_disp, base = m.group(1), m.group(2)
            disp = 0 if raw_disp in ('', '+') else int(raw_disp, 0)
        found.append({'site': hex(va), 'base': base, 'disp': disp})
    return found


def store_censuses(data):
    # advance: wheel-base (rbx) stores.  The horizon field
    # [wheel+0x28] has exactly one store; the flag byte
    # [wheel+0x30] is never accessed at all by this body.
    adv_rbx = store_census(data, *OWNERS['advance'],
                           bases={'rbx'})
    horizon = [e for e in adv_rbx if e['disp'] == 0x28]
    check(horizon == [{'site': '0x5ceabc4', 'base': 'rbx',
                       'disp': 0x28}],
          f'advance horizon store drift: {horizon}')
    adv_acc = access_census(data, *OWNERS['advance'], {0x30},
                            bases={'rbx'})
    check(adv_acc == [], f'advance +0x30 access drift: {adv_acc}')

    # flag writer: exactly one write to the flag byte,
    # the xchg at [rsi+0x80]; rsi is the driver sub-object
    # base, wheel = base+0x50, so +0x80 == wheel+0x30.
    fw_rsi = store_census(data, *OWNERS['flag_writer'],
                          bases={'rsi'})
    flag_writes = [e for e in fw_rsi if e['disp'] == 0x80]
    check(flag_writes == [{'site': '0x5ce093d', 'base': 'rsi',
                           'disp': 0x80}],
          f'flag write drift: {flag_writes}')

    # gate_c: no store to the record field +0x1d8 from any
    # base register (the checker sub-state byte position
    # for the &[record+0x150] instance).
    gate_acc = access_census(data, *PINNED_BODIES['gate_c'][:2],
                             {0x1D8})
    gate_stores = [e for e in gate_acc if e['store']]
    check(gate_stores == [],
          f'gate_c +0x1d8 store drift: {gate_stores}')

    # driver_c: the single bulk store that lands on
    # [record+0x1d8] (record = &[r13+0x220], so the field
    # is [r13+0x3f8]) is the big-endian block copy at
    # 0x2cdf724, after both gate calls.
    drv_acc = access_census(data, *PINNED_BODIES['driver_c'][:2],
                            {0x3F8}, bases={'r13'})
    drv_stores = [e for e in drv_acc if e['store']]
    check(drv_stores == [{'site': '0x2cdf724', 'base': 'r13',
                          'disp': 0x3F8, 'mnem': 'mov',
                          'store': True}],
          f'driver_c +0x3f8 store drift: {drv_stores}')

    # timer cluster: the wheel flag is one byte, so its
    # writer must be a byte-sized store.  The only
    # byte-sized stores to [reg+0x30] from a non-stack
    # base in 0x5ce0000..0x5cf8000 are three
    # lock-acquire cmpxchg sites in body 0x5cf47f0,
    # whose base object is a first-argument object with
    # fields at +0xc0/+0xc8 and a refcount at +0xf8 -
    # not a wheel (no traced body accesses a wheel past
    # +0x38, and wheel bases always derive from a
    # handle+selector field or the +0x50 sub-object).
    cluster = byte_store_census(data, 0x5CE0000, 0x5CF8000)
    cluster_30 = [e for e in cluster if e['disp'] == 0x30
                  and e['base'] not in ('rsp', 'rbp')]
    expect_30 = [{'site': '0x5cf4842', 'base': 'r14',
                  'disp': 0x30},
                 {'site': '0x5cf48d7', 'base': 'r14',
                  'disp': 0x30},
                 {'site': '0x5cf4a52', 'base': 'r14',
                  'disp': 0x30}]
    check(cluster_30 == expect_30,
          f'cluster +0x30 byte-store drift: {cluster_30}')

    return {
        'advance_rbx_stores': adv_rbx,
        'advance_horizon_stores': horizon,
        'advance_flag_accesses': adv_acc,
        'flag_writer_rsi_stores': fw_rsi,
        'flag_writer_flag_writes': flag_writes,
        'gate_c_record_1d8_accesses': gate_acc,
        'gate_c_record_1d8_stores': gate_stores,
        'driver_c_record_1d8_stores': drv_stores,
        'cluster_disp30_nonstack_byte_stores': cluster_30,
    }


CALL_TARGETS = {
    'bucket': 0x5CE29A0,
    'insert': 0x5CF6880,
    'setter': 0x5CEA7C0,
    'poll': 0x5CEAFD0,
    'conversion': 0x5CEAD40,
    'advance': 0x5CEAA20,
    'flag_writer': 0x5CE08E0,
    'gate_c': 0x2CB6500,
    'gate_a': 0x2AEAEF0,
    'checker_a': 0x2C7F360,
    'checker_a_clone': 0x2A90A50,
    'checker_b': 0x2C7FA40,
    'driver_c': 0x2CDE430,
    'driver_a': 0x2AE41E0,
    'dispatcher': 0x2AE1690,
    'thunk': 0x2CD8370,
}


def call_censuses(data):
    text = next(s for s in sections(data) if s['name'] == '.text')
    base_va, base_off = text['address'], text['offset']
    blob = data[base_off:base_off + text['size']]
    wanted = {v: k for k, v in CALL_TARGETS.items()}
    hits = {k: [] for k in CALL_TARGETS}
    for m in re.finditer(rb'[\xe8\xe9]', blob):
        i = m.start()
        rel = int.from_bytes(blob[i + 1:i + 5], 'little',
                             signed=True)
        tgt = base_va + i + 5 + rel
        if tgt in wanted:
            hits[wanted[tgt]].append(
                {'site': hex(base_va + i),
                 'kind': 'call' if blob[i] == 0xE8 else 'jmp'})
    expect_sites = {
        'bucket': [('0x5cea839', 'call'), ('0x5ceb06e', 'call')],
        'insert': [('0x5cea8d0', 'call')],
        'poll': [],
        'advance': [('0x5ce0950', 'call'), ('0x5cfe088', 'jmp')],
        'flag_writer': [('0x5ceb47e', 'call'),
                        ('0x5cfc20d', 'call')],
        'gate_c': [('0x2cde6f4', 'call'), ('0x2cdf58b', 'call')],
        'gate_a': [('0x2ae4627', 'call'), ('0x2ae548c', 'call')],
        'driver_c': [('0x2ae1eeb', 'call')],
        'dispatcher': [('0x2cd83a2', 'call')],
        'thunk': [],
    }
    for role, want in expect_sites.items():
        got = [(e['site'], e['kind']) for e in hits[role]]
        check(got == want, f'{role} call sites drift: {got}')
    return hits


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


def relative_refs(data):
    entries = rela_entries(data)
    by_target = {}
    for off, (typ, _sym, addend) in entries.items():
        if typ == 8:
            by_target.setdefault(addend, []).append(off)
    records = {}
    for role, target in CALL_TARGETS.items():
        records[role] = [hex(x) for x in
                         sorted(by_target.get(target, []))]
    check(records['poll'] == ['0x64dfe40'],
          f"poll relative refs drift: {records['poll']}")
    for role in ('gate_c', 'gate_a', 'driver_c', 'driver_a',
                 'dispatcher', 'thunk', 'flag_writer', 'advance'):
        check(records[role] == [],
              f'{role} relative refs drift: {records[role]}')
    return records


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
    return records


def strings_census(data):
    records = {}
    for role, (va, size, text) in STRINGS.items():
        raw = read(va, data, size)
        check(raw.decode() == text, f'string drift {role}')
        records[role] = {'va': hex(va), 'bytes': size, 'text': text}
    return records


def locations_census(data):
    entries = rela_entries(data)
    records = {}
    for va, (ptr, length, line, col) in LOCATIONS.items():
        qwords = list(struct.unpack_from('<3Q', read(va, data, 24),
                                         0))
        check(qwords[0] == 0, f'location {va:#x} ptr field in file')
        check(qwords[1] == length, f'location {va:#x} len drift')
        packed = qwords[2]
        check(packed & 0xFFFFFFFF == line and packed >> 32 == col,
              f'location {va:#x} line/col drift')
        check(va in entries, f'location {va:#x} has no relocation')
        typ, _, addend = entries[va]
        check(typ == 8 and addend == ptr,
              f'location {va:#x} ptr resolves to {addend:#x}')
        records[hex(va)] = {
            'qwords': [hex(q) for q in qwords],
            'file_ptr': hex(ptr), 'len': length,
            'line': line, 'col': col}
    return records


def tls_census(data):
    # PT_TLS program header (ELF64 phdr: type, flags, off,
    # vaddr, paddr, filesz, memsz, align; 56 bytes each).
    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
    e_phnum = struct.unpack_from('<H', data, 0x38)[0]
    tls = None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, _f, _o, _v, _p, filesz, memsz, _a = \
            struct.unpack_from('<IIQQQQQQ', data, off)
        if p_type == 7:
            tls = (filesz, memsz)
    check(tls is not None, 'no PT_TLS segment')
    filesz, memsz = tls
    check((filesz, memsz) == (0xB20, 0x1180),
          f'PT_TLS size drift: {filesz:#x}/{memsz:#x}')
    # The accessor's cell sits at fs:-0x1130; with the TLS
    # block occupying [tp-0x1180, tp) the cell anchor is
    # block offset 0x50, inside the file-backed template.
    tdata = next(s for s in sections(data) if s['name'] == '.tdata')
    base = tdata['address']
    cell = {}
    for name, off in (('counter', 0x50), ('tag', 0x58),
                      ('handle', 0x60)):
        cell[name] = hex(struct.unpack('<Q', read(base + off,
                                                  data, 8))[0])
    state = read(base + 0x98, data, 1)[0]
    check(cell == {'counter': '0x0', 'tag': '0x2',
                   'handle': '0x0'} and state == 0,
          f'TLS template drift: {cell} state={state}')
    return {
        'pt_tls_filesz': hex(filesz), 'pt_tls_memsz': hex(memsz),
        'cell_block_offset': '0x50',
        'template_counter': cell['counter'],
        'template_tag': cell['tag'],
        'template_handle': cell['handle'],
        'template_state_byte': state,
    }


def pins_census(data):
    records = {}
    for site, want in PINS.items():
        raw = read(site, data, len(bytes.fromhex(want)))
        check(raw.hex() == want, f'pin drift at {site:#x}')
        records[hex(site)] = want
    return records


FINDINGS = {
    'edge1_flag_writer': (
        'The wheel flag byte at [wheel+0x30] (read by the '
        'setter at 0x5cea881) is written by exactly one '
        'traced body: 0x5ce08e0.  Its argument rsi is the '
        'driver sub-object base; it loads the byte at '
        '[rsi+0x80] (0x5ce0926) and, only when it is 0, '
        'xchg-stores 1 there at 0x5ce093d - [rsi+0x80] is '
        '[wheel+0x30] for wheel = [rsi+0x50], the same '
        'base it forms at 0x5ce0934 (lea rax,[rsi+0x50]) '
        'to call the advance body 0x5ceaa20 at 0x5ce0950 '
        'with target u64::MAX, firing every pending '
        'entry.  Before the store it asserts dword '
        '[rsi+0x90] != 1_000_000_000 through the shared '
        'assert callee (slot 0x64df770) with the Location '
        'static 0x64c6fa8 (tokio runtime/time/mod.rs, '
        'line 190, col 32) and the timers-disabled message. '
        'If the byte is already nonzero it returns '
        'without storing or advancing: the write is the '
        '0->1 shutdown transition, taken once.'),
    'edge1_flag_callers': (
        'The flag writer has exactly two direct callers '
        'and no RELATIVE references: 0x5ceb47e in body '
        '0x5ceb330 (506 B), which calls it under the '
        'wheel lock byte (lock cmpxchg [r15+0x50] at '
        '0x5ceb468) after a refcounted registry-removal '
        'phase, passing &[obj+0x10] and ctx+0x150; and '
        '0x5cfc20d in body 0x5cfbfd0 (718 B), a '
        'state-machine step that calls it when the task '
        'state dword != 3, after draining its queue.  '
        'Both are handle/task teardown paths: the flag '
        'means "this timer driver is closed", set at '
        'teardown, after which the setter can no longer '
        'take its direct-store arm.'),
    'edge1_horizon_writer': (
        'The horizon field [wheel+0x28] the insert '
        'linked arm compares against has exactly one '
        'writer in the traced set: the advance body '
        '0x5ceaa20 stores it at 0x5ceabc4, on its '
        'no-more-due arm, with the value derived from '
        'the next-deadline body 0x5cf6390 (result at '
        '[rsp+0x28]: cmp 1 / adc 0, forced to 0 when the '
        'arm flag byte [rsp+0x10] is 0).  The advance '
        'body never accesses [wheel+0x30] at all.'),
    'edge1_completeness': (
        'Writer completeness is bounded by three '
        'censuses: (a) the whole timer cluster '
        '0x5ce0000..0x5cf8000 contains exactly three '
        'byte-sized stores to [reg+0x30] from a '
        'non-stack base - lock-acquire cmpxchg sites at '
        '0x5cf4842/0x5cf48d7/0x5cf4a52 in body '
        '0x5cf47f0, whose base is a first-argument '
        'object with map fields at +0xc0/+0xc8 and a '
        'refcount at +0xf8 (lock dec [r14+0xf8]), a '
        'shape no wheel has: traced wheel fields end at '
        '+0x30 and wheel bases always derive from a '
        'handle+selector field or the +0x50 sub-object '
        'base; (b) the direct '
        'callers of every wheel body (bucket 2, insert '
        '1, setter 2, poll 0 direct / slot 0x64dfe40 '
        'only, advance 2) are fully enumerated; (c) the '
        'flag writer, advance and poll have no RELATIVE '
        'references except poll\'s single table slot.  '
        'A writer that reaches the byte only through a '
        'computed pointer or a bulk copy over the whole '
        'wheel struct is outside these censuses and is '
        'recorded as a boundary, not a finding.'),
    'edge2_handle_pair': (
        'BOUNDED NEGATIVE.  The stored (sec, nsec) pair '
        'at [handle+sel+0x88]/[handle+sel+0x90] is only '
        'ever loaded in the traced set: the builder '
        '0x5cf2150 (timers-enabled assert), the '
        'conversion 0x5cead40 (two asserts and the '
        'difference against the deadline), its twin '
        '0x5ceae80 (loads at 0x5ceae9d/0x5ceaecf and a '
        'second assert), the flag writer 0x5ce08e0 (cmp '
        'at 0x5ce091a) and the two handle drop bodies '
        '0x5ce7f40/0x5cea100 (cmp [obj+0x90] vs 1e9 '
        'before freeing the 0x1860-byte levels array).  '
        'No body in the chain, its callers or its '
        'callees stores to either field from a handle '
        'base.  The pair is the runtime clock epoch the '
        'handle was built with: runtime data, written '
        'by runtime construction outside the traced '
        'chain.'),
    'edge2_tls_cell': (
        'BOUNDED NEGATIVE.  The accessor 0x5cf2b50 reads '
        'the thread-local cell at fs:-0x1130 (anchor '
        'loaded at 0x5cf2b5a): counter at +0x0, tag at '
        '+0x8, handle pointer at +0x10 (0x5cf2be7, then '
        'lock xadd +1 on the handle\'s first word at '
        '0x5cf2bf6), init-state byte at +0x48 '
        '(0x5cf2b61).  The PT_TLS template (filesz '
        '0xb20, memsz 0x1180) initialises the cell to '
        '{counter 0, tag 2, handle 0, state 0} - tag 2 '
        'is the no-live-context state the accessor\'s '
        'reset arm handles.  The only other traced body '
        'that writes the cell is its destructor '
        '0x5cdf410, registered through the guard slot '
        '0x64e0510 -> 0x5ca0d20: it stores state byte 2 '
        'at 0x5cdf411 and drops the old handle.  A live '
        'handle pointer is installed by runtime context '
        'entry code that no traced body calls.'),
    'edge4_reinvokers': (
        'The gates\' only direct re-invokers are two '
        'driver bodies: gate_c is called only from '
        'driver_c 0x2cde430 (0x2cde6f4 with record mode '
        'byte 2, 0x2cdf58b with mode byte 1; in both '
        'cases rdi = &[r13+0x220], a record sub-struct '
        'of the driver task object, refilled from the '
        'driver\'s own fields before the call), and '
        'gate_a only from driver_a 0x2ae41e0 (0x2ae4627 '
        '/ 0x2ae548c, same shape).  Neither gate nor '
        'driver has any RELATIVE reference.  Both '
        'drivers are called by one dispatcher body '
        '0x2ae1690 (driver_a at 0x2ae1a47, driver_c at '
        '0x2ae1eeb; driver_a also from 0x2b404b0), and '
        'the dispatcher\'s only direct caller is the '
        'stack-context thunk 0x2cd8370 at 0x2cd83a2.'),
    'edge4_state3_is_output': (
        'Through the gate path, checker state 3 is never '
        'a resumed input: gate_c zeroes the checker_a '
        'instance state byte [record+0x1e0] at 0x2cbb701 '
        'immediately before the funnel call at '
        '0x2cbb717, zeroes the r14-phase instance byte '
        '[rbx+0x168] at 0x2cb9914 before the call at '
        '0x2cb9923, and zeroes checker_b\'s dispatch '
        'byte [record+0x1c8] at 0x2cbb476 before the '
        'call at 0x2cbb490; gate_a mirrors this.  The '
        'same zero-before-call holds at driver_c\'s own '
        'direct checker_a call ([r13+0x2c8] := 0 at '
        '0x2cdfe3a, call at 0x2cdfe4f on &[r13+0x238]) '
        'and at the other censused checker_a callers '
        '(0x2cc0592, 0x2cc6c9e).  State 3 is written by '
        'the checkers during a call (checker_a: '
        '[arg+0x88] := 3 and [arg+0x90] := 3 on the '
        'predicate-nonzero arm) and consumed by the '
        'callers after it: gate_c tests [record+0x1e0] '
        '== 3 at 0x2cbb724, and caller 0x2b905a0 tests '
        '[rbx+0x180] == 3 at 0x2b90b12 right after its '
        'call at 0x2b90b05.'),
    'edge4_record_1d8': (
        '[record+0x1d8] - the &[record+0x150] checker_a '
        'instance\'s sub-state byte [arg+0x88] - has no '
        'store anywhere in gate_c (access census over '
        'the whole gate body), and before the first '
        'funnel call its value is never read: checker_a '
        'entry dispatch reads only [arg+0x90], the byte '
        'the gate just zeroed; [arg+0x88] is read only '
        'on the state-3 re-dispatch, which the zeroed '
        'entry byte makes unreachable on a first call, '
        'and by the gate only after the call returns.  '
        'Its writers are checker_a itself (every '
        'fresh-arm outcome that can be observed later '
        'writes it) and driver_c\'s big-endian block '
        'copy at 0x2cdf724 (one of four bswap qword '
        'stores to record+0x1c0..0x1e0 in a later '
        'phase).  The pre-first-call contents are '
        'construction leftovers in the driver task '
        'object and are functionally dead.'),
}

OPEN_EDGES = [
    'Two checker_a call windows (0x2b90b05 in body '
    '0x2b905a0, whose zero store to [rbx+0x180] sits at '
    '0x2b90ddb with untraced ordering, and 0x2cc7fb5 in '
    'body 0x2cc1120) and the gate_a-clone callers were '
    'not traced far enough to confirm the '
    'zero-before-call store; the checker resume arm\'s '
    'reachability through those callers stays open.',
    'The stack-context thunk 0x2cd8370 has no direct '
    'caller and no RELATIVE reference in the artifact; '
    'the mechanism that invokes it (and thus how often '
    'the dispatcher re-invokes the drivers) is outside '
    'the two censused reference forms.',
    'A writer of the wheel flag byte that works only '
    'through a computed pointer or a bulk copy over the '
    'whole wheel struct would be invisible to this '
    'packet\'s censuses (see edge1_completeness).',
    'The two carried edges of the bucket-second-caller '
    'packet (#2701) - the owning object of the '
    '0x64dfe40 method table and the wheel list\'s '
    'poll-side consumer - are different objects from '
    'this packet\'s three edges and are NOT folded in; '
    'the advance body was checked and does not touch '
    'the wheel list head/tail fields [wheel+0x18] / '
    '[wheel+0x20] (its list-shaped accesses are on '
    'entry fields), so it is not that consumer either.',
]


def derive(data):
    check(len(data) == TARGET_SIZE, 'artifact size mismatch')
    check(sha(data) == TARGET_SHA256, 'artifact sha256 mismatch')
    return {
        'artifact': {'size': len(data), 'sha256': sha(data)},
        'work_item': WORK_ITEM,
        'owners': owners(data),
        'pinned_bodies': pinned_bodies(data),
        'exported_bodies': EXPORTED,
        'slots': slots_census(data),
        'strings': strings_census(data),
        'locations': locations_census(data),
        'tls': tls_census(data),
        'store_censuses': store_censuses(data),
        'call_censuses': call_censuses(data),
        'relative_refs': relative_refs(data),
        'pins': pins_census(data),
        'findings': FINDINGS,
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
