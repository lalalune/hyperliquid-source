#!/usr/bin/env python3
"""Bind the node #115 observer's line writer 0x14c3370 (fifth stage).

Continues the observer packets for 0x1547530 (first to fourth stage). The
fourth stage found that the observer writes each window record with
`call 0x14c3370` at 0x15489bb into a `base` liner opened by 0x14c3b30. This
tool binds:

1. the write callee 0x14c3370: a 0x80-byte buffer, the record serializer
   0x1548f40, an appended b'\\n', the liner write 0x14c37f0, and the drop of a
   0x28-byte serializer error when serialization fails;
2. the serializer 0x1548f40: '{', sixteen named fields in a fixed order (name
   bytes, name length, record offset and value helper per field), '}';
3. the value helpers: f64 and Option<f64> write `null` when the value is not
   finite; Option<u64> writes `null` for None; the bool helper writes `true`
   or `false`; the time field is a quoted Display string;
4. the x50 flag: the observer stores it at rsp+0x17c and passes rsp+0xd8 as
   the record, so the flag is record +0xa4, the field `is_subsampled`;
5. the liner: lazy open with mode 0o666 and the append and create bytes set,
   a buffered write whose io::Error is dropped, and a time-gated flush whose
   interval is copied at open from a lazily initialised global.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses; ends are exclusive.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections
from fde_extents import fde_extents

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-abci-step-observer-writer-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

OBSERVER = (0x1547530, 0x1548ba3)
WRITE = (0x14c3370, 0x14c34e5)
SERIALIZE = (0x1548f40, 0x15492b3)
LINE_WRITE = (0x14c37f0, 0x14c389b)
BUFFER = (0x14c3950, 0x14c3ab2)
OPEN = (0x14c3b30, 0x14c3c86)
FLUSH = (0x14c3c90, 0x14c3cb1)
FLUSH_GATE = (0x154ce40, 0x154cfe0)
BOOL_FIELD = (0x1554100, 0x1554137)
BOOL_WRITE = (0x159b8a0, 0x159ba40)
U64 = (0x159b710, 0x159b89c)
F64 = (0x159c0f0, 0x159c353)
OPT_F64 = (0x159c4f0, 0x159c75d)
OPT_U64 = (0x159bf00, 0x159c0e3)
TIME = (0x159ca40, 0x159cbd5)
TIME_STR = (0x1598e80, 0x1598fc3)
ITOA = 0x1599300
ERROR_IO_DROP = 0x14c4d00
CLOSE = 0x153d250
CLOSE_BYTE = 0x466d50
ALLOC_SLOT = 0x64df480
FREE_SLOT = 0x64df4a0
MEMCPY_SLOT = 0x64df508
GATE_SLOT = 0x64e0008
COLD_WRITE_SLOT = 0x64e0010
COLD_WRITE = 0x1533d60
FLUSH_BUF = 0x1533e80
RYU_SLOT = 0x64e13d0
FMT_WRITE_SLOT = 0x64df6f0
TIME_DISPLAY = 0x15608d0
INTERVAL_SLOT = 0x64e0030
INTERVAL_GLOBAL = 0x64efce0
FALLBACK_DEADLINE = 0x4679d0
FLAG_STORE = 0x1548873
RECORD_ARG = 0x15489b0
WRITE_CALL = 0x15489bb
RECORD_BASE = 0xd8
FLAG_FRAME = 0x17c

KIND = {U64[0]: 'u64', F64[0]: 'f64 (non-finite -> null)', OPT_F64[0]: 'Option<f64> (None or non-finite -> null)',
        OPT_U64[0]: 'Option<u64> (None -> null)', TIME[0]: 'string (Display)'}

# (lea rcx va and bytes, lea rsi va, name, mov edx va, call va, helper); None = mov rcx, rbx
FIELDS = (
    (0x1548f77, '488d8b98000000', 0x1548f7e, b'time', 0x1548f8a, 0x1548f8f, TIME[0], 0x98),
    (0x1548fa8, '488d4b50', 0x1548fac, b'total_n', 0x1548fb8, 0x1548fbd, U64[0], 0x50),
    (0x1548fd6, '488d4b58', 0x1548fda, b'total_mean', 0x1548fe6, 0x1548feb, F64[0], 0x58),
    (0x1549004, '488d4b60', 0x1549008, b'n_buffer', 0x1549014, 0x1549019, U64[0], 0x60),
    (0x1549043, '4889d9', 0x1549032, b'work_frac', 0x154903e, 0x1549046, OPT_F64[0], 0x0),
    (0x154905f, '488d4b68', 0x1549063, b'mean', 0x154906f, 0x1549074, F64[0], 0x68),
    (0x154908d, '488d4b70', 0x1549091, b'med', 0x154909d, 0x15490a2, F64[0], 0x70),
    (0x15490bb, '488d4b78', 0x15490bf, b'p90', 0x15490cb, 0x15490d0, F64[0], 0x78),
    (0x15490e9, '488d8b80000000', 0x15490f0, b'p95', 0x15490fc, 0x1549101, F64[0], 0x80),
    (0x154911a, '488d8b88000000', 0x1549121, b'max', 0x154912d, 0x1549132, F64[0], 0x88),
    (0x154914b, '488d8b90000000', 0x1549152, b'std_dev', 0x154915e, 0x1549163, F64[0], 0x90),
    (0x154917c, '488d4b10', 0x1549180, b'bucket_mean', 0x154918c, 0x1549191, OPT_F64[0], 0x10),
    (0x15491aa, '488d4b20', 0x15491ae, b'bucket_work_frac', 0x15491ba, 0x15491bf, OPT_F64[0], 0x20),
    (0x15491d8, '488d4b30', 0x15491dc, b'bucket_n', 0x15491e8, 0x15491ed, OPT_U64[0], 0x30),
    (0x1549202, '488d4b40', 0x1549206, b'bucket_n_orig', 0x1549212, 0x1549217, OPT_U64[0], 0x40),
)
FLAG_FIELD = {'add': (0x1549221, '4881c3a4000000'), 'call': 0x1549230,
              'name_lea': 0x1554108, 'name': b'is_subsampled', 'len': (0x155410f, 'ba0d000000'),
              'jump': 0x1554114}

FIXED = {
    # observer: x50 flag at rsp+0x17c, record argument rsp+0xd8
    FLAG_STORE: '4488bc247c010000',
    RECORD_ARG: '488d9424d8000000',
    # write callee
    0x14c3384: 'bf80000000',            # mov edi, 0x80               (buffer capacity)
    0x14c3398: '48c744240880000000',    # mov qword [rsp+8], 0x80
    0x14c33f7: '4883f801',              # cmp rax, 1                  (error code Io?)
    0x14c3422: 'be28000000',            # mov esi, 0x28               (free the error box)
    0x14c345a: 'c604030a',              # mov byte [rbx+rax], 0xa     (newline)
    # serializer
    0x1548f60: 'c604017b',              # mov byte [rcx+rax], '{'
    0x1549259: 'ba01000000',            # mov edx, 1                  ('}')
    # bool helper
    0x1554100: '803f00',                # cmp byte [rdi], 0
    0x159b96a: 'c7043074727565',        # mov dword [rax+rsi], 'true'
    0x159b98f: 'c644300465',            # mov byte [rax+rsi+4], 'e'
    0x159b994: 'c7043066616c73',        # mov dword [rax+rsi], 'fals'
    # f64: |x| >= inf -> null
    0x159c1a5: '48b9ffffffffffffff7f',  # movabs rcx, 0x7fffffffffffffff
    0x159c1b2: '48b8000000000000f07f',  # movabs rax, 0x7ff0000000000000
    0x159c1bc: '4839c1',                # cmp rcx, rax
    0x159c1d9: 'c704306e756c6c',        # mov dword [rax+rsi], 'null'
    # Option<f64>: tag 1 = Some, then the same finiteness check
    0x159c57d: 'f30f7e4308',            # movq xmm0, [rbx+8]
    0x159c5a4: '4983fe01',              # cmp r14, 1
    0x159c5bc: '48b8000000000000f07f',
    0x159c5e3: 'c704306e756c6c',
    # Option<u64>: tag 1 = Some -> itoa, else null
    0x159bf8a: '488b7308',              # mov rsi, [rbx+8]
    0x159bfb0: '4983fe01',              # cmp r14, 1
    0x159bfd5: 'c704306e756c6c',
    # time string: opening and closing quotes
    0x1598ea9: 'c6043022',
    0x1598f11: 'c6043022',
    # liner write and flush gate
    0x14c3819: '4939c7',                # cmp r15, rax                (len vs spare capacity)
    0x14c3838: '488d7b38',              # lea rdi, [rbx+0x38]         (flush gate state)
    0x154ce54: '8b6f08',                # mov ebp, [rdi+8]            (stored date)
    0x154ce57: '85ed',                  # test ebp, ebp
    0x154cfc6: '894308',                # mov [rbx+8], eax            (store the new time)
    0x154cfcf: 'b001',                  # mov al, 1                   (flush)
    # liner open: interval copied to +0x38, stored date cleared at +0x40
    0x14c3b7c: 'f2410f104500',          # movsd xmm0, [r13]
    0x14c3ba8: 'f2410f114738',          # movsd [r15+0x38], xmm0
    0x14c3bae: '41c7474000000000',      # mov dword [r15+0x40], 0
    # lazy open options
    0x14c3976: '48b800000000b6010000',  # movabs rax, 0x1b600000000 (mode 0o666)
    0x14c3994: 'c644241201',            # append = 1
    0x14c3999: 'c644241401',            # create = 1
}
REFERENCES = (
    (WRITE_CALL, b'\xe8', 5, WRITE[0]),
    (0x14c3389, b'\xff\x15', 6, ALLOC_SLOT),
    (0x14c33c1, b'\xe8', 5, SERIALIZE[0]),
    (0x14c341d, b'\xe8', 5, ERROR_IO_DROP),
    (0x14c342c, b'\xff\x15', 6, FREE_SLOT),
    (0x14c346d, b'\xe8', 5, LINE_WRITE[0]),
    (0x1549230, b'\xe8', 5, BOOL_FIELD[0]),
    (0x1549252, b'\x48\x8d\x35', 7, CLOSE_BYTE),
    (0x154925e, b'\xe8', 5, CLOSE),
    (0x1554108, b'\x48\x8d\x35', 7, 0x466e2a),
    (0x1554114, b'\xe9', 5, BOOL_WRITE[0]),
    (0x159b7bc, b'\xe8', 5, ITOA),
    (0x159bfb6, b'\xe8', 5, ITOA),
    (0x159c1f2, b'\xff\x15', 6, RYU_SLOT),
    (0x159c5fc, b'\xff\x15', 6, RYU_SLOT),
    (0x159cb00, b'\xe8', 5, TIME_STR[0]),
    (0x1598ed5, b'\x48\x8d\x05', 7, TIME_DISPLAY),
    (0x1598ef7, b'\xff\x15', 6, FMT_WRITE_SLOT),
    (0x14c3807, b'\xe8', 5, BUFFER[0]),
    (0x14c382b, b'\xff\x15', 6, MEMCPY_SLOT),
    (0x14c3882, b'\xff\x15', 6, COLD_WRITE_SLOT),
    (0x14c3894, b'\xe8', 5, ERROR_IO_DROP),
    (0x14c383f, b'\xff\x15', 6, GATE_SLOT),
    (0x14c384c, b'\xe8', 5, BUFFER[0]),
    (0x14c3854, b'\xe8', 5, FLUSH_BUF),
    (0x14c3865, b'\xe8', 5, ERROR_IO_DROP),
    (0x14c3c91, b'\xe8', 5, BUFFER[0]),
    (0x14c3c99, b'\xe8', 5, FLUSH_BUF),
    (0x14c3caa, b'\xe8', 5, ERROR_IO_DROP),
    (0x154cf86, b'\x4c\x8d\x3d', 7, FALLBACK_DEADLINE),
    (0x14c3b6d, b'\x4c\x8b\x2d', 7, INTERVAL_SLOT),
)


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return off, data[off:off + size]


def rip_target(data, va, prefix, length):
    _, raw = read_va(data, va, length)
    if raw[:len(prefix)] != prefix:
        raise ValueError(f'instruction at {va:#x} changed')
    return va + length + struct.unpack_from('<i', raw, len(prefix))[0]


def fixed(data, va, expect):
    if read_va(data, va, len(expect) // 2)[1] != bytes.fromhex(expect):
        raise ValueError(f'instruction at {va:#x} changed')


def relocations(data):
    """R_X86_64_RELATIVE addends and GLOB_DAT symbol indexes by slot."""
    rel, glob = {}, {}
    for sec in sections(data):
        if sec['type'] != 4:
            continue
        if sec['size'] % 24:
            raise ValueError(f"relocation section {sec['name']} is truncated")
        for va, info, addend in struct.iter_unpack('<QQq', data[sec['offset']:sec['offset'] + sec['size']]):
            if info & 0xffffffff == 8:
                rel[va] = addend
            elif info & 0xffffffff == 6:
                glob[va] = info >> 32
    return rel, glob


def dynamic_symbol_name(data, index):
    secs = sections(data)
    dynsym = next(s for s in secs if s['name'] == '.dynsym')
    dynstr = next(s for s in secs if s['name'] == '.dynstr')
    name_off = struct.unpack_from('<I', data, dynsym['offset'] + 24 * index)[0]
    start = dynstr['offset'] + name_off
    return data[start:data.index(b'\0', start)]


def frame(fdes, va):
    rows = [(f['start'], f['end']) for f in fdes if f['start'] <= va < f['end']]
    if len(rows) != 1:
        raise ValueError(f'expected one FDE at {va:#x}')
    return rows[0]


def direct_callers(data, target):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    base, raw = sec['address'], data[sec['offset']:sec['offset'] + sec['size']]
    out, start = [], 0
    while True:
        index = raw.find(b'\xe8', start)
        if index < 0 or index + 5 > len(raw):
            break
        start = index + 1
        if base + index + 5 + struct.unpack_from('<i', raw, index + 1)[0] == target:
            out.append(base + index)
    return out


def bind(data, fdes):
    rel, glob = relocations(data)
    for slot, target in ((ALLOC_SLOT, 0x6355830), (FREE_SLOT, 0x635de30), (GATE_SLOT, FLUSH_GATE[0]),
                         (COLD_WRITE_SLOT, COLD_WRITE), (RYU_SLOT, 0x5d0e4c0), (FMT_WRITE_SLOT, 0x1680500),
                         (INTERVAL_SLOT, INTERVAL_GLOBAL)):
        if rel.get(slot) != target:
            raise ValueError(f'slot {slot:#x} changed')
    if MEMCPY_SLOT not in glob or dynamic_symbol_name(data, glob[MEMCPY_SLOT]) != b'memcpy':
        raise ValueError('memcpy slot changed')
    for span in (OBSERVER, WRITE, SERIALIZE, LINE_WRITE, BUFFER, OPEN, FLUSH, FLUSH_GATE, BOOL_FIELD,
                 U64, F64, OPT_F64, OPT_U64, TIME, TIME_STR):
        if frame(fdes, span[0]) != span:
            raise ValueError(f'FDE at {span[0]:#x} changed')

    for va, expect in FIXED.items():
        fixed(data, va, expect)
    for va, prefix, length, expect in REFERENCES:
        if rip_target(data, va, prefix, length) != expect:
            raise ValueError(f'reference at {va:#x} changed')
    if read_va(data, CLOSE_BYTE, 1)[1] != b'}':
        raise ValueError('closing byte changed')

    # The serializer writes sixteen fields in this order.
    fields = []
    for rcx_va, rcx, rsi_va, name, len_va, call_va, helper, offset in FIELDS:
        fixed(data, rcx_va, rcx)
        fixed(data, len_va, 'ba' + struct.pack('<I', len(name)).hex())
        if read_va(data, rip_target(data, rsi_va, b'\x48\x8d\x35', 7), len(name))[1] != name:
            raise ValueError(f'field name at {rsi_va:#x} changed')
        if rip_target(data, call_va, b'\xe8', 5) != helper:
            raise ValueError(f'field helper at {call_va:#x} changed')
        if not SERIALIZE[0] <= call_va < SERIALIZE[1]:
            raise ValueError('field outside the serializer')
        fields.append({'name': name.decode(), 'record_offset': hex(offset), 'helper': hex(helper),
                       'kind': KIND[helper]})
    if [f['name'] for f in fields] != [f[3].decode() for f in FIELDS]:
        raise ValueError('field order changed')
    fixed(data, *FLAG_FIELD['add'])
    fixed(data, *FLAG_FIELD['len'])
    if read_va(data, rip_target(data, FLAG_FIELD['name_lea'], b'\x48\x8d\x35', 7), 13)[1] != FLAG_FIELD['name']:
        raise ValueError('flag field name changed')
    flag_offset = struct.unpack('<I', bytes.fromhex(FLAG_FIELD['add'][1])[3:])[0]
    if RECORD_BASE + flag_offset != FLAG_FRAME:
        raise ValueError('flag offset does not match the observer store')
    fields.append({'name': 'is_subsampled', 'record_offset': hex(flag_offset), 'helper': hex(BOOL_FIELD[0]),
                   'kind': 'bool (true/false)'})

    write_callers = direct_callers(data, WRITE[0])
    serialize_callers = direct_callers(data, SERIALIZE[0])
    if WRITE_CALL not in write_callers or serialize_callers != [0x14c33c1]:
        raise ValueError('call census changed')
    interval_raw = read_va(data, INTERVAL_GLOBAL, 8)[1]

    return {
        'target': RELATIVE,
        'sha256': SHA256,
        'task': 'RE-008',
        'component': 'abci',
        'observer': {'flag_store': hex(FLAG_STORE) + ' mov byte [rsp+0x17c], r15b',
                     'record_argument': hex(RECORD_ARG) + ' lea rdx, [rsp+0xd8]',
                     'write_call': hex(WRITE_CALL),
                     'flag_record_offset': hex(FLAG_FRAME - RECORD_BASE)},
        'write': {
            'fde': [hex(v) for v in WRITE], 'direct_callers': len(write_callers),
            'buffer_capacity': 0x80, 'serializer': hex(SERIALIZE[0]),
            'line_end': '0x0a appended after the serializer', 'line_write': hex(LINE_WRITE[0]),
            'serialize_error': 'error box (0x28 bytes) dropped; code 1 drops an io::Error via %s; '
                               'nothing is written' % hex(ERROR_IO_DROP),
        },
        'serializer': {
            'fde': [hex(v) for v in SERIALIZE], 'direct_callers': len(serialize_callers),
            'open': '{', 'close': '}', 'fields': fields,
            'line_inferred': 'one compact JSON object per line',
        },
        'value_helpers': {
            'u64': hex(U64[0]) + ' -> ' + hex(ITOA),
            'f64': hex(F64[0]) + ': |x| >= 0x7ff0000000000000 -> null, else slot ' + hex(RYU_SLOT),
            'option_f64': hex(OPT_F64[0]) + ': tag 1 = Some (value at +0x8), same finiteness check',
            'option_u64': hex(OPT_U64[0]) + ': tag 1 = Some (value at +0x8) -> ' + hex(ITOA) + ', else null',
            'bool': hex(BOOL_FIELD[0]) + ' -> ' + hex(BOOL_WRITE[0]) + ': true / false',
            'time': hex(TIME[0]) + ' -> ' + hex(TIME_STR[0]) + ': quoted, Display ' + hex(TIME_DISPLAY),
        },
        'liner': {
            'buffer': hex(BUFFER[0]) + ' (lazy open: mode 0o666, append, create)',
            'write': {'fde': [hex(v) for v in LINE_WRITE],
                      'fast_path': 'memcpy when len < spare capacity',
                      'slow_path': 'slot %s -> %s; an io::Error is dropped' % (hex(COLD_WRITE_SLOT), hex(COLD_WRITE))},
            'flush_gate': {'fde': [hex(v) for v in FLUSH_GATE], 'state': 'liner +0x38',
                           'interval': 'f64 at +0x38, copied at open from %s (%s at rest)'
                                       % (hex(INTERVAL_GLOBAL), interval_raw.hex()),
                           'flush_when': 'stored date (+0x40) is 0, or the record time is later than '
                                         'stored + interval (fallback deadline %s)' % hex(FALLBACK_DEADLINE),
                           'flush': hex(FLUSH_BUF) + '; an io::Error is dropped'},
            'explicit_flush': {'fde': [hex(v) for v in FLUSH], 'flush': hex(FLUSH_BUF),
                               'error': 'dropped'},
        },
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    data = binary.read_bytes()
    _, fdes, _ = fde_extents(data)
    result = bind(data, fdes)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_bytes(render(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    expected = (PACKET / 'evidence.json').read_bytes() if args.check else None
    result = generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    print(f"fields={len(result['serializer']['fields'])} write_callers={result['write']['direct_callers']}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
