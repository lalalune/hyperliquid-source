#!/usr/bin/env python3
"""Extract selected EvmState serialization and reader decisions from node #94."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
# FDE extents and body hashes; the addresses identify inspected code, not a census.
FUNCTIONS = (
    (0x2206a70, 0x2206bdc, 'd709f2167aae52818f1aaceffcdba8b16e25d71e0a0cbf06e9a69d27653818cc'),
    (0x2206be0, 0x2206e71, '75b10be15f93681e559e76ae4ca51f0e85977dab1d173d685b0364723b0116dd'),
    (0x1e5a190, 0x1e5a253, '35810daa83350d31b0fb03be4d8110ab7fe836f236e2b9215c5446390ef53416'),
    (0x295ed40, 0x295ee27, '12adbe3fd3eb553eb00581a7a3efd56de6d4b97c904489e8e94d75409f1c98c1'),
    (0x25ede50, 0x25edf19, 'ab0b7a49303281580b37bb5373e87d15829d34f318bf42205cc636dbb0d7f506'),
    (0x1e31f20, 0x1e321ab, '977a5af4f7246ec634d8609bafcb51a2e45ea371abf59f6946eef4c9934fbd48'),
    (0x1854ef0, 0x18565c6, 'ce78fb5882f4c3954c4df2e15b4c74507e5a9d65e9614ec9d000172792de12d4'),
    (0x16891f0, 0x1689414, 'a886ce1acad9c6a5ca820e29800ea9c753951f540c29ac2b89ecfc3442db036d'),
    (0x18cec20, 0x18cf318, '02016d1c341a96784e72cf4ad0e1e9cbf0fb148ade1209af8e256f865242d09a'),
    (0x22e4cb0, 0x22e4d88, '7a56b0b3a86092d0b8cad844f792954616e706609d67080892b021ff8da057ba'),
    (0x22e4d90, 0x22e4dcb, '59a4cbb739e691599451d6e92a8f70b3ee6be844321c521c78d2827a68079366'),
    (0x1cc7c00, 0x1cc8807, '2a5fb4368bd2760a1af21f7b88e344db989811e64dde6981b87237379b336013'),
    (0x25a8f80, 0x25a9249, '03314d63423cd87d32a952a091906a1f33a112832b2ff2c16ed38101a52cd8a8'),
    (0x25a9bd0, 0x25a9e99, '7a377f120225b9ee6a9ede8d9fcdb9f55afa5426aae870909710f3b1a46e9223'),
    (0x25aa7f0, 0x25aaca9, '7959c723e690a8b949e794907dca4d9f4ca8808fa74ce7c86fe59adb26df4eed'),
    (0x25acc20, 0x25acc6e, '97a69885f4ce8f473e5c0139e173b3c35bbee945b4519ffa9ad5d7e5bdbe1aaa'),
    (0x2567250, 0x2567540, '350bde2256a9f4ceb26ae380a42ba95efaac9d3cb3422802da2468b9ce689669'),
)
WINDOWS = (
 ('writer',0x2206a90,0x2206bdc), ('variant_writer',0x1e5a1ae,0x1e5a244),
 ('json_fields',0x2206c29,0x2206ccc), ('json_variant',0x295ed40,0x295ede5),
 ('hashes_container',0x25ede5f,0x25edecd), ('hashes_sequence',0x1e31f39,0x1e31f9b), ('hashes_loop',0x1e320d3,0x1e3212a),
 ('map_end',0x18552ab,0x185532a), ('missing_block_hashes',0x1855741,0x1855789),
 ('sequence_missing_first',0x1855509,0x1855528), ('sequence_missing_second',0x185557d,0x185559d), ('sequence_decision',0x185543e,0x1855482),
 ('sequence_remainder',0x185559d,0x18555ee), ('reader_keys',0x1855cc6,0x1855d9e),
 ('reader_dispatch',0x18560a0,0x1856174), ('duplicate_fields',0x1856428,0x18564a8),
 ('variant_container',0x16891fb,0x16892fb), ('variant_size_failure',0x16893c4,0x16893f3), ('variant_scalar_name',0x22e4cb7,0x22e4cf4),
 ('variant_word_name',0x22e4d90,0x22e4dcb), ('json_key_dispatch',0x1cc7dbb,0x1cc7e63),
 ('json_missing',0x1cc82fd,0x1cc8320), ('json_missing_evm_db',0x1cc83e4,0x1cc8420),
 ('json_missing_hashes',0x1cc8485,0x1cc84c1), ('json_duplicate',0x1cc861a,0x1cc86ba), ('map_header',0x25a8f8e,0x25a8fa7),
 ('array_header',0x25a9bde,0x25a9bf7), ('string_header',0x25aa803,0x25aa80e),
 ('marker_combine',0x25acc20,0x25acc6e),
 ('empty_collect',0x2567258,0x25672d0), ('collect_return',0x25674db,0x25674f5),
)
CALLS = (0x2206aa3,0x2206ad5,0x2206afb,0x2206b2c,0x2206b5a,0x2206b77,
         0x1e5a1b8,0x1e5a1d3,0x1e5a1f2,0x1e5a229,0x2206c46,
         0x295ed9c,0x25edeba,0x25edec8,0x1e31f87,0x1e3210e,0x185544d,
         0x1855473,0x1856153,0x18560c9,0x185612a,0x16892de,
         0x16892f6,0x18cee7c,0x18cef86)
BRANCHES = (0x2206a94,0x2206ab1,0x2206aea,0x2206b04,0x2206b42,
            0x1e5a1c6,0x1e5a1dc,0x1e5a1e8,0x1e5a200,0x1e5a237,
            0x1855441,0x1855458,0x185545e,0x1855480,0x18555c3,
            0x1855cca,0x1855cd0,0x18560a8,0x18560ad,0x18560b6,
            0x1856147,0x1856189,0x185532a,0x168925a,0x16892c6,0x22e4cbe,
            0x22e4cbe+5,0x22e4d94,0x22e4da7,0x1cc7c82,0x1cc7c8b,
            0x1cc7dc4,0x1cc7dca,0x1cc7df0,0x1cc7e5d,0x1cc7f04,
            0x1cc8310,0x1cc831a)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checked_digest(data):
    if sha(data) != DIGEST:
        raise ValueError('node #94 digest mismatch')


def va_bytes(data, secs, address, length):
    if length < 0:
        raise ValueError('negative size')
    matches = [s for s in secs if s['type'] != 8 and s['size'] and
               s['address'] <= address and address + length <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('unmapped, non-file-backed or ambiguous VA')
    s = matches[0]
    off = s['offset'] + address - s['address']
    return data[off:off + length]


def call_target(data, secs, va):
    insn = va_bytes(data, secs, va, 5)
    if insn[0] != 0xe8:
        raise ValueError('expected rel32 call')
    return va + 5 + struct.unpack_from('<i', insn, 1)[0]


def branch_target(data, secs, va):
    x = va_bytes(data, secs, va, 2)
    if 0x70 <= x[0] <= 0x7f:
        return va + 2 + struct.unpack('b', x[1:])[0]
    if x[0] == 0x0f and 0x80 <= x[1] <= 0x8f:
        return va + 6 + struct.unpack('<i', va_bytes(data, secs, va + 2, 4))[0]
    raise ValueError('expected conditional branch')


def read_name_compare(data, secs, start, count):
    # cmp byte [r15],imm8 then cmp byte [r15+disp8],imm8.
    p = start
    value = bytearray()
    for i in range(count):
        if i == count - 1 and va_bytes(data, secs, p, 2) in (b'\x31\xc0', b'\xb0\x01'):
            p += 2
        if i == 0:
            code = va_bytes(data, secs, p, 4)
            if code[:3] != b'\x41\x80\x3f':
                raise ValueError('first byte compare changed')
            value.append(code[3]); p += 4
        else:
            code = va_bytes(data, secs, p, 5)
            if code[:3] != b'\x41\x80\x7f' or code[3] != i:
                raise ValueError('field byte compare changed')
            value.append(code[4]); p += 5
        if i < count - 1:
            j = va_bytes(data, secs, p, 2)
            if j[0] == 0x75:
                p += 2
            elif j == b'\x0f\x85':
                p += 6
            else:
                # The first classifier sets EAX just before its last compare.
                if i == count - 2 and va_bytes(data,secs,p,2) == b'\x31\xc0':
                    p += 2
                else:
                    raise ValueError('field mismatch branch changed')
    return bytes(value)


def variant_name(data, secs):
    ins = va_bytes(data, secs, 0x22e4d90, 29)
    if ins[:7] != bytes.fromhex('4883fa07751ab8') or ins[11:14] != bytes.fromhex('3306b9') or ins[18:23] != bytes.fromhex('334e0309c1'):
        raise ValueError('variant name classifier changed')
    left, right = ins[7:11], ins[14:18]
    if left[3:] != right[:1]:
        raise ValueError('variant compare words do not overlap')
    return left + right[1:]


def classify_variant(data, secs, candidate):
    # The two overlapping DWORD XOR comparisons plus the length guard.
    ins = va_bytes(data, secs, 0x22e4d90, 29)
    variant_name(data, secs)  # Fail closed on an unrecognized instruction shape.
    if len(candidate) != ins[3]:
        return False
    left = struct.unpack_from('<I', ins, 7)[0]
    right = struct.unpack_from('<I', ins, 14)[0]
    return ((struct.unpack_from('<I', candidate, 0)[0] ^ left) |
            (struct.unpack_from('<I', candidate, 3)[0] ^ right)) == 0


def analyze(data):
    checked_digest(data)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    fby = {}
    for f in fdes:
        if f['start'] in fby:
            raise ValueError('duplicate FDE start')
        fby[f['start']] = f
    indexed = {(e['start'], e['fde']) for e in index}
    functions = []
    for start, end, expected in FUNCTIONS:
        f = fby.get(start)
        if f is None or f['end'] != end or (start, f['fde']) not in indexed:
            raise ValueError('FDE extent or index changed')
        body = va_bytes(data, secs, start, end - start)
        actual = sha(body)
        if actual != expected:
            raise ValueError('code body changed')
        functions.append({'start':hex(start),'end_exclusive':hex(end), 'fde':hex(f['fde']),
                          'body_sha256':actual,'bytes':len(body)})
    windows = []
    for label,start,end in WINDOWS:
        owners = [f for f in fdes if f['start'] <= start < end <= f['end']]
        if len(owners) != 1 or owners[0]['start'] not in {f[0] for f in FUNCTIONS}:
            raise ValueError('window is not in exactly one selected FDE')
        windows.append({'label':label,'start':hex(start),'end_exclusive':hex(end),
                        'owner':hex(owners[0]['start']), 'bytes':va_bytes(data,secs,start,end-start).hex()})
    calls = [{'site':hex(a),'target':hex(call_target(data,secs,a))} for a in CALLS]
    branches = [{'site':hex(a),'target':hex(branch_target(data,secs,a))} for a in BRANCHES]
    field1 = read_name_compare(data,secs,0x1855cd6,6)
    field2 = read_name_compare(data,secs,0x1855d47,12)
    variant = variant_name(data,secs)
    if (field1,field2,variant) != (b'evm_db',b'block_hashes',b'NoEvmDb'):
        raise ValueError('field bytes changed')
    if va_bytes(data,secs,0x3d6c39,18) != field1+field2 or va_bytes(data,secs,0x3dfee1,7) != variant:
        raise ValueError('literal and comparison disagree')
    map_base = va_bytes(data,secs,0x25a8fa0,4)[0]  # immediate of mov ebp,0x80
    array_base = va_bytes(data,secs,0x25a9bf0,4)[0]
    string_base = va_bytes(data,secs,0x25aa80d,1)[0]
    if (map_base,array_base,string_base) != (0x80,0x90,0xa0):
        raise ValueError('marker base changed')
    def mov_imm(site, opcode):
        raw = va_bytes(data, secs, site, 5)
        if raw[0] != opcode:
            raise ValueError('expected immediate instruction')
        return struct.unpack_from('<I', raw, 1)[0]
    field_count = mov_imm(0x2206a9e, 0xba)
    variant_count = mov_imm(0x1e5a1b3, 0xba)
    if (field_count, variant_count) != (2, 1):
        raise ValueError('container arity changed')
    def string(x):
        if len(x) >= 32: raise ValueError('not a fixstr')
        return bytes([string_base | len(x)]) + x
    # block_hashes child's bytes are intentionally opaque; empty iterator uses the zero-length array header.
    named = bytes([map_base|field_count])+string(field1)+bytes([map_base|variant_count])+string(variant)+bytes([map_base])+string(field2)+bytes([array_base])
    positional = bytes([array_base|field_count,map_base|variant_count])+string(variant)+bytes([array_base,array_base])
    result = {'schema':'re009-evm-state-wire/1','target_sha256':sha(data),
              'functions':functions,'windows':windows,'calls':calls,'branches':branches,
              'fields':[field1.decode(),field2.decode()],'variant':variant.decode(),
              'diagnostic_template_bytes':{'missing':va_bytes(data,secs,0x1df8f3,19).hex(),
                                           'duplicate':va_bytes(data,secs,0x1e0fd5,21).hex()},
              'marker_bases':{'map':map_base,'array':array_base,'string':string_base},
              'container_counts':{'outer':field_count,'variant_map':variant_count},
              'examples':{'named_empty_hashes':named.hex(),'positional_empty_hashes':positional.hex()},
              'example_scope':'Static successful path model; empty child iterator only, no target execution.',
              'limitations':['FDE extents do not alone prove complete function boundaries.',
                             'Only selected instruction windows and direct calls were interpreted.',
                             'The ordering and encoding of nonempty block_hashes, complete reader grammar, runtime reachability and cross-release compatibility remain unresolved.']}
    return result


def write_outputs(data, out):
    evidence = analyze(data)
    out.mkdir(parents=True, exist_ok=True)
    (out/'evidence.json').write_text(json.dumps(evidence,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    rows = io.StringIO(newline='')
    w = csv.writer(rows,delimiter='\t',lineterminator='\n')
    w.writerow(['case','condition','selected_route','destination_va'])
    branches = {int(x['site'], 16): int(x['target'], 16) for x in evidence['branches']}
    count = evidence['container_counts']['outer']
    field1, field2 = evidence['fields']
    # Conditions and destinations are tied to the selected instruction sites;
    # child successes are prerequisites, not assertions about arbitrary input.
    for row in [
        ('writer_mode','0','array header; omit outer names',hex(branches[0x2206a94])),
        ('writer_mode','1','map header; emit outer names',hex(0x2206a94 + 2)),
        ('reader_sequence','length 0','first-field error',hex(branches[0x1855441])),
        ('reader_sequence',f'length {count-1}, first child succeeds','second-field error',hex(branches[0x185545e])),
        ('reader_sequence',f'length {count}, both children succeed','normal join',hex(branches[0x18555c3])),
        ('reader_sequence',f'length >{count}, both children succeed','extra-element error',hex(0x18555c3 + 6)),
        ('reader_map',f'duplicate {field1}','duplicate-field path',hex(branches[0x1856147])),
        ('reader_map',f'duplicate {field2}','duplicate-field path',hex(branches[0x18560b6])),
        ('reader_map',f'missing {field1}','missing-field path',hex(branches[0x1856189])),
        ('reader_map',f'missing {field2} after {field1}','missing-field path',hex(branches[0x185532a]))]:
        w.writerow(row)
    (out/'decisions.tsv').write_text(rows.getvalue(),encoding='utf-8')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out',required=True,type=Path)
    args=ap.parse_args()
    write_outputs(BINARY.read_bytes(),args.out)

if __name__ == '__main__':
    main()
