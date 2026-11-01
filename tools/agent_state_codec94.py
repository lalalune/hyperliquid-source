#!/usr/bin/env python3
"""Recover selected AgentTracker snapshot field decisions from node 94 ELF bytes."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
# FDE ranges are unwind metadata; selected instruction boundaries were checked
# manually. Full hashes catch mutations outside the selected decision windows.
BODIES = {
  0x230d1b0: (0x230d3a6, '42307b51c300bb7527756c71d71d51b252c172039b6eb8c76339b1e65ae6ae25'),
  0x230d3b0: (0x230d6b7, '02ded28fe6513392dd13e59e6571a0fc782771a152040388e3e624bd41c7442e'),
  0x23d1f80: (0x23d2049, 'cf31d7d14ac6357162212882358b8d6749400276d25b7cc35ad8ee00f134c09e'),
  0x2d9e1e0: (0x2da0caf, 'b4f27f05d777cb9c72f5852d7063c72d70ce90f030a823168662042978067410'),
  0x31b0240: (0x31b2e55, '14096e519fdf201649baa579a4763bb8d217a69714153009278b169de3be915a'),
  0x341e420: (0x341e546, 'a9fff3bc3fd3c3302cce224723bc5d15fcc15f3e3bab17b5f04c753e2d54f56f'),
}
PINS = {
  0x2fe78ac:'488dbc24800700004c89f6e884891c00',
  0x275afcb:'488d35ac42c9fdba0d0000004c89ffe811f8e4ff4883f8020f85ca070000498db6d03600004889e74c89fae8b521bbff',
  0x275b9a6:'488d35d138c9fd4889e7ba0d000000e8d6872100803c24010f84f5070000488dbbd03600004c8b',
  0x275b9f9:'4c89f6e8af19bbff4885c00f85a307',
  0x31b02d1:'83ff5b0f847c06000083ff7b0f85df180000',
  0x31b0468:'e8b3df260080bc2440010000010f84a01200000fb6842441010000488d0d4ac73cfd486304814801c848',
  0x31b04ac:'4d85c90f85301f0000', 0x31b0609:'4d85db0f85891c0000',
  0x31b055d:'4d85e40f85901c0000', 0x31b05b3:'4d85ff0f85841d0000',
  0x31b0502:'488b4c24104885c90f857a1f0000',
  0x31b1028:'4d85c90f84a60100004d85db0f84f0010000',
  0x31b1272:'4d85e40f9444242074424d85ff0f944424080f8499010000',
  0x31b145f:'4d85ed74260f104424400f104c24',
  0x31b122a:'b00189442418488d3d31815202e8f4b46a000f10053d8152020f29842490020000f3',
  0x31b1423:'488d3d3e7f5202e801b36a000f10054a7f52020f',
  0x31b148a:'488d3dd77e5202e89ab26a004989c54889d50f10',
  0x2d9e82e:'488d3d5b7d9302e8f6deab000f1005677d93020f29842490000000f30f6f',
  0x2d9ea52:'488d3d377b9302e8d2dcab000f1005437b93020f298424c0000000f30f6f',
  0x2d9eb89:'488d3d007a9302e89bdbab0048895424184889442448488d05ea4246fd48',
  0x2d9e91c:'488d15d5959302488d0d8e7c9302488dbc2420030000be02000000e8b4bbd4fff30f6f',
  0x31b09d6:'83fa5d0f84bd070000488dbc24800100004c89f6e871ec52004c',
  0x31b11d7:'488d0599c93cfd488984244001000048c784244801000012000000',
  0x31b12be:'488d05d8c83cfd488984244001000048c78424480100000d000000',
  0x2d9e7a5:'4585ed0f84e5020000410fb65624',
  0x2d9e828:'4183fd017566488d3d5b7d93', 0x2d9e912:'4183fd020f85ae000000488d',
  0x2d9ea48:'4183fd030f85af000000488d', 0x2d9eb7f:'4183fd040f850f040000488d',
  0x2d9efe3:'418d45fb4889442408', 0x2d9ed4e:'488b44240885c00f84020200004129c50f8284090000',
  0x230d1d0:'807a0b007432488d7c24084c89f6ba05000000e898bd2900488b',
  0x230d208:'488d7c24084c89f6ba05000000e8b6c92900488b4424084883f80275ce41807e0b01',
  0x230d225:'41807e0b01751e488d35022f0dfeba120000004c89f7e8b0d529004883f8020f8522010000',
  0x230d3d6:'c6462000498b46104939060f8403020000498b4e08c604017b48ffc0498946',
  0x230d59b:'41c64620014881c3c0000000488d7c24084889dee8cc490c00',
  0x23d1f89:'803f0075674889f34989fe488d35e1e100feba1e000000e8eb215a00',
  0x341e420:'4889f84883c2f34883fa110f87fa000000488d0dd4df16fd486314914801caffe2',
}
# Writer LEAs followed by a little-endian length; JSON's fifth key is in a child.
WRITER_KEYS = (0x230d22c,0x230d271,0x230d2b2,0x230d2f3,0x230d32f)
JSON_KEYS = (0x230d402,0x230d46a,0x230d4d3,0x230d53c,0x23d1f94)
GUARDS = (0x31b04af,0x31b060c,0x31b0560,0x31b05b6,0x31b050a)
DIAG_KEYS = (0x31b2437,0x31b22ed,0x31b2248,0x31b2392,0x31b24d7)
VALUE_CALLS = (0x31b0871,0x31b08ff,0x31b0783,0x31b07f8,0x31b070a)
COMPACT_CALLS = (0x230d255,0x230d29b,0x230d2dc,0x230d31c,0x230d35b)
JSON_VALUE_CALLS = (0x230d457,0x230d4c0,0x230d529,0x230d591,0x23d1fda)
INPUT_OFFSET_SITES = (0x230d24f,0x230d28f,0x230d2d0,0x230d30d,0x230d349)
KEY_FAILURES = (0x230d244,0x230d289,0x230d2ca,0x230d30b,0x230d347)
VALUE_FAILURES = (0x230d264,0x230d2a5,0x230d2e6,0x230d326,0x230d365)


def read_va(data, secs, va, size):
    if size < 0:
        raise ValueError('negative size')
    hits = [s for s in secs if s['type'] != 8 and s['address'] <= va
            and va + size <= s['address'] + s['size']]
    if len(hits) != 1:
        raise ValueError('address is not uniquely file-backed')
    s = hits[0]
    off = s['offset'] + va - s['address']
    if off + size > len(data):
        raise ValueError('file range truncated')
    return bytes(data[off:off + size])


def check_pins(data, secs):
    result = []
    for va, hx in sorted(PINS.items()):
        raw = read_va(data, secs, va, len(hx) // 2)
        if raw != bytes.fromhex(hx):
            raise ValueError(f'instruction mismatch at {va:#x}')
        result.append({'va':hex(va), 'bytes':raw.hex()})
    return result


def rel32(data, secs, site, op):
    raw = read_va(data, secs, site, len(op) + 4)
    if raw[:len(op)] != op:
        raise ValueError('unexpected relative instruction')
    return site + len(raw) + struct.unpack_from('<i', raw, len(op))[0]


def rip_lea(data, secs, site):
    return rel32(data, secs, site, b'\x48\x8d\x35')


def writer_field(data, secs, site, *, json_form=False):
    va = rip_lea(data, secs, site)
    # JSON sets up arguments between LEA and length; compact writer is adjacent.
    length_site = site + (10 if site == 0x275b9a6 else 12 if json_form and site != 0x23d1f94 else 7)
    raw = read_va(data, secs, length_site, 5)
    if raw[0] != 0xba:
        raise ValueError('field length instruction changed')
    n = struct.unpack_from('<I', raw, 1)[0]
    if n > 128:
        raise ValueError('field length is out of bounds')
    return va, read_va(data, secs, va, n).decode('ascii')


def diag_field(data, secs, site):
    va = rel32(data, secs, site, b'\x48\x8d\x05')
    code = read_va(data, secs, site + 15, 12)
    if code[:8] != bytes.fromhex('48c7842448010000'):
        raise ValueError('diagnostic length setup changed')
    n = struct.unpack_from('<I', code, 8)[0]
    if n > 128:
        raise ValueError('diagnostic name too long')
    return va, read_va(data, secs, va, n).decode('ascii')


def relative_table(data, secs, va, count, lower, upper):
    raw = read_va(data, secs, va, count * 4)
    targets = [va + v for v in struct.unpack('<' + 'i'*count, raw)]
    if not all(lower <= x < upper for x in targets):
        raise ValueError('table target outside FDE')
    return targets


def jump(data, secs, site):
    raw = read_va(data, secs, site, 2)
    if raw[0] == 0x75:
        return site + 2 + struct.unpack('<b',raw[1:])[0]
    if raw == b'\x0f\x85':
        return rel32(data,secs,site,b'\x0f\x85')
    raise ValueError('unexpected conditional branch')


def input_offset(data, secs, site, field_index):
    lengths = (3,4,4,7,7)
    raw = read_va(data,secs,site,lengths[field_index])
    if field_index == 0 and raw == b'\x4c\x89\xfe':
        return 0
    if field_index in (1,2) and raw[:3] == b'\x49\x8d\x77':
        return raw[3]
    if field_index == 3 and raw[:3] == b'\x49\x8d\xb7':
        return struct.unpack_from('<I',raw,3)[0]
    if field_index == 4 and raw[:3] == b'\x49\x81\xc7':
        return struct.unpack_from('<I',raw,3)[0]
    raise ValueError('unexpected writer input instruction')


def classify(name, names):
    if not isinstance(name, bytes):
        raise ValueError('field name must be bytes')
    for tag, known in enumerate(names):
        if name == known:
            return tag
    return len(names)


def presence(mask):
    if not 0 <= mask < 32:
        raise ValueError('presence mask outside 5 fields')
    if not mask & 1:
        return 'missing_0'
    if not mask & 4:
        return 'missing_2'
    return 'required_present'


def sequence(count):
    if count < 0 or count > 0xffffffff:
        raise ValueError('sequence count outside u32')
    if count == 0:
        return 'short_0'
    if count in (1,2):
        return 'short_2'
    if count == 3:
        return 'default_3_4'
    if count == 4:
        return 'default_4'
    if count == 5:
        return 'five_children'
    return 'forward_extra_count'


def as_tsv(header, rows):
    f = io.StringIO(newline='')
    w = csv.writer(f, delimiter='\t', lineterminator='\n')
    w.writerow(header)
    w.writerows(rows)
    return f.getvalue()


def extract(data, expected_digest=SHA256):
    if hashlib.sha256(data).hexdigest() != expected_digest:
        raise ValueError('node 94 SHA-256 mismatch')
    secs = sections(data)
    pins = check_pins(data, secs)
    _, fdes = eh_frame_records(data, secs)
    funcs = []
    for start,(end,sha) in sorted(BODIES.items()):
        matches = [f for f in fdes if f['start'] == start]
        if len(matches) != 1 or matches[0]['end'] != end:
            raise ValueError('FDE mismatch')
        actual = hashlib.sha256(read_va(data, secs, start, end-start)).hexdigest()
        if actual != sha:
            raise ValueError('function body mismatch')
        funcs.append({'start':hex(start), 'end':hex(end), 'fde':hex(matches[0]['fde']), 'sha256':actual})
    # Three independent string representations: both writers and diagnostics.
    fields = []
    table = relative_table(data, secs, 0x57cbd4, 6, 0x31b0240, 0x31b2e55)
    lengths = relative_table(data, secs, 0x58c40c, 18, 0x341e420, 0x341e546)
    expected_arms = [GUARDS[i] - (8 if i == 4 else 3) for i in range(5)] + [0x31b065f]
    if table != expected_arms:
        raise ValueError('JSON dispatch does not select the checked guards')
    for i in range(5):
        va, name = writer_field(data, secs, WRITER_KEYS[i])
        jva, json_name = writer_field(data, secs, JSON_KEYS[i], json_form=True)
        dva, diagnostic = diag_field(data, secs, DIAG_KEYS[i])
        if name != json_name or name != diagnostic:
            raise ValueError('field copies disagree')
        dup = rel32(data, secs, GUARDS[i], b'\x0f\x85')
        if not 0 <= DIAG_KEYS[i] - dup < 0x100:
            raise ValueError('duplicate diagnostic is not on its selected branch')
        if jump(data,secs,KEY_FAILURES[i]) != 0x230d36c or jump(data,secs,VALUE_FAILURES[i]) != 0x230d37b:
            raise ValueError('unexpected writer failure target')
        fields.append({'tag':i, 'name':name, 'compact_name_va':hex(va),
            'json_name_va':hex(jva), 'diagnostic_name_va':hex(dva),
            'writer_input_offset':hex(input_offset(data,secs,INPUT_OFFSET_SITES[i],i)), 'json_map_arm':hex(table[i]),
            'duplicate_guard':hex(GUARDS[i]), 'duplicate_target':hex(dup),
            'key_failure_target':hex(jump(data,secs,KEY_FAILURES[i])),
            'value_failure_target':hex(jump(data,secs,VALUE_FAILURES[i])),
            'json_value_call':hex(VALUE_CALLS[i]),
            'json_value_target':hex(rel32(data, secs, VALUE_CALLS[i], b'\xe8')),
            'compact_value_call':hex(COMPACT_CALLS[i]),
            'compact_value_target':hex(rel32(data, secs, COMPACT_CALLS[i], b'\xe8')),
            'json_write_value_call':hex(JSON_VALUE_CALLS[i]),
            'json_write_value_target':hex(rel32(data, secs, JSON_VALUE_CALLS[i], b'\xe8'))})
    names = [x['name'].encode('ascii') for x in fields]
    # Verify the exact SIMD/immediate comparands used by this classifier.
    compare = [
      read_va(data,secs,0x2048b0,16) + read_va(data,secs,0x2073c0,2),
      read_va(data,secs,0x2068b0,16) + read_va(data,secs,0x207a30,4),
      read_va(data,secs,0x341e443,8) + read_va(data,secs,0x341e450,8)[3:],
      read_va(data,secs,0x203f60,16) + read_va(data,secs,0x205250,4),
      read_va(data,secs,0x2048a0,16) + read_va(data,secs,0x207060,16)[2:],
    ]
    if compare != names:
        raise ValueError('classifier comparison constants disagree')
    expected_lengths = {13:0x341e441,18:0x341e4cd,20:0x341e46e,30:0x341e502}
    for n, dest in expected_lengths.items():
        if lengths[n-13] != dest:
            raise ValueError('classifier length route differs')
    for i,dest in enumerate(lengths):
        if i+13 not in expected_lengths and dest != 0x341e52b:
            raise ValueError('unexpected classifier length route')
    calls = []
    for site, dest in ((0x2fe78b7,0x31b0240),(0x31b0468,0x341e420),
                       (0x230d1e3,0x25a8f80),(0x230d215,0x25a9bd0),
                       (0x230d5af,0x23d1f80),(0x275aff6,0x230d1b0),(0x275b9fc,0x230d3b0)):
        got = rel32(data,secs,site,b'\xe8')
        if got != dest:
            raise ValueError('unexpected call target')
        calls.append({'site':hex(site),'target':hex(got)})
    parent1, label1 = writer_field(data,secs,0x275afcb)
    parent2, label2 = writer_field(data,secs,0x275b9a6,json_form=True)
    one = read_va(data,secs,0x275afe9,7)
    two = read_va(data,secs,0x275b9c4,7)
    if label1 != 'agent_tracker' or label1 != label2 or one[:3] != b'\x49\x8d\xb6' or two[:3] != b'\x48\x8d\xbb':
        raise ValueError('context writer label or layout differs')
    off1 = struct.unpack_from('<I',one,3)[0]
    off2 = struct.unpack_from('<I',two,3)[0]
    if off1 != off2:
        raise ValueError('context writer offsets differ')
    diag = read_va(data,secs,0x57dbdc,35).decode('ascii')
    if diag != 'struct AgentTracker with 5 elements':
        raise ValueError('type diagnostic differs')
    evidence = {'target_sha256':expected_digest,'coordinate_system':'linked ELF virtual address',
      'functions':funcs,'instruction_windows':pins,'context_calls':calls,'fields':fields,
      'context_writer_field':{'name':label1,'compact_name_va':hex(parent1),'json_name_va':hex(parent2),'input_offset':hex(off1)},
      'json_unknown_dispatch':hex(table[5]),'json_dispatch_table':hex(0x57cbd4),
      'classifier_length_table':hex(0x58c40c),'classifier_length_targets':[hex(x) for x in lengths],
      'classifier_comparands_hex':[x.hex() for x in compare], 'diagnostic':diag,
      'model_notice':'Presence and sequence tables model selected branches with successful child returns; they are not native executions.'}
    rows = [(x['tag'],x['name'],x['writer_input_offset'],x['json_map_arm'],x['duplicate_target'],
             x['json_value_target'],x['compact_value_target'],x['json_write_value_target'],x['key_failure_target'],x['value_failure_target']) for x in fields]
    name_cases = []
    for tag, name in enumerate(names):
        name_cases.append((tag,'exact',name.hex(),classify(name,names)))
        name_cases.append((tag,'short',name[:-1].hex(),classify(name[:-1],names)))
        for offset in range(len(name)):
            mutated = bytearray(name)
            mutated[offset] ^= 1
            name_cases.append((tag,f'flip_{offset}',mutated.hex(),classify(bytes(mutated),names)))
    masks = [(f'{i:05b}',presence(i)) for i in range(32)]
    counts = [(i,sequence(i)) for i in range(9)]
    return {'evidence.json':json.dumps(evidence,indent=2,sort_keys=True)+'\n',
       'fields.tsv':as_tsv(('tag','field','input_offset','json_map_arm','duplicate_target','json_reader_child','compact_writer_child','json_writer_child','key_failure_target','value_failure_target'),rows),
       'presence.tsv':as_tsv(('presence_bits_43210','map_completion'),masks),
       'name-cases.tsv':as_tsv(('original_tag','mutation','input_hex','modeled_tag'),name_cases),
       'sequence.tsv':as_tsv(('count','selected_compact_sequence_path'),counts)}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    args=p.parse_args()
    outputs=extract(TARGET.read_bytes())
    args.out.mkdir(parents=True,exist_ok=True)
    for name,value in outputs.items():
        (args.out/name).write_text(value,encoding='utf-8',newline='\n')

if __name__ == '__main__':
    main()
