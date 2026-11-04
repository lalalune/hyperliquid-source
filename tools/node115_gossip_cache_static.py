"""Digest-specific static cache update/storage-family observations for node115.
No captured process, CPU interpreter, networking, or helper execution.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import decimal_scaled_u64 as elf
from elf_index import sections
from fde_extents import eh_frame_records
import capstone

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-014-gossip-cache-update-115'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BODIES = {
    'update': (0x5a5d5a0, 0x5a5d950, '6c875979df1c9d8fa13ebe3038048e85d1a9014b6fb6ed3f84b6ede69c0f296c'),
    'clear': (0x4dc0950, 0x4dc0ac0, 'b8cf0bf4058c9f335a752cab9cbab8b5ea811451d4c27610a089e7fc0b9dbb83'),
    'insert': (0x4ddb720, 0x4ddbc4f, 'f052f6887c37e0672b50555f8604d10a3f099b76ce82dc593292fe3accd1a0f9'),
    'pop': (0x4de4340, 0x4de4551, '064ffd707b844e22b2977d28fdb3b75d8bbfb7516b15806e407727e9627b0ae9'),
}
ANCHORS = [
    ('shared-pointer', 0x5a5d5c1, '488b6f30'),
    ('lock', 0x5a5d5d2, 'f00fb04d10'),
    ('tree-tag-plus-one', 0x5a5d5dd, '49b80100000000000080'),
    ('tree-key-last', 0x5a5d6ee, '4805b0000000'),
    ('ring-last-sum', 0x5a5d703, '4801d1'),
    ('ring-last-minus-one', 0x5a5d706, '48ffc9'),
    ('ring-capacity-compare', 0x5a5d70b, '4839c1'),
    ('ring-single-wrap', 0x5a5d70e, '480f43d0'),
    ('ring-row-three-words', 0x5a5d715, '488d0449'),
    ('ring-row-times-eight', 0x5a5d719, '48c1e003'),
    ('fallback', 0x5a5d725, '4983c438'),
    ('incoming-tag', 0x5a5d738, '498b4728'),
    ('incoming-second-shape', 0x5a5d751, '498d97b8000000'),
    ('incoming-shape-select', 0x5a5d75f, '490f44d5'),
    ('comparison-field', 0x5a5d767, '48394a30'),
    ('comparison-keep', 0x5a5d76b, '7418'),
    ('clear-call', 0x5a5d772, 'e8d93136ff'),
    ('derived-key-field', 0x5a5d797, '488b4210'),
    ('derived-key-increment', 0x5a5d79b, '48ffc0'),
    ('derived-key-saturation', 0x5a5d7a5, '480f45f0'),
    ('insert-call', 0x5a5d7b4, 'e867df37ff'),
    ('initial-limit', 0x5a5d7f0, '48817d60f1490200'),
    ('initial-unsigned-branch', 0x5a5d7f8, '727c'),
    ('repeat-limit', 0x5a5d820, '48817d60f0490200'),
    ('repeat-unsigned-branch', 0x5a5d828, '764c'),
    ('pop-call', 0x5a5d830, 'e80b6b38ff'),
    ('clear-capacity', 0x4dc0a41, '48c70300000000'),
    ('clear-empty-pointer', 0x4dc0a48, '48c7430808000000'),
    ('clear-head-length', 0x4dc0a53, '0f114310'),
    ('insert-tree-conversion-cutoff', 0x4ddb767, '4883f820'),
    ('insert-ring-conversion-cutoff', 0x4ddb8a1, '4883fe40'),
    ('pop-tree-conversion-cutoff', 0x4de4385, '4883f820'),
    ('pop-head', 0x4de441a, '49894e10'),
    ('pop-length', 0x4de4421, '49894618'),
    ('source-location-reference', 0x5a5d8a8, '488d3d21aca500'),
]
LOCATION = 0x64b84d0
LOCATION_PATH = 0x44af16
UPDATE_SLOT = 0x64e76f0


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, indent=2) + '\n'


def core(data, identity=True, body_hashes=True, _layout=None):
    if identity:
        need(len(data) == 105896032 and sha(data) == SHA, 'target identity')
    if _layout is None:
        image = elf.Image(data)
        _, fdes = eh_frame_records(data, sections(data))
    else:
        image, fdes = _layout
    bodies = []
    for role, (lo, hi, digest) in BODIES.items():
        matches = [row for row in fdes if row['start'] == lo]
        need(len(matches) == 1 and matches[0]['end'] == hi and image.fde_of(lo) == (lo, hi), 'FDE ' + role)
        raw = data[image.file_offset(lo):image.file_offset(hi)]
        if body_hashes:
            need(sha(raw) == digest, 'body ' + role)
        bodies.append({'role': role, 'start': hex(lo), 'end': hex(hi), 'bytes': hi-lo,
                       'file_offset': hex(image.file_offset(lo)), 'sha256': sha(raw), 'fde': matches[0]})
    anchors = []
    for label, va, raw in ANCHORS:
        actual = data[image.file_offset(va):image.file_offset(va)+len(bytes.fromhex(raw))]
        need(actual.hex() == raw, 'instruction obligation: ' + label)
        anchors.append({'label': label, 'va': hex(va), 'raw_hex': raw})
    raw, length, line, column = struct.unpack_from('<QQII', data, image.file_offset(LOCATION))
    need(raw == 0 and image.slots.get(LOCATION) == LOCATION_PATH, 'Location relocation')
    need((length, line, column) == (22, 245, 43), 'Location coordinates')
    need(data[image.file_offset(LOCATION_PATH):image.file_offset(LOCATION_PATH)+22] == b'node/src/gossip_rpc.rs', 'source path')
    need(image.slots.get(UPDATE_SLOT) == 0x5a5d5a0, 'update slot')
    return image, {'target_sha256': SHA, 'bodies': bodies, 'anchors': anchors,
                   'location': {'va': hex(LOCATION), 'relative_addend': hex(LOCATION_PATH), 'raw_pointer': raw,
                                'path': 'node/src/gossip_rpc.rs', 'length': length, 'line': line, 'column': column},
                   'update_slot': hex(UPDATE_SLOT)}


def observe(data):
    image, result = core(data)
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); cs.detail = True
    exports = {}; all_rows = []
    for body in result['bodies']:
        lo, hi = int(body['start'],16), int(body['end'],16)
        rows = list(cs.disasm(data[image.file_offset(lo):image.file_offset(hi)], lo))
        need(sum(row.size for row in rows) == hi-lo and rows[-1].address+rows[-1].size == hi, 'complete Capstone extent')
        command = ['objdump', '-d', '-Mintel', '--insn-width=16', f'--start-address={lo}', f'--stop-address={hi}', str(TARGET.relative_to(ROOT))]
        text = subprocess.check_output(command, cwd=ROOT, text=True)
        gnu = []
        for line in text.splitlines():
            match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)', line)
            if match:
                gnu.append((int(match[1],16), bytes.fromhex(match[2])))
        need(gnu == [(row.address, bytes(row.bytes)) for row in rows], 'GNU/Capstone boundary mismatch')
        exports[body['role']+'.objdump.txt'] = text
        body['instructions'] = len(rows); body['gnu_command'] = command; body['calls'] = []
        for ins in rows:
            row = {'va': hex(ins.address), 'raw_hex': ins.bytes.hex(), 'mnemonic': ins.mnemonic, 'operands': ins.op_str}
            all_rows.append(row)
            if ins.mnemonic == 'call' or ins.mnemonic == 'jmp':
                raw = bytes(ins.bytes)
                if raw[0] in (0xe8,0xe9):
                    row = {'site': hex(ins.address), 'kind': ins.mnemonic, 'direct_target': hex(ins.address+ins.size+struct.unpack_from('<i',raw,1)[0])}
                elif raw[:2] in (b'\xff\x15',b'\xff\x25'):
                    slot=ins.address+ins.size+struct.unpack_from('<i',raw,2)[0]
                    row = {'site': hex(ins.address), 'kind': ins.mnemonic, 'slot': hex(slot), 'relative_target': hex(image.slots[slot]) if slot in image.slots else None}
                else:
                    if ins.mnemonic != 'call': continue
                    row = {'site': hex(ins.address), 'kind': 'register call', 'operand': ins.op_str}
                body['calls'].append(row)
    # Whole-text FF15 candidate census for this one relocation slot; not register calls.
    text = data[image.text_off:image.text_off+image.text_size]; at=text.find(b'\xff\x15'); callers=[]
    while at >= 0:
        va=image.text_va+at
        if at+6 <= len(text) and va+6+struct.unpack_from('<i',text,at+2)[0] == UPDATE_SLOT:
            lo,hi=image.fde_of(va); decoded=list(cs.disasm(data[image.file_offset(lo):image.file_offset(hi)],lo))
            boundary=next((x for x in decoded if x.address==va),None)
            callers.append({'site':hex(va),'owner_start':hex(lo),'owner_end':hex(hi),
                            'instruction_start':boundary is not None and bytes(boundary.bytes)==text[at:at+6]})
        at=text.find(b'\xff\x15',at+1)
    result.update(primary_bytes=sum(x['bytes'] for x in result['bodies']),
                  primary_instructions=sum(x['instructions'] for x in result['bodies']),
                  callers=callers, captured_process_executed=False, helper_execution=False,
                  tools={'capstone':capstone.__version__, 'objdump':subprocess.check_output(['objdump','--version'],text=True).splitlines()[0]})
    exports['instructions.json'] = encoded(all_rows)
    return result,exports


def controls(data):
    image, baseline = core(data)
    _, fdes = eh_frame_records(data, sections(data))
    mutations = [(image.file_offset(va)+len(bytes.fromhex(raw))-1,label) for label,va,raw in ANCHORS]
    mutations += [(image.file_offset(LOCATION)+8, 'Location length'), (image.file_offset(LOCATION)+16, 'Location line')]
    out=[]
    for offset,label in mutations:
        # These edits cannot affect section/FDE/relocation layout. Reuse only
        # already authenticated metadata, keeping the byte obligations live.
        need(image.text_off <= offset < image.text_off+image.text_size or
             offset in (image.file_offset(LOCATION)+8, image.file_offset(LOCATION)+16),
             'layout-changing mutation requires fresh parse')
        changed=bytearray(data); changed[offset]^=1
        try: core(bytes(changed), identity=False, body_hashes=False, _layout=(image,fdes))
        except ValueError as error: out.append({'obligation':label,'file_offset':hex(offset),'rejection':str(error)})
        else: raise ValueError('corruption escaped: '+label)
    # A layout corruption always reparses both independent FDE views.
    fde = baseline['bodies'][0]['fde']['fde']
    offset = image.file_offset(fde)+12
    changed=bytearray(data); changed[offset]^=1
    try: core(bytes(changed), identity=False, body_hashes=False)
    except ValueError as error: out.append({'obligation':'FDE extent','file_offset':hex(offset),'rejection':str(error)})
    else: raise ValueError('FDE corruption escaped')
    _, rel_offset, rel_size = image.sections['.rela.dyn']
    for slot, label in ((LOCATION, 'Location relocation'), (UPDATE_SLOT, 'update relocation')):
        entries = [at for at in range(rel_offset,rel_offset+rel_size,24)
                   if struct.unpack_from('<Q',data,at)[0] == slot]
        need(len(entries)==1, 'unique relocation control row')
        offset=entries[0]+16; changed=bytearray(data); changed[offset]^=1
        try: core(bytes(changed),identity=False,body_hashes=False)
        except ValueError as error:out.append({'obligation':label,'file_offset':hex(offset),'rejection':str(error)})
        else:raise ValueError('relocation corruption escaped')
    return {'target_and_body_hash_checks_bypassed':True,'layout_reuse':'only unchanged-layout instruction/Location coordinate edits; FDE edit freshly parsed','rejected':out,'survived':[]}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write',action='store_true')
    parser.add_argument('--controls',action='store_true')
    args=parser.parse_args();data=TARGET.read_bytes();record,exports=observe(data)
    exports['records.json']=encoded(record)
    if args.controls:exports['controls.json']=encoded(controls(data))
    for name,text in exports.items():
        path=PACKET/name
        if args.write:path.write_text(text)
        else:need(path.read_text()==text,'regeneration differs: '+name)
    print(json.dumps({'bodies':len(record['bodies']),'bytes':record['primary_bytes'],'instructions':record['primary_instructions'],'callers':record['callers']}))


if __name__=='__main__':main()
