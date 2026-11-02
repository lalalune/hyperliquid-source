#!/usr/bin/env python3
"""Recover static byte witnesses for the node 94 price-level insertion tree."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
INPUT = ROOT / 'artifacts/node/94/hl-node'
FUNCTIONS = ((0x4956990, 0x4956ae0, 'entry'), (0x4239fc0, 0x423ad0a, 'insert_and_propagate'))
# Each signature is a fixed instruction sequence reviewed in the linked ELF.
# No instruction discovery or disassembler output is used by this collector.
PINS = (
 ('entry_tag',0x4956998,'48833f00747b'),
 ('initial_option_tags',0x49569b7,'48c74424300000000048c744244000000000'),
 ('empty_node_test',0x49569c9,'48837c2410007460'),
 ('occupied_address',0x4956a19,'488b4f1848c1e10548034f08'),
 ('leaf_allocation',0x4956a31,'488b5c2408bfc8010000ff159775e1004885c0'),
 ('leaf_initialization',0x4956a46,'48c780600100000000000066c780c2010000000048890348c7430800000000'),
 ('leaf_capacity_check',0x4956a65,'0fb788c20100004883f90b7355488b1424'),
 ('leaf_insert',0x4956a72,'488b14248d71016689b0c2010000488994c86801000089cac1e2050f104424300f104c24400f114c10100f110410'),
 ('count_and_return',0x4956aa0,'48ff431048c1e1054801c14889c8'),
 ('leaf_full_check',0x4239fda,'410fb79ac20100004883fb0b'),
 ('leaf_insert_index',0x4239ffc,'488b4e104c8d6101498d04ca4805680100004939dc48894c2408'),
 ('leaf_split_threshold',0x423a020,'488b5e104883fb054c896c24100f83e0000000'),
 ('leaf_split_left',0x423a033,'48895c2408bb040000004531ff'),
 ('leaf_split_other_arms',0x423a113,'74194883fb06751dbb0500000041b70148c744240800000000eb1b4531ff48895c2408eb114883c3f948895c2408bb0600000041b701'),
 ('leaf_sibling_alloc',0x423a149,'488b46084889442440bfc8010000ff157b3e53014885c00f84e80a0000'),
 ('leaf_split_length',0x423a182,'488b14240fb782c20100004889dd48f7d54801c5664189adc2010000488b84da6801000048894424204889d848c1e005'),
 ('leaf_split_bound',0x423a1cd,'4883fd0c0f835e0a0000'),
 ('leaf_key_copy',0x423a1dc,'488d82680100004c8d7301488d34d84883c608498dbd68010000'),
 ('leaf_value_copy',0x423a208,'49c1e6054c03342448c1e5054c89ef4c89f64889ea41ffd44c8b14246641899ac2010000'),
 ('leaf_selected_node',0x423a241,'4531e44584ff4c896c24384d0f44ea4c0f44642440'),
 ('leaf_insert_position',0x423a266,'488b4c2408488d34cd680100004c01ee4839cb7664'),
 ('leaf_insert_after_split',0x423a2e7,'4c8b742420ffc34889c848c1e005488b4c24100f10010f104910410f114c0510410f114405006641899dc2010000'),
 ('parent_pointer',0x423a38d,'498b9a600100004885db0f84f5060000'),
 ('parent_height_and_full',0x423a3b0,'4c3b6424400f85fe070000450fb7a2c0010000440fb79bc20100004983fb0b0f830b010000'),
 ('parent_split_left',0x423a4e0,'664183fc054c896c243848894c24104c895c24180f83460100004c89242441bc0400000031ed'),
 ('parent_split_other_arms',0x423a640,'4983fc0574194183fc06751b40b50141bc0500000048c7042400000000eb2131ed4c892424eb194983c4f94c89242440b50141bc06000000'),
 ('internal_sibling_alloc',0x423a680,'bf28020000ff154d3953014885c00f8476050000'),
 ('internal_split_length',0x423a6b3,'0fb783c20100004c89e548f7d54801c5664189adc20100004a8b84e36801000048894424304489e0c1e005'),
 ('internal_edge_bounds',0x423a774,'450fb7b7c2010000498d56014983fe0c0f8364040000488b4424184429e039d00f8580040000'),
 ('repair_moved_child',0x423a7ba,'31c00f1f40004889c14c39f04883d000498b94cfc80100004c89ba6001000066898ac0010000'),
 ('parent_insert_child',0x423a923,'418d4c2401498d442402488b5424384b8994c5d00100006641898dc2010000'),
 ('root_absence',0x423aa9c,'488b842400010000488b184c8b2b4d85ed0f84ab010000'),
 ('root_promote',0x423aae7,'4c89a8c80100004889e848ffc00f84830100004d89b5600100006641c785c001000000004c893348894308'),
 ('root_height_capacity',0x423ab12,'4939ec0f8571010000410fb786c20100004883f80b0f8378010000'),
 ('root_right_child',0x423ab68,'4d89bcc6d00100004d89b7600100006641898fc0010000'),
 ('return_location',0x423ab7f,'488b842490000000488b8c24b0000000488908488b8c24b800000048894808488b4c240848894810'),
)
# Fixed sites, with their expected opcode and destination, covering decisions
# used in the narrative. The displacement is always decoded from file bytes.
BRANCHES = (
 (0x495699c,0x74,0x4956a19,'occupied entry'),
 (0x49569cf,0x74,0x4956a31,'empty root'),
 (0x4956a44,0x74,0x4956ab7,'leaf allocation failure'),
 (0x4956a70,0x73,0x4956ac7,'initial node capacity failure'),
 (0x4239ffa,0x73,0x423a020,'leaf full'),
 (0x423a016,0x76,0x423a045,'leaf shift needed'),
 (0x423a02d,0x83,0x423a113,'leaf index at least five'),
 (0x423a113,0x74,0x423a12e,'leaf index five'),
 (0x423a119,0x75,0x423a138,'leaf index above six'),
 (0x423a160,0x84,0x423ac4e,'leaf sibling allocation failure'),
 (0x423a1d1,0x83,0x423ac35,'leaf split copy bound'),
 (0x423a279,0x76,0x423a2df,'split destination append'),
 (0x423a397,0x84,0x423aa92,'no parent root propagation'),
 (0x423a3b5,0x85,0x423abb9,'parent height mismatch'),
 (0x423a3cf,0x83,0x423a4e0,'parent full'),
 (0x423a3de,0x83,0x423a510,'parent append'),
 (0x423a4f4,0x83,0x423a640,'parent index at least five'),
 (0x423a644,0x74,0x423a65f,'parent index five'),
 (0x423a64a,0x75,0x423a667,'parent index above six'),
 (0x423a68e,0x84,0x423ac0a,'internal sibling allocation failure'),
 (0x423a6fd,0x83,0x423abd2,'internal split copy bound'),
 (0x423a784,0x83,0x423abee,'edge copy bound'),
 (0x423a794,0x85,0x423ac1a,'edge copy length mismatch'),
 (0x423a826,0x86,0x423a8f0,'internal split destination append'),
 (0x423aa8a,0x85,0x423a3b0,'propagate to parent'),
 (0x423aaad,0x84,0x423ac5e,'missing old root failure'),
 (0x423aaca,0x84,0x423ac6b,'new root allocation failure'),
 (0x423aaf4,0x84,0x423ac7d,'root height wrap failure'),
 (0x423ab15,0x85,0x423ac8c,'root height mismatch'),
 (0x423ab27,0x83,0x423aca5,'new root capacity failure'),
 (0x423a0f9,0x85,0x423a35b,'initial local tag differs from two'),
 (0x423a355,0x84,0x423a0ff,'split payload tag equals two'),
 (0x423a554,0x83,0x423a61a,'parent child repair empty'),
 (0x423a565,0x74,0x423a5a2,'parent child repair no remainder'),
 (0x423a59d,0x75,0x423a580,'parent child repair remainder loop'),
 (0x423a5a9,0x72,0x423a61a,'parent child repair skips groups'),
 (0x423a618,0x75,0x423a5b0,'parent child repair group loop'),
 (0x423a62b,0x85,0x423aa56,'parent result tag differs from two'),
 (0x423a7e3,0x73,0x423a7ea,'moved-child loop complete'),
 (0x423a7e8,0x76,0x423a7c0,'moved-child loop continue'),
 (0x423a945,0x83,0x423aa0a,'internal child repair empty'),
 (0x423a955,0x74,0x423a990,'internal child repair no remainder'),
 (0x423a98b,0x75,0x423a970,'internal child repair remainder loop'),
 (0x423a994,0x72,0x423aa0a,'internal child repair skips groups'),
 (0x423aa08,0x75,0x423a9a0,'internal child repair group loop'),
 (0x423aa50,0x84,0x423ab7f,'internal result tag equals two'),
)
# Location descriptors in the exceptional arms; all have RELATIVE relocations.
LOCATIONS = (0x571c408,0x571c420,0x571c438,0x571c450,0x571c468,
             0x571c4b0,0x571c4c8,0x571c4e0,0x571c4f8)
MESSAGES = ((0x6ee281,0x35),(0x6ee259,0x28),(0x6ee1cb,0x30),(0x20ca60,0x20))
CALLS = ((0x4312d9c,0x45a3890,'existing insertion context'),
         (0x45a3922,0x4956990,'existing lookup: occupied'),
         (0x45a3941,0x4956990,'existing lookup: empty tree'),
         (0x45a396a,0x4956990,'existing lookup: absent key'),
         (0x4956a00,0x4239fc0,'entry to insert and propagation'),
         (0x493ec29,0x4239fc0,'additional caller, ownership unresolved'))


# Direct RIP-relative imports and the two move function pointers loaded into
# registers. Labels describe observed use; relocation metadata is separate.
IMPORT_SITES = (
 (0x4956a3b,'call',0x576dfd8,'initial leaf allocation'),
 (0x4956ac1,'call',0x576e020,'initial allocation failure'),
 (0x4956ada,'call',0x576e108,'capacity assertion'),
 (0x423a063,'load',0x576e0e0,'leaf shifts'),
 (0x423a157,'call',0x576dfd8,'leaf sibling allocation'),
 (0x423a1fe,'load',0x576dfe0,'leaf split copies'),
 (0x423a299,'load',0x576e0e0,'parent shifts'),
 (0x423a42e,'call',0x576e0e0,'parent key shift'),
 (0x423a470,'load',0x576e0e0,'parent value and edge shifts'),
 (0x423a685,'call',0x576dfd8,'internal sibling allocation'),
 (0x423a72f,'call',0x576dfe0,'internal split key copy'),
 (0x423a749,'call',0x576dfe0,'internal split value copy'),
 (0x423a7b4,'call',0x576dfe0,'internal child copy'),
 (0x423a89c,'call',0x576e0e0,'internal value shift'),
 (0x423a8dd,'call',0x576e0e0,'internal edge shift'),
 (0x423aac1,'call',0x576dfd8,'new root allocation'),
 (0x423abcc,'call',0x576e108,'parent height assertion'),
 (0x423abe3,'call',0x576e2e0,'internal split bound failure'),
 (0x423abff,'call',0x576e2e0,'edge bound failure'),
 (0x423ac14,'call',0x576e020,'internal allocation failure'),
 (0x423ac2d,'call',0x576e108,'edge length assertion'),
 (0x423ac46,'call',0x576e2e0,'leaf split bound failure'),
 (0x423ac58,'call',0x576e020,'leaf allocation failure'),
 (0x423ac65,'call',0x576e470,'missing root failure'),
 (0x423ac75,'call',0x576e020,'new root allocation failure'),
 (0x423ac84,'call',0x576e470,'root height wrap failure'),
 (0x423ac9f,'call',0x576e108,'root height assertion'),
 (0x423acb8,'call',0x576e108,'root capacity assertion'),
 (0x423acc8,'call',0x576e010,'root cleanup'),
 (0x423acdf,'call',0x576e010,'leaf unwind cleanup'),
 (0x423acfc,'call',0x576e010,'internal unwind cleanup'),
)


def authenticate(data):
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('node 94 SHA-256 mismatch')


def read_va(data, secs, va, size):
    if va < 0 or size < 0:
        raise ValueError('negative address or size')
    hits = [s for s in secs if s['type'] != 8 and s['size'] and
            s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(hits) != 1 or size == 0:
        raise ValueError('address lacks a unique file-backed section')
    s = hits[0]
    off = s['offset'] + va - s['address']
    if off < 0 or off + size > len(data):
        raise ValueError('mapped bytes outside input')
    return data[off:off + size], off


def check_pins(data, secs, pins=PINS):
    result = []
    for name, addr, expected in pins:
        want = bytes.fromhex(expected)
        got, off = read_va(data, secs, addr, len(want))
        if got != want:
            raise ValueError('instruction witness mismatch: ' + name)
        result.append((name, hex(addr), hex(off), got.hex()))
    return result


def decode_branch(data, secs, va):
    first, _ = read_va(data, secs, va, 2)
    if 0x70 <= first[0] <= 0x7f:
        opcode = first[0]
        size = 2
        displacement = struct.unpack('<b', first[1:])[0]
    elif first[0] == 0x0f and 0x80 <= first[1] <= 0x8f:
        raw, _ = read_va(data, secs, va, 6)
        opcode, size = raw[1], 6
        displacement = struct.unpack('<i', raw[2:])[0]
    else:
        raise ValueError('unsupported branch opcode')
    return opcode, va + size + displacement, size


def branch_rows(data, secs):
    rows = []
    for va, expected_op, expected_target, label in sorted(BRANCHES):
        op, target, size = decode_branch(data, secs, va)
        if op != expected_op or target != expected_target:
            raise ValueError('unexpected branch: ' + label)
        raw, off = read_va(data, secs, va, size)
        rows.append((label,hex(va),hex(off),raw.hex(),hex(target)))
    return rows


def call_rows(data, secs):
    rows = []
    for va, expected, label in CALLS:
        raw, off = read_va(data, secs, va, 5)
        if raw[0] != 0xe8:
            raise ValueError('not a rel32 call')
        dest = va + 5 + struct.unpack('<i', raw[1:])[0]
        if dest != expected:
            raise ValueError('unexpected call target')
        rows.append((label,hex(va),hex(off),raw.hex(),hex(dest)))
    return rows



def import_rows(data, secs):
    targets = set(site[2] for site in IMPORT_SITES)
    rela = next(s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4)
    dynsym = next(s for s in secs if s['name'] == '.dynsym' and s['type'] == 11)
    dynstr = next(s for s in secs if s['name'] == '.dynstr' and s['type'] == 3)
    if rela['size'] % 24 or dynsym['size'] % 24:
        raise ValueError('invalid relocation or symbol size')
    reloc = {}
    for off in range(rela['offset'],rela['offset']+rela['size'],24):
        slot,info,addend = struct.unpack_from('<QQq',data,off)
        if slot in targets:
            if slot in reloc:
                raise ValueError('ambiguous import relocation')
            kind, sym = info & 0xffffffff, info >> 32
            if kind not in (6,8) or (kind == 8 and sym != 0):
                raise ValueError('unexpected import relocation')
            symbol = ''
            if sym:
                if sym * 24 + 24 > dynsym['size']:
                    raise ValueError('import symbol outside table')
                name = struct.unpack_from('<I',data,dynsym['offset']+sym*24)[0]
                if name >= dynstr['size']:
                    raise ValueError('import name outside table')
                start = dynstr['offset']+name
                end = data.find(b'\0',start,dynstr['offset']+dynstr['size'])
                if end < 0:
                    raise ValueError('unterminated import name')
                symbol = data[start:end].decode('ascii')
            reloc[slot] = (kind,symbol,addend)
    if set(reloc) != targets:
        raise ValueError('missing import relocation')
    rows=[]
    for site,mode,expected,label in IMPORT_SITES:
        length = 6 if mode == 'call' else 7
        raw,offset = read_va(data,secs,site,length)
        if mode == 'call':
            if raw[:2] != b'\xff\x15':
                raise ValueError('unexpected indirect call')
        elif raw[:2] != b'\x4c\x8b' or raw[2] not in (0x3d,0x25,0x35):
            raise ValueError('unexpected indirect load')
        slot = site + length + struct.unpack('<i',raw[-4:])[0]
        if slot != expected:
            raise ValueError('unexpected indirect slot')
        kind,symbol,addend = reloc[slot]
        rows.append((label,mode,hex(site),hex(offset),raw.hex(),hex(slot),kind,symbol,hex(addend)))
    return rows


def split_parameters(data, secs):
    # Immediate bytes and branch opcodes are covered by the fixed signatures.
    check_pins(data, secs)
    byte = lambda a: read_va(data, secs, a, 1)[0][0]
    capacity = byte(0x4239fe5)
    lower, upper = byte(0x423a027), byte(0x423a118)
    p0, p1, p2 = byte(0x423a039), byte(0x423a11c), byte(0x423a142)
    right_bias = -struct.unpack('<b',read_va(data, secs,0x423a13b,1)[0])[0]
    if (capacity,lower,upper,p0,p1,p2,right_bias) != (11,5,6,4,5,6,7):
        raise ValueError('unexpected split parameters')
    return capacity,lower,upper,p0,p1,p2,right_bias


def split_case(index, params):
    cap, lower, upper, p0, p1, p2, bias = params
    if not 0 <= index <= cap:
        raise ValueError('insertion index outside full node')
    if index < lower:
        pivot, side, dst = p0, 'left', index
    elif index == lower:
        pivot, side, dst = p1, 'left', index
    elif index == upper:
        pivot, side, dst = p1, 'right', 0
    else:
        pivot, side, dst = p2, 'right', index - bias
    left = pivot + (side == 'left')
    right = cap - pivot - 1 + (side == 'right')
    return pivot, side, dst, left, right


def fixture_rows(params):
    rows = []
    cap = params[0]
    old = list(range(2,2*cap+2,2))
    for index in range(cap+1):
        pivot, side, dst, left_n, right_n = split_case(index,params)
        key = index * 2 + 1
        left, promoted, right = old[:pivot],old[pivot],old[pivot+1:]
        (left if side == 'left' else right).insert(dst,key)
        if len(left) != left_n or len(right) != right_n or left + [promoted] + right != sorted(old + [key]):
            raise ValueError('invalid abstract split')
        rows.append((index,key,pivot,side,dst,left_n,right_n,promoted,
                     ','.join(map(str,left)),','.join(map(str,right))))
    return rows



def nonfull_cases(params):
    cap = params[0]
    rows = []
    for length in range(cap):
        old = list(range(2,2*length+2,2))
        for index in range(length+1):
            key = 2*index + 1
            updated = old[:index] + [key] + old[index:]
            rows.append((length,index,key,length-index,','.join(map(str,updated))))
    return rows


def parent_cases(params):
    cap = params[0]
    old = list(range(2,2*cap+2,2))
    children = list(range(cap+1))
    rows = []
    for index in range(cap+1):
        pivot,side,dst,left_n,right_n = split_case(index,params)
        left_keys, right_keys = old[:pivot],old[pivot+1:]
        left_edges, right_edges = children[:pivot+1],children[pivot+1:]
        key, child = 2*index+1, cap+1
        if side == 'left':
            left_keys.insert(dst,key)
            left_edges.insert(dst+1,child)
        else:
            right_keys.insert(dst,key)
            right_edges.insert(dst+1,child)
        expected = children[:index+1]+[child]+children[index+1:]
        if (len(left_keys),len(right_keys)) != (left_n,right_n):
            raise ValueError('invalid parent key counts')
        if len(left_edges) != left_n+1 or len(right_edges) != right_n+1 or left_edges+right_edges != expected:
            raise ValueError('invalid parent edge conservation')
        rows.append((index,pivot,side,dst,child,','.join(map(str,left_edges)),','.join(map(str,right_edges))))
    return rows


def diagnostic_rows(data, secs):
    sec = next(s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4)
    if sec['size'] % 24:
        raise ValueError('invalid RELA length')
    found = {}
    for pos in range(sec['offset'],sec['offset']+sec['size'],24):
        addr, info, addend = struct.unpack_from('<QQq',data,pos)
        if addr in LOCATIONS:
            if addr in found or info != 8:
                raise ValueError('unexpected location relocation')
            found[addr] = addend
    if set(found) != set(LOCATIONS):
        raise ValueError('missing location relocation')
    rows = []
    for addr in LOCATIONS:
        raw, off = read_va(data,secs,addr,24)
        pointer, length, line, col = struct.unpack('<QQII',raw)
        if pointer != 0 or not 0 < length < 256:
            raise ValueError('unexpected location descriptor')
        path, _ = read_va(data,secs,found[addr],length)
        # The target embeds a build path. Publish a stable suffix plus the hash
        # of the complete original bytes, without emitting a machine path.
        marker = b'library/'
        if marker not in path:
            raise ValueError('unexpected location path')
        suffix = path[path.index(marker):].decode('ascii')
        rows.append((hex(addr),hex(off),hex(found[addr]),length,line,col,suffix,hashlib.sha256(path).hexdigest()))
    return rows


def tsv(header, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out,delimiter='\t',lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return out.getvalue().encode()


def generate(data):
    authenticate(data)
    secs = sections(data)
    _, fdes = eh_frame_records(data,secs)
    fn = []
    for start,end,name in FUNCTIONS:
        matches = [f for f in fdes if f['start'] == start]
        if len(matches) != 1 or matches[0]['end'] != end:
            raise ValueError('FDE extent mismatch')
        raw, off = read_va(data,secs,start,end-start)
        fn.append({'role':name,'start_va':hex(start),'end_va_exclusive':hex(end),
                   'fde_va':hex(matches[0]['fde']),'file_offset':hex(off),
                   'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                   'bytes_hex':raw.hex()})
    witnesses = check_pins(data,secs)
    branches = branch_rows(data,secs)
    calls = call_rows(data,secs)
    imports = import_rows(data,secs)
    params = split_parameters(data,secs)
    cases = fixture_rows(params)
    nonfull = nonfull_cases(params)
    parents = parent_cases(params)
    locations = diagnostic_rows(data,secs)
    messages = []
    for addr,length in MESSAGES:
        raw,off = read_va(data,secs,addr,length)
        messages.append({'va':hex(addr),'file_offset':hex(off),'length':length,'ascii':raw.decode('ascii')})
    meta = {'artifact_sha256':hashlib.sha256(data).hexdigest(),'coordinate_system':'linked ELF virtual address',
            'functions':fn,'split_parameters':list(params),'diagnostic_messages':messages,
            'limits':'FDE extents are unwind ranges, not proven source-function boundaries. Branches are a selected fixed-site list, not a full instruction census. Split cases are abstract derivations, not target execution.'}
    files = {
      'evidence.json':(json.dumps(meta,indent=2,sort_keys=True)+'\n').encode(),
      'witnesses.tsv':tsv(('name','va','file_offset','bytes_hex'),witnesses),
      'branches.tsv':tsv(('condition','va','file_offset','bytes_hex','taken_va'),branches),
      'calls.tsv':tsv(('role','va','file_offset','bytes_hex','target_va'),calls),
      'imports.tsv':tsv(('role','mode','va','file_offset','bytes_hex','slot_va','reloc_type','symbol','addend'),imports),
      'split-cases.tsv':tsv(('insertion_index','inserted_key','old_pivot_index','side','side_index','left_count','right_count','promoted_key','left_keys','right_keys'),cases),
      'nonfull-cases.tsv':tsv(('old_length','index','inserted_key','shifted_keys','result_keys'),nonfull),
      'parent-split-cases.tsv':tsv(('index','old_pivot_index','side','side_index','new_child','left_edges','right_edges'),parents),
      'locations.tsv':tsv(('descriptor_va','file_offset','path_va','path_length','line','column','path_suffix','full_path_sha256'),locations),
    }
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',required=True,type=Path)
    args = parser.parse_args()
    files = generate(INPUT.read_bytes())
    args.out.mkdir(parents=True,exist_ok=True)
    for name,contents in sorted(files.items()):
        (args.out / name).write_bytes(contents)


if __name__ == '__main__':
    main()
