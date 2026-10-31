#!/usr/bin/env python3
"""Reproduce node #94 Duration-related floating guard evidence, statically."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/foundation-duration-guards-94'
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIGN, ONE = 1 << 63, 0x3ff0000000000000
MAX_FINITE, INF = 0x7fefffffffffffff, 0x7ff0000000000000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def guard_flags(bits):
    """Architectural comparison with +0; masked exceptions, DAZ=0 assumed.

    Integer classification only; does not execute any captured instructions.
    """
    require(0 <= bits < 1 << 64, 'Expected a binary64 bit pattern')
    magnitude = bits & (SIGN-1)
    if magnitude > INF:
        return dict(CF=1, PF=1, ZF=1)
    if magnitude == 0:
        return dict(CF=0, PF=0, ZF=1)
    if bits & SIGN:
        return dict(CF=1, PF=0, ZF=0)
    return dict(CF=0, PF=0, ZF=0)


def prefix_result(bits):
    """Symbolic result of the two identical finite-only clamp/guard fragments.

    This is a scoped architectural model, not a recovered Duration method or
    an oracle for the complete function, preceding arithmetic, or live inputs.
    """
    magnitude = bits & (SIGN-1)
    if magnitude > MAX_FINITE:
        return None if guard_flags(bits)['CF'] else bits
    if bits & SIGN and magnitude:
        return 0
    if not bits & SIGN and bits > ONE:
        return ONE
    return bits  # Includes -0: MAXSD selects its source for equal zeros.


def partition():
    spans = [('+zero',0,0), ('positive_finite_to_one',1,ONE),
             ('positive_finite_above_one',ONE+1,MAX_FINITE), ('+infinity',INF,INF),
             ('positive_nan',INF+1,SIGN-1), ('-zero',SIGN,SIGN),
             ('negative_finite',SIGN+1,SIGN+MAX_FINITE),
             ('-infinity',SIGN+INF,SIGN+INF), ('negative_nan',SIGN+INF+1,(1<<64)-1)]
    cursor = 0; result = []
    for name,first,last in spans:
        require(first == cursor and first <= last, 'Partition gap/overlap')
        out = prefix_result(first)
        result.append(dict(name=name,first_bits=hex(first),last_bits=hex(last),
                           pattern_count=last-first+1,
                           isolated_guard_flags=guard_flags(first),
                           prefix_result_kind=('error_arm' if out is None else
                                               'constant_one' if name=='positive_finite_above_one' else
                                               'constant_positive_zero' if name=='negative_finite' else 'input_bits')))
        cursor = last+1
    require(cursor == 1 << 64, 'Incomplete partition')
    return result


def decode_export(output,start,end,body):
    rows = []
    for line in output.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)',line)
        if match:
            rows.append((int(match[1],16),bytes.fromhex(match[2])))
    cursor = start
    for address,raw in rows:
        require(address == cursor, 'Off-by-one or noncontiguous disassembly')
        cursor += len(raw)
    require(cursor == end and b''.join(raw for _,raw in rows) == body, 'Disassembly bytes/extent changed')
    return dict(rows)


def analyze(data,records,objdump=None):
    secs = sections(data); named = {s['name']:s for s in secs}

    def read(va,size):
        matches = [s for s in secs if s['type']!=8 and s['address']<=va and va+size<=s['address']+s['size']]
        require(len(matches)==1,'Unmapped or ambiguous VA')
        sec = matches[0]; offset = sec['offset']+va-sec['address']
        return data[offset:offset+size]

    require(records['target_sha256']==SHA256,'Record target changed')
    start,end = int(records['start_va'],16),int(records['end_va_exclusive'],16)
    require((start,end)==(0x392fab0,0x392fcba),'Scope changed')
    body = read(start,end-start)
    require(hashlib.sha256(body).hexdigest()==records['body_sha256'],'Instruction window changed')
    eh = named['.eh_frame']['address']; fde_offset = int(records['fde_offset'],16)
    fde,cie = bytes.fromhex(records['fde_hex']),bytes.fromhex(records['cie_hex'])
    require(read(eh+fde_offset,len(fde))==fde,'FDE changed')
    require(read(eh+int(records['cie_offset'],16),len(cie))==cie,'CIE changed')
    # Narrow raw locks and the two known pcrel/sdata4 PC/range fields; this is
    # not a general FDE/CFI decoder or a replacement for RE-001.
    pc = eh+fde_offset+8+struct.unpack_from('<i',fde,8)[0]
    require((pc,pc+struct.unpack_from('<I',fde,12)[0])==(start,end),'FDE range disagrees')
    if objdump:
        output = subprocess.check_output([objdump,'-d',f'--start-address={start:#x}',
                                          f'--stop-address={end:#x}','artifacts/node/94/hl-node'],cwd=ROOT,text=True)
    else:
        output = (PACKET/'function.objdump.txt').read_text()
    instructions = decode_export(output,start,end,body)

    def exact(va,raw):
        require(va in instructions and instructions[va]==bytes.fromhex(raw),'Instruction anchor changed')

    def rip(va,length,offset,target):
        require(va in instructions,'Reference not on instruction boundary')
        require(va+length+struct.unpack('<i',read(va+offset,4))[0]==target,'RIP-relative target changed')

    def branch(va,target,opcode):
        require(va in instructions,'Branch not on instruction boundary')
        raw = instructions[va]; op = bytes.fromhex(opcode)
        require(raw.startswith(op),'Branch opcode changed')
        displacement = struct.unpack('<b' if len(raw)==2 else '<i',raw[len(op):])[0]
        require(va+len(raw)+displacement==target,'Branch target changed')

    for va in [0x392fae4,0x392fc20]:
        require(struct.unpack('<Q',read(va+2,8))[0]==SIGN-1,'Sign mask changed')
    for va in [0x392faf1,0x392fc2d]:
        require(struct.unpack('<Q',read(va+2,8))[0]==MAX_FINITE,'Finite threshold changed')
    for va in [0x392fb04,0x392fc40]:exact(va,'f2 0f 5f d1')
    for va in [0x392fb1e,0x392fc5a]:exact(va,'66 0f 2e c8')
    for va in [0x392fb60,0x392fc78]:exact(va,'66 0f 2e c1')
    for va in [0x392fb08,0x392fc44]:rip(va,8,4,0x20a730)
    require(read(0x20a730,8)==struct.pack('<Q',ONE),'Clamp bound changed')
    for args in [(0x392fafe,0x392fb1a,'7f'),(0x392fc3a,0x392fc56,'7f'),
                 (0x392fb18,0x392fb2c,'77'),(0x392fc54,0x392fc64,'77'),
                 (0x392fb26,0x392fc88,'0f82'),(0x392fc62,0x392fc88,'72'),
                 (0x392fb64,0x392fca1,'0f82'),(0x392fc7c,0x392fca1,'72')]:branch(*args)
    rel = named['.rela.dyn']; raw = read(rel['address'],rel['size'])
    require(len(raw)%24==0,'Truncated RELA section')
    rels = {a:(info,addend) for a,info,addend in struct.iter_unpack('<QQq',raw)}
    for address,target in records['relative_slots'].items():
        require(rels.get(int(address,16))==(8,int(target,16)),'Relative call slot changed')
    for location in records['source_locations']:
        address,path_va = int(location['record_va'],16),int(location['path_va'],16)
        path = location['path'].encode()
        require(rels.get(address)==(8,path_va),'Source relocation changed')
        require(struct.unpack('<QII',read(address+8,16))==(len(path),location['line'],location['column']),
                'Source location changed')
        require(read(path_va,len(path))==path,'Source path changed')
    for args in [(0x392fc88,7,3,0x219d71),(0x392fc8f,7,3,0x566ab58),
                 (0x392fca1,7,3,0x219f59),(0x392fca8,7,3,0x566ae58),
                 (0x392fc9b,6,2,0x576e108),(0x392fcb4,6,2,0x576e108)]:rip(*args)
    for address,message in [(0x219d71,b'assertion failed: self >= 0.'),
                             (0x219f59,b'assertion failed: self.0 >= 0.')]:
        require(read(address,len(message))==message,'Assertion text changed')
    return dict(target_release='94',target_sha256=SHA256,coordinate_system='ELF virtual addresses',
                window=dict(start_va=hex(start),end_va_exclusive=hex(end),bytes=len(body),
                            instruction_count=len(instructions),body_sha256=records['body_sha256']),
                source_locations=records['source_locations'],relative_slots=records['relative_slots'],
                guarded_compare_vas=['0x392fb1e','0x392fc5a','0x392fb60','0x392fc78'],
                error_arm_vas=['0x392fc88','0x392fca1'],
                symbolic_assumptions=['binary64','DAZ disabled','SIMD exceptions masked',
                                      'scope begins at fragment entry, after preceding arithmetic'],
                bit_partition=partition(),partition_patterns=1<<64,
                full_function_semantics=False,live_input_reachability=False,
                captured_binary_executed=False,progress_gate_requested=False)


def _unique_record_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f'Duplicate key in retained records input: {key}')
        out[key] = value
    return out


def load_records(path):
    return json.loads(Path(path).read_text(), object_pairs_hook=_unique_record_object)


def inspect(path,objdump=None):
    data = Path(path).read_bytes()
    require(len(data)==91774280 and hashlib.sha256(data).hexdigest()==SHA256,'Expected exact node #94 size/SHA-256')
    return analyze(data,load_records(PACKET/'records.json'),objdump)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=TARGET)
    parser.add_argument('--objdump',help='Rerun LLVM instead of using the retained export')
    parser.add_argument('--check',type=Path)
    args = parser.parse_args(); result = inspect(args.binary,args.objdump)
    if args.check:
        require(result==json.loads(args.check.read_text()),'Retained evidence differs')
        print('Duration floating guard evidence reproduces exactly.')
    else:
        print(json.dumps(result,indent=2))


if __name__=='__main__':main()
