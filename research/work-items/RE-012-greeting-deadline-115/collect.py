#!/usr/bin/env python3
"""Bind a conditional node115 greeting deadline route; never execute the target."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
from fractions import Fraction

TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BASE = '8fd8db680ec4bfef40996e5616bce3d5156d0b86'
RANGES = [('caller',0x2b67e50,0x2b69279),('sender-context',0x2b7a290,0x2b7b523),
          ('conversion',0x15ed960,0x15edb81)]
# These selected operands express the measured route, rather than a source ABI.
ANCHORS = {
 0x2b6847a:'48c7832002000000000000',  # input first word zero
 0x2b68485:'48b80000000000004e40',  # adjacent input word: binary64 60
 0x2b6848f:'48898328020000',
 0x2b684a4:'c6833005000000',         # sender state +0x310 = zero
 0x2b684ab:'488dbb20020000',
 0x2b684b5:'e8d61d0100',
 0x2b7a2a8:'4889fb',0x2b7a2ab:'0fb68710030000',
 0x2b7a2b2:'488d0d03aaa8fd',0x2b7a2b9:'48630481',0x2b7a2bd:'4801c8',
 0x2b7a2d6:'488b0b',0x2b7a2d9:'f20f104308',
 0x2b7a30a:'48894b28',0x2b7a30e:'f20f114330',
 0x2b7a33d:'48894b58',0x2b7a341:'f20f114360',
 0x2b7a48c:'488b4b28',0x2b7a490:'f20f104330',
 0x2b7a4a0:'48894b58',0x2b7a4a4:'f20f114360',
 0x2b7b28c:'f20f104360',0x2b7b291:'807b5800',0x2b7b295:'7508',
 0x2b7b297:'f20f1005d1e88dfd',0x2b7b29f:'4c8d83e0000000',
 0x2b7b2ee:'f20f11442460',0x2b7b2f4:'f20f118360010000',
 0x2b7ab7b:'f20f10642460',0x2b7ab81:'f20f11a3e8020000',
 0x2b7ac2f:'f20f11a3f0020000',0x2b7ac6c:'f20f1083f0020000',
 0x2b7ac74:'ff15f6629603',0x2b7ac94:'4d01fe',
 0x2b7acab:'4501ec',0x2b7acae:'4181fc00ca9a3b',
 0x2b7b315:'e979f7ffff',
 0x15eda39:'66480f7ec6',0x15eda41:'48c1e934',
 0x15eda45:'81e1ff070000',0x15edae7:'81ff33040000',
 0x15edaef:'8d9101fcffff',0x15edaf5:'40b733',0x15edaf8:'4028cf',
 0x15edafd:'48d3e8',0x15edb03:'89d1',0x15edb05:'48d3e6',
 0x15edb08:'4c21c6',0x15edb0b:'b900ca9a3b',0x15edb13:'48f7e1',
 0x15edb67:'4889f8',0x15edb6a:'4801f0',0x15edb6d:'c3',
}

def digest(data):
    return hashlib.sha256(data).hexdigest()

class Image:
    def __init__(self, data, sections, fdes):
        self.data,self.sections,self.fdes=data,sections,fdes
    def offset(self, va, length):
        matches=[s for s in self.sections if s['type']!=8 and s['address']<=va<va+length<=s['address']+s['size']]
        if len(matches)!=1:
            raise ValueError('Non-unique/missing mapped bytes')
        s=matches[0]
        return s['offset']+va-s['address']
    def read(self, va, length):
        off=self.offset(va,length)
        return self.data[off:off+length]
    def relocations(self):
        rows={}
        for s in self.sections:
            if s['type']==4:
                for slot,info,addend in struct.iter_unpack('<QQq',self.data[s['offset']:s['offset']+s['size']]):
                    rows.setdefault(slot,[]).append((info,addend))
        return rows

def bindings(image):
    for va, expected in ANCHORS.items():
        if image.read(va,len(bytes.fromhex(expected))).hex()!=expected:
            raise ValueError(f'Changed route operand at {va:#x}')
    # Actual encoded call/branch/RIP operands are decoded independently of labels.
    if 0x2b684b5+5+struct.unpack('<i',image.read(0x2b684b6,4))[0]!=0x2b7a290:
        raise ValueError('Caller target')
    if 0x2b7b295+2+struct.unpack('<b',image.read(0x2b7b296,1))[0]!=0x2b7b29f:
        raise ValueError('Selector branch')
    if 0x2b7b297+8+struct.unpack('<i',image.read(0x2b7b29b,4))[0]!=0x459b70:
        raise ValueError('Default RIP target')
    if image.read(0x459b70,8)!=bytes.fromhex('0000000000003440'):
        raise ValueError('Default constant')
    if 0x604cbc+struct.unpack('<i',image.read(0x604cbc,4))[0]!=0x2b7a2ca:
        raise ValueError('Initial sender dispatch')
    rels=image.relocations()
    if rels.get(0x64e0f70)!=[(8,0x15ed960)]:
        raise ValueError('Conversion relocation is not unique/correct')
    return {
      'caller_state_zero':{'store':'0x2b684a4','callee_relative_offset':'0x310','dispatch_entry_va':'0x604cbc','destination':'0x2b7a2ca'},
      'input_pair':{'caller_relative_offset':'0x220','flag_word':0,'provided_binary64_bits':'0x404e000000000000'},
      'selector':{'condition_va':'0x2b7b291','field':'sender+0x58 low byte','zero_binary64_bits':'0x4034000000000000','nonzero':'retain sender+0x60 bits'},
      'conversion_slot':{'va':'0x64e0f70','type':8,'symbol':0,'addend':'0x15ed960'},
      'anchors':[{'va':hex(va),'bytes_hex':v} for va,v in ANCHORS.items()],
      'data':[{'va':'0x459b70','bytes_hex':image.read(0x459b70,8).hex()},
              {'va':'0x604cbc','bytes_hex':image.read(0x604cbc,4).hex()}],
    }

def native_rows(path, image, start, end):
    raw=path.read_bytes();cursor=start;rows=[]
    for line in raw.decode().splitlines():
        m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)',line)
        if m:
            pc=int(m[1],16);data=bytes.fromhex(m[2])
            if pc!=cursor or data!=image.read(pc,len(data)):
                raise ValueError('Native byte gap/overlap/mismatch')
            rows.append((pc,data));cursor+=len(data)
    if cursor!=end:
        raise ValueError('Incomplete native interval')
    return rows,{'file':path.name,'sha256':digest(raw),'bytes':len(raw),'raw_rows':len(rows)}

def collect(root, packet):
    data=(root/'artifacts/node/115/hl-node').read_bytes()
    if len(data)!=105896032 or digest(data)!=TARGET:
        raise ValueError('Wrong target')
    sys.path.insert(0,str(root/'tools'))
    from elf_index import sections
    from fde_extents import eh_frame_records
    secs=sections(data);_,fdes=eh_frame_records(data,secs)
    image=Image(data,secs,fdes)
    route=bindings(image)
    import capstone
    cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    cs.detail=True
    records=[];all_starts=set()
    for name,start,end in RANGES:
        found=[f for f in fdes if (f['start'],f['end'])==(start,end)]
        if len(found)!=1:
            raise ValueError('Selected FDE is not unique')
        if not any(s['flags']&4 and s['address']<=start<end<=s['address']+s['size'] for s in secs):
            raise ValueError('Non-executable selected interval')
        body=image.read(start,end-start)
        g,gn=native_rows(packet/'native'/f'{name}.gnu.objdump',image,start,end)
        l,ln=native_rows(packet/'native'/f'{name}.llvm.objdump',image,start,end)
        li=0;joins=[]
        for pc,chunk in g:
            lp,lc=l[li];li+=1
            if lp!=pc:
                raise ValueError('Native boundary difference')
            if lc!=chunk:
                np,nc=l[li];li+=1
                if lc!=b'\xf0' or np!=pc+1 or lc+nc!=chunk:
                    raise ValueError('Unexplained native display difference')
                joins.append({'va':hex(pc),'gnu':chunk.hex(),'llvm':[lc.hex(),nc.hex()]})
        if li!=len(l):
            raise ValueError('Extra LLVM rows')
        instructions=list(cs.disasm(body,start))
        decoded=[(i.address,bytes(i.bytes)) for i in instructions]
        if decoded!=g:
            raise ValueError('Capstone partition differs')
        all_starts.update(pc for pc,_ in g)
        field_access=[]
        if name=='sender-context':
            for instruction in instructions:
                for operand in instruction.operands:
                    if operand.type==capstone.x86.X86_OP_MEM and operand.mem.base==capstone.x86.X86_REG_RBX and operand.mem.disp in (0x58,0x60):
                        field_access.append({'va':hex(instruction.address),'offset':hex(operand.mem.disp),
                                              'width':operand.size,'access':operand.access,
                                              'assembly':instruction.mnemonic+' '+instruction.op_str})
            writes=[a['va'] for a in field_access if a['access'] & capstone.CS_AC_WRITE]
            if writes!=['0x2b7a33d','0x2b7a341','0x2b7a4a0','0x2b7a4a4']:
                raise ValueError(f'Unexpected directly encoded selector-field writer: {field_access}')
        records.append({'name':name,'start':hex(start),'end':hex(end),'fde_va':hex(found[0]['fde']),
                        'file_offset':image.offset(start,len(body)),'bytes':len(body),'body_sha256':digest(body),
                        'instruction_rows':len(g),'native':{'gnu':gn,'llvm':ln},'lock_display_joins':joins,
                        'selected_direct_rbx_field_accesses':field_access})
    if set(ANCHORS)-all_starts:
        raise ValueError('Anchor is not an instruction start')
    integral_examples=[]
    for bits in (0x4034000000000000,0x404e000000000000):
        exponent=(bits>>52)&0x7ff
        significand=(bits&((1<<52)-1))+(1<<52)
        value=Fraction(significand)*Fraction(2)**(exponent-1023-52)
        if value.denominator!=1 or value!=Fraction.from_float(struct.unpack('<d',struct.pack('<Q',bits))[0]):
            raise ValueError('Independent binary64 arithmetic disagrees')
        integral_examples.append({'bits':hex(bits),'biased_exponent':exponent,
                                  'integer_seconds':int(value),'fractional_nanos':0,
                                  'meaning':'Independent arithmetic worksheet; not target execution or general converter equivalence'})
    return {'target_sha256':TARGET,'baseline':BASE,'body_bytes':sum(r['bytes'] for r in records),
            'instruction_rows':sum(r['instruction_rows'] for r in records),'capstone_partitions_checked':True,
            'intervals':records,'route':route,'integral_examples':integral_examples,'byte_masks':0,'captured_execution':False,
            'scope':'Conditional static deadline selection/creation route only; native byte denominator is exported context, not recovered/matching code coverage.'}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('root',type=Path);parser.add_argument('packet',type=Path)
    parser.add_argument('--write',action='store_true')
    args=parser.parse_args()
    result=collect(args.root.resolve(),args.packet.resolve())
    encoded=json.dumps(result,indent=2,sort_keys=True)+'\n'
    path=args.packet/'records.json'
    if args.write:
        path.write_text(encoded)
    elif path.read_text()!=encoded:
        raise ValueError('Frozen records differ')
    version=sys.modules['capstone'].__version__
    print(f"Bound {len(result['intervals'])} FDE intervals / {result['body_bytes']} bytes / {result['instruction_rows']} instruction rows; Capstone={version}; masks=0; captured execution=false")

if __name__=='__main__':
    try:
        main()
    except (ValueError,OSError,IndexError,StopIteration) as error:
        raise SystemExit(str(error)) from None
