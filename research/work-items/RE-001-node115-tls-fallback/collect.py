#!/usr/bin/env python3
"""Reproduce static node115 TLS fallback evidence; never execute/emulate the target."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BASE = '8fd8db680ec4bfef40996e5616bce3d5156d0b86'
def digest(data):
    return hashlib.sha256(data).hexdigest()
RANGES = [('key-init',
  97127968,
  97128170,
  'peer-PR2050-dependency-context',
  'bea533989049ed882a20589020adb2b23db8218efbcc41b11629b58828f2a462'),
 ('drain', 97145840, 97146128, 'new', 'e32e17af191316ba5e7fbd05c65979559175c89fab47e115285f849a29a58fcb'),
 ('growth-wrapper',
  97039904,
  97039945,
  'peer-PR2050-dependency-context',
  'f143a6425fb7f36b91ff4f6e52d7b7a617244c3dc803f931965870c7648bff0a'),
 ('growth-install',
  97040768,
  97040878,
  'peer-PR2050-dependency-context',
  '724cae113b04eab18a557583c3834c85644447108e649130dea85ed0a4de167a'),
 ('registration-context',
  97127712,
  97127967,
  'own-PR2266-context',
  'b41b5cc834002de4b875118dffe3ede7cd50f595dd8e5103a0f08a9cedae254e')]
FDE_PINS = [('key-init', {'fde': 16656448, 'cie': 13266648, 'start': 97127968, 'end': 97128170, 'lsda': None}, '11b003ef17b78f63c4f1e7ffd27accd390aff047a75273cfc4eddd4ce5361d2e', {'va': 13266648, 'augmentation': 'zR', 'code_align': 1, 'data_align': -8, 'fde_encoding': 27, 'lsda_encoding': None, 'personality_slot': None}), ('drain', {'fde': 20764340, 'cie': 17028612, 'start': 97145840, 'end': 97146128, 'lsda': 4194072}, 'e797f9cf11a2d82bb0c2ea7a611e1a2cace95936e6bdcbf3a1c82cd15d54198b', {'va': 17028612, 'augmentation': 'zPLR', 'code_align': 1, 'data_align': -8, 'fde_encoding': 27, 'lsda_encoding': 27, 'personality_slot': 105839144}), ('growth-wrapper', {'fde': 16653852, 'cie': 13266648, 'start': 97039904, 'end': 97039945, 'lsda': None}, '4e34d2137547272509928e8ddd861f4df796cdd8d32ba7d4329913bf099430c7', {'va': 13266648, 'augmentation': 'zR', 'code_align': 1, 'data_align': -8, 'fde_encoding': 27, 'lsda_encoding': None, 'personality_slot': None}), ('growth-install', {'fde': 16654040, 'cie': 13266648, 'start': 97040768, 'end': 97040878, 'lsda': None}, '8b77e1b445d94fc589b6b580cd086f2fb53894a8a33d8dd2471425899aab7688', {'va': 13266648, 'augmentation': 'zR', 'code_align': 1, 'data_align': -8, 'fde_encoding': 27, 'lsda_encoding': None, 'personality_slot': None}), ('registration-context', {'fde': 20763624, 'cie': 17028612, 'start': 97127712, 'end': 97127967, 'lsda': 4193440}, '22313492e71daefe3a5ac780eff32aa9d511e7e5322a625c7e4c946dee34796c', {'va': 17028612, 'augmentation': 'zPLR', 'code_align': 1, 'data_align': -8, 'fde_encoding': 27, 'lsda_encoding': 27, 'personality_slot': 105839144})]
ANCHORS = {97039908: '488b37',
 97039911: 'e854030000',
 97039916: '48b90100000000000080',
 97039926: '4839c8',
 97039929: '7502',
 97039939: 'ff154f3e8500',
 97040782: '48ffc6',
 97040785: '488b07',
 97040788: '488d0c00',
 97040792: '4839ce',
 97040795: '480f46f1',
 97040799: '4883fe05',
 97040803: '41be04000000',
 97040809: '4c0f43f6',
 97040813: '488b5708',
 97040821: '4889c6',
 97040824: '4c89f1',
 97040827: 'e830ffffff',
 97040832: '807dd800',
 97040836: '740a',
 97040838: '488b45e0',
 97040842: '488b55e8',
 97040852: '48894308',
 97040856: '4c8933',
 97040859: '48b80100000000000080',
 97127727: '4889f3',
 97127730: '4989fe',
 97127733: '48833d73bc840000',
 97127741: '741f',
 97127743: '488d1502d78500',
 97127750: '4889df',
 97127753: '4c89f6',
 97127768: 'ff2552bc8400',
 97127774: '6448833c25b0eeffff00',
 97127784: '757c',
 97127795: '6448c70425b0eeffffffffffff',
 97127808: 'e89b000000',
 97127813: '644c8b3c25c8eeffff',
 97127822: '644c3b3c25b8eeffff',
 97127831: '7512',
 97127833: '498dbc24b0eeffff',
 97127841: '4883c708',
 97127845: 'ff15cdba8400',
 97127851: '64488b0425c0eeffff',
 97127860: '4c89f9',
 97127863: '48c1e104',
 97127867: '4c893408',
 97127871: '48895c0808',
 97127876: '49ffc7',
 97127879: '644c893c25c8eeffff',
 97127888: '6448ff0425b0eeffff',
 97127950: '6448ff0425b0eeffff',
 97127959: '4889c7',
 97127962: 'e831fc7400',
 97127977: '488b3d78df8500',
 97127987: '7569',
 97127989: '488b3574df8500',
 97128007: 'ff156bbb8400',
 97128015: '755f',
 97128022: '752b',
 97128024: '488b3551df8500',
 97128042: 'ff1548bb8400',
 97128050: '753c',
 97128055: '31ff',
 97128057: 'ff1541bb8400',
 97128065: '743f',
 97128069: '31c0',
 97128071: 'f0480fb13d18df8500',
 97128080: '740c',
 97128082: '4889c3',
 97128085: 'ff1525bb8400',
 97128091: '4889df',
 97128094: 'be01000000',
 97128099: 'ff151fbb8400',
 97128112: '488d353890cafa',
 97128123: 'ba5f000000',
 97128130: '488d359184cafa',
 97128141: 'ba9b000000',
 97128146: 'e889c60000',
 97128159: 'e80c23fdff',
 97128164: 'ff15fef38300',
 97145848: '6448833c25b0eeffff00',
 97145858: '7564',
 97145872: '6448c70425b0eeffffffffffff',
 97145885: '64488b0425c8eeffff',
 97145897: '744c',
 97145899: '48ffc8',
 97145902: '6448890425c8eeffff',
 97145911: '64488b0c25c0eeffff',
 97145920: '48c1e004',
 97145924: '488b3c01',
 97145928: '488b440108',
 97145933: '6448c70425b0eeffff00000000',
 97145946: 'ffd0',
 97145948: '6448833c25b0eeffff00',
 97145958: '74a8',
 97145960: '488d3d89e78100',
 97145967: 'ff156bbe8300',
 97145973: '0f0b',
 97145975: '6448833c25b8eeffff00',
 97145985: '741d',
 97145987: '64488b3c25c0eeffff',
 97145996: 'ff1546cc8300',
 97146002: '64488b0425b0eeffff',
 97146011: '48ffc0',
 97146014: 'eb02',
 97146016: '31c0',
 97146018: '6448c70425b8eeffff00000000',
 97146031: '6448c70425c0eeffff08000000',
 97146044: '6448c70425c8eeffff00000000',
 97146057: '6448890425b0eeffff',
 97146066: '48c7c1d8fbffff',
 97146077: '4883f803',
 97146081: '7221',
 97146083: '6448c70102000000',
 97146091: '488d48f0',
 97146099: 'f048ff48f0',
 97146104: '750a',
 97146110: 'ff1554a98300',
 97146122: 'ff1578b08300'}
EDGES = [(97127977, 7, 8773496, 105901480),
 (97127989, 7, 8773492, 105901488),
 (97128007, 6, 8698731, 105826744),
 (97128024, 7, 8773457, 105901488),
 (97128042, 6, 8698696, 105826744),
 (97128057, 6, 8698689, 105826752),
 (97128071, 9, 8773400, 105901480),
 (97128085, 6, 8698661, 105826752),
 (97128099, 6, 8698655, 105826760),
 (97128112, 7, -87388104, 9740015),
 (97128128, 2, None, 97128146),
 (97128130, 7, -87391087, 9737050),
 (97128146, 5, None, 97178976),
 (97128159, 5, None, 96940528),
 (97128164, 6, 8647678, 105775848),
 (97145960, 7, 8513417, 105659384),
 (97145967, 6, 8633963, 105779936),
 (97145996, 6, 8637510, 105783512),
 (97146014, 2, None, 97146018),
 (97146110, 6, 8628564, 105774680),
 (97146122, 6, 8630392, 105776520),
 (97039911, 5, None, 97040768),
 (97039939, 6, 8732239, 105772184),
 (97040827, 5, None, 97040624),
 (97040846, 2, None, 97040869),
 (97127733, 8, 8698995, 105826736),
 (97127743, 7, 8771330, 105899080),
 (97127768, 6, 8698962, 105826736),
 (97127808, 5, None, 97127968),
 (97127845, 6, 8698573, 105826424),
 (97127910, 7, -87387987, 9739930),
 (97127926, 5, None, 97178976),
 (97127939, 5, None, 96940528),
 (97127944, 6, 8647898, 105775848),
 (97127962, 5, None, 104794704),
 (104794704, 6, 1038114, 105832824)]
BINDINGS = [(105659384, 8, 4440734, None),
 (105772184, 8, 21095012, None),
 (105774680, 8, 97094464, None),
 (105775848, 8, 97103952, None),
 (105776520, 8, 23596579, None),
 (105779936, 8, 23595888, None),
 (105783512, 253403070470, 0, 'free'),
 (105826424, 8, 97039904, None),
 (105826736, 850403524614, 0, '__cxa_thread_atexit_impl'),
 (105826744, 854698491910, 0, 'pthread_key_create'),
 (105826752, 858993459206, 0, 'pthread_key_delete'),
 (105826760, 863288426502, 0, 'pthread_setspecific'),
 (105832824, 25769803783, 0, '_Unwind_Resume'),
 (105839144, 8, 97179568, None),
 (105899080, 8, 105839136, None),
 (105901488, 8, 97145840, None)]
DATA_PINS = {4440734: '2f72757374632f353938303736313665316661323534303732346266626163313464373937366437653461333836302f6c6962726172792f7374642f7372632f7379732f7468726561645f6c6f63616c2f64657374727563746f72732f6c6973742e7273',
 104794704: 'ff2522d70f00',
 105659384: '000000000000000064000000000000001a0000001f000000',
 105901480: '0000000000000000',
 105901488: '0000000000000000'}
HELPER_BOUNDARIES = [{'cie': 13266648, 'end': 21095033, 'fde': 13267464, 'lsda': None, 'start': 21095012},
 {'cie': 13266648, 'end': 23595935, 'fde': 13381556, 'lsda': None, 'start': 23595888},
 {'cie': 13266648, 'end': 23596599, 'fde': 13381808, 'lsda': None, 'start': 23596579},
 {'cie': 13266648, 'end': 96940539, 'fde': 16648428, 'lsda': None, 'start': 96940528},
 {'cie': 13266648, 'end': 97040768, 'fde': 16654000, 'lsda': None, 'start': 97040624},
 {'cie': 13266648, 'end': 97094537, 'fde': 16655376, 'lsda': None, 'start': 97094464},
 {'cie': 13266648, 'end': 97103961, 'fde': 16655780, 'lsda': None, 'start': 97103952},
 {'cie': 17028612, 'end': 97179124, 'fde': 20765584, 'lsda': 4194760, 'start': 97178976},
 {'cie': 17028612, 'end': 97181007, 'fde': 20765628, 'lsda': 4194792, 'start': 97179568}]
class Image:
    def __init__(self,data,sections,fdes,cies):
        self.data,self.sections,self.fdes,self.cies=data,sections,fdes,cies
    def offset(self,va,length):
        spans=[s for s in self.sections if s['type']!=8 and s['address']<=va<va+length<=s['address']+s['size']]
        if len(spans)!=1:
            raise ValueError('Non-unique mapped bytes')
        return spans[0]['offset']+va-spans[0]['address']
    def read(self,va,length):
        off=self.offset(va,length)
        return self.data[off:off+length]
    def relocations(self):
        rows={}
        for s in self.sections:
            if s['type']==4:
                for slot,info,addend in struct.iter_unpack('<QQq',self.data[s['offset']:s['offset']+s['size']]):
                    rows.setdefault(slot,[]).append((info,addend))
        return rows
    def symbol(self,index):
        sym=next(s for s in self.sections if s['name']=='.dynsym')
        strings=next(s for s in self.sections if s['name']=='.dynstr')
        name=struct.unpack_from('<I',self.data,sym['offset']+index*24)[0]
        if name>=strings['size']:
            raise ValueError('Bad symbol name offset')
        start=strings['offset']+name
        return self.data[start:self.data.index(b'\0',start,strings['offset']+strings['size'])].decode('ascii')

def load(root):
    data=(root/'artifacts/node/115/hl-node').read_bytes()
    if len(data)!=105896032 or digest(data)!=TARGET:
        raise ValueError('Wrong target')
    sys.path.insert(0,str(root/'tools'))
    from elf_index import sections
    from fde_extents import eh_frame_records
    secs=sections(data);cies,fdes=eh_frame_records(data,secs)
    return Image(data,secs,fdes,cies)

def rip(image,pc,size,displacement):
    return pc+size+struct.unpack('<i',image.read(pc+displacement,4))[0]

def uleb(data,pos,end):
    value=shift=0
    while pos<end and shift<=63:
        byte=data[pos];pos+=1;value|=(byte&127)<<shift
        if byte<128:
            if value>=1<<64: break
            return value,pos
        shift+=7
    raise ValueError('Truncated/oversized LSDA ULEB')

def native_rows(raw,image,start,end):
    cursor=start;rows=[]
    for line in raw.decode().splitlines():
        m=re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)',line)
        if m:
            pc=int(m[1],16);chunk=bytes.fromhex(m[2])
            if pc!=cursor or pc+len(chunk)>end or chunk!=image.read(pc,len(chunk)):
                raise ValueError('Native byte gap/overlap/mismatch')
            rows.append((pc,chunk));cursor+=len(chunk)
    if cursor!=end:
        raise ValueError('Incomplete native interval')
    return rows


def lsda_rows(data,start,end):
    if len(data)<4 or data[0]!=255 or data[1] not in (255,155):
        raise ValueError('Unsupported LSDA header')
    pos=2; type_base=None
    if data[1]==155:
        offset,pos=uleb(data,pos,len(data));type_base=pos+offset
    if data[pos]!=1:raise ValueError('Unsupported call-site encoding')
    size,pos=uleb(data,pos+1,len(data));table_end=pos+size
    if table_end>len(data) or type_base is not None and not table_end<=type_base<=len(data):
        raise ValueError('LSDA bounds')
    rows=[];previous=0
    while pos<table_end:
        fields=[]
        for _ in range(4):
            v,pos=uleb(data,pos,table_end);fields.append(v)
        lo,length,lp,action=fields
        if not length or lo<previous or start+lo+length>end or lp and not start<=start+lp<end:
            raise ValueError('LSDA interval')
        previous=lo+length
        rows.append([start+lo,start+lo+length,start+lp if lp else None,action])
    return rows

def validate(image,body_hashes=True):
    """Structural checks remain active when tests bypass whole-input/body hashes."""
    for name,want,raw_hash,cie in FDE_PINS:
        actual=[f for f in image.fdes if f['start']==want['start']]
        if actual!=[want] or image.cies.get(want['cie'])!=cie:
            raise ValueError('FDE/CIE mismatch: '+name)
        n=struct.unpack('<I',image.read(want['fde'],4))[0]+4
        if n>256 or digest(image.read(want['fde'],n))!=raw_hash:
            raise ValueError('Raw FDE mismatch')
    for name,lo,hi,kind,want in RANGES:
        if not any(s['flags']&4 and s['type']!=8 and s['address']<=lo<hi<=s['address']+s['size'] for s in image.sections):
            raise ValueError('Non-executable body')
        if body_hashes and digest(image.read(lo,hi-lo))!=want:
            raise ValueError('Body hash mismatch: '+name)
    for pc,b in ANCHORS.items():
        if image.read(pc,len(bytes.fromhex(b))).hex()!=b:
            raise ValueError('Instruction anchor mismatch: '+hex(pc))
    for va,b in DATA_PINS.items():
        if image.read(va,len(bytes.fromhex(b))).hex()!=b:raise ValueError('Data/PLT bytes mismatch')
    for want in HELPER_BOUNDARIES:
        if [f for f in image.fdes if f['start']==want['start']]!=[want]:
            raise ValueError('Outside helper FDE boundary mismatch')
    rels=image.relocations()
    for slot,info,add,name in BINDINGS:
        if rels.get(slot)!=[(info,add)]:raise ValueError('Relocation mismatch: '+hex(slot))
        if name and image.symbol(info>>32)!=name:raise ValueError('Import name mismatch')
    # Independently recompute each retained direct or RIP edge from its instruction.
    import capstone
    cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
    for pc,size,disp,want in EDGES:
        ins=list(cs.disasm(image.read(pc,size),pc))
        if len(ins)!=1 or ins[0].size!=size:raise ValueError('Edge instruction size')
        operands=ins[0].operands
        if disp is None:
            got=[o.imm for o in operands if o.type==capstone.x86.X86_OP_IMM]
        else:
            got=[pc+size+o.mem.disp for o in operands if o.type==capstone.x86.X86_OP_MEM and o.mem.base==capstone.x86.X86_REG_RIP]
        if got!=[want]:raise ValueError('Edge mismatch')
    # Global sentinel really starts zero in file-backed .data; callback is a unique RELATIVE binding.
    if image.read(0x64feda8,8)!=b'\0'*8:raise ValueError('Initial key word')
    expected=[
      (0x3ffca0,16,0x5ca0d20,0x5ca0e1f,[[0x5ca0d80,0x5ca0dab,0x5ca0e0e,0],[0x5ca0dab,0x5ca0e1f,None,0]]),
      (0x3fff18,20,0x5ca53f0,0x5ca5510,[[0x5ca53f0,0x5ca5468,None,0],[0x5ca5468,0x5ca5475,0x5ca550a,1]])]
    tables=[]
    for va,n,lo,hi,want in expected:
        raw=image.read(va,n);rows=lsda_rows(raw,lo,hi)
        if rows!=want:raise ValueError('LSDA mapping mismatch')
        tables.append({'va':hex(va),'context_bytes':n,'context_hex':raw.hex(),'rows':rows,
          'bound':'ends at next FDE-referenced LSDA, not a proven object extent',
          'action_type_tables_interpreted':False})
    return tables

def join_lock(rows):
    result=[];joins=[];i=0
    allowed={0x5ca0e87:'480fb13d18df8500',0x5ca54f3:'48ff48f0'}
    while i<len(rows):
        pc,b=rows[i];i+=1
        if pc in allowed and b==b'\xf0':
            tail=bytes.fromhex(allowed[pc])
            if i>=len(rows) or rows[i]!=(pc+1,tail):raise ValueError('Invalid LOCK continuation')
            b+=rows[i][1];i+=1;joins.append(hex(pc))
        result.append((pc,bytes(b)))
    return result,joins

def collect(root,packet):
    image=load(root);tables=validate(image)
    import capstone
    cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    bodies=[]
    for name,lo,hi,kind,want in RANGES:
        raw=image.read(lo,hi-lo);cap=[(i.address,bytes(i.bytes)) for i in cs.disasm(raw,lo)]
        if b''.join(x[1] for x in cap)!=raw:raise ValueError('Incomplete Capstone body')
        captures=[]
        for tool in ('objdump','llvm-objdump'):
            file=packet/'native'/f'{name}.{tool}.txt';data=file.read_bytes()
            native=native_rows(data,image,lo,hi);joined,joins=join_lock(native)
            if joined!=cap:raise ValueError('Native/Capstone partition mismatch')
            captures.append({'path':str(file.relative_to(packet)),'sha256':digest(data),
                             'raw_rows':len(native),'logical_instructions':len(joined),'lock_joins':joins})
        bodies.append({'name':name,'start':hex(lo),'end':hex(hi),'file_offset':image.offset(lo,hi-lo),
                       'bytes':hi-lo,'sha256':want,'ownership':kind,'instructions':len(cap),'captures':captures})
    return {'schema_version':1,'task':'RE-001','component':'foundation','base':BASE,
      'target':{'release':115,'bytes':len(image.data),'sha256':TARGET},'coordinate_system':'ELF link-time VA; half-open ranges',
      'bodies':bodies,'bindings':[{'slot':hex(s),'r_info':i,'addend':a,'import':n} for s,i,a,n in BINDINGS],
      'edges':[{'pc':hex(pc),'size':size,'kind':'direct' if disp is None else 'rip','target':hex(t)} for pc,size,disp,t in EDGES],
      'instruction_anchors':[{'pc':hex(pc),'bytes':b} for pc,b in sorted(ANCHORS.items())],
      'data':[{'va':hex(v),'bytes_hex':b} for v,b in DATA_PINS.items()],
      'external_helper_boundaries':HELPER_BOUNDARIES,
      'fdes':[{'name':n,'fde':f,'raw_sha256':h,'cie':c} for n,f,h,c in FDE_PINS],
      'lsda_contexts':tables,'capstone_version':capstone.__version__,
      'counts':{'new_complete_bodies':1,'new_body_bytes':288,'context_body_bytes':608,
                'total_complete_bodies':5,'total_body_bytes':896,'new_byte_comparison_credit':0,'acceptance_gates_changed':0},
      'limitations':{'captured_execution':False,'emulation':False,'rust_reconstruction':False,
                     'original_rust_type_or_build_flags_established':False,'pthread_runtime_success_established':False,
                     'allocation_body_owned_by_peer_PR':2310,'full_helper_implementation_closure':False}}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[3])
    parser.add_argument('--check',action='store_true');args=parser.parse_args()
    packet=Path(__file__).resolve().parent;actual=collect(args.root,packet)
    file=packet/'records.json'
    if args.check:
        expected=json.loads(file.read_text());expected['capstone_version']=actual['capstone_version']
        if actual!=expected:raise ValueError('Evidence record drift')
        print('Verified 288 new + 608 context bytes, five FDEs, every native partition, all retained bindings and two LSDA call-site maps')
    else:file.write_text(json.dumps(actual,indent=2,sort_keys=True)+'\n')
if __name__=='__main__':main()
