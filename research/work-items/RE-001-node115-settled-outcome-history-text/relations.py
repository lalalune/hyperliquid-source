#!/usr/bin/env python3
"""Static structural relations. Does not execute or emulate captured instructions."""
import argparse,json,math,struct
import capstone
import verify

# Each triple identifies the literal-producing LEA, its explicit length and
# the instruction supplying the field's object-relative offset (None = zero).
FIELDS={
 'history':[(0x3c03e3f,0x3c03e49,None),(0x3c03e6d,0x3c03e77,0x3c03e69),(0x3c03e97,0x3c03ea1,0x3c03e90),(0x3c03ebd,0x3c03ec7,0x3c03eb6),(0x3d2dc78,0x3d2dc7f,0x3c03ed6)],
 'settled_outcome':[(0x3c03444,0x3c0344e,None),(0x3c034b0,0x3c034ba,0x3c034a9),(0x3c034de,0x3c034e8,0x3c034d7)],
 'settled_question':[(0x3c03c5f,0x3c03c69,None),(0x3c03c89,0x3c03c93,0x3c03c85),(0x3c03cac,0x3c03cb6,0x3c03ca8),(0x3c03ccf,0x3c03cd9,0x3c03ccb)],
 'outcome':[(0x3c05100,0x3c0510c,None),(0x3c05131,0x3c0513d,0x3c0512d),(0x3c0515b,0x3c05167,0x3c05157),(0x3c05181,0x3c0518d,0x3c0517d),(0x3c051a7,0x3c051b3,0x3c051a3)],
 'side':[(0x3c053b8,0x3c053c2,0x3c053b4),(0x3c053df,0x3c053e9,None)],
}
EXPECTED={
 'history':[['sots',0],['sotq',72],['sqts',144],['sqp',216],['sqpq',248]],
 'settled_outcome':[['o',0],['f',168],['d',144]],
 'settled_question':[['N',0],['D',24],['u',48],['o',56]],
 'outcome':[['s',0],['n',64],['d',88],['D',120],['f',112]],
 'side':[['t',24],['n',0]],
}

def operands(data):
    im=verify.Image(data);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
    ins=lambda a:next(cs.disasm(im.get(a,15),a))
    def imm(a):return ins(a).operands[-1].imm
    def disp(a):return ins(a).operands[-1].mem.disp
    schema={}
    for typ,fields in FIELDS.items():
        schema[typ]=[]
        for a,l,d in fields:
            i=ins(a);va=a+i.size+i.operands[-1].mem.disp
            offset=0 if d is None else (imm(d) if ins(d).mnemonic=='add' else disp(d))
            schema[typ].append([im.get(va,imm(l)).decode('ascii'),offset])
    return {'schema':schema,'sots_key':disp(0x465cd0c),'sqts_key':disp(0x4649dcc),
      'sotq_key':disp(0x465e43d),'sotq_value':disp(0x465e51d),
      'sots_stride':imm(0x465cc95),'sqts_stride':imm(0x4649d55),'sotq_stride':imm(0x465e3b8),
      'side_delta':imm(0x464ce14),'sqp_step':disp(0x4658de5),
      'sqpq_step':disp(0x465ab25),'float_mask':imm(0x4643f2d),
      'float_nonfinite_start':imm(0x4643f3a),'address_bytes':imm(0x464751c),
      'address_capacity':imm(0x4647517),'hex':im.get(0x455d40,16).decode()}

def record(typ,offset_values,o):
    return {key:offset_values[offset] for key,offset in o['schema'][typ]}

def dense_pairs(raw,count,stride,key_offset,value_reader):
    return [[struct.unpack_from('<Q',raw,i*stride+key_offset)[0],value_reader(raw,i*stride)] for i in range(count)]

def ring(storage,head,length,step):
    capacity=len(storage)
    if not length:return []
    head-=capacity if head>=capacity else 0
    tail=capacity-head
    first=min(length,tail);second=max(0,length-tail)
    # The native implementation serializes two physical slices, in this order.
    return [storage[head+i*(step//8)] for i in range(first)]+[storage[i] for i in range(second)]

def fraction(bits,o):
    return None if bits&o['float_mask']>=o['float_nonfinite_start'] else struct.unpack('<d',struct.pack('<Q',bits))[0]

def address(value,o):
    if value is None:return None
    verify.require(len(value)==o['address_bytes'],'address width boundary')
    return '0x'+''.join(o['hex'][b>>4]+o['hex'][b&15] for b in value)

def evaluate(data):
    o=operands(data)
    verify.require(o['schema']==EXPECTED,'field keys/order/layout')
    verify.require({k:v for k,v in o.items() if k!='schema'}=={
     'sots_key':184,'sqts_key':88,'sotq_key':8,'sotq_value':16,
     'sots_stride':192,'sqts_stride':96,'sotq_stride':24,'side_delta':32,
     'sqp_step':8,'sqpq_step':8,'float_mask':(1<<63)-1,
     'float_nonfinite_start':0x7ff0000000000000,'address_bytes':20,
     'address_capacity':42,'hex':'0123456789abcdef'},'collection and scalar operands')
    # Values below are synthetic schema fixtures, not observations of live state.
    sides=[record('side',{0:'yes',24:11},o),record('side',{0:'no',24:12},o)]
    outcome=record('outcome',{0:sides,64:'market',88:'description',120:address(bytes(range(20)),o),112:0.25},o)
    settled=record('settled_outcome',{0:outcome,168:0.75,144:'resolved'},o)
    question=record('settled_question',{0:'question',24:'details',48:2**64-1,56:[11,12]},o)
    populated=record('history',{0:[[7,settled]],72:[[7,9]],144:[[9,question]],216:[7],248:[9]},o)
    empty=record('history',{offset:[] for _,offset in EXPECTED['history']},o)
    verify.require(list(empty)==['sots','sotq','sqts','sqp','sqpq'] and all(v==[] for v in empty.values()),'empty fields are present')
    verify.require(populated['sots'][0][1]['o']['s'][1]=={'t':12,'n':'no'},'fixed pair nested records')
    # A map-like row container is exported as pairs, with storage order intact.
    # Repeated synthetic keys remain distinct here; no insertion rule is claimed.
    dense_cases=0
    for count in [0,1,2,3,16]:
        for stride,keyoff in [(192,184),(24,8),(96,88)]:
            raw=bytearray(count*stride);keys=[(2**64-1,0,7,7)[i%4] for i in range(count)]
            for i,key in enumerate(keys):struct.pack_into('<Q',raw,i*stride+keyoff,key)
            actual=dense_pairs(raw,count,stride,keyoff,lambda b,pos:pos//stride)
            verify.require(actual==[[k,i] for i,k in enumerate(keys)],'dense pair storage order and width');dense_cases+=1
    ring_cases=0
    for capacity in range(1,33):
        storage=[i+101 for i in range(capacity)]
        for head in range(capacity+1):
            for length in range(capacity+1):
                expected=[storage[(head+j)%capacity] for j in range(length)]
                for step in [o['sqp_step'],o['sqpq_step']]:
                    verify.require(ring(storage,head,length,step)==expected,'wrapped logical queue order');ring_cases+=1
    scalar_cases=0
    floats=[0,1,0x8000000000000000,0x0010000000000000,0x3fe0000000000000,0x7fefffffffffffff,0x7ff0000000000000,0xfff0000000000000,0x7ff8000000000001,0xfff0000000000001]
    for bits in floats:
        f=struct.unpack('<d',struct.pack('<Q',bits))[0];actual=fraction(bits,o)
        verify.require((actual is None)==(not math.isfinite(f)),'nonfinite versus finite fraction')
        if actual is not None:verify.require(struct.pack('<d',actual)==struct.pack('<d',f),'finite fraction bits including negative zero')
        scalar_cases+=1
    for value in [None,bytes(20),bytes([255])*20,bytes(range(20))]:
        verify.require(address(value,o)==(None if value is None else '0x'+value.hex()),'full lowercase address');scalar_cases+=1
    # Counterfactuals read changed native operands without permitting target execution.
    mutants=[];im=verify.Image(data)
    def change(va,new,label,project):
        changed=bytearray(data);changed[im.off(va)]=new
        before=project(o);after=project(operands(changed))
        verify.require(before!=after,'counterfactual survived: '+label)
        mutants.append({'va':hex(va),'replacement':new,'meaning':label,'before':before,'after':after})
    change(0x459f58,ord('x'),'history field literal',lambda x:[k for k,_ in x['schema']['history']])
    change(0x4658de8,16,'first ring span advances twice as far',lambda x:ring(list(range(8)),1,2,x['sqp_step']))
    change(0x4643f42,0xe0,'largest finite range becomes null',lambda x:fraction(0x7fe0000000000000,x))
    row=bytearray(192);struct.pack_into('<Q',row,176,99);struct.pack_into('<Q',row,184,7)
    change(0x465cd0f,0xb0,'dense outcome key offset',lambda x:dense_pairs(row,1,192,x['sots_key'],lambda b,p:'value'))
    return {'native_operands':o,'dense_cases':dense_cases,'ring_cases':ring_cases,'scalar_cases':scalar_cases,
      'schema_cases':2,'synthetic_empty':empty,'synthetic_populated':populated,'counterfactuals':mutants,
      'limits':'Successful structural text projection only, not exact pretty whitespace/float spelling, decoding/defaults, transition policy or target execution/emulation. Dense containers and ring descriptors must be valid; question outcome set is a supplied valid ordered traversal. Primitive allocation/error paths and string escaping are retained as context, not rebuilt.'}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target');text=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(text)
    else:verify.require((verify.PACKET/'relations.json').read_text()==text,'relations drift')
    print('PASS: settled-history structural relations')
