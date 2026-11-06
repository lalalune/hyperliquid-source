#!/usr/bin/env python3
"""Outer serde admission relations over child outcomes, not a native JSON parser."""
import argparse,itertools,json,struct
import capstone
import verify

def operands(data):
    im=verify.Image(data);cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
    ins=lambda a:next(cs.disasm(im.get(a,15),a))
    imm=lambda a:ins(a).operands[-1].imm
    disp=lambda a:next(op.mem.disp for op in ins(a).operands if op.type==capstone.x86.X86_OP_MEM)
    def literal(a,l):
        i=ins(a);return im.get(a+i.size+i.operands[-1].mem.disp,imm(l)).decode()
    keys=[imm(a).to_bytes(4,'little').decode() for a in [0x1e8c47a,0x1e8c486,0x1e8c492]]
    keys.append(imm(0x1e8c513).to_bytes(2,'little').decode()+chr(imm(0x1e8c51d)))
    keys.append(imm(0x1e8c49e).to_bytes(4,'little').decode())
    missing=[literal(a,l) for a,l in [(0x1e8d06e,0x1e8d07d),(0x1e8d210,0x1e8d21f),(0x1e8d390,0x1e8d39f),(0x1e8d486,0x1e8d495),(0x1e8d5c9,0x1e8d5d8)]]
    parent_key=imm(0x22e2b06).to_bytes(2,'little').decode()+chr(imm(0x22e2b10))
    variant=imm(0x22e2b1c);i=ins(0x1eeeee4);table=i.address+i.size+i.operands[-1].mem.disp
    return {'keys':keys,'missing_order':missing,'parent_key':parent_key,'parent_variant':variant,
      'parent_branch':table+struct.unpack('<i',im.get(table+variant*4,4))[0],
      'parent_child':imm(0x1eef996),'default_child':imm(0x1ef14b8),
      'parent_object_base':disp(0x1ef0d57),'parent_object_bytes':imm(0x1ef0d5f),
      'parent_history_offset':disp(0x1ef1644)-disp(0x1ef0d57),'history_bytes':imm(0x1ef1654),
      'duplicate_branches':[ins(a).mnemonic for a in [0x1e8c700,0x1e8c765,0x1e8c7ca,0x1e8c62b,0x1e8c4b9]],
      'map_children':[imm(a) for a in [0x1e8c83a,0x1e8c8c9,0x1e8c955,0x1e8c697,0x1e8c5ca]],
      'sequence_children':[imm(a) for a in [0x1e8ca35,0x1e8d102,0x1e8d511,0x1e8dadb,0x1e8de8a]],
      'whitespace_mask':imm(0x1e8c2ee),'map_delimiter':imm(0x1e8c360),'sequence_delimiter':imm(0x1e8c357),
      'depth_error':imm(0x1e8de62),'sequence_close':imm(0x1d77d9e),'map_close':imm(0x1d77beb),
      'trailing_comma_error':imm(0x1d77db9),'extra_value_error':imm(0x1d77dce),
      'default_dense_lengths':[imm(a) for a in [0x1d791d7,0x1d79224,0x1d792d0]],
      'default_queue_capacities':[imm(0x1d792f7),imm(0x1d79317)],
      'queue_zero_source':[ins(0x1d7930d).mnemonic,ins(0x1d7930d).op_str],
      'queue_zero_stores':[[disp(a),ins(a).operands[0].size,ins(a).reg_name(ins(a).operands[1].reg)] for a in [0x1d79310,0x1d7932d]]}

def map_body(pairs,o):
    values={};trace=[]
    for key,outcome in pairs:
        if key not in o['keys']:
            trace.append('ignore:'+key)
            if outcome!='ok':return ('error','unknown-value',trace)
            continue
        i=o['keys'].index(key);present=key in values
        condition=o['duplicate_branches'][i]
        duplicate=present if condition=='jne' else not present
        if duplicate:return ('error','duplicate:'+key,trace)
        trace.append('child:'+key)
        if outcome!='ok':return ('error','child:'+key,trace)
        values[key]=outcome
    for key in o['missing_order']:
        if key not in values:return ('error','missing:'+key,trace)
    return ('ok',list(o['keys']),trace)

def sequence_body(children,o):
    trace=[]
    for i,key in enumerate(o['keys']):
        if i>=len(children):return ('error','length:'+str(i),trace)
        trace.append('child:'+key)
        if children[i]!='ok':return ('error','child:'+key,trace)
    return ('ok',list(o['keys']),trace)

def finish(body,closing_error=None):
    # Both native branches call the closing helper even after a body error.
    # The existing body error wins when both report failure.
    if body[0]=='error':return body[:2]
    return ('error',closing_error) if closing_error else body[:2]

def enter_depth(depth,bypass,o):
    verify.require(0<=depth<=255,'depth byte')
    if bypass:return ('entered',depth)
    if depth==0:return ('invalid-state',None)
    if depth-1==0:return ('error',o['depth_error'])
    return ('entered',depth-1)

def evaluate(data):
    o=operands(data);keys=['sots','sotq','sqts','sqp','sqpq']
    children=[0x1e3d400,0x1e39ae0,0x1e2fa90,0x1e3c940,0x1e38660]
    verify.require(o['keys']==keys and o['missing_order']==keys,'field classification and required order')
    verify.require(o['parent_key']=='soh' and o['parent_variant']==13 and o['parent_branch']==0x1eef2f2 and o['parent_child']==0x1e8c2c0,'parent identity chain')
    verify.require(o['parent_object_base']==0xc20 and o['parent_object_bytes']==0x5f0,'parent assembled-object copy')
    verify.require(o['default_child']==0x1d79180 and o['parent_history_offset']==952 and o['history_bytes']==280,'parent default and value layout')
    verify.require(o['duplicate_branches']==['jne']*5 and o['map_children']==children and o['sequence_children']==children,'map and sequence dispatch')
    verify.require(o['whitespace_mask']==0x100002600 and o['depth_error']==24,'framing operands')
    verify.require([o[k] for k in ['map_delimiter','sequence_delimiter','map_close','sequence_close']]==[123,91,125,93],'container delimiters')
    verify.require(o['trailing_comma_error']==21 and o['extra_value_error']==22,'closing diagnostics')
    verify.require(o['default_dense_lengths']==[0,0,0] and o['default_queue_capacities']==[0,0],'empty default collections')
    verify.require(o['queue_zero_source']==['xorps','xmm0, xmm0'] and o['queue_zero_stores']==[[232,16,'xmm0'],[264,16,'xmm0']],'zeroed queue head and length pairs')
    map_cases=0
    for perm in itertools.permutations(keys):
        pairs=[(k,'ok') for k in perm]
        verify.require(map_body(pairs,o)[:2]==('ok',keys),'map order independent');map_cases+=1
        for key in keys:
            actual=map_body([(key,'ok'),(key,'bad')]+pairs,o)
            verify.require(actual[:2]==('error','duplicate:'+key) and actual[2]==['child:'+key],'duplicate wins before child');map_cases+=1
    for mask in range(32):
        present=[k for i,k in enumerate(keys) if mask&(1<<i)];missing=[k for k in keys if k not in present]
        result=map_body([(k,'ok') for k in reversed(present)],o)
        verify.require(result[:2]==(('error','missing:'+missing[0]) if missing else ('ok',keys)),'missing priority and no defaults');map_cases+=1
    for unknown in ['', 'SOH','SOTS','sotsx','sot','sqpqx','x']:
        actual=map_body([(unknown,'ok')]*2+[(k,'ok') for k in keys],o)
        verify.require(actual[:2]==('ok',keys) and actual[2][:2]==['ignore:'+unknown]*2,'unknown fields do not fill slots');map_cases+=1
        verify.require(map_body([(unknown,'bad')],o)[:2]==('error','unknown-value'),'walker failure propagates');map_cases+=1
    sequence_cases=0
    for n in range(9):
        body=sequence_body(['ok']*n,o);close='extra' if n>5 else None
        expected=('error','length:'+str(n)) if n<5 else (('error','extra') if n>5 else ('ok',keys))
        verify.require(finish(body,close)==expected,'exact positional arity');sequence_cases+=1
    for i,key in enumerate(keys):
        items=['ok']*5;items[i]='bad';body=sequence_body(items,o)
        verify.require(finish(body,'late-closing-error')==('error','child:'+key),'body error dominates closing');sequence_cases+=1
        verify.require(finish(map_body([(key,'bad')],o),'late-closing-error')==('error','child:'+key),'map body error dominates closing');map_cases+=1
    verify.require(finish(map_body([],o),'late-closing-error')==('error','missing:sots'),'missing dominates closing');map_cases+=1
    framing_cases=0
    whitespace=[b for b in range(256) if b<=32 and (o['whitespace_mask']>>b)&1]
    verify.require(whitespace==[9,10,13,32],'only JSON whitespace bytes');framing_cases+=256
    for depth in range(256):
        actual=enter_depth(depth,False,o)
        verify.require(actual==(('invalid-state',None) if depth==0 else ('error',24) if depth==1 else ('entered',depth-1)),'guarded depth')
        verify.require(enter_depth(depth,True,o)==('entered',depth),'bypass depth');framing_cases+=2
    # Absent entire member invokes default; present empty map fails independently.
    default=[[] for _ in range(5)]
    verify.require(default==[[],[],[],[],[]] and map_body([],o)[1]=='missing:sots','whole-member absence differs from present empty map')
    mutants=[];im=verify.Image(data)
    def change(va,new,label,project):
        modified=bytearray(data);modified[im.off(va)]=new
        before=project(o);after=project(operands(modified))
        verify.require(before!=after,'counterfactual survived: '+label)
        mutants.append({'va':hex(va),'replacement':new,'meaning':label,'before':json.loads(json.dumps(before)),'after':json.loads(json.dumps(after))})
    change(0x1e8c47c,ord('x'),'recognized sots spelling changes',lambda x:map_body([('sots','bad')],x)[:2])
    change(0x1e8c701,0x84,'duplicate branch reverses',lambda x:map_body([('sots','ok')],x)[:2])
    change(0x1e8c2f1,0x00,'tab no longer counts as whitespace',lambda x:bool(x['whitespace_mask']&(1<<9)))
    change(0x1e8de6a,0x17,'depth diagnostic changes',lambda x:enter_depth(1,False,x))
    return {'native_operands':o,'map_cases':map_cases,'sequence_cases':sequence_cases,'framing_cases':framing_cases,'counterfactuals':mutants,
      'limits':'Outer admission over decoded keys and opaque child/walker outcomes; not a byte-complete JSON decoder, child grammar, escape implementation, allocator/TLS seed model, full parent schema or native round trip. No captured execution/emulation.'}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true');args=parser.parse_args()
    data=verify.TARGET.read_bytes();verify.require(verify.sha(data)==verify.DIGEST,'wrong target');text=verify.encoded(evaluate(data))
    if args.write:(verify.PACKET/'relations.json').write_text(text)
    else:verify.require((verify.PACKET/'relations.json').read_text()==text,'relations drift')
    print('PASS: settled-history outer JSON admission relations')
