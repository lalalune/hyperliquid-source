#!/usr/bin/env python3
"""Independent high-level integral-padding request/state oracle before Rust.

Computes layout from integer lengths and Unicode scalar count, then applies
supplied opaque callback replies/cell transitions. No PC/register/opcode model.
"""
from pathlib import Path
import hashlib,json,datetime

ROOT=Path(__file__).resolve().parent
PLUS=1<<21;ALT=1<<23;ZERO=1<<24
MASK64=(1<<64)-1
cases=[];seen=set();families={}

def step(ordinal,reply=0,actions=()):
    return [ordinal,reply,list(actions)]

def add(family,*,sign=1,prefix='0x',digits=b'7b',width=0,fill=32,align=1,
        plus=False,alt=False,zero=False,extra=0,precision=0x4a3b,
        tailword=None,data=11,table=1,methods=None,script=(),alignment=0):
    flags=fill|(align<<29)|(PLUS if plus else 0)|(ALT if alt else 0)|(ZERO if zero else 0)|extra
    tailword=flags|(width<<32)|(precision<<48) if tailword is None else tailword
    assert 0<=sign<1<<32 and 0<=tailword<=MASK64 and 0<=alignment<8
    assert isinstance(prefix,str) and isinstance(digits,bytes)
    methods=[[1,101,102],[2,201,202]] if methods is None else methods
    item={'sign':sign,'prefix_hex':prefix.encode().hex(),'digits_hex':digits.hex(),
          'tailword':tailword,'data':data,'table':table,'methods':methods,
          'script':list(script),'alignment':alignment}
    key=json.dumps(item,sort_keys=True,separators=(',',':'))
    if key in seen:return
    seen.add(key);item['id']=f'p{len(cases):05d}';item['family']=family;cases.append(item)
    families[family]=families.get(family,0)+1

def answer(case):
    initial=case['tailword'];flags=initial&0xffffffff;width=(initial>>32)&65535
    prefix=bytes.fromhex(case['prefix_hex']);text=prefix.decode('utf-8')
    digits=bytes.fromhex(case['digits_hex'])
    sign=45 if case['sign']==0 else (43 if flags&PLUS else None)
    enabled=bool(flags&ALT)
    total=len(digits)+(sign is not None)+(len(text) if enabled else 0)
    assert total<1<<64
    gap=max(width-total,0)
    # This declarative sequence is a mathematical layout, not native branches.
    start=[]
    if sign is not None:start.append(('char',sign,1))
    if enabled:start.append(('str',prefix.hex(),1))
    if gap==0:
        operations=start+[('str',digits.hex(),1)]
        category='no-padding';restore=False
    elif flags&ZERO:
        operations=start+[('char',48,gap),('str',digits.hex(),1)]
        category='zero-padding';restore=True
    else:
        align=(flags>>29)&3
        left=0 if align==0 else gap//2 if align==2 else gap
        operations=[('char',flags&0x1fffff,left)]+start+[('str',digits.hex(),1),('char',flags&0x1fffff,gap-left)]
        category='ordinary-padding';restore=False
    state={'data':case['data'],'table':case['table'],'tailword':initial}
    tables={t:[c,s] for t,c,s in case['methods']}
    assert case['table'] in tables
    scripts={ordinal:(reply,actions) for ordinal,reply,actions in case['script']}
    assert len(scripts)==len(case['script'])
    cached_data=state['data'];cached_table=state['table']
    if restore:
        state['tailword']=(initial&~0xffffffff)|((flags&0x9fe00000)|0x20000030)
    events=[];calls=0;status=0;failed=False
    for operation_index,(kind,argument,count) in enumerate(operations):
        for _ in range(count):
            reply,actions=scripts.get(calls,(0,[]))
            assert 0<=reply<256
            event={'kind':kind,'method':tables[cached_table][kind=='str'],
                   'data':cached_data,'table':cached_table,'argument':argument,
                   'context_data':state['data'],'context_table':state['table'],
                   'context_tailword':state['tailword'],'reply':reply}
            if events and events[-1]['event']==event:events[-1]['count']+=1
            else:events.append({'count':1,'event':event})
            calls+=1
            for action in actions:
                if action[0]=='T':state['tailword']=action[1]
                elif action[0]=='D':state['data']=action[1]
                elif action[0]=='B':state['table']=action[1]
                elif action[0]=='M':
                    assert action[1] in tables;tables[action[1]]=[action[2],action[3]]
                else:raise ValueError(action)
            if reply:
                final_nopad_digit=category=='no-padding' and operation_index==len(operations)-1
                status=reply if final_nopad_digit else 1
                failed=True;break
        if failed:break
    if restore and not failed:state['tailword']=initial
    assert sum(x['count'] for x in events)==calls
    return {'id':case['id'],'prefix_alignment':case['alignment'],'raw_status':status,
            'callback_count':calls,'events':events,'final_data':state['data'],
            'final_table':state['table'],'final_tailword':state['tailword'],
            'final_methods':[[t,*tables[t]] for t in sorted(tables)]}

# Layout covers every selection/align combination, independent display widths,
# zero-length callbacks, raw digit bytes and scalar-count versus byte-count.
prefixes=['','0x','é🦀']
digitsets=[b'',b'0',b'123',b'\x00\xff']
for sign in (0,1):
 for pi,prefix in enumerate(prefixes):
  for di,digits in enumerate(digitsets):
   for plus in (False,True):
    for alt in (False,True):
     for zero in (False,True):
      total=len(digits)+(sign==0 or plus)+(len(prefix) if alt else 0)
      for align in range(4):
       for width in sorted({0,max(total-1,0),total,total+1,total+5}):
        add('layout-matrix',sign=sign,prefix=prefix,digits=digits,width=width,
            plus=plus,alt=alt,zero=zero,align=align,
            fill=[32,42,233,0x1f9ca][(pi+di+align)%4])

status_scenarios=[
 ('nopad-digits',dict(prefix='',digits=b'',width=0),[0]),
 ('nopad-sign-prefix-digits',dict(sign=0,plus=True,alt=True,width=0),[0,1,2]),
 ('nopad-empty-prefix',dict(prefix='',alt=True,width=0),[0,1]),
 ('right',dict(sign=0,alt=True,width=8,align=1),[0,2,3,4,5]),
 ('left',dict(sign=0,alt=True,width=8,align=0),[0,1,2,3,5]),
 ('center',dict(sign=0,alt=True,width=9,align=2),[0,1,2,3,4,5,6]),
 ('zero',dict(sign=0,alt=True,zero=True,width=8),[0,1,2,4,5]),
]
for name,options,ordinals in status_scenarios:
 for ordinal in ordinals:
  for reply in range(256):
   add('all-raw-u8-replies-'+name,**options,script=[step(ordinal,reply)])

# Full ESI nonzero behavior and irrelevant flag retention in observed context.
for sign in (2,255,256,0xffffffff):
 for extra in (0,1<<22,1<<25,1<<26,1<<27,1<<28,1<<31):
  for zero in (False,True):
   add('noncanonical-positive-and-other-flags',sign=sign,plus=True,alt=True,
       zero=zero,width=10,extra=extra,precision=65535)

# Explicit callback cell mutations challenge cached data/table versus live methods,
# local layout snapshots and success-only restoration of the full original word.
mutations=[['D',0xabc],['B',2],['T',0xfedcba9876543210],['M',1,777,888]]
for category,options in [('no-pad',dict(sign=0,alt=True,width=0)),
                         ('ordinary',dict(sign=0,alt=True,width=12,align=2)),
                         ('zero',dict(sign=0,alt=True,width=12,zero=True))]:
 for failure in (None,0,1,2,3,5,8,10):
  script=[step(0,231 if failure==0 else 0,mutations),step(1,231 if failure==1 else 0,[['T',0x1122334455667788],['M',1,909,1001]])]
  if failure is not None and failure>1:script.append(step(failure,231,[['T',0x8877665544332211]]))
  add('live-cell-mutations-'+category,**options,script=script)
add('no-padding-zero-flag-no-restore',zero=True,alt=True,width=1,script=[step(0,0,[['T',0xffffffffffffffff]])])
add('final-raw-digit-mutation',width=0,script=[step(0,229,[['T',0x9988776655443322],['D',99],['B',2]])])

# Long UTF8 prefixes cross inline/word/SIMD/batch boundaries at all8 physical
# alignment requests. High-level expectations use scalar len(str), no raw helper.
def exact_prefix(length):
    result='';used=0
    motif=['a','é','四','🦀']
    while used<length:
        item=motif[len(result)%len(motif)]
        if used+len(item.encode())>length:item='a'
        result+=item;used+=len(item.encode())
    assert len(result.encode())==length
    return result
for length in (0,1,2,3,4,7,8,15,16,23,24,27,28,31,32,33,63,64,65,127,128,129,1535,1536,1537,3071,3072,3073,65535):
 prefix=exact_prefix(length)
 for alignment in range(8):
  width=min(65535,len(prefix)+4)
  add('unicode-count-all-alignments',prefix=prefix,alt=True,plus=True,digits=b'1',
      width=width,align=2,alignment=alignment)
for length in (31,32,1536,3073):
 add('alternate-disabled-ignores-prefix',prefix=exact_prefix(length),width=3,alt=False)

# Exact u16 endpoints, all align splits, failure at the final actual fill and
# zero-success whole-word restoration. RLE retains the exact65535 calls.
for align in range(4):
 for zero in (False,True):
  for last_error in (False,True):
   opts=dict(prefix='',digits=b'',width=65535,align=align,zero=zero,fill=0)
   base={'sign':1,'prefix_hex':'','digits_hex':'','tailword':(0x4a3b<<48)|(65535<<32)|(align<<29)|(ZERO if zero else 0),'data':11,'table':1,'methods':[[1,101,102],[2,201,202]],'script':[],'alignment':0,'id':'max'}
   observed=answer(base)
   cursor=0;last_char=None
   for group in observed['events']:
    if group['event']['kind']=='char':last_char=cursor+group['count']-1
    cursor+=group['count']
   assert last_char is not None
   add('maximum-width-and-last-failure',**opts,script=[step(last_char,254)] if last_error else [])

def encode_script(script):
 if not script:return '-'
 entries=[]
 for ordinal,reply,actions in script:
  terms=[]
  for action in actions:
   if action[0]=='M':terms.append('M'+','.join(format(x,'x') for x in action[1:]))
   else:terms.append(action[0]+format(action[1],'x'))
  entries.append(f'{ordinal}~{reply}~'+('/'.join(terms) or '-'))
 return ';'.join(entries)

inputs=[];expected=[]
for case in cases:
 methods=','.join(':'.join(format(x,'x') for x in row) for row in case['methods'])
 inputs.append('\t'.join([case['id'],str(case['sign']),case['prefix_hex'],case['digits_hex'],
                          format(case['tailword'],'016x'),format(case['data'],'x'),format(case['table'],'x'),
                          methods,encode_script(case['script']),str(case['alignment'])])+'\n')
 expected.append(answer(case))
input_raw=''.join(inputs).encode();expected_raw=''.join(json.dumps(x,sort_keys=True,separators=(',',':'))+'\n' for x in expected).encode()
authority_raw=(json.dumps({'schema':'integral-padding-pre-Rust-authority/1','cases':cases,'expected':expected},sort_keys=True,indent=2)+'\n').encode()
for name,raw in [('inputs.tsv',input_raw),('expected.jsonl',expected_raw),('authority.json',authority_raw)]:
 (ROOT/name).write_bytes(raw)

freeze={'schema':'integral-padding-independent-pre-source/1','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'target_sha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
 'primary':{'va':['0x15723b0','0x15728bf'],'bytes':1295,'rows':341,'body_sha256':'8999b0718558a75e048359c74e547192461d16e0b843c97cba6951d31d556aed'},
 'helpers':[{'va':['0x1572350','0x15723a4'],'bytes':84,'rows':37},{'va':['0x15796c0','0x1579c8b'],'bytes':1483,'rows':365}],
 'cases':len(cases),'distinct_complete_inputs_excluding_ID':len(seen),'families':families,
 'maximum_case_callbacks':max(x['callback_count'] for x in expected),
 'total_semantic_callback_observations':sum(x['callback_count'] for x in expected),
 'total_lossless_RLE_records':sum(len(x['events']) for x in expected),
 'source_independence':{'new_Rust_read_or_authored_by_peer':False,'repository_imports':False,'target_execution':False,'PC_register_opcode_evaluator':False,
                        'oracle':'Unicode scalar len(str), integer layout and supplied opaque callback cell transitions'},
 'protocol':'TSV id, sign_decimal, prefix_hex, digits_hex, tailword_hex16, data_hex, table_hex, methods table:char:str hex, sparse script ordinal~reply~actions;..., alignment_decimal. JSON output all numeric fields are decimal integers; argument is rawu32 for char and lowercasehex string for str. Events losslessly RLE adjacent identical full observations, callbacks still performed individually.',
 'callback_observation':'event captured before supplied cell actions; includes raw reply. Cache original data/table, reload actual live method slots on every dispatch. Final all method cells/context recorded.',
 'qualification_limits':['chosen safe Cell/proxy interface, not privateABI/pointeridentity','immutable input slices and normal callbacks; no input/code/frame mutation or faults/unwind','prefix validUTF8 and prefix/digit lengths <=isizeMAX','write_char arguments are rawu32, no physical rendering or downstreamUTF8writer claim','no originalcompiler/machinebyte/fullcomponentgate claim'],
 'files':{n:{'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()} for n,raw in [('freeze.py',Path(__file__).read_bytes()),('inputs.tsv',input_raw),('expected.jsonl',expected_raw),('authority.json',authority_raw)]}}
path=ROOT/'FREEZE.json';path.write_text(json.dumps(freeze,sort_keys=True,indent=2)+'\n')
print(json.dumps({'freeze_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'cases':len(cases),'families':families,'max_callbacks':freeze['maximum_case_callbacks'],'total_callbacks':freeze['total_semantic_callback_observations'],'RLE_records':freeze['total_lossless_RLE_records'],'input_sha256':hashlib.sha256(input_raw).hexdigest(),'expected_sha256':hashlib.sha256(expected_raw).hexdigest()},sort_keys=True))
