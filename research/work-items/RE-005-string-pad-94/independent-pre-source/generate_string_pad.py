#!/usr/bin/env python3
"""Pre-Rust high-level Unicode/segment authority; no native instruction evaluator."""
from pathlib import Path
import copy, hashlib, json

OUT=Path(__file__).parent
U=1<<27;P=1<<28;MASK=(1<<21)-1
PROOF=OUT/'string-pad-1081-PROOF.md'
sha=lambda raw:hashlib.sha256(raw).hexdigest()
canonical=lambda value:json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)
cases=[];seen={}

def word(flags=U,width=0,precision=0,align=0,fill=32,other=0):
    assert 0<=width<=65535 and 0<=precision<=65535 and 0<=align<4 and 0<=fill<=MASK
    return ((flags|other|(align<<29)|fill)&0xffffffff)|(width<<32)|(precision<<48)

def add(text='',header=None,data=11,table=1,methods=None,script=None,alignment=0,category='base'):
    assert isinstance(text,str) and text.encode('utf8').decode('utf8')==text and alignment in range(8)
    if header is None:header=word()
    if methods is None:methods=[[1,101,102],[2,201,202]]
    if script is None:script=[]
    c={'text':text,'tailword':header,'data':data,'table':table,'methods':copy.deepcopy(methods),
       'script':copy.deepcopy(sorted(script)),'text_alignment':alignment}
    assert len({x[0]for x in c['methods']})==len(c['methods']) and table in {x[0]for x in c['methods']}
    assert len({x[0]for x in c['script']})==len(c['script'])
    for ordinal,reply,actions in c['script']:
        assert ordinal>=0 and 0<=reply<=255
        for action in actions:
            assert action[0] in ('T','D','B','M')
            assert all(isinstance(v,int)and 0<=v<(1<<64)for v in action[1:])
            if action[0] in ('B','M'):assert action[1]in{x[0]for x in c['methods']}
    key=canonical(c)
    if key in seen:
        old=cases[seen[key]]
        if category not in old['categories']:old['categories'].append(category)
        return
    seen[key]=len(cases);c['id']=f's{len(cases):05d}';c['categories']=[category];cases.append(c)

def selected_and_layout(c):
    h=c['tailword']&0xffffffff;width=(c['tailword']>>32)&65535;precision=c['tailword']>>48
    if not h&(U|P):return [('str',c['text'].encode().hex(),1)],False
    selected=c['text'][:precision]if h&P else c['text']
    count=len(selected)
    if count>=width:return [('str',selected.encode().hex(),1)],False
    difference=width-count;before=[0,difference,difference//2,0][(h>>29)&3]
    segments=[]
    if before:segments.append(('char',h&MASK,before))
    segments.append(('str',selected.encode().hex(),1))
    if difference-before:segments.append(('char',h&MASK,difference-before))
    return segments,True

def expected(c):
    segments,padded=selected_and_layout(c)
    methods={row[0]:row[1:]for row in c['methods']}
    script={row[0]:(row[1],row[2])for row in c['script']}
    context={'data':c['data'],'table':c['table'],'tailword':c['tailword']}
    cached_data,cached_table=c['data'],c['table']
    ordinal=0;events=[];status=0
    for kind,argument,total in segments:
        remaining=total
        while remaining:
            if ordinal in script:reply,actions=script[ordinal];run=1
            else:
                reply,actions=0,[]
                next_action=min((key for key in script if key>ordinal),default=ordinal+remaining)
                run=min(remaining,next_action-ordinal)
            event={'kind':kind,'argument':argument,'data':cached_data,'table':cached_table,
                   'method':methods[cached_table][0 if kind=='char' else 1],'reply':reply,
                   'context_data':context['data'],'context_table':context['table'],'context_tailword':context['tailword']}
            if events and events[-1]['event']==event:events[-1]['count']+=run
            else:events.append({'count':run,'event':event})
            for action in actions:
                if action[0]=='T':context['tailword']=action[1]
                elif action[0]=='D':context['data']=action[1]
                elif action[0]=='B':context['table']=action[1]
                else:methods[action[1]]=action[2:]
            ordinal+=run;remaining-=run
            if reply:
                status=1 if padded else reply
                return {'id':c['id'],'callback_count':ordinal,'events':events,'raw_status':status,
                        'final_data':context['data'],'final_table':context['table'],'final_tailword':context['tailword'],
                        'final_methods':[[key,*methods[key]]for key in sorted(methods)],'text_alignment':c['text_alignment']}
    return {'id':c['id'],'callback_count':ordinal,'events':events,'raw_status':status,
            'final_data':context['data'],'final_table':context['table'],'final_tailword':context['tailword'],
            'final_methods':[[key,*methods[key]]for key in sorted(methods)],'text_alignment':c['text_alignment']}

texts=['','A','AB','ABC','\0\0','é','€','🦀','Aé€🦀Z','e\u0301','👩\u200d💻','\ufeffB\0',
       '\t\r\n ','A'*31,'A'*32,'A'*33,'\x7f\u0080\u07ff\u0800\ud7ff\ue000\uffff\U00010000\U0010ffff']
# Raw option/header combinations, independently selected Unicode precision boundaries.
for index,text in enumerate(texts):
    length=len(text)
    for flags in [0,U,P,U|P]:
        for precision in sorted({0,1,max(0,length-1),length,length+1,65535}):
            count=len(text[:precision])if flags&P else length
            for width in sorted({0,max(0,count-1),count,count+1,count+2,count+3,count+7}):
                for align in range(4):
                    fill=[0,32,0xd800,MASK][(index+align+precision+width)%4]
                    ignored=[0,0x87e00000][(index+precision+width)&1] # outside fill/options/alignment
                    add(text,word(flags,width,precision,align,fill,ignored),alignment=(index+width+align)%8,category='option-precision-width-matrix')

# Every short/long count byte boundary and all requested input pointer alignments.
for byte_length in range(66):
    for unit in ['A','é','€','🦀']:
        unit_bytes=len(unit.encode());text=unit*(byte_length//unit_bytes)+'Z'*(byte_length%unit_bytes)
        assert len(text.encode())==byte_length
        for alignment in range(8):
            add(text,word(U,len(text)+3,65535,alignment%4,0x1fffff),alignment=alignment,category='byte-boundary-count-alignment')
            for precision in sorted({0,1,max(0,len(text)-1),len(text),len(text)+1}):
                add(text,word(P,len(text[:precision])+2,precision,(alignment+1)%4,0x10ffff),alignment=alignment,category='byte-boundary-scalar-truncation')

# Sparse failure points distinguish raw tail returns from every padded failure.
for text in ['', 'é🦀Z','e\u0301','A'*32]:
    for flags in [0,U,P,U|P]:
        for align in range(4):
            for width in [0,1,len(text)+3]:
                h=word(flags,width,1,align,0xd800)
                dummy={'text':text,'tailword':h};segments,padded=selected_and_layout(dummy)
                count=sum(x[2]for x in segments)
                boundaries={0,count-1,count}
                position=0
                for kind,arg,n in segments:boundaries.update({position,position+n-1});position+=n
                for ordinal in sorted(boundaries):
                    for reply in [1,2,127,128,255]:
                        add(text,h,script=[[ordinal,reply,[]]],category='raw-versus-canonical-failure-boundaries')

actions=[['T',(1<<64)-1],['D',99],['B',2],['M',1,31,32],['M',2,0x1000000000000001,0xffffffffffffffff]]
for text in ['', 'Aé€🦀Z','A'*31,'é'*16,'A'*33]:
    for flags in [0,U,P,U|P]:
        for align in range(4):
            h=word(flags,len(text)+6,2,align,0x110000,0x80600000)
            segments,padded=selected_and_layout({'text':text,'tailword':h});count=sum(s[2]for s in segments)
            for ordinal in sorted({0,1,2,max(0,count-2),count-1,count}):
                for reply in [0,2,255]:
                    add(text,h,script=[[ordinal,reply,actions]],alignment=7,category='ordered-live-cell-mutation')
            add(text,h,script=[[0,0,actions],[1,0,[['M',1,41,42],['D',7],['T',0]]],
                              [max(2,count-1),0,[['B',1],['M',1,51,52],['T',0x0123456789abcdef]]]],category='multi-invocation-live-method-order')

# Raw maximum-width loop endpoints, including the 16-bit wrap sentinel.
for align in range(4):
    for flags,text,precision in [(U,'',65535),(P,'🦀é',0),(U|P,'A',0)]:
        h=word(flags,65535,precision,align,MASK,0x80000000)
        add(text,h,alignment=align,category='maximum-65536-callbacks')
        for ordinal in [0,32766,32767,32768,65534,65535,65536]:
            for reply in [0,255]:add(text,h,script=[[ordinal,reply,actions]],alignment=7,category='maximum-loop-boundary-effects')

# Precision and raw-width maximum do not truncate Unicode bytes or wrap counts.
for text in ['A'*65535,'A'*65536,'A'*65534+'🦀é','🦀'*65536]:
    for flags in [U,P,U|P]:
        for precision in [0,65534,65535]:
            for alignment in [0,7]:
                add(text,word(flags,65535,precision,3,32),script=[[0,255,[]]],alignment=alignment,category='maximum-precision-and-count')

# Full opaque u64 state/method identities and all remaining raw low-byte replies.
for reply in range(256):
    for padded in [False,True]:
        add('é',word(P,3 if padded else 0,1,0,0),data=0xffffffffffffffff,table=2,
            methods=[[1,0xffffffffffffffff,0x8000000000000000],[2,0x8000000000000001,0xfffffffffffffffe]],
            script=[[0,reply,[['T',0xfeedface12345678],['D',0x8000000000000000],['B',1]]]],
            category='all-raw-replies-and-full-u64-identities')

def serialize(c):
    methods=','.join(f'{table:x}:{char:x}:{string:x}'for table,char,string in c['methods'])
    def action(a):
        return 'M'+','.join(f'{v:x}'for v in a[1:])if a[0]=='M'else a[0]+f'{a[1]:x}'
    script=';'.join(f'{ordinal}~{reply}~'+('/'.join(map(action,actions))or '-')for ordinal,reply,actions in c['script'])or '-'
    return '\t'.join([c['id'],c['text'].encode().hex(),f'{c["tailword"]:016x}',f'{c["data"]:x}',f'{c["table"]:x}',methods,script,str(c['text_alignment'])])

proof_raw=PROOF.read_bytes();assert sha(proof_raw)=='68c3d18571f27a41454e82a7c732e270a46fe2413394db4df43f6d3a7e3fe8fc'
authority={'schema':'string-pad-1081-pre-source-authority-v1','target_sha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
           'main_range':['0x1573450','0x1573889'],'main_bytes':1081,'native_rows':300,
           'normal_domain':'Immutable valid UTF8, explicit raw header/opaque writer Cells and supplied normal callbacks; rendering/private ABI excluded.',
           'native_admission_sha256':'175919e0989e668267383b26edb20b438d1ca6a9f75275be8cb3c8f38280efce',
           'data_bindings_sha256':'880beb5befe1b1a2d7e8c1bb0d8c17cb5f1a116b77865dd866afb0bd877ab232',
           'proof_sha256':sha(proof_raw),'method':'High-level Unicode selection/count and declarative callback segments; separate raw serializer; no author implementation or captured instruction evaluation.',
           'helper_credit':'Prior1439 qualified1483-byte UTF8 scalar count, same target/body hash; not new helper credit.',
           'cases':cases}
authority_raw=(canonical(authority)+'\n').encode()
input_raw=('\n'.join(map(serialize,cases))+'\n').encode()
answers=[expected(c)for c in cases]
expected_raw=('\n'.join(map(canonical,answers))+'\n').encode()
files={'string-pad-1081-authority.json':authority_raw,'string-pad-1081-input.tsv':input_raw,'string-pad-1081-expected.jsonl':expected_raw}
for name,raw in files.items():(OUT/name).write_bytes(raw)
categories=sorted({x for c in cases for x in c['categories']})
freeze={'schema':'string-pad-1081-pre-source-freeze-v1','before_new_Rust':True,'case_count':len(cases),
        'unique_raw_inputs_excluding_id':len(seen),'total_callback_observations':sum(x['callback_count']for x in answers),
        'exact_RLE_records':sum(len(x['events'])for x in answers),'maximum_case_callbacks':max(x['callback_count']for x in answers),
        'categories':categories,'raw_statuses':sorted({x['raw_status']for x in answers}),
        'files':{name:{'bytes':len(raw),'sha256':sha(raw)}for name,raw in files.items()},
        'proof_sha256':sha(proof_raw),'generator_sha256':sha(Path(__file__).read_bytes()),
        'captured_or_opcode_PC_register_evaluator':False,'new_Rust_seen_or_executed':False,
        'limits':['Finite supporting corpus, not exhaustive strings or executed target calls.','Expected plans remain external; raw input contains no selected substring/count/layout/answer.','RLE is lossless; every supplied action and callback remains an individual logical invocation.']}
assert len(cases)==len(seen)==len({c['id']for c in cases})
assert all(sum(run['count']for run in x['events'])==x['callback_count']for x in answers)
assert freeze['maximum_case_callbacks']==65536
(OUT/'string-pad-1081-FREEZE.json').write_text(json.dumps(freeze,sort_keys=True,indent=2)+'\n')
print(json.dumps(freeze,sort_keys=True))
