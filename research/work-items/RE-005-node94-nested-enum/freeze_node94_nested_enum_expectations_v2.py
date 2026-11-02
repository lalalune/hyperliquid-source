"""Construct actual255eba0 authorities from supplied fields, not a byte parser.

The child constructors are credited, independently authored field arithmetic
from1779/1853, extracted without their case-generation loops. This source and
proof are frozen before a new whole-caller protocol checker exists. No target
execution, instruction evaluator or checker/model import is involved.
"""
from pathlib import Path
import collections,datetime,gzip,hashlib,importlib.util,io,itertools,json,sys
B=Path(__file__).resolve().parent

def authority(name):
    spec=importlib.util.spec_from_file_location(name,B/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

single=authority('node94_enum_single_authority')
two=authority('node94_enum_two_authority')
U=(1<<64)-1
rows=[];seen={};categories=collections.Counter()
encoded=two.encoded;plan=two.plan;rankkey=two.rankkey;sequence=two.sequence;cell=two.cell

def child_projection(module,*args,**kwargs):
    module.rows=[];module.seen={};module.categories=collections.Counter()
    module.construct('supplied-child-fields',*args,**kwargs)
    if len(module.rows)!=1:raise ValueError('Exactly one child authority')
    return module.rows[0]['expected']

def body_for(tag,counts,plans,widths,prefix,suffix,bad_counts,words):
    if tag in (0,1):
        parts=[encoded(k,w) if bad is None else bytes([bad[0]])+b'\xa5'*bad[1]
               for k,w,bad in zip(counts,widths,bad_counts)]
        return prefix+b''.join(parts[j]+b''.join(p['key']+b''.join(p['chunks'])+p['tail'] for p in plans[j])
                                for j in range(tag+1))+suffix
    if tag==2:return b''.join(w['chunk'] for w in words)+suffix
    return suffix

def word(value=0,width=None,bad=None,padding=0):
    return {'value':value,'chunk':encoded(value,width) if bad is None else bytes([bad])+b'\xa5'*padding,'bad':bad}

def construct(category,tag=0,charge=0,selector_width=None,selector_bad=None,counts=(0,0),plans=((),()),
              widths=(None,None),prefix=bytes(range(32)),suffix=b'',cut=None,
              bad_counts=(None,None),words=None):
    if not 0<=charge<=1000 or not 0<=tag<1<<32 or len(prefix)!=32:raise ValueError('Selected domain')
    words=[word(),word()] if words is None else words
    selector=encoded(tag,selector_width)
    if len(selector)>5:raise ValueError('Supplied u32 tag')
    if selector_bad is None:
        body=body_for(tag,counts,plans,widths,prefix,suffix,bad_counts,words);wire=selector+body
    else:
        wire=bytes([selector_bad[0]])+b'\xa5'*selector_bad[1]+suffix;body=b''
    data=wire if cut is None else wire[:cut]
    counter=charge+4;stores=[counter];cursor=0
    maps=[];allocations=[];releases=[];comparisons=[];movements=[]

    def finish(kind=None,needed=None,expected=None,found=None,cells=None):
        if cells is None:
            cells=[cell(0,3),cell(8,kind,1)]
            if kind==0:cells.append(cell(16,needed))
            if kind==3:cells.extend([cell(9,expected,1),cell(10,found,1)])
        projection={'charge':counter,'stores':stores[:],'consumed':cursor,'remainingHex':data[cursor:].hex(),
          'cells':cells,'maps':maps,'allocationRequests':allocations,'releaseRequests':releases,
          'comparisons':comparisons,'movements':movements}
        identity=(data,charge)
        if identity in seen:
            if seen[identity]!=projection:raise ValueError('Supplied-field authorities disagree '+category)
            return len(wire)
        seen[identity]=projection
        rows.append({'id':str(len(rows)),'category':category,
          'input':{'dataHex':data.hex(),'charge':charge,'mode':1,'limit':1000},'expected':projection})
        categories[category]+=1
        return len(wire)

    if counter>1000:return finish(2)
    if selector_bad is not None:
        if not data:return finish(0,needed=1)
        marker=selector_bad[0]
        if marker not in (253,254,255):raise ValueError('Invalid u32 metadata')
        if len(data)<=4:cursor=1
        return finish(3,expected=2,found={253:3,254:4,255:12}[marker])
    if len(data)<len(selector):
        if data:cursor=1
        return finish(0,needed=len(selector)-len(data) if data else 1)
    cursor=len(selector)
    if tag>2:
        return finish(cells=[cell(0,3),cell(8,5,1),cell(12,tag,4),
          {'offset':16,'symbol':'literal:GreetingHash@3e635f'},cell(24,12),
          {'offset':32,'symbol':'range:0..2@209410'}])
    available=len(data)-cursor
    if tag==0:
        counter+=32;stores.append(counter)
        if counter>1000:return finish(2)
        if available<32:return finish(0,needed=32-available)
        cursor+=32
        child=child_projection(single,counts[0],plans[0],charge=counter,count_width=widths[0],
           suffix=suffix,cut=len(data)-cursor,bad_count=bad_counts[0])
        counter=child['charge'];stores.extend(child['stores']);cursor+=child['consumed']
        allocations.extend(dict(x,symbol='map0') for x in child['allocationRequests'])
        releases.extend(dict(x,symbol='map0') for x in child['releaseRequests'])
        comparisons.extend(dict(x,map='map0') for x in child['comparisons'])
        movements.extend(dict(x,symbol='map0') for x in child['movements'])
        if child['cells'][0]==cell(0,18,1):
            maps.append(child['associations'])
            cells=[cell(0,0),{'offset':8,'hex':prefix.hex()}]
            cells.extend(dict(x,offset=x['offset']+32,**({'symbol':'map0'} if 'symbol' in x else {})) for x in child['cells'][1:])
        else:cells=[cell(0,3)]+[dict(x,offset=x['offset']+8) for x in child['cells']]
        return finish(cells=cells)
    if tag==1:
        child=child_projection(two,counts,plans,charge=counter,widths=widths,prefix=prefix,
                               suffix=suffix,cut=available,bad_counts=bad_counts)
        counter=child['charge'];stores.extend(child['stores']);cursor+=child['consumed']
        maps.extend(child['maps']);allocations.extend(child['allocationRequests']);releases.extend(child['releaseRequests'])
        comparisons.extend(child['comparisons']);movements.extend(child['movements'])
        cells=[cell(0,1 if child['cells'][0]==cell(0,0) else 3)]+child['cells'][1:]
        return finish(cells=cells)
    for supplied in words:
        counter+=8;stores.append(counter)
        if counter>1000:return finish(2)
        available=len(data)-cursor
        if not available:return finish(0,needed=1)
        if supplied['bad'] is not None:
            if available<=8:cursor+=1
            return finish(3,expected=5,found=4 if supplied['bad']==254 else 12)
        width=len(supplied['chunk'])
        if available<width:
            cursor+=1
            return finish(0,needed=width-available)
        cursor+=width
    counter+=2048;stores.append(counter)
    if counter<=1000:raise ValueError('Box exclusion theorem')
    return finish(2)

def run_cases():
    for c,tag in itertools.product(range(1001),range(3)):
        construct('all-entry-counters',tag,charge=c)
    for tag,w in itertools.product(range(3),[1,3,5]):
        construct('valid-selector-widths',tag,selector_width=w)
        for cut in range(w):construct('short-selector-extensions',tag,selector_width=w,cut=cut)
    for marker,padding,c in itertools.product([253,254,255],range(8),[0,996,997,1000]):
        construct('bad-u32-selector-and-charge-order',charge=c,selector_bad=(marker,padding))
        construct('bad-u32-selector-empty-cut',charge=c,selector_bad=(marker,padding),cut=0)
    for tag in list(range(3,251))+[251,255,256,65535,65536,(1<<32)-1]+[1<<b for b in range(8,32)]:
        for width in [None,5]:construct('unknown-tag-active-diagnostic',tag,selector_width=width,suffix=b'\xfe'*9)
    for tag in [0,1]:
        for m,n in itertools.product(range(13),range(13) if tag else [0]):
            bounds=[0,1,1000,996,964,956-96*m,948-85*m-96*n]
            cs={x+d for x in bounds for d in [-1,0,1] if 0<=x+d<=1000}
            for c,wide,duplicate in itertools.product(sorted(cs),[False,True],[False,True]):
                ps=(sequence(m,wide,duplicate) if m<=9 else [],sequence(n,wide,duplicate,19) if n<=9 else [])
                construct('actual-joint-admission-boundaries',tag,charge=c,counts=(m,n),plans=ps,
                          selector_width=5 if wide else 1,widths=(9,9) if wide else (None,None))
        for m,n,wide,dup in itertools.product([0,1,2,9],[0,1,2,8] if tag else [0],[False,True],[False,True]):
            if 44+96*m>1000 or (tag and 52+85*m+96*n>1000):continue
            ps=(sequence(m,wide,dup),sequence(n,wide,dup,19))
            kw={'tag':tag,'counts':(m,n),'plans':ps,'widths':(9,9) if wide else (None,None),
                'selector_width':5 if wide else 1}
            length=construct('full-and-suffix-witness',**kw,suffix=b'\xfe\xff'+b'\xa5'*9)-11
            for cut in range(length):construct('every-selected-wire-cut',**kw,cut=cut)
        for position,bit in itertools.product(range(32),range(8)):
            p=bytearray(32);p[position]=1<<bit
            construct('actual-fixed32-all-bits',tag,prefix=bytes(p))
        for m,n in [(1,9),(2,8),(9,1),(10,1),(0,9)]:
            if not tag and n:continue
            for c in [0,1,9,10,11,12,13,21,22,23,24,25,86,87,88,89]:
                construct('fresh-child-eleven-exclusion-and-ten-bound',tag,charge=c,counts=(m,n),
                   plans=(sequence(m),sequence(n,seed=19)))
        for which,c,k in itertools.product(range(tag+1),[0,1,7,8,11,12,13,15,16,19,20,21,23,24,25,947,948,949,955,956,957],
                                          [U//96-1,U//96,U//96+1,U]):
            counts=[0,0];counts[which]=k
            construct('multiplication-versus-addition-overflow',tag,charge=c,counts=tuple(counts))
        for which,width,cut in itertools.product(range(tag+1),[3,5,9],range(9)):
            if cut>=width:continue
            widths=[None,None];widths[which]=width
            construct('short-map-count',tag,widths=tuple(widths),cut=1+32+which+cut)
        for which,marker,padding in itertools.product(range(tag+1),[254,255],range(11)):
            bad=[None,None];bad[which]=(marker,padding)
            construct('bad-map-count-fast-and-slow',tag,bad_counts=tuple(bad),cut=1+32+which+1+padding)
        for which,done,index,marker,padding in itertools.product(range(tag+1),[0,1,7],range(8),[254,255],range(11)):
            ps=[[],[]];bad=plan(rankkey(100),values=(0,)*8)
            bad['chunks']=[b'\x00']*index+[bytes([marker])+b'\xa5'*padding]
            bad['tail']=b'';bad['bad']=(index,marker)
            ps[which]=sequence(done,seed=17*which)+[bad]
            if which:ps[0]=sequence(1)
            counts=tuple(map(len,ps));length=1+32+sum(1+sum(20+sum(map(len,p['chunks']))+len(p['tail']) for p in ps[j]) for j in range(which+1))
            construct('ordered-child-error-cleanup',tag,counts=counts,plans=tuple(ps),cut=length)
            construct('cut-immediately-before-invalid-value',tag,counts=counts,plans=tuple(ps),cut=length-padding-1)
        histories=[r for n in range(4) for r in itertools.product(range(2),repeat=n)]
        for left,right in itertools.product(histories,histories if tag else [()]):
            ps=([plan(rankkey(k),i) for i,k in enumerate(left)], [plan(rankkey(k),i+17) for i,k in enumerate(right)])
            construct('separate-map-duplicate-histories',tag,counts=tuple(map(len,ps)),plans=ps)
        for which,ranks in itertools.product(range(tag+1),itertools.permutations(range(4))):
            ps=[[],[]];ps[which]=[plan(rankkey(k),i) for i,k in enumerate(ranks)]
            construct('key-insertion-orders',tag,counts=tuple(map(len,ps)),plans=ps)
        for which,(a,b) in itertools.product(range(tag+1),itertools.combinations(range(20),2)):
            ka=bytearray(20);kb=bytearray(20);ka[a]=1;kb[b]=2
            ps=[[],[]];ps[which]=[plan(bytes(ka),0),plan(bytes(kb),1),plan(bytes(ka),2)]
            construct('cross-position-map-key-order',tag,counts=tuple(map(len,ps)),plans=ps)
        for which,index,value in itertools.product(range(tag+1),range(8),[0,1,250,251,65535,65536,(1<<32)-1,1<<32,U]+[1<<b for b in range(64)]):
            values=[0]*8;values[index]=value;ps=[[],[]];ps[which]=[plan(rankkey(3),values=values)]
            construct('actual-map-word-preservation',tag,counts=tuple(map(len,ps)),plans=ps)
        for which,last in itertools.product(range(tag+1),range(256)):
            ps=[[],[]];ps[which]=[plan(rankkey(3),last=0),plan(rankkey(3),index=17,last=last)]
            construct('raw-tail-last-value-wins',tag,counts=tuple(map(len,ps)),plans=ps,suffix=b'\xfe'*9)
    # Pre-checker V2 expands high-bit key order; V1 remains preserved.
    for tag in [0,1]:
        for which,position,bit in itertools.product(range(tag+1),range(20),range(8)):
            key=bytearray(20);key[position]=1<<bit
            ps=[[],[]];ps[which]=[plan(bytes(key),0),plan(bytes(20),1),plan(bytes(key),2)]
            construct('key-all-bits-and-unsigned-order',tag,counts=tuple(map(len,ps)),plans=ps)
    for width1,width2,c in itertools.product([1,3,5,9],[1,3,5,9],[0,979,980,981,988,989,996]):
        supplied=[word(1,width1),word(250,width2)]
        for cut in range(1+width1+width2+1):
            construct('tag2-leading-scalar-cuts-and-budget',2,charge=c,words=supplied,cut=cut)
        for padding in [0,1,2047,2048,4096]:
            construct('tag2-array-unread-and-box-unreachable',2,charge=c,words=supplied,suffix=b'\xa5'*padding)
    for which,marker,padding,c in itertools.product(range(2),[254,255],range(11),[0,980,981,988,989,996]):
        supplied=[word(),word()];supplied[which]=word(bad=marker,padding=padding)
        construct('tag2-expected5-error-and-no-box',2,charge=c,words=supplied,cut=1+which+1+padding)

if __name__=='__main__':
    if (B/'check_node94_nested_enum_relation.py').exists():raise ValueError('New checker already exists')
    stem=sys.argv[1];out=B/(stem+'.jsonl.gz');meta_path=B/(stem+'.json')
    if out.exists() or meta_path.exists():raise ValueError('Preserve frozen authorities')
    run_cases()
    payload=('\n'.join(json.dumps(r,sort_keys=True,separators=(',',':')) for r in rows)+'\n').encode()
    buf=io.BytesIO()
    with gzip.GzipFile(filename='',mode='wb',fileobj=buf,mtime=0,compresslevel=9) as z:z.write(payload)
    raw=buf.getvalue()
    sources=['freeze_node94_nested_enum_expectations_v2.py','freeze_node94_nested_enum_expectations.py','node94_enum_single_authority.py','node94_enum_two_authority.py']
    hashes={s:hashlib.sha256((B/s).read_bytes()).hexdigest() for s in sources}
    meta={'state':'actual-nested-enum-supplied-field-expectations-frozen-before-new-checker',
      'frozenAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
      'base':'e5c9b6436876b2a4a39daef813171f9879317699',
      'targetSha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
      'sourceSha256':hashes,'manualProofSha256':hashlib.sha256((B/'node94-nested-enum-proof-draft.md').read_bytes()).hexdigest(),
      'cases':len(rows),'categories':dict(sorted(categories.items())),
      'uncompressedBytes':len(payload),'compressedBytes':len(raw),'uncompressedSha256':hashlib.sha256(payload).hexdigest(),
      'compressedSha256':hashlib.sha256(raw).hexdigest(),'gzipOsByte':raw[9],
      'checkerCreated':False,'capturedExecution':False,'instructionEvaluation':False,'nativeEquivalence':False,
      'scope':'Actual255eba0 selected mode1/L1000/C0..1000 whole-caller conditional field/charge/error/ownership mathematics. Credited generic schema and child primitives; no native ABI/CPU execution/whole greeting/component gate.'}
    out.write_bytes(raw);meta_path.write_text(json.dumps(meta,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps(meta,sort_keys=True))
