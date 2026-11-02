"""Independent integer/set oracle, written before the tier-cap Rust addition.

No target instruction evaluation. All price/size words are synthetic caller
arguments. Entries obey the existing independently reconstructed constructor.
"""
import json, struct, hashlib
from pathlib import Path
U64=(1<<64)-1
LIMIT=(1<<63)-2
TABLES=[('root-null',[]),('singleton-zero',[(0,0)]),('singleton17',[(0,17)]),('two-max-bound',[(0,25),(10**15,1)]),('three',[(0,50),(1000,20),(10**6,10)])]
PRICES=[0,1,2,3,7,999,1000,1001,(1<<31)-1,1<<32,(1<<63)-2,(1<<63)-1,1<<63,U64]
SIZES=[-(1<<63),-(1<<63)+1,-1000,-143,-2,-1,0,1,2,143,1000,(1<<63)-1]
def query(p,s):
    product=p*abs(s)
    high,low=divmod(product,1<<64)
    return {'magnitude':abs(s),'low':low,'wide_overflow':high!=0,'low_above_signed_limit':low>LIMIT,'upper_tag':2 if high or low>LIMIT else 0}
def answer(entries,p,s):
    if not entries:return 50
    # Set membership against an arbitrary precision product; no wrapped multiply.
    product=p*abs(s)
    upper=None if product>LIMIT else product
    admitted=[(k,v) for k,v in entries if upper is None or k<=upper]
    return max(admitted)[1] if admitted else 50

def wrong(entries,p,s,name):
    if not entries:return 49 if name=='default49' else 50
    if name=='positive-size-only':s=max(s,0)
    if name=='min-magnitude-zero' and s==-(1<<63):s=0
    if name=='truncate-price32':p&=(1<<32)-1
    if name=='reject-high-unsigned-price' and p>(1<<63)-1:return 50
    magnitude=s&U64 if name=='negative-cast-u64' else abs(s)
    product=p*magnitude
    high,low=divmod(product,1<<64)
    unbounded=low>LIMIT if name=='ignore-wide-overflow' else bool(high or low>LIMIT)
    if name=='unbounded-first' and unbounded:return entries[0][1]
    members=[(k,v) for k,v in entries if unbounded or (k<low if name=='exclusive-upper' else k<=low)]
    if not members:return 50
    return (min if name=='first-eligible' else max)(members)[1]
NAMES=['ignore-wide-overflow','positive-size-only','min-magnitude-zero','truncate-price32','reject-high-unsigned-price','negative-cast-u64','unbounded-first','exclusive-upper','first-eligible','default49']
def cases():
    out=[]
    for label,entries in TABLES:
        pairs={(p,s) for p in PRICES for s in SIZES}
        for boundary in [0,1,1000,10**6,10**15,LIMIT,LIMIT+1]:
            for d in [-1,0,1]:
                value=boundary+d
                if 0<=value<=U64:
                    pairs.add((value,1));pairs.add((value,-1))
        # Asymmetric factorizations straddle the same lower boundaries.
        pairs.update({(7,142),(7,143),(7,-143),(10,100),(100,10),(1000,1),(1,1000),(1<<63,2),(U64,2),(U64,-2),(2,-(1<<63))})
        for p,s in sorted(pairs):
            q=None if not entries else query(p,s)
            out.append({'id':len(out),'table':label,'entries':entries,'price_u64':p,'size_i64':s,'query':q,'cap':answer(entries,p,s)})
    return out

def emit(folder):
    folder=Path(folder);folder.mkdir(parents=True,exist_ok=True)
    rows=cases();inputs=bytearray(b'TCP1'+struct.pack('<I',len(rows)));outputs=bytearray()
    for r in rows:
        inputs+=struct.pack('<IBQq',r['id'],len(r['entries']),r['price_u64'],r['size_i64'])
        for k,v in r['entries']:inputs+=struct.pack('<QB',k,v)
        outputs+=struct.pack('<IB',r['id'],r['cap'])
    (folder/'input.bin').write_bytes(inputs);(folder/'expected.bin').write_bytes(outputs)
    # Reviewable boundary rows, not the complete generated Cartesian corpus.
    wanted={(0,0),(1,1),(1,-1),(999,1),(1000,1),(1001,1),(7,143),(7,-143),(10**6,1),(10**15,1),(LIMIT,1),(LIMIT+1,1),(1<<63,2),(U64,2),(1,-(1<<63))}
    (folder/'samples.json').write_text(json.dumps([r for r in rows if (r['price_u64'],r['size_i64']) in wanted],indent=2)+'\n')
    controls=[]
    for name in NAMES:
        witnesses=[{'id':r['id'],'expected_cap':r['cap'],'wrong_cap':wrong(r['entries'],r['price_u64'],r['size_i64'],name)} for r in rows if wrong(r['entries'],r['price_u64'],r['size_i64'],name)!=r['cap']]
        assert witnesses,name
        controls.append({'name':name,'class':'normal returned-u8 control','changed_cap_cases':len(witnesses),'witness':witnesses[0]})
    (folder/'wrong-cap-controls.json').write_text(json.dumps(controls,indent=2)+'\n')
    tags=[]
    for p,s in [(LIMIT,1),(LIMIT+1,1),(1<<63,2),(U64,2),(1,-(1<<63)),(0,-(1<<63))]:
        q=query(p,s);tags.append({'price_u64':p,'size_i64':s,**q,'finite_only_wrong_tag':0,'threshold_ge_wrong_tag':2 if p*abs(s)>=LIMIT else 0,'drop_wide_wrong_tag':2 if q['low']>LIMIT else 0})
    (folder/'query-construction.json').write_text(json.dumps({'class':'native intermediate query construction; not compiled cap-mutant denominator','cases':tags},indent=2)+'\n')
    endpoints={'class':'conditional generic helper examples; outside validated1..3-tier Rust denominator','tree':{'root_keys':[1000],'left_leaf':[0,100,200,300,400],'right_leaf':[2000,3000,4000,5000,6000],'height':1,'stable_consistent_parent_links':True},'cases':[{'upper':p,'back_leaf':'left' if p<1000 else 'right','back_edge':sum(k<=p for k in ([0,100,200,300,400] if p<1000 else [2000,3000,4000,5000,6000])),'last_key':max(k for k in [0,100,200,300,400,1000,2000,3000,4000,5000,6000] if k<=p),'requires_parent_predecessor':1000<=p<2000} for p in [0,99,100,999,1000,1001,1999,2000,6000]],'empty_leaf_case':{'keys':[100,200,300,400,500],'upper':99,'front_node':0,'back_node':0,'other_words':'not initialized/claimed'}}
    (folder/'endpoint-examples.json').write_text(json.dumps(endpoints,indent=2)+'\n')
    payloads=['oracle.py','input.bin','expected.bin','samples.json','wrong-cap-controls.json','query-construction.json','endpoint-examples.json']
    manifest={name:hashlib.sha256((folder/name).read_bytes()).hexdigest() for name in payloads}
    freeze={'status':'external expected outputs and wrong-cap/query plans frozen before new Rust','target_sha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f','native_freeze_sha256':'b67e8bfe569e5ca612d4b3c7424a3f5a9cabf35b1037101bd0f306da08d80ab1','native_proof_sha256':'3213c7c67ca1e57adeb3686f53d343b453824352841574cbf16e9f3252c93401','case_count':len(rows),'tables':TABLES,'final_cap_controls':len(controls),'payload_sha256':manifest,'captured_execution':False,'instruction_interpreter':False,'runtime_caller_admission_claimed':False,'ABI_claimed':False}
    (folder/'PRE-RUST-FREEZE.json').write_text(json.dumps(freeze,sort_keys=True,indent=2)+'\n')
    print('cases',len(rows),'freeze',hashlib.sha256((folder/'PRE-RUST-FREEZE.json').read_bytes()).hexdigest());print([(r['name'],r['changed_cap_cases'],r['witness']) for r in controls])
if __name__=='__main__':emit(Path(__file__).resolve().parent)
