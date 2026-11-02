"""Independent pre-Rust logical decision freeze. No target/interpreter execution."""
from pathlib import Path
import hashlib,json,base64,struct
HERE=Path(__file__).resolve().parent
U64=(1<<64)-1;U32=(1<<32)-1;LIMIT=(1<<63)-2
TABLES=[[(0,0)],[(0,17)],[(0,25),(10**15,1)],[(0,50),(1000,20),(10**6,10)]]
SCALARS=[(0,1),(1,-1),(999,1),(1000,-1),(10**6,1),(1<<63,2),(1,-(1<<63)),(7,-143),(1<<32,1)]

def position_cap(table,p,s):
    wide=p*abs(s)
    entries=[(key,value) for key,value in table if wide>LIMIT or key<=wide]
    return max(entries)[1]

def native(r,mutant=None):
    # Four output fields are logical, never a native status-memory ABI.
    # Fields absent on native branches are represented as absent, not raw zeros.
    table=r['tiers'];level=r['requested_u32'];mode=r['mode_word_u32']
    if mutant=='truncate-request-u8':level&=255
    if mutant=='read-mode-byte':mode&=255
    maximum=table[-1][1] if mutant=='overall-max-last-tier' else table[0][1]
    if r['cross'] and r['kind_byte']!=0 and mutant!='ignore-cross-kind':return ('Reject',0x44,None)
    if mutant!='skip-global-maximum' and (level>=maximum if mutant=='reject-max-equality' else level>maximum):return ('Reject',0x43,None)
    cap=position_cap(table,0 if mutant=='zero-price-cap-join' else r['price_u64'],r['size_i64'])
    if mutant=='cap-before-mode' and level>cap:return ('Reject',0x50,cap)
    if (mode==0)!=r['cross']:return ('Reject',0x45,None)
    if level>=cap if mutant=='reject-cap-equality' else level>cap:return ('Reject',0x50,cap)
    return ('EnterCommit',None,None)

MUTANTS=['truncate-request-u8','reject-max-equality','reject-cap-equality','read-mode-byte','cap-before-mode','overall-max-last-tier','zero-price-cap-join','ignore-cross-kind','skip-global-maximum']

def qualified_cases():
    unique={}
    def add(table,p,s,level,old=0,mode=0,cross=True,kind=0):
        r={'custom_id_u32':50,'position_table_u32':50,'tiers':table,'price_u64':p,'size_i64':s,'requested_u32':level,'old_leverage_u32':old,'mode_word_u32':mode,'cross':cross,'kind_byte':kind}
        assert s!=0 and level>=old and 0<=level<=U32
        key=json.dumps(r,sort_keys=True);unique[key]=r
    for table in TABLES:
        maximum=table[0][1]
        for p,s in SCALARS:
            cap=position_cap(table,p,s)
            for level in sorted({0,1,max(0,cap-1),cap,cap+1,max(0,maximum-1),maximum,maximum+1,255,256,U32}):add(table,p,s,level)
            add(table,p,s,cap,old=cap);add(table,p,s,U32,old=U32)
        # Mode/kind matrix at below/at/above cap, preserving global ordering.
        p,s=10**6,1;cap=position_cap(table,p,s)
        for level in sorted({0,cap,cap+1,maximum,maximum+1}):
            for mode,cross,kind in [(0,False,0),(1,False,0),(2,False,0),(256,False,0),(256,True,0),(U32,False,0),(1,True,0),(0,True,1),(1,True,1),(1,False,1),(0,True,255)]:add(table,p,s,level,mode=mode,cross=cross,kind=kind)
    out=[]
    for r in unique.values():r=dict(r,id=len(out));r['expected']=native(r);out.append(r)
    return out

def policy_cases():
    base=dict(custom_id_u32=50,position_table_u32=50,tiers=TABLES[-1],price_u64=1000,size_i64=1,requested_u32=20,old_leverage_u32=10,mode_word_u32=0,cross=True,kind_byte=0)
    return [dict(base,**changed,chosen_policy=label) for changed,label in [({'custom_id_u32':49},'OutsideCustomId'),({'position_table_u32':51},'OutsideSameTable'),({'size_i64':0},'OutsideActivePosition'),({'old_leverage_u32':21},'OutsideIncrease')]]

def freeze():
    rows=qualified_cases();policy=policy_cases();controls=[]
    for name in MUTANTS:
        changed=[r for r in rows if native(r,name)!=native(r)]
        commit_change=[r for r in changed if (native(r,name)[0]=='EnterCommit')!=(native(r)[0]=='EnterCommit')]
        assert changed,name
        witness=(commit_change or changed)[0]
        controls.append({'name':name,'different_decision_cases':len(changed),'different_commit_vs_refusal_cases':len(commit_change),'class':'commit/refusal distinguishing' if commit_change else 'refusal tag/detail distinguishing only','witness_id':witness['id'],'expected':native(witness),'wrong':native(witness,name)})
    inputs=[];expected=[]
    for row in rows:
        r=dict(row);expected.append({'id':r['id'],'decision':r.pop('expected')});inputs.append(r)
    for name,obj in [('inputs.json',inputs),('expected.json',expected),('planned-controls.json',controls),('policy-cases.json',policy)]:
        (HERE/name).write_text(json.dumps(obj,sort_keys=True,separators=(',',':'))+'\n')
    # A small nonrepeating review sample; full expected outputs remain separate.
    ids={0,1}
    ids.update(c['witness_id'] for c in controls)
    ids.update(r['id'] for r in rows if r['old_leverage_u32']==U32)
    (HERE/'samples.json').write_text(json.dumps([r for r in rows if r['id'] in ids],indent=2)+'\n')
    names=['freeze_decisions.py','inputs.json','expected.json','planned-controls.json','policy-cases.json','samples.json','NATIVE.md','NATIVE-FREEZE.json']
    frozen={'status':'qualified custom-table gate decisions frozen before new Rust','target_sha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f','case_count':len(rows),'chosen_policy_count':len(policy),'planned_control_count':len(controls),'EnterCommit_is_not_success':True,'external_table_and_lookup_provenance_open':True,'source_algorithm':'logical first tier maximum, arbitrary precision full product/set membership, independent ordered gate list','files':{n:hashlib.sha256((HERE/n).read_bytes()).hexdigest() for n in names},'new_Rust_written':False,'captured_execution':False,'instruction_interpreter':False}
    raw=(json.dumps(frozen,sort_keys=True,indent=2)+'\n').encode();(HERE/'PRE-RUST-FREEZE.json').write_bytes(raw)
    print('cases',len(rows),'policy',len(policy),'freeze',hashlib.sha256(raw).hexdigest());print('decisions',dict((str(x),sum(r['expected'][1]==x for r in rows)) for x in [None,0x43,0x44,0x45,0x50]));print('controls',controls)
if __name__=='__main__':freeze()
