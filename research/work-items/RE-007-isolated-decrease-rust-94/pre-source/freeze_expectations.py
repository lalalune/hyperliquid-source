"""Independent integer decision oracle; written before new decrease Rust.

No native instruction evaluation. All account/table/price inputs are synthetic
conditional normal-path values; none is a chain-state admission witness.
"""
from pathlib import Path
import json,hashlib
HERE=Path(__file__).resolve().parent
MIN=-(1<<63);MAX=(1<<63)-1;U32=(1<<32)-1
TABLES={'three':[(0,50),(1000,20),(10**6,10)],'single17':[(0,17)],'two25':[(0,25),(10**15,1)],'single0':[(0,0)]}
def clip(value):return max(MIN,min(MAX,value))
def cap(table,p,s):
    product=p*abs(s);eligible=[(k,l) for k,l in table if product>MAX-1 or k<=product];return max(eligible)[1]
def initial(table,n):
    prior=0;selected=None;prev=table[0][1]
    for i,(key,lev) in enumerate(table):
        if i:prior+=key//(2*lev)-key//(2*prev)
        if key<=n:selected=(lev,prior)
        prev=lev
    lev,prior=selected;return max(0,n//(2*lev)-prior)
def normal(r):
    return r['custom_id']>=50 and r['position_table']==r['custom_id'] and r['mode_word']==1 and not r['cross'] and r['size']!=0 and 0<r['requested']<r['old']<=U32 and 0<=r['price']<=MAX and MIN<=r['price']*r['size']<=MAX and abs(r['price']*r['size'])//r['requested']<=MAX

def value(r,wrong=None):
    table=r['tiers'];new=r['requested'];p=r['price'];s=r['size'];m=r['margin']
    if new>table[0][1]:return ['Reject',0x43,None]
    c=cap(table,p,s)
    if wrong!='skip-cap' and new>c:return ['Reject',0x50,c]
    if wrong=='price-zero-in-shadow':p=0
    if wrong=='absolute-size-in-shadow':s=min(abs(s),MAX)
    if wrong=='zero-margin-in-shadow':m=0
    n=p*s
    req=initial(table,abs(n)) if wrong=='tiered-initial-instead-mode1' else abs(n)//(r['old'] if wrong=='old-divisor-in-shadow' else new)
    surplus=clip(clip(m+n)-req)
    if surplus<=0 if wrong=='reject-zero-surplus' else surplus<0:return ['Reject',0x46 if wrong=='wrong-cross-refusal-tag' else 0x47,None]
    return ['EnterCommit',None,None]
CONTROLS=['old-divisor-in-shadow','tiered-initial-instead-mode1','absolute-size-in-shadow','reject-zero-surplus','zero-margin-in-shadow','price-zero-in-shadow','skip-cap','wrong-cross-refusal-tag']

def cases():
    found={}
    def add(label,p,s,new,m,old=None):
        old=old if old is not None else new+1
        r={'table_name':label,'tiers':TABLES[label],'custom_id':50,'position_table':50,'mode_word':1,'cross':False,'price':p,'size':s,'requested':new,'old':old,'margin':m}
        if not normal(r):return
        found[json.dumps(r,sort_keys=True)]=r
    def boundaries(label,p,s,new):
        n=p*s
        if not MIN<=n<=MAX or abs(n)//new>MAX:return
        threshold=abs(n)//new-n
        for m in [threshold-1,threshold,threshold+1]:
            if MIN<=m<=MAX:add(label,p,s,new,m)
        if (p,s) in [(0,1),(1,1),(1,-1),(1,MIN)]:
            for m in [MIN,MIN+1,MAX-1,MAX]:add(label,p,s,new,m)
    for p,s in [(0,1),(1,1),(1,-1),(999,1),(1000,-1),(10**6,1),(1,MIN),(MAX,1),(MAX,-1),(7,-143)]:
        for new in [1,2,10,11,20,50,51]:boundaries('three',p,s,new)
    for p,s in [(1,1),(1000,-1),(7,-143)]:
        for new in [1,17,18]:boundaries('single17',p,s,new)
    for s in [1,-1]:
        for new in [1,2,25,26]:boundaries('two25',10**15,s,new)
    add('single0',1,1,1,0)
    add('three',0,1,U32-1,0,old=U32)
    # Explicit two-stage saturation witnesses and the price/clone boundary.
    add('three',1,-1,2,MIN);add('three',1,-1,1,MIN+1)
    return [dict(r,id=i) for i,r in enumerate(found.values())]

def freeze():
    rows=cases();assert all(normal(r) for r in rows);expect=[{'id':r['id'],'value':value(r)} for r in rows];controls=[]
    for name in CONTROLS:
        changed=[r for r in rows if value(r,name)!=value(r)];branch=[r for r in changed if (value(r,name)[0]=='EnterCommit')!=(value(r)[0]=='EnterCommit')];assert changed,name
        w=(branch or changed)[0];controls.append({'name':name,'changed_values':len(changed),'changed_commit_vs_refusal':len(branch),'class':'commit/refusal' if branch else 'refusal tag only','witness_id':w['id'],'expected':value(w),'wrong':value(w,name)})
    base=dict(rows[0]);base.pop('id');policies=[]
    for label,change in [('Builtin',{'custom_id':49}),('TableChange',{'position_table':51}),('NoncanonicalIsolated',{'mode_word':256}),('NotDecrease',{'old':base['requested']}),('ZeroRequested',{'requested':0}),('Inactive',{'size':0}),('UnsignedHighPrice',{'price':1<<63}),('SignedProductOverflow',{'price':MAX,'size':2}),('UnsignedRequirementTooLarge',{'price':1,'size':MIN,'requested':1,'old':2})]:policies.append({'reason':label,'input':dict(base,**change),'class':'outside qualified normal path; no native refusal projection'})
    for name,obj in [('inputs.json',rows),('expected.json',expect),('controls.json',controls),('excluded-domain.json',policies)]:
        (HERE/name).write_text(json.dumps(obj,sort_keys=True,separators=(',',':'))+'\n')
    wanted={c['witness_id'] for c in controls};samples=[]
    for r in rows:
        if r['id'] not in wanted:continue
        n=r['price']*r['size'];req=abs(n)//r['requested'];samples.append(dict(r,signed_notional=n,margin_after=clip(r['margin']+n),requirement=req,surplus=clip(clip(r['margin']+n)-req),expected=value(r)))
    (HERE/'samples.json').write_text(json.dumps(samples,indent=2)+'\n')
    names=['freeze_expectations.py','NATIVE-FREEZE.json','NATIVE.md','inputs.json','expected.json','controls.json','excluded-domain.json','samples.json'];doc={'status':'normal-path decisions frozen before new decrease Rust','target_sha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f','cases':len(rows),'excluded_domain_examples':len(policies),'controls':len(controls),'whole_action_admission_claimed':False,'EnterCommit_is_not_success':True,'files':{n:hashlib.sha256((HERE/n).read_bytes()).hexdigest() for n in names},'new_Rust_written':False,'captured_execution':False,'instruction_interpreter':False};raw=(json.dumps(doc,sort_keys=True,indent=2)+'\n').encode();(HERE/'PRE-RUST-FREEZE.json').write_bytes(raw)
    counts={str(tag):sum(x['value'][1]==tag for x in expect) for tag in [None,0x43,0x50,0x47]}
    print('cases',len(rows),'outcomes',counts,'freeze',hashlib.sha256(raw).hexdigest());print('controls',controls)
if __name__=='__main__':freeze()
