#!/usr/bin/env python3
"""Logical integer/state oracle for warm-resident SSTORE; no target execution."""
from pathlib import Path
import hashlib,json,random,sys
U=(1<<64)-1; LO=-(1<<63); HI=(1<<63)-1


def signed(x):return x if x<=HI else x-(1<<64)
def sat(x):return max(LO,min(HI,x))


def calculate(row,wrong_modern=False,rollback=False,always_journal=False):
    (spec,static,length,enabled,flags,original,current,new,gas,reserve,spent,refund,
     fixed,set_cost,reset,clear,sentry,restore_zero,restore_nonzero,amount)=row
    old_flags,old_current=flags,current
    journal=0
    def done(code):
        f,c,j=(old_flags,old_current,0) if rollback and code!='ok' else (flags,current,journal)
        return (code,gas,reserve,spent,refund,length,f,c,j)
    if static:return done('28')
    if length<2:return done('2c')
    length-=2
    if spec>5 and gas<=sentry:return done('25')
    if gas<fixed:return done('20')
    gas-=fixed
    if not flags&4:flags|=4;journal|=1
    before=current
    if current!=new or always_journal:journal|=2
    current=new
    modern=spec>=(7 if wrong_modern else 6)
    if not modern:cost=set_cost if before==0 and new!=0 else reset
    elif before==new or original!=before:cost=0
    else:cost=set_cost if original==0 else reset
    if gas<cost:return done('20')
    gas-=cost
    if enabled and before!=new:
        if original==before==0:
            needed=max(0,amount-reserve)
            if gas<needed:return done('20')
            gas-=needed;reserve=max(0,reserve-amount)
            spent=sat(spent+signed(amount))
        if original==new==0 and amount:
            reserve=min(U,reserve+amount);spent=sat(spent-signed(amount))
    if not modern:
        delta=clear if before!=0 and new==0 else 0
    elif before==new:
        delta=0
    elif original==before and new==0:
        delta=clear
    else:
        delta=0
        if original!=0:
            if before==0:
                if clear==LO:return done('neg')
                delta=-clear
            elif new==0:delta=clear
        if original==new:
            delta+=restore_zero if original==0 else restore_nonzero
            if not LO<=delta<=HI:return done('delta')
    if not LO<=refund+delta<=HI:return done('acc')
    refund+=delta
    return done('ok')


def main():
    rng=random.Random(11539183343)
    rows=['# spec static stack_len reserve_enabled flags original_tag current_tag new_tag gas reserve spent refund fixed set reset clear sentry restore_zero restore_nonzero amount | outcome gas reserve spent refund stack_len flags current_tag journal_mask']
    outcomes={};controls={'modern_cutoff_seven':0,'rollback_host_on_failure':0,'journal_same_value':0}
    for i in range(16000):
        spec=(0,5,6,7,255)[i%5]
        static=int(i%97==0);length=(0,1,2,3,4)[i%5] if i<3000 else 2
        enabled=i%2;flags=rng.randrange(256)
        original,current,new=[rng.randrange(7) for _ in range(3)]
        if i<10000:
            gas=rng.randrange(0,10001);reserve=rng.randrange(0,1000);spent=rng.randrange(-10000,10000);refund=rng.randrange(-10000,10000)
            fixed,set_cost,reset,clear,sentry,rz,rn,amount=100,2000,500,480,230,1900,400,800
        else:
            gas,reserve,amount=[rng.choice([0,1,99,500,1<<63,U]) for _ in range(3)]
            spent,refund,clear,rz,rn=[rng.choice([LO,-100,-1,0,1,100,HI]) for _ in range(5)]
            fixed,set_cost,reset,sentry=[rng.choice([0,1,100,U]) for _ in range(4)]
        row=(spec,static,length,enabled,flags,original,current,new,gas,reserve,spent,refund,fixed,set_cost,reset,clear,sentry,rz,rn,amount)
        out=calculate(row);outcomes[out[0]]=outcomes.get(out[0],0)+1
        for key,kw in [('modern_cutoff_seven',{'wrong_modern':True}),('rollback_host_on_failure',{'rollback':True}),('journal_same_value',{'always_journal':True})]:controls[key]+=calculate(row,**kw)!=out
        rows.append(' '.join(map(str,row))+' | '+' '.join(map(str,out)))
    data=('\n'.join(rows)+'\n').encode();path=Path(__file__).resolve().parents[3]/'src/node115-sstore-warm/tests/reference-vectors.txt'
    if '--write' in sys.argv:path.write_bytes(data)
    else:assert path.read_bytes()==data
    assert all(controls.values()),controls
    print(json.dumps({'cases':16000,'outcomes':outcomes,'controls_differing':controls,'sha256':hashlib.sha256(data).hexdigest(),'method':'Arbitrary-precision logical integer/state oracle; not native execution/emulation'},indent=2))

if __name__=='__main__':main()
