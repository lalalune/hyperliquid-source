"""Construct small-limit map authorities from supplied values/field boundaries.

No arbitrary-byte parser, captured instruction evaluator, target invocation,
checker import or inferred source is used. This source precedes a new checker.
"""
from pathlib import Path
import collections,gzip,hashlib,io,itertools,json,sys
B=Path(__file__).resolve().parent
U=(1<<64)-1
rows=[];seen={};categories=collections.Counter()

def encoded(v,width=None):
    if width is None:width=1 if v<251 else 3 if v<65536 else 5 if v<1<<32 else 9
    if width==1:
        if not 0<=v<251:raise ValueError('One-byte value')
        return bytes([v])
    if width not in [3,5,9] or not 0<=v<1<<(8*(width-1)):raise ValueError('Encoded width')
    return bytes([{3:251,5:252,9:253}[width]])+v.to_bytes(width-1,'little')

def cell(offset,value,width=8):return {'offset':offset,'hex':value.to_bytes(width,'little').hex()}
def error(kind,needed=None,expected=None,found=None):
    out=[cell(0,kind,1)]
    if kind==0:out.append(cell(8,needed))
    if kind==3:out.extend([cell(1,expected,1),cell(2,found,1)])
    return out

V=[0,1,250,251,65535,65536,(1<<32)-1,1<<32,U]
def plan(key,index=0,wide=False,values=None,last=None):
    if len(key)!=20:raise ValueError('Key length')
    values=tuple(V[(index+i)%len(V)] for i in range(8)) if values is None else tuple(values)
    if len(values)!=8:raise ValueError('Eight logical words')
    last=(index*37+128)%256 if last is None else last
    return {'key':key,'values':values,'chunks':[encoded(v,9 if wide else None) for v in values],
            'tail':bytes([last]),'last':last,'bad':None}

def rankkey(rank):return rank.to_bytes(20,'big')

def construct(category,count,plans=(),charge=0,count_width=None,suffix=b'',cut=None,bad_count=None):
    plans=list(plans)
    if not 0<=charge<=U:raise ValueError('Charge domain')
    if bad_count is not None:
        marker,padding=bad_count
        prefix=bytes([marker])+b'\xa5'*padding
    else:prefix=encoded(count,count_width)
    body=b''.join(p['key']+b''.join(p['chunks'])+p['tail'] for p in plans)
    whole=prefix+body+suffix
    data=whole if cut is None else whole[:cut]
    cursor=0;counter=charge;stores=[];completed=[];comparisons=[];moves=[];allocated=False

    def finish(cells,success=False):
        nonlocal allocated
        associations=[]
        if success:
            keys=sorted({p['key'] for p in completed})
            for key in keys:
                final=next(p for p in reversed(completed) if p['key']==key)
                associations.append({'keyHex':key.hex(),'words':list(final['values']),'byte':final['last']})
        projection={'charge':counter,'stores':stores[:],'consumed':cursor,'remainingHex':data[cursor:].hex(),
          'cells':cells,'associations':associations,
          'allocationRequests':[{'symbol':'leaf0','bytes':1024}] if allocated else [],
          'releaseRequests':[{'symbol':'leaf0','bytes':1024,'flags':0}] if allocated and not success else [],
          'comparisons':comparisons[:],'movements':moves[:]}
        inp={'dataHex':data.hex(),'charge':charge,'mode':1,'limit':1000}
        identity=(data,charge)
        if identity in seen:
            if seen[identity]!=projection:raise ValueError('Constructive authorities disagree')
            return
        seen[identity]=projection
        rows.append({'id':str(len(rows)),'category':category,'input':inp,'expected':projection})
        categories[category]+=1

    # Constructed count scalar: charge before any availability or marker test.
    if counter>U-8:return finish(error(2))
    counter+=8;stores.append(counter)
    if counter>1000:return finish(error(2))
    if bad_count is not None:
        marker,_=bad_count
        if not data:return finish(error(0,needed=1))
        fast=len(data)>8
        if not fast:cursor=1
        return finish(error(3,expected=2 if fast else 3,found=4 if marker==254 else 12))
    if len(data)<len(prefix):
        if data:cursor=1
        return finish(error(0,needed=len(prefix)-len(data) if data else 1))
    cursor=len(prefix)
    reservation=96*count
    if reservation>U or counter+reservation>U:return finish(error(2))
    counter+=reservation;stores.append(counter)
    if counter>1000:return finish(error(2))
    if count>10:raise ValueError('Admission proof failed')
    if len(plans)!=count:raise ValueError('Known admitted rows required')
    admitted=counter
    for j,p in enumerate(plans):
        # This arithmetic assertion is a theorem check, never a CPU interpreter.
        if counter!=admitted-11*j or counter<96:raise ValueError('Refund invariant')
        counter-=96;stores.append(counter)
        counter+=20;stores.append(counter)
        if len(data)-cursor<20:return finish(error(0,needed=20-(len(data)-cursor)))
        cursor+=20
        for group in range(2):
            counter+=32;stores.append(counter)
            if counter>admitted:raise ValueError('Admitted-stage budget invariant')
            for i in range(group*4,(group+1)*4):
                available=len(data)-cursor
                if p['bad'] is not None and i==p['bad'][0]:
                    if not available:return finish(error(0,needed=1))
                    marker=p['bad'][1];fast=available>8
                    if not fast:cursor+=1
                    return finish(error(3,expected=2 if fast else 3,found=4 if marker==254 else 12))
                width=len(p['chunks'][i])
                if available<width:
                    if available:cursor+=1
                    return finish(error(0,needed=width-available if available else 1))
                cursor+=width
        counter+=1;stores.append(counter)
        if counter>admitted:raise ValueError('Final-byte budget invariant')
        if cursor==len(data):return finish(error(0,needed=1))
        cursor+=1
        # Derive insertion rank and search/move requests from a sorted prefix set.
        before=sorted({x['key'] for x in completed});key=p['key']
        candidates=[k for k in before if k<key]
        upper=[k for k in before if k>=key]
        if upper:candidates.append(upper[0])
        comparisons.extend({'leftKeyHex':key.hex(),'rightKeyHex':k.hex(),'bytes':20} for k in candidates)
        if key not in before:
            if not before:allocated=True
            else:
                index=sum(k<key for k in before);moved=len(before)-index
                if moved:
                    moves.extend([
                      {'symbol':'leaf0','sourceOffset':800+20*index,'destinationOffset':800+20*(index+1),'bytes':20*moved},
                      {'symbol':'leaf0','sourceOffset':8+72*index,'destinationOffset':8+72*(index+1),'bytes':72*moved}])
        completed.append(p)
    if counter!=admitted-11*count:raise ValueError('Final accounting')
    cells=[cell(0,18,1),{'offset':8,'symbol':'leaf0'} if allocated else cell(8,0)]
    if allocated:cells.append(cell(16,0))
    cells.append(cell(24,len({p['key'] for p in completed})))
    return finish(cells,True)

def sequence(keys,wide=False):return [plan(k,i,wide) for i,k in enumerate(keys)]
