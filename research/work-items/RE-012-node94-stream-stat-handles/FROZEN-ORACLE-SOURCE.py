"""Independent mathematical request/field expectations, frozen before a checker.

No ELF, captured CPU state, network or live allocation is used. Pointer-like
values are opaque synthetic tokens in an aggregate-field relation.
"""
from pathlib import Path
import gzip,hashlib,io,itertools,json,sys
B=Path(__file__).resolve().parent
rows=[]
def add(family,i,e):rows.append({'family':family,'id':family+'-'+str(len(rows)),'input':i,'expected':e})
keys={}
for direction,position,value in itertools.product([0,1],range(6),range(256)):
    raw=bytearray([192,0,2,17,0x81,0x1f]);raw[position]=value
    a=int.from_bytes(raw[:4],'little');p=int.from_bytes(raw[4:],'little')
    keys[(direction,a,p)]=None
for direction,a,p in itertools.product([0,1],[0,1,0x80000000,0xffffffff],[0,1,0x8000,0xffff]):keys[(direction,a,p)]=None
for direction,a,p in sorted(keys):
    packed=a.to_bytes(4,'little')+p.to_bytes(2,'little')+bytes([direction,0])
    transcript=[direction.to_bytes(8,'little').hex(),a.to_bytes(4,'little').hex(),p.to_bytes(2,'little').hex()]
    add('key-request',{'direction':direction,'address':a,'port':p},
        {'packedKeyHex':packed.hex(),'hashUpdateHex':transcript,'hashUpdateWidths':[8,4,2]})
for direction,poison in itertools.product([0,1],[0,1,0xff,0xffff,0x7fffffff,0xffffffff]):
    a=0xc0000211;p=0x1f81
    add('key-request',{'direction':direction+(poison<<8),'address':a+(poison<<32),'port':p+(poison<<16)},
        {'packedKeyHex':(a.to_bytes(4,'little')+p.to_bytes(2,'little')+bytes([direction,0])).hex(),
         'hashUpdateHex':[direction.to_bytes(8,'little').hex(),a.to_bytes(4,'little').hex(),p.to_bytes(2,'little').hex()],
         'hashUpdateWidths':[8,4,2]})
# Equality is independent of fingerprint collisions and of the unused byte7.
q=bytes([192,0,2,17,0x81,0x1f,0])
candidates={q+bytes([pad]) for pad in range(256)}
for position,value in itertools.product(range(6),range(256)):
    raw=bytearray(q+bytes([0]));raw[position]=value;candidates.add(bytes(raw))
candidates.add(q[:6]+bytes([1,0]))
for raw,control,fingerprint in itertools.product(sorted(candidates),[0,1,63,127],[0,1,63,127]):
    same=raw[:4]==q[:4] and raw[4:6]==q[4:6] and raw[6]==q[6]
    add('candidate-key',{'queryHex':(q+bytes([0])).hex(),'entryHex':raw.hex(),'control':control,'fingerprint':fingerprint},
        {'eligibleExactKey':control==fingerprint and same})
# Literal three-cell increment projection. Out-of-invariant bit patterns are
# not asserted to be reachable live reference counts.
counts=[0,1,2,127,0x7fffffff,0xffffffff,0x7ffffffffffffffe,0x7fffffffffffffff,0x8000000000000000,0xffffffffffffffff]
for initial in itertools.product(counts,repeat=3):
    after=list(initial);steps=0;complete=True
    for n in range(3):
        after[n]=(initial[n]+1)%(2**64);steps+=1
        if after[n]==0 or after[n]>=2**63:complete=False;break
    add('clone-projection',{'counts':list(initial)},
        {'countsAfter':after,'increments':steps,'outputWritten':complete,'aborted':not complete})
for pool,hit,port,direction,clock in itertools.product(['traffic','lz4'],[False,True],[0,0x1f81,0xffff],[0,1],[[0,0],[1,999999999],[0x7fffffffffffffff,0xffffffff]]):
    resources=[0x1000,0x2000,0x3000] if hit else [0x4000,0x5000,0x6000]
    i={'pool':pool,'hit':hit,'existingResources':[0x1000,0x2000,0x3000],
       'freshResources':[0x4000,0x5000,0x6000],'port':port,'direction':direction,'clockPair':clock,
       'cachedPort':(port+17)%65536,'cachedDirection':1-direction}
    e={'resources':resources,'allocationSizes':[] if hit else ([24,24,40] if pool=='traffic' else [24,24,24]),
       'timestampRequests':0 if hit or pool=='lz4' else 1,'initialCells':[]}
    if not hit:
        for n in range(3):
            cell={'resource':resources[n],'header0':1,'header1':1,'data0':0}
            if pool=='traffic' and n==2:cell['clockPair']=clock
            e['initialCells'].append(cell)
    if pool=='lz4':
        e['returnedPort']=i['cachedPort'] if hit else port
        e['returnedDirection']=i['cachedDirection'] if hit else direction
    add('handle-fields',i,e)
registrations={bytes(32),bytes([255])*32,bytes(range(32))}
for bit in range(256):
    raw=bytearray(32);raw[bit//8]=2**(bit%8);registrations.add(bytes(raw))
for registration in sorted(registrations):
    a=0xc0000211;p=0x1f81
    handles={'traffic0':[0x1000,0x2000,0x3000],'traffic1':[0x4000,0x5000,0x6000],
             'lz40':[0x7000,0x8000,0x9000,p,0],'lz41':[0xa000,0xb000,0xc000,p,1]}
    regions=[{'offset':0,'hex':registration.hex()}]
    for label,offset in [('lz40',0x20),('lz41',0x40),('traffic0',0x60),('traffic1',0x78)]:
        h=handles[label];raw=b''.join(x.to_bytes(8,'little') for x in h[:3])
        if label.startswith('lz4'):raw+=h[3].to_bytes(2,'little')+bytes([h[4]])
        regions.append({'offset':offset,'hex':raw.hex()})
    regions.append({'offset':0x90,'hex':p.to_bytes(2,'little').hex()})
    add('constructor-fields',{'registrationHex':registration.hex(),'address':a,'port':p,'handles':handles},
        {'requests':[['traffic',0,a,p],['traffic',1,a,p],['lz4',0,a,p],['lz4',1,a,p]],
         'definedRegions':regions,'undefinedWithin152':[[0x3b,5],[0x5b,5],[0x92,6]]})
payload=('\n'.join(json.dumps(x,sort_keys=True,separators=(',',':')) for x in rows)+'\n').encode()
buffer=io.BytesIO()
with gzip.GzipFile(filename='',mode='wb',fileobj=buffer,compresslevel=9,mtime=0) as gz:gz.write(payload)
raw=buffer.getvalue();stem=sys.argv[1];archive=B/(stem+'.jsonl.gz');receipt=B/(stem+'.json')
if archive.exists() or receipt.exists():raise ValueError('Preserve previous freeze')
meta={'state':'stream-stat-expectations-frozen-before-checker','base':'966865f1637a29ce75b019e1bf11d5529cc6f519',
 'targetSha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
 'sourceSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
 'manualProofSha256':hashlib.sha256((B/'node94-stream-stat-proof-draft.md').read_bytes()).hexdigest(),
 'cases':len(rows),'families':{f:sum(x['family']==f for x in rows) for f in sorted({x['family'] for x in rows})},
 'uncompressedBytes':len(payload),'compressedBytes':len(raw),
 'uncompressedSha256':hashlib.sha256(payload).hexdigest(),'compressedSha256':hashlib.sha256(raw).hexdigest(),
 'gzipOsByte':raw[9],'capturedExecution':False,'instructionEvaluation':False,'checkerCreated':False,
 'scope':'Aggregate key/update-request/candidate/clone/handle/constructor projections. No invented hash output. Synthetic arbitrary count/cached-tail/clock patterns are literal field representatives, not live-state reachability claims. Padding and dynamic runtime table/once values excluded.'}
archive.write_bytes(raw);receipt.write_text(json.dumps(meta,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(meta,sort_keys=True))
