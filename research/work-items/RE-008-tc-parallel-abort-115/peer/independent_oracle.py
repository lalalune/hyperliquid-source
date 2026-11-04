"""Reviewer event/snapshot calculation; no author module is imported."""
from pathlib import Path
import argparse,gzip,json,hashlib,collections
U=(1<<64)-1

def requests(b):
    answer=[]
    if b[0] in (16,19,32):
        for o in ([8,32] if b[0]==16 else [8]):
            length=sum(b[o+k]<<(8*k) for k in range(8))
            pointer=sum(b[o+8+k]<<(8*k) for k in range(8))
            if length:answer.append((pointer,length,0))
    return answer

def dr(ds):return ','.join(':'.join(str(x) for x in d) for d in ds) or '-'

def independent(line):
    p=line.split('\t');kind=p.pop(0)
    if kind=='M':
        out,l,r=[bytearray.fromhex(x) for x in p];d=[]
        if l[0]!=46:out[:]=l;index=0
        elif r[0]!=46:out[:]=r;index=1
        else:out[0]=46;index=2
        if l[0]!=46 and r[0]!=46:d=requests(r)
        fields=[out.hex(),index,dr(d),'O'+''.join('D' for _ in d)]
    elif kind=='F':
        out=bytearray.fromhex(p[0]);cursor,stride=map(int,p[1:3]);rows=[] if p[3]=='-' else p[3].split(',');flags=b'' if p[4]=='-' else bytes.fromhex(p[4])
        consumed=reads=writes=reason=0;events=[];d=[]
        for raw,flag in zip(rows,flags):
            r=bytes.fromhex(raw);events.append('C');consumed+=1;cursor=(cursor+stride)&U
            if r[0]==47:reason=1;break
            if out[0]!=46:
                if r[0]!=46:
                    ds=requests(r);d.extend(ds);events.extend('D' for _ in ds)
            elif r[0]!=46:out[:72]=r
            if out[0]!=46:events.append('W');writes+=1
            events.append('S')
            if out[0]!=46:reason=2;break
            events.append('R');reads+=1
            if flag:reason=3;break
        events.append('O');fields=[out.hex(),consumed,reads,writes,reason,cursor,dr(d),''.join(events)]
    elif kind=='P':
        stride,cancel,logical,count,migrated,budget,minimum,workers,start=map(int,p)
        fields=[0]*7
        if not cancel:
            half=logical>>1;fields[1]=half
            if half<minimum or (not migrated and budget==0):fields[0]=1;fields[5]=(start+stride*count)&U
            else:
                new=budget>>1
                if migrated:fields[6]=1;new=workers if new<workers else new
                fields[2]=new
                if count<half:fields[0]=3
                else:fields[0]=2;fields[3]=count-half;fields[4]=(start+stride*half)&U
    elif kind=='C':
        prefix=bytes.fromhex(p[0]);cert,value=map(int,p[1:3]);key=bytes.fromhex(p[3]);valueptr,keyptr,snapshot,heap,al,outptr=map(int,p[4:10]);out=bytearray.fromhex(p[10]);mem=bytearray(52)
        for i,x in enumerate(prefix):mem[i]=x
        for i in range(8):mem[16+i]=(cert>>(i*8))&255;mem[24+i]=(value>>(i*8))&255
        for i,x in enumerate(key):mem[32+i]=x
        out[0]=9
        if al:out[0]=46
        fields=[mem.hex(),out.hex(),':'.join(map(str,[2,heap,keyptr,(valueptr+8)&U,snapshot])),outptr]
    elif kind=='A':
        out,hist,col,nested,parallel=[bytearray.fromhex(x) for x in p[:5]];rows=[] if p[5]=='-' else list(map(int,p[5].split(',')));wanted,round_,quorum,outptr=map(int,p[6:]);events=['H'];cleanup=False
        if hist[0]!=46:out[:]=hist
        else:
            events.append('C')
            if col[0]!=46:out[:]=col
            else:
                cleanup=True;events.append('I')
                if not rows:out[0]=8
                else:
                    highest=rows[0]
                    for n in rows[1:]:
                        if n>highest:highest=n
                    if highest!=wanted or not highest<round_:out[0]=11
                    else:
                        events.append('Q')
                        if quorum==0:out[0]=8
                        else:
                            events.append('N')
                            if nested[0]!=46:out[:]=nested
                            else:events.extend(['V','P']);out[:]=parallel
                events.append('D')
        fields=[out.hex(),''.join(events),int(cleanup),outptr]
    elif kind=='E':
        representation,cap,count,start,workers,tls0,tls1,local,global_=map(int,p);fields=[0]*8
        if representation:
            fields[0]=1
            if tls0==0:
                fields[3]=1
                if tls1==0:fields[2]=1
                elif local!=global_:fields[2]=2
        elif cap<count:fields[2]=3
        else:fields=[0,0,4,1,count,workers,start,(cap*16)&U]
    else:raise ValueError(kind)
    return '\t'.join(map(str,fields))

def main(root,out):
    packet=root/'research/work-items/RE-008-tc-parallel-abort-115';raw=gzip.decompress((packet/'inputs.tsv.gz').read_bytes());expected=gzip.decompress((packet/'expected.tsv.gz').read_bytes())
    inputs=raw.decode().splitlines();want=expected.decode().splitlines()
    if len(inputs)!=len(want):raise ValueError('line count')
    actual=[];counts=collections.Counter()
    for i,(line,e) in enumerate(zip(inputs,want),1):
        got=independent(line)
        if got!=e:raise ValueError({'line':i,'input':line,'expected':e,'actual':got})
        actual.append(got);counts[line[0]]+=1
    encoded=('\n'.join(actual)+'\n').encode();sha=lambda b:hashlib.sha256(b).hexdigest()
    result={'cases':len(inputs),'categories':dict(counts),'actual_sha256':sha(encoded),'expected_sha256':sha(expected),'inputs_sha256':sha(raw),'author_modules_imported':False,'captured_execution':False,'method':'Direct conditional events and staged byte writes, compared with author frozen predicate/least-terminal-index oracle. Reviewer read author source; not a blind discovery.'}
    out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('out',type=Path);a=p.parse_args();main(a.root,a.out)
