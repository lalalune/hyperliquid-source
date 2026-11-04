#!/usr/bin/env python3
"""Declarative normal command-construction fields, no process execution."""
from pathlib import Path
import itertools,json,hashlib,gzip,sys
P=Path(__file__).resolve().parent;R=P.parents[2];sys.path.insert(0,str(P));import verify
PLACEHOLDER=b'<string-with-nul>\0'
def convert(b):return (PLACEHOLDER,True) if 0 in b else (b+b'\0',False)
def result(program,args):
 kind=2 if program.startswith(b'/') else 1 if b'/' in program else 0
 p,nul=convert(program);values=[p]
 for a in args:
  value,bad=convert(a);values.append(value);nul|=bad
 return f'{kind}|{int(nul)}|{p.hex()}|'+','.join(b.hex() for b in values)+f'|{len(values)+1}'
def cases():
 out=set();tokens=[b'',b'mv',b'/',b'//x',b'a/b',b'abc',b'\\',b'a\\b',b'\0',b'\0/x',b'x/\0',bytes([255,128]),b'a\0b']
 programs=tokens+[bytes([65])*n for n in range(80)]
 for n in [15,16,17,31,32,33,127,128,255,383,384,1023]:
  for pos in [0,n//2,n-1]:
   base=bytes([0x80])*n;programs += [base[:pos]+b'/'+base[pos+1:],base[:pos]+b'\0'+base[pos+1:]]
 for p in programs:
  for t in tokens:out.add((p,(t,)))
  out.add((p,()));out.add((p,(b'ok',b'\0bad',b'fine')));out.add((p,(b'',)*8))
 for a,b,c in itertools.product(tokens,repeat=3):out.add((b'program',(a,b,c)))
 return sorted(out)
def freeze():
 verify.collect(verify.TARGET.read_bytes(),True);rows=cases();raw=''.join(f'{p.hex() or "-"}\t'+(';'.join(a.hex() or '-' for a in args) if args else '~')+'\t'+result(p,args)+'\n' for p,args in rows).encode();return raw,{'cases':len(rows),'fixture_sha256':hashlib.sha256(raw).hexdigest(),'new_rust_exists':(R/'src/node115-command-construction').exists(),'oracle_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'scope_sha256':hashlib.sha256((P/'scope.json').read_bytes()).hexdigest(),'target_sha256':verify.SPEC['target_sha256'],'fixture_storage':'gzip(mtime0)+hex before Rust'}
if __name__=='__main__':
 raw,j=freeze();assert not j['new_rust_exists'];(P/'freeze.json').write_text(verify.dump(j));(P/'cases.tsv.gz.hex').write_text(gzip.compress(raw,mtime=0).hex()+'\n');print(verify.dump(j))
