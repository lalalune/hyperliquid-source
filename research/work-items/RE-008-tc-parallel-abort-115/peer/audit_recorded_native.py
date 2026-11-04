"""Check recorded native streams without executing or rebuilding anything."""
from pathlib import Path
import argparse,json,gzip,lzma,base64,hashlib

def main(packet,out):
    sha=lambda b:hashlib.sha256(b).hexdigest();r=json.loads((packet/'native/result.json').read_bytes());compressed=(packet/'native/raw-streams.json.xz').read_bytes();raw=lzma.decompress(compressed)
    if sha(compressed)!=r['archive']['sha256'] or sha(raw)!=r['archive']['raw_json_sha256'] or len(raw)!=r['archive']['raw_json_bytes']:raise ValueError('archive binding')
    s=json.loads(raw)['streams'];del raw
    if len(s)!=258:raise ValueError('inventory')
    for n,e in s.items():
        data=base64.b64decode(e['base64'],validate=True)
        if len(data)!=e['bytes'] or sha(data)!=e['sha256']:raise ValueError(n)
    expected=gzip.decompress((packet/'expected.tsv.gz').read_bytes()).splitlines()
    for c in r['commands']:
        for k in ('stdout','stderr'):
            if s[c['label']+'.'+k]['sha256']!=c[k+'_sha256']:raise ValueError('command stream')
    result=[]
    for c in r['normal']+r['mutants']:
        actual=base64.b64decode(s[c['label']+'-run.stdout']['base64']).splitlines()
        if len(actual)!=len(expected):raise ValueError('line count')
        diff=[i for i,(a,e) in enumerate(zip(actual,expected)) if a!=e]
        if len(diff)!=c['mismatches'] or diff[:10]!=c['first_indices']:raise ValueError('comparison count')
        result.append({'label':c['label'],'cases':len(actual),'mismatches':len(diff)})
    source=(packet/'rust/lib.rs').read_bytes();driver=(packet/'rust/driver.rs').read_bytes()
    if sha(source)!=r['source_sha256'] or sha(driver)!=r['driver_sha256']:raise ValueError('source pins')
    out.write_text(json.dumps({'streams_verified':len(s),'commands_verified':len(r['commands']),'runs_recomputed':result,'source_sha256':sha(source),'driver_sha256':sha(driver),'new_native_execution':False,'independence_limit':'Reauthenticates retained streams and recomputes mismatch indices; does not reproduce builds, binary hashes or compiler execution.'},indent=2)+'\n')
    print(json.dumps({'streams':len(s),'commands':len(r['commands']),'normal':len(r['normal']),'mutants':len(r['mutants']),'cases_per_run':len(expected)}))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('packet',type=Path);p.add_argument('out',type=Path);a=p.parse_args();main(a.packet,a.out)
