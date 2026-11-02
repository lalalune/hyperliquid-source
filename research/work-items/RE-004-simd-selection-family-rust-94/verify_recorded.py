"""Audit retained native observations without compiling or executing a target."""
import base64,gzip,hashlib,json,struct
from pathlib import Path
P=Path(__file__).resolve().parent
R=P.parents[2]
def sha(b):return hashlib.sha256(b).hexdigest()
def require(ok,why):
    if not ok:raise ValueError(why)
def audit():
    r=json.loads((P/'native-result.json').read_text())
    a=json.loads(gzip.decompress((P/'native-streams.json.gz').read_bytes()))
    expected=gzip.decompress((P/'expected.bin.gz').read_bytes())
    require(len(expected)==9944*688,'expected framing')
    payloads={h:base64.b64decode(b,validate=True) for h,b in a['payloads'].items()}
    for h,b in payloads.items():require(sha(b)==h,'payload digest')
    streams={n:payloads[h] for n,h in a['streams'].items()}
    require(set(streams)==set(r['streams']),'stream inventory')
    for n,b in streams.items():require(r['streams'][n]=={'raw_bytes':len(b),'raw_sha256':sha(b)},'stream metadata '+n)
    for n,h in r['rust_sources'].items():require(sha((R/'src/node94-simd-selection-family'/n).read_bytes())==h,'source identity '+n)
    for n,h in r['verification_sources'].items():require(sha((P/n).read_bytes())==h,'verifier identity '+n)
    commands=json.loads((P/'native-commands.json').read_text())
    for c in commands:
        label=c['label']
        for s in ['stdout','stderr']:require(sha(streams[label+'.'+s])==c[s+'_sha256'],'command stream '+label)
        require((c['returncode']!=0)==label.endswith(('-partial','-descriptor')),'command outcome '+label)
    for label in ['opt0','opt0-repeat','opt3','opt3-repeat']:require(streams[label+'-run.stdout']==expected,'native full comparison '+label)
    counts={}
    for label,m in r['native_mutants'].items():
        raw=streams[label+'-run.stdout'];require(len(raw)==len(expected),'mutant framing')
        categories={'successful_value_changes':0,'admission_changes':0,'refusal_image_changes':0}
        for i in range(0,len(raw),688):
            got,want=raw[i:i+688],expected[i:i+688]
            if got==want:continue
            gs,ws=struct.unpack_from('<Q',got)[0],struct.unpack_from('<Q',want)[0]
            key='admission_changes' if gs!=ws else ('successful_value_changes' if ws else 'refusal_image_changes')
            categories[key]+=1
        require(sum(categories.values())==m['mismatches']>0,'effective mutant '+label)
        counts[label]=categories
    return {'streams':len(streams),'commands':len(commands),'cases':9944,'native_builds':4,'comparisons':39776,'mutants':counts,'native_archive_bytes':(P/'native-streams.json.gz').stat().st_size,'captured_code_executed':False}
if __name__=='__main__':print(json.dumps(audit(),indent=2,sort_keys=True))
