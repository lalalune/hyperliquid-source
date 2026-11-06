"""Lossless evidence packaging; large tables stay available outside diff budgets."""
from pathlib import Path
import gzip,hashlib,json
p=Path(__file__).resolve().parent
def packed(name,data):
 target=p/(name+'.gz');target.write_bytes(gzip.compress(data,mtime=0))
 return {'archive':target.name,'raw_sha256':hashlib.sha256(data).hexdigest(),'raw_bytes':len(data)}
receipt=json.loads((p/'rust-results.json').read_text())
raw=(p/'rust-results.json').read_bytes() if 'commands' in receipt else gzip.decompress((p/'rust-results.full.json.gz').read_bytes())
full=json.loads(raw);summary={k:v for k,v in full.items() if k!='commands'};summary['commands_count']=len(full['commands']);summary['full_receipt']=packed('rust-results.full.json',raw);(p/'rust-results.json').write_text(json.dumps(summary,indent=2)+'\n')
controls=json.loads((p/'native-controls.json').read_text())
raw=(p/'native-controls.json').read_bytes() if 'full_evidence' not in controls else gzip.decompress((p/'native-controls.full.json.gz').read_bytes());full=json.loads(raw)
summary={'output_changes':[{k:c[k] for k in ['name','va','old','new','original','changed']} for c in full['output_changes']],'rejections':[{k:c[k] for k in ['name','va','new','rejected']} for c in full['rejections']],'full_evidence':packed('native-controls.full.json',raw)};(p/'native-controls.json').write_text(json.dumps(summary,indent=2)+'\n')
fixture=p/'client_fixture.rs';data=fixture.read_bytes() if fixture.exists() else gzip.decompress((p/'client_fixture.rs.gz').read_bytes());assert hashlib.sha256(data).hexdigest()==receipt['fixture_sha256'];packed('client_fixture.rs',data)
selection=json.loads((p/'fixture-selection.json').read_text());selection['rust_fixture_sha256']=hashlib.sha256(data).hexdigest();(p/'fixture-selection.json').write_text(json.dumps(selection,indent=2)+'\n')
print('PACKED: exact full command receipt, native controls and101-case Rust fixture; no source/value changes')
