"""Compare actual offline parser records; never execute a captured ELF."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--base-tools',type=Path,required=True)
parser.add_argument('--root',type=Path,default=Path.cwd())
parser.add_argument('--output',type=Path,default=Path('work/leb-width'))
args=parser.parse_args()
root=args.root.resolve()
sys.path.insert(0,str(root/'tools'))
from artifacts import check

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

before=load('before',args.base_tools/'fde_extents.py')
after=load('after',root/'tools/fde_extents.py')
manifest=json.loads((root/'provenance/artifacts.json').read_text())
rows=[]
for release in ('94','115'):
    rel=f'artifacts/node/{release}/hl-node'
    item=next(i for i in manifest['files'] if i['path']==rel)
    check(root/rel,item)
    data=(root/rel).read_bytes()
    old=before.fde_extents(data)
    new=after.fde_extents(data)
    if old!=new:
        raise ValueError(f'Parser records differ for release {release}')
    rows.append({'release':release,'sha256':item['sha256'],'bytes':len(data),
                 'all_summary_extent_and_gap_records_equal':True,
                 'fde_records':len(new[1]),
                 'serialized_records_sha256':hashlib.sha256(json.dumps(new,sort_keys=True).encode()).hexdigest()})
args.output.mkdir(parents=True,exist_ok=True)
(args.output/'comparison.json').write_text(json.dumps(rows,indent=2)+'\n')
print(json.dumps(rows,indent=2))
