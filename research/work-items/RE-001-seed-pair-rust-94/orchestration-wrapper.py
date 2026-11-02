"""Private disk guard/cleanup orchestration; tracked qualifier semantics unchanged."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
FLOOR=300*1024*1024
HEADROOM=16*1024*1024


def sha(raw):return hashlib.sha256(raw).hexdigest()
def js(value):return (json.dumps(value,indent=2,sort_keys=True)+'\n').encode()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('kind',choices=['inline','key-hash']);parser.add_argument('output',type=Path);args=parser.parse_args()
    packet='RE-001-inline-carrier-rust-94' if args.kind=='inline' else 'RE-001-key-hash-rust-94'
    path=ROOT/'research/work-items'/packet/'verify.py'
    spec=importlib.util.spec_from_file_location('unchanged_current_qualifier',path);core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core)
    output=args.output.resolve()
    if output.exists():raise ValueError('fresh output required')
    audit=output.parent/(output.name+'-orchestration.json')
    checkpoint=output.parent/(output.name+'-checkpoint.json')
    record={'schema':'bounded-current-requalification-orchestration/1','kind':args.kind,'wrapper_sha256':sha(Path(__file__).read_bytes()),
            'unchanged_core_path':str(path.relative_to(ROOT)),'unchanged_core_sha256':sha(path.read_bytes()),'disk_floor_bytes':FLOOR,
            'additional_transient_headroom_bytes':HEADROOM,'guarded_compiler_calls':[],'completed_product_cleanup':[],
            'completed_checkpoint_events':[],
            'preserved':'all source/input/raw logs/receipts and ALL baseline products; old historical/candidate directories untouched'}
    def save():audit.write_bytes(js(record))
    def free(reserve):
        value=shutil.disk_usage(ROOT).free
        if value<FLOOR+reserve:raise ValueError(f'compiler reservation pending: free={value}, need={FLOOR+reserve}')
        return value
    free(HEADROOM);save()
    real_run=core.subprocess.run
    def guarded_run(*pos,**kw):
        argv=pos[0] if pos else kw.get('args')
        guarded=bool(argv) and str(argv[0])==str(core.RUSTC)
        if guarded:before=free(HEADROOM)
        cp=real_run(*pos,**kw)
        if guarded:
            record['guarded_compiler_calls'].append({'argv':[str(x) for x in argv],'version_query':'-vV' in argv,
                'exit':cp.returncode,'free_before_bytes':before,'free_after_bytes':free(0)})
            save()
        return cp
    real_print=print
    def progress(*items,**kw):
        text=' '.join(str(x) for x in items)
        match=re.match(r'^(\S+) opt([03])(?: repeat([01]))?: compiler0;',text)
        if match:
            name,opt,repeat=match.groups()
            # Observe only this authored Python qualifier's completed-build data.
            # Never reconstruct the prior stopped attempt or evaluate target code.
            caller=sys._getframe(1)
            if caller.f_code is not core.qualify.__code__:
                raise ValueError('unexpected checkpoint caller')
            current=caller.f_locals['receipt']
            builds=current['builds']
            latest=builds[-1]
            if latest['variant']!=name or latest['opt']!=int(opt):
                raise ValueError('completed build marker differs from actual record')
            if len(builds)!=len(record['completed_checkpoint_events'])+1:
                raise ValueError('checkpoint build sequence changed')
            free(0)
            snapshot={'schema':'private-actual-build-checkpoint/1',
                      'status':'PARTIAL: not final qualifier success',
                      'wrapper_sha256':record['wrapper_sha256'],
                      'core_sha256':record['unchanged_core_sha256'],
                      'completed_builds':len(builds),'actual_receipt_so_far':current}
            raw=js(snapshot)
            temporary=checkpoint.with_name(checkpoint.name+'.tmp')
            temporary.write_bytes(raw)
            os.replace(temporary,checkpoint)
            record['completed_checkpoint_events'].append({'variant':name,'opt':int(opt),
                'completed_builds':len(builds),'checkpoint_sha256':sha(raw)})
            save()
            if name!='baseline':
                known={r[0] for r in core.RECIPES}
                if name not in known:raise ValueError('unrecognized completed variant')
                directory=output/(f'{name}-opt{opt}-repeat{repeat}' if args.kind=='inline' else f'{name}-opt{opt}')
                for filename in ['libnode94_alias.rlib','input-only']:
                    product=directory/filename
                    if product.is_symlink() or product.parent.parent!=output:raise ValueError('unsafe product scope')
                    raw=product.read_bytes();entry={'path':str(product.relative_to(ROOT)),'bytes':len(raw),'sha256':sha(raw),'free_before_bytes':shutil.disk_usage(ROOT).free}
                    product.unlink();entry['free_after_bytes']=free(0);record['completed_product_cleanup'].append(entry);save()
        real_print(*items,**kw)
    core.subprocess.run=guarded_run
    core.print=progress
    try:
        if args.kind=='inline':
            data=core.NODE.read_bytes();secs=core.authenticate(data);cases=core.vectors();controls=core.native_controls(data,secs,cases)
            core.qualify(output,cases,controls)
        else:
            core.authenticate((ROOT/'artifacts/node/94/hl-node').read_bytes());rows,inputs,expected=core.fixtures()
            core.qualify(output,inputs,expected)
        record['receipt_sha256']=sha((output/'receipt.json').read_bytes());record['status']='completed'
    finally:
        core.subprocess.run=real_run
        record['free_final_bytes']=shutil.disk_usage(ROOT).free;save()
    real_print('orchestration',sha(audit.read_bytes()),'wrapper',record['wrapper_sha256'])

if __name__=='__main__':main()
