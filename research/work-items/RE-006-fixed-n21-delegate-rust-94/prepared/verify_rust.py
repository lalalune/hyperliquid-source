"""Guarded compiled comparison to the pre-source n21 full-array freeze."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import shutil
import struct
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
COMPONENT = ROOT / 'src/node94-orderbook'
MODULE = COMPONENT / 'src/n21_right_merge.rs'
FREEZE_SHA = 'cd9fdc6771ad75f3d14c7c61e4c365d0a8712606e5c79907f13193a7262da4dc'
PLAN_SHA = '3ff3e5fd16263618f4f435bbb3c399a1f35ec1e008b088c5ad06a2ecd690e405'
spec = importlib.util.spec_from_file_location('n21_fixed_snapshot', HERE/'source_snapshot.py')
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)
S.bind(ROOT, COMPONENT, MODULE, HERE)
sha, require = S.sha, S.require


def render(obj):
    return json.dumps(obj, indent=2, sort_keys=True)+'\n'


def wire(rows):
    stimulus=b'N21IN001'+struct.pack('<I',len(rows))
    expected=b'N21OUT01'+struct.pack('<I',len(rows))
    for row in rows:
        stimulus+=struct.pack('<I58Q',row['id'],*row['source21'],*row['scratch37'])
        expected+=struct.pack('<II58Q',row['id'],row['status'],*row['expected_source21'],*row['expected_scratch37'])
        expected+=struct.pack('<8I',*row['insertion_positions'],row['center_side'],*row['final_cursors'])
        expected+=struct.pack('<30I',*[value for pair in row['pairs'] for value in pair])
        expected+=struct.pack('<I',len(row['writes']))
        expected+=b''.join(struct.pack('<IIQ',*event) for event in row['writes'])
        expected+=bytes((54-len(row['writes']))*16)
    return stimulus,expected


def frozen():
    payload=(HERE/'PRE-SOURCE-FULL-ARRAY-FREEZE.json').read_bytes()
    require(sha(payload)==FREEZE_SHA,'frozen corpus identity')
    record=json.loads(payload);rows=record['cases']
    require(len(rows)==84 and sum(r['native_domain'] for r in rows)==80,'native/policy denominator')
    stimulus,expected=wire(rows)
    require(len(stimulus)==39324 and len(expected)==125340,'frozen wire sizes')
    require(sha(stimulus)==record['input_sha256'] and sha(expected)==record['expected_sha256'],'wire identity')
    return record,rows,stimulus,expected


def compare(raw,rows):
    require(len(raw)==12+len(rows)*1492 and raw[:8]==b'N21OUT01','output frame/length')
    require(struct.unpack_from('<I',raw,8)[0]==len(rows),'output count')
    changed=[]
    for index,row in enumerate(rows):
        at=12+1492*index;rid,status=struct.unpack_from('<II',raw,at)
        require(rid==row['id'],'output ID/order')
        output=list(struct.unpack_from('<21Q',raw,at+8));scratch=list(struct.unpack_from('<37Q',raw,at+176))
        insertion=list(struct.unpack_from('<3I',raw,at+472));center=struct.unpack_from('<I',raw,at+484)[0]
        cursors=list(struct.unpack_from('<4I',raw,at+488));pairs=[list(struct.unpack_from('<3I',raw,at+504+12*i)) for i in range(10)]
        count=struct.unpack_from('<I',raw,at+624)[0];require(count<=54,'logical write count')
        writes=[list(struct.unpack_from('<IIQ',raw,at+628+16*i)) for i in range(54)]
        expected_writes=row['writes']+[[0,0,0]]*(54-len(row['writes']))
        groups=[]
        if output!=row['expected_source21'] or scratch!=row['expected_scratch37']:groups.append('array-values')
        if status!=row['status']:groups.append('api-status')
        if (insertion,center,cursors,pairs)!=(row['insertion_positions'],row['center_side'],row['final_cursors'],row['pairs']):groups.append('cursor-index-provenance')
        if count!=len(row['writes']) or writes!=expected_writes:groups.append('chosen-logical-writes')
        if groups:
            changed.append(dict(name=row['name'],id=index,native_domain=row['native_domain'],groups=groups,
                                output_indices=[j for j,(a,b) in enumerate(zip(output,row['expected_source21'])) if a!=b],
                                scratch_indices=[j for j,(a,b) in enumerate(zip(scratch,row['expected_scratch37'])) if a!=b],
                                actual_status=status,actual_insertion_indices=insertion,actual_center=center,actual_cursors=cursors,
                                changed_pair_indices=[j for j,(a,b) in enumerate(zip(pairs,row['pairs'])) if a!=b],
                                actual_logical_write_count=count,
                                actual_array_sha256=sha(struct.pack('<58Q',*output,*scratch))))
    return changed


def variants(source):
    edits={
        'right-signed-comparisons': [('value < scratch[10 + destination - 1]','(value as i64) < (scratch[10 + destination - 1] as i64)')],
        'right-skip-final-source': [('for j in 8..11 {','for j in 8..10 {')],
        'right-source-index-minus-one': [('let value = output[10 + j];','let value = output[9 + j];')],
        'right-omit-initial-append': [('        scratch[10 + j] = value;','        // append omitted')],
        'right-omit-final-insertion': [('            scratch[10 + destination] = value;','            // final store omitted')],
        'right-stop-before-front': [('destination > 0','destination > 1')],
        'right-truncate-loaded-word': [('let value = output[10 + j];','let value = u64::from(output[10 + j] as u32);')],
        'front-signed-comparison': [('right_front_word < left_front_word','(right_front_word as i64) < (left_front_word as i64)')],
        'front-choose-greater': [('(right_front_word, Half::Right)','(left_front_word, Half::Right)'),('(left_front_word, Half::Left)','(right_front_word, Half::Left)')],
        'back-signed-comparisons': [('right_back_word > left_back_word','(right_back_word as i64) > (left_back_word as i64)'),('right_back_word < left_back_word','(right_back_word as i64) < (left_back_word as i64)')],
        'back-choose-smaller': [('right_back_word > left_back_word','right_back_word < left_back_word')],
        'omit-center-store': [('    output[10] = center;','    // center store omitted')],
        'center-always-left': [('if left_front < left_exclusive {','if true {')],
        'center-always-right': [('if left_front < left_exclusive {','if false {')],
        'left-exclusive-plus-two': [('let left_exclusive = (left_back + 1) as usize;','let left_exclusive = (left_back + 2) as usize;')],
        'right-shift-equal': [('value < scratch[10 + destination - 1]','value <= scratch[10 + destination - 1]')],
        'front-equality-retires-right': [('right_front_word < left_front_word','right_front_word <= left_front_word')],
        'back-equality-value-from-right': [('right_back_word > left_back_word','right_back_word >= left_back_word')],
        'reverse-pair-logical-store-order': [(
            '        output[t] = front_word;\n        observation.record(Area::Output, t, front_word);',
            '        output[20 - t] = back_word;\n        observation.record(Area::Output, 20 - t, back_word);'),(
            '        output[20 - t] = back_word;\n        observation.record(Area::Output, 20 - t, back_word);\n        match back_retired',
            '        output[t] = front_word;\n        observation.record(Area::Output, t, front_word);\n        match back_retired')],
    }
    raw=(HERE/'PRE-SOURCE-RUST-CONTROL-PLAN.json').read_bytes();require(sha(raw)==PLAN_SHA,'pre-source control plan identity')
    require(set(edits)=={x['name'] for x in json.loads(raw)['controls']},'planned control denominator')
    result={}
    for name,replacements in edits.items():
        changed=source
        for before,after in replacements:
            require(changed.count(before)==1,'mutation source anchor '+name)
            changed=changed.replace(before,after)
        result[name]=changed
    return result


def checked_input(out,identity):
    payloads={}
    for name,digest in identity.items():
        p=out/name;require(p.is_file() and not p.is_symlink(),'fixture absent/symlink')
        payloads[name]=p.read_bytes();require(sha(payloads[name])==digest,'fixture artifact changed')
    return payloads['input.bin']


def run(out,rustc=None):
    record,rows,stimulus,expected=frozen();require(not compare(expected,rows),'literal/wire agreement')
    require(not out.exists(),'fresh output directory required');out.mkdir(parents=True)
    snapshot=out/'source-snapshot';snapshot.mkdir()
    for name,path in S.source_files().items():
        require(path.is_file() and not path.is_symlink(),'source absent/symlink')
        dest=snapshot/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(path.read_bytes())
    manifest=S.manifest(snapshot);S.check_live(manifest)
    identity={'input.bin':sha(stimulus),'expected.bin':sha(expected)}
    for name,payload in [('input.bin',stimulus),('expected.bin',expected)]: (out/name).write_bytes(payload)
    harness={name:sha((HERE/name).read_bytes()) for name in ['verify_rust.py','source_snapshot.py']}
    base=dict(source_manifest=manifest,fixture_identity=identity,frozen_sha256=FREEZE_SHA,control_plan_sha256=PLAN_SHA,
              harness_files=harness,native_cases=80,api_policy_cases=4,target_execution=False,instruction_evaluation=False)
    (out/'preparation.json').write_text(render(base))
    if rustc is None:return base
    rustc=rustc.resolve();version=subprocess.check_output([str(rustc),'-vV'],text=True)
    require(version.startswith('rustc 1.94.1 '),'pinned compiler required');compiler_sha=sha(rustc.read_bytes())
    component=snapshot/'component';driver=snapshot/'driver/input_only_driver.rs';commands=[]
    def command(label,argv,stdin=None):
        p=subprocess.run(list(map(str,argv)),input=stdin,capture_output=True)
        for kind in ['stdout','stderr']:(out/(label+'.'+kind)).write_bytes(getattr(p,kind))
        commands.append(dict(label=label,argv=list(map(str,argv)),exit_code=p.returncode,
                             stdout_sha256=sha(p.stdout),stderr_sha256=sha(p.stderr)))
        require(p.returncode==0,'command failed '+label);return p.stdout
    builds=[]
    for opt in [0,3]:
        flags=['--edition=2024','-D','warnings','-C',f'opt-level={opt}','-C','overflow-checks=yes']
        for repeat in [0,1]:
            name=f'o{opt}-r{repeat}';library=out/('libnode94_orderbook-'+name+'.rlib');client=out/(name+'-client')
            S.check_snapshot(snapshot,manifest)
            command(name+'-library',[rustc,'--crate-name','node94_orderbook','--crate-type=rlib',component/'src/lib.rs','-o',library,*flags])
            command(name+'-client-build',[rustc,driver,'--extern','node94_orderbook='+str(library),'-o',client,*flags])
            result=command(name+'-client-run',[client],checked_input(out,identity))
            require(result==expected and not compare(result,rows),'production full-array/observation mismatch')
            builds.append(dict(profile=name,library_sha256=sha(library.read_bytes()),client_sha256=sha(client.read_bytes()),output_sha256=sha(result)))
        unit=out/f'o{opt}-unit'
        command(f'o{opt}-unit-build',[rustc,'--test',component/'src/lib.rs','-o',unit,*flags]);command(f'o{opt}-unit-run',[unit])
    controls=[];failed=[]
    for name,source in variants((component/'src/n21_right_merge.rs').read_text()).items():
        S.check_snapshot(snapshot,manifest);directory=out/('mutant-'+name);shutil.copytree(component,directory)
        (directory/'src/n21_right_merge.rs').write_text(source);mutant_manifest=S.manifest(directory)
        library=out/('libnode94_orderbook-'+name+'.rlib');client=out/(name+'-client')
        flags=['--edition=2024','-C','opt-level=3','-C','overflow-checks=yes']
        command(name+'-library',[rustc,'--crate-name','node94_orderbook','--crate-type=rlib',directory/'src/lib.rs','-o',library,*flags])
        command(name+'-client-build',[rustc,driver,'--extern','node94_orderbook='+str(library),'-o',client,*flags])
        raw=command(name+'-client-run',[client],checked_input(out,identity));differences=compare(raw,rows)
        native=[x for x in differences if x['native_domain']];policy=[x for x in differences if not x['native_domain']]
        counts={group:sum(group in x['groups'] for x in native) for group in ['array-values','api-status','cursor-index-provenance','chosen-logical-writes']}
        row=dict(name=name,native_counts=counts,policy_mismatches=len(policy),first_counterexample=native[0] if native else None,
                 output_sha256=sha(raw),source_manifest=mutant_manifest);controls.append(row)
        if not native:failed.append(dict(name=name,reason='no native projection distinction'))
        if name not in ['right-shift-equal','front-equality-retires-right','back-equality-value-from-right','reverse-pair-logical-store-order'] and not counts['array-values']:
            failed.append(dict(name=name,reason='planned native array-value prediction failed'))
        if name in ['back-equality-value-from-right','reverse-pair-logical-store-order'] and counts['array-values']:
            failed.append(dict(name=name,reason='planned no-array-value prediction failed'))
        S.check_snapshot(directory,mutant_manifest)
    S.check_snapshot(snapshot,manifest);S.check_live(manifest);checked_input(out,identity);frozen()
    require(sha(rustc.read_bytes())==compiler_sha,'compiler changed')
    require(all(sha((HERE/name).read_bytes())==digest for name,digest in harness.items()),'running harness changed')
    result=dict(base,compiler_version=version,compiler_sha256=compiler_sha,builds=builds,controls=controls,commands=commands,
                failed_control_predictions=failed,limits='Prepared-state n21 continuation only; no seed reachability/originalA sort/ABI/failure/target runtime/physical compiler store proof.')
    (out/'build-report.json').write_text(render(result))
    if failed:(out/'CONTROL-PREDICTION-FAILURE.json').write_text(render(result))
    require(not failed,'pre-source control prediction failed; receipt retained')
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);p.add_argument('--rustc',type=Path);args=p.parse_args()
    result=run(args.out.resolve(),args.rustc)
    print('PASS: four84record runs,19 planned controls; static-derived only' if args.rustc else 'Prepared only; no compiler run')
