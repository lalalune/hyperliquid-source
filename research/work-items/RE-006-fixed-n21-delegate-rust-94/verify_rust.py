"""Guarded compiled comparison to the pre-source original-input n21 freeze."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import shutil
import struct
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COMPONENT = ROOT / 'src/node94-orderbook'
MODULE = COMPONENT / 'src/n21_seed_prepare.rs'
FREEZE_SHA = '01d890d7b29a54f756955b5767bc7db1bf96a753c4908052f42d0e76e44e6e7b'
PLAN_SHA = '2d343ce0e55b509e0c1d3ba7b59a2d5fe76ac589e4763f10d8263ad88da3e64c'
spec = importlib.util.spec_from_file_location('n21_fixed_snapshot', HERE/'source_snapshot.py')
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)
S.bind(ROOT, COMPONENT, MODULE, HERE)
sha, require = S.sha, S.require


def render(obj):
    return json.dumps(obj, indent=2, sort_keys=True)+'\n'


def frozen():
    raw=(HERE/'seed/SEED-PRE-SOURCE-FREEZE.json').read_bytes()
    require(sha(raw)==FREEZE_SHA,'frozen original-input identity')
    record=json.loads(raw);rows=[dict(row,native_domain=True) for row in record['cases']]
    require(len(rows)==80,'original-input denominator')
    planraw=(HERE/'seed/SEED-PRE-SOURCE-RUST-PLAN.json').read_bytes()
    require(sha(planraw)==PLAN_SHA,'pre-source semantic plan identity')
    plan=json.loads(planraw)
    stimulus=b'S21IN001'+struct.pack('<I',80)
    expected=b'S21OUT02'+struct.pack('<I',80)
    original=b'S21OUT01'+struct.pack('<I',80)
    for row in rows:
        stimulus+=struct.pack('<I58Q',row['id'],*row['source21'],*row['initial_scratch37'])
        words=[*row['source_after_seeds21'],*row['scratch_after_seeds37'],*row['prepared_scratch37'],*row['final_source21'],*row['final_scratch37']]
        expected+=struct.pack('<II153Q',row['id'],0,*words)
        original+=struct.pack('<I153Q',row['id'],*words)
    require(sha(stimulus)==record['input_sha256'] and sha(original)==record['expected_sha256'],'original wire binding')
    require(len(stimulus)==37452 and len(expected)==98572 and sha(expected)==plan['expected_v2_sha256'],'pre-source status-refined wire')
    return record,rows,stimulus,expected


def compare(raw,rows):
    require(len(raw)==12+len(rows)*1232 and raw[:8]==b'S21OUT02','output frame/length')
    require(struct.unpack_from('<I',raw,8)[0]==len(rows),'output count')
    changed=[]
    for index,row in enumerate(rows):
        at=12+1232*index;rid,status=struct.unpack_from('<II',raw,at)
        require(rid==row['id'],'output ID/order')
        actual=list(struct.unpack_from('<153Q',raw,at+8))
        expected=[*row['source_after_seeds21'],*row['scratch_after_seeds37'],*row['prepared_scratch37'],*row['final_source21'],*row['final_scratch37']]
        differences=[j for j,(a,b) in enumerate(zip(actual,expected)) if a!=b]
        groups=[]
        if differences:groups.append('array-values')
        if status:groups.append('api-status')
        if groups:
            changed.append(dict(name=row['name'],id=index,native_domain=True,groups=groups,
                                changed_word_indices=differences,actual_status=status,
                                actual_array_sha256=sha(struct.pack('<153Q',*actual))))
    return changed


def variants(source):
    signed_helper='\nfn signed_order_two(first:u64,second:u64)->(u64,u64) { if (second as i64)<(first as i64) {(second,first)} else {(first,second)} }\n'
    edits={
        'quad-signed-pairs':[('order_two(words[0], words[1])','signed_order_two(words[0], words[1])'),('order_two(words[2], words[3])','signed_order_two(words[2], words[3])')],
        'quad-invert-p':[('let p = low2 < low1;','let p = low2 > low1;')],
        'quad-invert-q':[('let q = high2 < high1;','let q = high2 > high1;')],
        'quad-reverse-middle':[('[low1.min(low2), low_middle, high_middle, high1.max(high2)]','[low1.min(low2), high_middle, low_middle, high1.max(high2)]')],
        'quad-minimum-from-maximum':[('[low1.min(low2), low_middle','[high1.max(high2), low_middle')],
        'quad-maximum-from-minimum':[('high_middle, high1.max(high2)]','high_middle, low1.min(low2)]')],
        'seed-swap-temporary-halves':[('temporary[..4].copy_from_slice(&first);','temporary[..4].copy_from_slice(&second);'),('temporary[4..].copy_from_slice(&second);','temporary[4..].copy_from_slice(&first);')],
        'seed-omit-temporary-last':[('temporary[4..].copy_from_slice(&second);','temporary[4..7].copy_from_slice(&second[..3]);')],
        'seed-truncate-input':[('    let first = sort_four([input[0]','    let input = input.map(|word| u64::from(word as u32));\n    let first = sort_four([input[0]')],
        'seed-front-choose-greater':[('if take_right_front { right_front_word } else { left_front_word }','if take_right_front { left_front_word } else { right_front_word }')],
        'seed-back-choose-smaller':[('if right_back_word > left_back_word {','if right_back_word < left_back_word {')],
        'seed-omit-output-last':[('destination[7 - t] = back_word;','if t != 0 { destination[7 - t] = back_word; }')],
        'caller-second-input-minus-one':[('output[10 + index]','output[9 + index]')],
        'caller-swap-auxiliary-halves':[('seed_eight(first, (&mut prefix[..8]).try_into().unwrap(), (&mut auxiliary[..8]).try_into().unwrap());','seed_eight(first, (&mut prefix[..8]).try_into().unwrap(), (&mut auxiliary[8..]).try_into().unwrap());'),('seed_eight(second, (&mut prefix[10..18]).try_into().unwrap(), (&mut auxiliary[8..]).try_into().unwrap());','seed_eight(second, (&mut prefix[10..18]).try_into().unwrap(), (&mut auxiliary[..8]).try_into().unwrap());')],
        'left-skip-j8':[('let _ = first_left_insertion::insert_loaded(window, value);','let _: (&mut [u64; 9], u64) = (window, value); let _ = first_left_insertion::insert_loaded;')],
        'left-skip-j9':[('let _ = j9_first_front::insert_j9_loaded(window, value);','let _: (&mut [u64; 10], u64) = (window, value); let _ = j9_first_front::insert_j9_loaded;')],
        'overwrite-original-input':[('    let first = std::array::from_fn(|index| output[index]);','    output[0] = 0;\n    let first = std::array::from_fn(|index| output[index]);')],
    }
    raw=(HERE/'seed/SEED-PRE-SOURCE-RUST-PLAN.json').read_bytes();require(sha(raw)==PLAN_SHA,'pre-source plan identity')
    require(set(edits)=={row['name'] for row in json.loads(raw)['controls']},'planned seventeen-control denominator')
    result={}
    for name,replacements in edits.items():
        changed=source
        for before,after in replacements:
            require(changed.count(before)==1,'mutation source anchor '+name)
            changed=changed.replace(before,after)
        if name=='quad-signed-pairs':changed+=signed_helper
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
              harness_files=harness,native_cases=80,api_policy_cases=0,target_execution=False,instruction_evaluation=False)
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
    for name,source in variants((component/'src/n21_seed_prepare.rs').read_text()).items():
        S.check_snapshot(snapshot,manifest);directory=out/('mutant-'+name);shutil.copytree(component,directory)
        (directory/'src/n21_seed_prepare.rs').write_text(source);mutant_manifest=S.manifest(directory)
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
        if not counts['array-values']:
            failed.append(dict(name=name,reason='planned native array-value prediction failed'))
        S.check_snapshot(directory,mutant_manifest)
    S.check_snapshot(snapshot,manifest);S.check_live(manifest);checked_input(out,identity);frozen()
    require(sha(rustc.read_bytes())==compiler_sha,'compiler changed')
    require(all(sha((HERE/name).read_bytes())==digest for name,digest in harness.items()),'running harness changed')
    result=dict(base,compiler_version=version,compiler_sha256=compiler_sha,builds=builds,controls=controls,commands=commands,
                failed_control_predictions=failed,limits='Fixed-n21 original delegate-entry value route only; no generic count/outer-core reachability/ABI/failure/target runtime/physical compiler store proof.')
    (out/'build-report.json').write_text(render(result))
    if failed:(out/'CONTROL-PREDICTION-FAILURE.json').write_text(render(result))
    require(not failed,'pre-source control prediction failed; receipt retained')
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);p.add_argument('--rustc',type=Path);args=p.parse_args()
    result=run(args.out.resolve(),args.rustc)
    print('PASS: four80original-input records,17 planned controls; static-derived only' if args.rustc else 'Prepared only; no compiler run')
