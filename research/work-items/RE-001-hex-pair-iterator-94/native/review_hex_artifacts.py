#!/usr/bin/env python3
"""Independently validate retained actual hex build streams, no compilation."""
from pathlib import Path
import gzip,hashlib,json,re

ROOT=Path(__file__).resolve().parent
RUN=ROOT.parent/'hex-iterator-build-c1'
REPO=ROOT.parent/'formatter'
PACKET=REPO/'research/work-items/RE-001-hex-pair-iterator-94'
sha=lambda raw:hashlib.sha256(raw).hexdigest()
jread=lambda path:json.loads(path.read_bytes())
result=jread(RUN/'result.json')
commands=jread(RUN/'commands.json')
before=jread(RUN/'before.json');after=jread(RUN/'after.json')
assert before==after and before['head']=='01723660c6b76e5e3cb69a2d49ff89454b40a080' and not before['status']
for relative,expected in before['sources'].items():
    assert sha((REPO/relative).read_bytes())==expected,relative
prebuild=jread(ROOT/'HEX-PREBUILD-SOURCE-REVIEW.json')
for relative,expected in prebuild['source_sha256'].items():
    assert sha((REPO/relative).read_bytes())==expected==before['sources'][relative]
expected_raw=(ROOT/'hex-iterator-expected.txt').read_bytes()
expected=expected_raw.splitlines()
inputs=(ROOT/'hex-iterator-input.txt').read_bytes()
assert sha(expected_raw)=='5ef611b5b3a99435d2ac9415d56bd3207f534753d9d647be75bc392b69a6f5cb'
assert sha(inputs)=='bf3bdfde49e8c2668159af0141db74bb9f1101000f281445d323b35f50cdcd2f'
assert len(expected)==185490 and len(inputs.splitlines())==39850
assert len({row.split(b'|',1)[1] for row in inputs.splitlines()})==39850
assert len(commands)==32 and len({row['label'] for row in commands})==32
raw={}
for command in commands:
    assert command['exit']==(128 if command['label']=='base-production-absent' else 0)
    for kind in ('stdout','stderr'):
        data=gzip.decompress((RUN/(command['label']+'.'+kind+'.gz')).read_bytes())
        assert sha(data)==command[kind+'_sha256']
        raw[command['label'],kind]=data
    if command['stdin_sha256'] is not None:
        assert command['stdin_sha256']==sha(inputs)
profiles=[]
for profile in result['profiles']:
    opt=profile['opt_level'];directory=RUN/('opt'+str(opt))
    data=raw[f'opt{opt}-observations','stdout']
    assert data==expected_raw and not raw[f'opt{opt}-observations','stderr']
    library=directory/'libnode94_hex_pair_iterator.rlib'
    assert library.read_bytes()==(directory/'rebuild'/library.name).read_bytes()
    assert sha(library.read_bytes())==profile['rlib_sha256']
    assert sha((directory/'input-only').read_bytes())==profile['driver_sha256']
    assert b'3 passed; 0 failed' in raw[f'opt{opt}-tests-run','stdout']
    profiles.append({'opt_level':opt,'cases':39850,'complete_observations':185490,
                     'raw_stdout_sha256':sha(data),'rlib_sha256':sha(library.read_bytes()),
                     'raw_rlib_rebuild_equal':True,'driver_sha256':profile['driver_sha256'],
                     'external_unique_test_methods':3})
mutants=[]
for mutant in result['mutants']:
    name=mutant['name'];actual=raw[name+'-observations','stdout'].splitlines()
    assert len(actual)==185490 and not raw[name+'-observations','stderr']
    assert sha((RUN/name/'lib.rs').read_bytes())==mutant['source_sha256']
    mismatches=[];cases=set()
    for found,wanted in zip(actual,expected):
        fields=found.split(b'|');want=wanted.split(b'|')
        assert len(fields)==7 and fields[:2]==want[:2]
        assert re.fullmatch(rb'[0-9a-f]{32}',fields[2])
        assert fields[3].isdigit() and fields[4].isdigit() and fields[3]==fields[4]
        assert fields[5] in (b'0',b'1') and fields[6]==b'1'
        if found!=wanted:
            mismatches.append(b'|'.join(want[:2]).decode())
            cases.add(want[0])
    assert len(mismatches)==mutant['mismatches']>0
    assert mismatches[:16]==mutant['first_mismatch_ids']
    mismatch_hash=sha(('\n'.join(mismatches)+'\n').encode())
    assert mismatch_hash==mutant['all_mismatch_ids_sha256']
    mutants.append({'name':name,'normal_complete_rows':len(actual),'normal_exit':0,
                    'different_observations':len(mismatches),'affected_unique_cases':len(cases),
                    'all_mismatch_ids_sha256':mismatch_hash,'source_sha256':mutant['source_sha256']})
assert [row['different_observations'] for row in mutants]==[57060,1341,76,152657,6690]
audit_raw=(PACKET/'provider/PROVIDER-AUDIT.json').read_bytes()
assert sha(audit_raw)=='56969b4e39acf17cf6f60f7c94d840a06bb37feb89cc577d0dcadfed7a71fdd6'
audit=json.loads(audit_raw);prefix=ROOT.parent/'toolchain/prefix'
assert len(audit['payloads'])==103
for record in audit['payloads']:
    relative=Path(record['path']);assert not relative.is_absolute() and '..' not in relative.parts
    data=(prefix/relative).read_bytes()
    assert len(data)==record['bytes'] and sha(data)==record['sha256']
for name,expected_hash in audit['installed_manifest_sha256'].items():
    assert sha((prefix/'lib/rustlib'/name).read_bytes())==expected_hash
assert sha((prefix/'bin/rustc').read_bytes())==result['provider_identity']['rustc_sha256']
for key in ('cc','ld'):
    assert sha(Path(result['linker'][key]).resolve().read_bytes())==result['linker'][key+'_sha256']
target=(REPO/'artifacts/node/94/hl-node').read_bytes()
assert len(target)==91774280 and sha(target)==result['target']['sha256']
for span in result['target']['spans']:
    assert sha(target[span['file_offset']:span['file_offset']+span['bytes']])==span['sha256']
python_stdout=(ROOT.parent/'hex-iterator-python-c1.stdout').read_bytes()
python_stderr=(ROOT.parent/'hex-iterator-python-c1.stderr').read_bytes()
assert b'Ran 3 tests' in python_stderr and python_stderr.rstrip().endswith(b'OK')
replays=jread(ROOT/'HEX-INDEPENDENT-REPLAYS.json')
assert len(replays['calls'])==2 and all(row['exit']==0 and row['observations']==185490 and row['stdout_sha256']==sha(expected_raw) for row in replays['calls'])
receipt={'schema':'hex953-scalar140-independent-actual-artifact-review-v1','status':'PASS',
         'source_build_head':before['head'],'source_before_after_equal':True,
         'all_five_current_execution_hashes_match_prebuild_and_actual_build':True,
         'result_sha256':sha((RUN/'result.json').read_bytes()),
         'commands_sha256':sha((RUN/'commands.json').read_bytes()),'commands':32,'raw_streams_verified':64,
         'provider_payloads_independently_rechecked':103,'installed_manifests_rechecked':True,
         'full_target_and_both_native_spans_reauthenticated':True,
         'native_and_helper_proof_receipt_sha256':sha((ROOT/'HEX-NATIVE-REVIEW.json').read_bytes()),
         'profiles':profiles,'compiled_normal_semantic_mutants':mutants,
         'python_unique_test_methods':3,'python_stdout_sha256':sha(python_stdout),
         'python_stderr_sha256':sha(python_stderr),
         'independent_actual_replay_receipt_sha256':sha((ROOT/'HEX-INDEPENDENT-REPLAYS.json').read_bytes()),
         'own_compiler_runs_by_reviewer':0,
         'limits':['Full953-byte native normal-domain relation and supporting140-byte valid-scalar proof remain distinct denominators.',
                   'Public core chars.next is an explicit real dependency, with no claimed new140-byte rebuilt identity or private ABI.',
                   'Malformed UTF8/forgedstates and native fault/panic/unwind behavior are excluded; all3exceptional routes are proved unreachable in this constructor domain.',
                   'No outerASCII20-byte API, captured execution/instruction evaluator, whole-node identity or gate advance.',
                   'Expanded make test and hostedCI remain NOT_RUN pending authorization.']}
out=ROOT/'HEX-ACTUAL-ARTIFACT-REVIEW.json';out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
print(json.dumps({'receipt_sha256':sha(out.read_bytes()),'profiles':profiles,'mutants':mutants,
                  'commands':32,'raw_streams':64},sort_keys=True))
