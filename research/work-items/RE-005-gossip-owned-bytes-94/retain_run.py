"""Lossless task-local retention of actual982 byte-pipeline evidence, no binaries."""
from pathlib import Path
import hashlib
import json
import zipfile

PACKET=Path(__file__).resolve().parent
ROOT=PACKET.parents[2]
RUN=ROOT/'work/gossip-owned-bytes-982-run1'

def digest(raw): return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

def main():
    commands=json.loads((RUN/'COMMANDS.json').read_bytes())
    assert len(commands)==68
    names={}
    def retain(name,path):
        assert not name.startswith('/') and '..' not in Path(name).parts and name not in names
        names[name]=path
    for c in commands:
        for side in ['stdout','stderr']:
            info=c[side]
            assert Path(info['path']).name==info['path']
            path=RUN/info['path']
            assert digest(path.read_bytes())=={k:info[k] for k in ['bytes','sha256']}
            retain('streams/'+path.name,path)
    for name in ['RESULT.json','COMMANDS.json','AUDIT-BEFORE.json','AUDIT-AFTER.json','COMPARATOR-CONTROLS.json']:
        retain(name,RUN/name)
    for side in ['stdout','stderr']:
        retain('wrapper.'+side,ROOT/'work'/('gossip-owned-bytes-982-run1.'+side))
    native=json.loads((RUN/'native/COMMANDS.json').read_bytes())
    assert len(native)==7
    for c in native:
        for side in ['stdout','stderr']:
            path=RUN/'native'/(c['label']+'.'+side)
            assert digest(path.read_bytes())==c[side]
            retain('native/'+path.name,path)
    for name in ['COMMANDS.json','REPORT.json']:
        retain('native/'+name,RUN/'native'/name)
    for role in ['primary','collection','validator','context-u64-wrapper','context-u64-reader','context-error']:
        retain('native/'+role+'.raw',RUN/'native'/(role+'.raw'))
    result=json.loads((RUN/'RESULT.json').read_bytes())
    artifacts={}
    for label,row in result['results'].items():
        for key,name in [('library','libnode94_gossip_owned_bytes.rlib'),('client','compare'),('tests','relations'),('own_IR','node94_gossip_owned_bytes.ll')]:
            raw=(RUN/label/name).read_bytes()
            assert digest(raw)==row[key]
            artifacts[label+'/'+name]={'retained_in_archive':False,**digest(raw)}
        if label not in ['O0','O3']:
            retain('mutants/'+label+'.rs',RUN/(label+'.rs'))
    for opt,wanted in result['dependency_artifacts'].items():
        name='dependency-O'+opt+'/libhl_bincode_varint.rlib'
        actual=digest((RUN/name).read_bytes());assert actual==wanted
        artifacts[name]={'retained_in_archive':False,**actual}
    name='repeat/libnode94_gossip_owned_bytes.rlib'
    actual=digest((RUN/name).read_bytes());assert actual==result['results']['O3']['library']
    artifacts[name]={'retained_in_archive':False,**actual}
    archive=PACKET/'ACTUAL-STREAMS.zip'
    assert not archive.exists()
    records={}
    with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for name,path in sorted(names.items()):
            raw=path.read_bytes();records[name]=digest(raw)
            info=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0))
            info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o100644<<16
            z.writestr(info,raw,compresslevel=9)
    with zipfile.ZipFile(archive) as z:
        assert set(z.namelist())==set(records)
        for name,path in names.items():
            assert z.read(name)==path.read_bytes()
    manifest={'schema':'owned982-actual-lossless-transport/1','source_checkpoint':result['source_checkpoint'],
              'encoding':'ZIP deflate, complete original bytes; fixed timestamps; no normalization',
              'archive':digest(archive.read_bytes()),'files':records,
              'original_bytes':sum(x['bytes'] for x in records.values()),
              'recorded_commands':len(commands),'outer_raw_streams':len(commands)*2,
              'nested_native_commands':len(native),'nested_native_raw_streams':len(native)*2,
              'compiled_artifacts_excluded':artifacts,
              'limits':['No private holdout inputs or answers.','No compiled binaries, full ELF or provider payloads.','All original raw files remain in ignored work.']}
    (PACKET/'ACTUAL-STREAMS.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    for name in ['RESULT.json','COMPARATOR-CONTROLS.json']:
        (PACKET/('RUST-'+name)).write_bytes((RUN/name).read_bytes())
    print(json.dumps({'files':len(records),'original_bytes':manifest['original_bytes'],'archive':manifest['archive'],'artifacts_hashed':len(artifacts)},sort_keys=True))

if __name__=='__main__': main()
