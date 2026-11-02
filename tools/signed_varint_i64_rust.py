#!/usr/bin/env python3
"""Qualify the actual signed357 projection with two real Rust libraries.

Only independently authored/project Rust executes. Original code, native
instruction interpreters, network services and expanded suites never run.
"""
from pathlib import Path
import argparse,hashlib,json,os,re,shutil,stat,subprocess,sys,time

from libcore_fmt_correspondence import Elf,ar_members
import signed_varint_i64_reference as reference

ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-005-signed-varint-i64-94'
COMPONENT=ROOT/'src/node94-signed-varint-i64'
SOURCE=COMPONENT/'lib.rs'
DRIVER=COMPONENT/'input_only_driver.rs'
DEP=ROOT/'src/bincode-varint/src/lib.rs'
CRATE='node94_signed_varint_i64'
DEP_CRATE='hl_bincode_varint'
RUSTC_SHA='ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d'
CARGO_SHA='638ab45125934a94e94980d5ae6aa3641257914f0882fcbf116d643fa7ec405b'
PROVIDER_SHA='56969b4e39acf17cf6f60f7c94d840a06bb37feb89cc577d0dcadfed7a71fdd6'

def need(ok,message):
    if not ok:raise ValueError(message)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb')as f:
        for raw in iter(lambda:f.read(1<<20),b''):h.update(raw)
    return h.hexdigest()

def physical(path):
    path=Path(path);mode=oct(stat.S_IMODE(path.lstat().st_mode))
    if path.is_symlink():
        raw=os.readlink(path).encode();return {'kind':'symlink-text','physical_mode':mode,'bytes':len(raw),'sha256':sha(raw)}
    need(path.is_file(),'Missing physical file: '+str(path))
    return {'kind':'regular-file','physical_mode':mode,'bytes':path.stat().st_size,'sha256':digest(path)}

def audit(root,rustc,cargo,provider_path):
    config_roots=set([root,*root.parents,COMPONENT,*COMPONENT.parents,DEP.parent.parent])
    for directory in config_roots:
        for name in ('config','config.toml'):
            need(not os.path.lexists(directory/'.cargo'/name),
                 'Unadmitted ancestor/component Cargo configuration: '+str(directory/'.cargo'/name))
    def git(repo,*args):
        return subprocess.check_output(['/usr/bin/git',*args],cwd=repo,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},stdin=subprocess.DEVNULL)
    files={};pins={}
    def walk(repo,prefix=''):
        for raw in git(repo,'ls-files','--stage','-z').split(b'\0'):
            if not raw:continue
            header,name=raw.split(b'\t',1);mode,oid,stage=header.decode().split();need(stage=='0','Unmerged physical input')
            name=name.decode();rel=Path(name);need(not rel.is_absolute()and'..'not in rel.parts,'Tracked path escapes root')
            path=repo/rel;key=prefix+name
            if mode=='160000':
                head=git(path,'rev-parse','HEAD').decode().strip();status=git(path,'status','--porcelain=v1','--untracked-files=all').decode()
                need(head==oid and not status,'Actual child pin/content changed: '+key)
                pins[key]={'index':oid,'actual':head,'clean':True};walk(path,key+'/')
            else:
                need(mode in ('100644','100755','120000')and(mode=='120000')==path.is_symlink(),'Unexpected physical kind')
                files[key]={'index_mode':mode,**physical(path)}
    walk(root);need(len(pins)==7,'Seven actual pinned children required')
    need(digest(provider_path)==PROVIDER_SHA,'Authenticated provider audit differs')
    provider=json.loads(Path(provider_path).read_text());prefix=rustc.parent.parent;payloads={};manifests={}
    for row in provider['payloads']:
        rel=Path(row['path']);need(not rel.is_absolute()and'..'not in rel.parts,'Provider path escapes prefix')
        value=physical(prefix/rel);need(value['bytes']==row['bytes']and value['sha256']==row['sha256'],'Provider payload differs')
        payloads[row['path']]=value
    need(len(payloads)==provider['payload_count']==103,'Provider denominator differs')
    for name,wanted in provider['installed_manifest_sha256'].items():
        need(Path(name).name==name,'Installed manifest path escapes prefix')
        value=physical(prefix/'lib/rustlib'/name);need(value['sha256']==wanted,'Installed manifest differs');manifests[name]=value
    need(len(manifests)==2,'Two installed manifests required')
    tools={}
    for name,path in [('rustc',rustc),('rustdoc',rustc.with_name('rustdoc')),('cargo',cargo)]+[(n,Path(shutil.which(n,path='/usr/bin:/bin')or'/nonexistent'))for n in ['cc','ld.bfd','objdump']]:
        canonical=path.resolve(strict=True);tools[name]={'chosen':str(path),'canonical':str(canonical),**physical(canonical)}
    return {'head':git(root,'rev-parse','HEAD').decode().strip(),'tree':git(root,'rev-parse','HEAD^{tree}').decode().strip(),
            'status':git(root,'status','--porcelain=v1','--untracked-files=all').decode(),
            'physical_count':len(files),'physical_inputs':files,'pins':pins,
            'provider_payloads':payloads,'installed_manifests':manifests,'tools':tools}

def compare(actual,expected):
    rows,wanted=actual.splitlines(),expected.splitlines();need(len(rows)==len(wanted),'Observation row denominator differs')
    different=[]
    for i,(a,b)in enumerate(zip(rows,wanted)):
        x,y=json.loads(a),json.loads(b)
        need(list(x)==reference.KEYS and a==json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode(),'Actual observation is not canonical JSONL')
        need(x['id']==y['id']and x['call']==y['call'],'Actual observation identities/order differ')
        if a!=b:different.append(i)
    need(actual.endswith(b'\n')and b'\r'not in actual,'Actual observation framing differs')
    return different

def comparator_controls(expected):
    rows=expected.splitlines();changed=list(rows);first=json.loads(changed[0])
    need(first['tag']==0 and first['additional']==1,'Independent initial control row differs')
    first['additional']=2
    changed[0]=json.dumps(first,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
    need(compare(b'\n'.join(changed)+b'\n',expected)==[0],'Altered-content comparator control failed')
    results=[{'name':'altered-active-content','different_row_indices':[0]}]
    for name,raw in [('missing-row',b'\n'.join(rows[:-1])+b'\n'),
                     ('extra-row',expected+rows[-1]+b'\n')]:
        try:compare(raw,expected)
        except ValueError as error:results.append({'name':name,'refusal':str(error)})
        else:raise ValueError('Comparator admitted '+name)
    return results

def artifacts(folder,crate,execute,label,objdump):
    files=[folder/('lib'+crate+'.rlib'),folder/(crate+'.o'),folder/(crate+'.ll')]
    need(all(p.is_file()for p in files),'Actual Rust recipe omitted rlib/object/IR')
    undefined=set();definitions=[]
    for member,raw in ar_members(files[0].read_bytes()).items():
        if raw[:4]!=b'\x7fELF':continue
        elf=Elf(raw,1)
        for table in elf.sections:
            if table['type']!=2:continue
            for s in elf.symbols(table['index']):
                if not s['section']and s['name']:undefined.add(s['name'])
                if s['section']and s['info']&15==2 and crate in s['name']and('read_i64'in s['name']or'read_u64'in s['name']):
                    function=elf.function(s['section'],s['name']);body=elf.section_bytes(s['section'])
                    definitions.append({'member':member,'symbol':function,'bytes':len(body),'sha256':sha(body),'code_relocations':elf.relocations(s['section'])})
    need(len(definitions)==1,'Actual selected Rust decoder function missing/ambiguous')
    execute(label+'-own-object-disassembly',[objdump,'-dr','-Mintel',files[1]])
    return {'files':{p.name:{'bytes':p.stat().st_size,'sha256':digest(p)}for p in files},
            'undefined_symbols':sorted(undefined),'selected_decoder_definitions':definitions,
            'scope':'Actual own/project compiled artifacts; object inspection is not target-byte identity.'}

def mutations(text):
    changes=[{'name':'opposite-parity','needle':'let sign = -((unsigned & 1) as i64);',
              'replacement':'let sign = -(((unsigned ^ 1) & 1) as i64);','relation':'Use the opposite sign parity for every successful unsigned payload.'},
             {'name':'unmapped-found-code','needle':'found_code: signed_code(found_code),',
              'replacement':'found_code,','relation':'Fail to rewrite the active found-type code while still rewriting expected.'},
             {'name':'fast-type-errors-use-reader','needle':'if input.len() > 8 {',
              'replacement':'if input.len() > 8 && input[0] < 254 {','relation':'Wrongly give fast invalid markers Reader consumption and expected-code behavior.'}]
    for x in changes:need(text.count(x['needle'])==1,'Semantic mutant needle is not unique: '+x['name'])
    return changes

def build(binary,rustc,cargo,provider_path,output):
    rustc,cargo,provider_path,output=[Path(x).absolute()for x in (rustc,cargo,provider_path,output)]
    need(not os.path.lexists(output),'New output directory required; preserve previous runs')
    need(digest(rustc)==RUSTC_SHA and digest(cargo)==CARGO_SHA,'Selected actual compiler/Cargo differs')
    expected=reference.fresh(binary)
    before=audit(ROOT,rustc,cargo,provider_path);need(not before['status'],'Commit a clean source checkpoint first')
    output.mkdir(parents=True);(output/'tmp').mkdir();(output/'cargo-home').mkdir()
    (output/'inputs.tsv').write_bytes(expected['inputs']);(output/'expected.jsonl').write_bytes(expected['expected'])
    (output/'oracle.json').write_text(json.dumps(expected['metadata'],indent=2)+'\n')
    (output/'native.json').write_text(json.dumps(expected['native_record'],indent=2)+'\n')
    calls=[];env={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C','TZ':'UTC','TMPDIR':str(output/'tmp')}
    def execute(label,argv,code=0,extra_env=None):
        start=time.monotonic();p=subprocess.run([str(x)for x in argv],cwd=ROOT,env={**env,**(extra_env or{})},stdin=subprocess.DEVNULL,capture_output=True)
        logs={}
        for kind,raw in [('stdout',p.stdout),('stderr',p.stderr)]:
            name=label+'.'+kind;(output/name).write_bytes(raw);logs[kind]={'file':name,'bytes':len(raw),'sha256':sha(raw)}
        calls.append({'label':label,'argv':[str(x)for x in argv],'exit_code':p.returncode,'seconds':round(time.monotonic()-start,3),'logs':logs})
        (output/'CALLS.json').write_text(json.dumps(calls,indent=2)+'\n')
        need(p.returncode==code,label+' unexpected exit; exact streams retained')
        return p.stdout,p.stderr
    try:
        versions={}
        for name,argv in [('rustc',[rustc,'-vV']),('cargo',[cargo,'--version']),('cc',['/usr/bin/cc','--version']),('ld.bfd',['/usr/bin/ld.bfd','--version']),('objdump',['/usr/bin/objdump','--version'])]:
            versions[name]=execute(name+'-identity',argv)[0].decode()
        need(versions['rustc'].startswith('rustc 1.94.1 ')and'e408947bfd200af42db322daf0fadfe7e26d3bd1'in versions['rustc'],'Actual rustc version/commit differs')
        need(versions['cargo'].startswith('cargo 1.89.0 (d96b80636'),'Actual reused Cargo version differs')
        selected=execute('cc-selected-ld-bfd',['/usr/bin/cc','-print-prog-name=ld.bfd'])[0].decode().strip()
        chosen=Path(selected)if Path(selected).is_absolute()else Path(shutil.which(selected,path=env['PATH'])or'/nonexistent')
        need(chosen.resolve(strict=True)==Path('/usr/bin/ld.bfd').resolve(strict=True),'C driver selects another actual bfd')
        static_stdout,static_stderr=execute('native-focused-controls',[sys.executable,'-B','-m','unittest','tests.test_signed_varint_i64_contract','-v'])
        need(re.search(rb'Ran 11 tests in ',static_stdout+static_stderr)is not None and b'\nOK\n'in static_stdout+static_stderr,
             'All eleven actual native/static methods did not pass')
        comparison_controls=comparator_controls(expected['expected'])
        def flags(opt):return ['--edition=2024','-D','warnings','-C','codegen-units=1','-C',f'opt-level={opt}','-C','overflow-checks=on','-C','linker=/usr/bin/cc','-C','link-arg=-fuse-ld=bfd','--remap-path-prefix',str(ROOT)+'=/reconstruction']
        checks=[];dependency_outputs={}
        def library(label,source,opt,folder,dependency=None):
            folder.mkdir(parents=True,exist_ok=False);crate=CRATE if dependency is not None else DEP_CRATE
            args=[rustc,'--crate-name',crate,'--crate-type=rlib',source,'--emit=link,obj,llvm-ir','--out-dir',folder,'-C','metadata=research-signed64',*flags(opt)]
            if dependency is not None:args+=['--extern',DEP_CRATE+'='+str(dependency),'-L','dependency='+str(dependency.parent)]
            execute(label,args);checks.append({'label':label,**artifacts(folder,crate,execute,label,'/usr/bin/objdump')})
            return folder/('lib'+crate+'.rlib')
        def production(label,lib,opt,dep,folder):
            program=folder/'production'
            execute(label+'-link',[rustc,DRIVER,'--crate-name','signed64_observer','--extern',CRATE+'='+str(lib),'-L','dependency='+str(dep.parent),'-o',program,*flags(opt)])
            raw=execute(label+'-run',[program,output/'inputs.tsv'])[0]
            return program,raw
        def ordinary(label,source,opt,dep,folder,failed=False):
            program=folder/'ordinary-tests'
            execute(label+'-build',[rustc,'--test',source,'--crate-name',CRATE,'--extern',DEP_CRATE+'='+str(dep),'-L','dependency='+str(dep.parent),'-o',program,*flags(opt)])
            stdout,stderr=execute(label+'-run',[program,'--nocapture','--test-threads=1'],101 if failed else 0)
            if failed:need(b'FAILED'in stdout+stderr and b'panicked at'in stdout+stderr,'Expected genuine semantic assertion failure absent')
            else:need(b'test result: ok. 1 passed; 0 failed;'in stdout,'One actual ordinary unit method did not pass')
            return {'expected_exit':101 if failed else 0,'ordinary_methods':1,'first_call_vectors':20,'program_sha256':digest(program)}
        profiles=[]
        for name,opt in [('debug',0),('optimized',3)]:
            dep=library(name+'-dependency',DEP,opt,output/(name+'-dependency'));dependency_outputs[name]=dep
            folder=output/name;lib=library(name+'-signed-library',SOURCE,opt,folder,dep)
            tests=ordinary(name+'-ordinary',SOURCE,opt,dep,folder)
            program,raw=production(name+'-production',lib,opt,dep,folder)
            need(not compare(raw,expected['expected'])and raw==expected['expected'],name+' exact independent observations differ')
            profiles.append({'name':name,'opt_level':opt,'stimuli':27671,'observations':89218,'actual_sha256':sha(raw),'expected_sha256':sha(expected['expected']),
                             'program':str(program),'program_sha256':digest(program),'library_sha256':digest(lib),'dependency_sha256':digest(dep),'ordinary':tests})
        optimized=output/'optimized'/('lib'+CRATE+'.rlib')
        repeat=library('repro-b',SOURCE,3,output/'repro-b',dependency_outputs['optimized'])
        reproducibility={'scope':'Signed rlib only, using the same qualified unchanged optimized dependency artifact','a_bytes':optimized.stat().st_size,'b_bytes':repeat.stat().st_size,'a_sha256':digest(optimized),'b_sha256':digest(repeat),'raw_equal':optimized.read_bytes()==repeat.read_bytes(),'normalization':'none','target_byte_identity':False}
        need(reproducibility['raw_equal'],'Own signed rlib rebuild differs')
        mutants=[];source_text=SOURCE.read_text()
        for change in mutations(source_text):
            folder=output/('mutant-'+change['name']);folder.mkdir()
            for file in [SOURCE,COMPONENT/'unit-vectors.tsv']:shutil.copy2(file,folder/file.name)
            altered=folder/'lib.rs';altered.write_text(source_text.replace(change['needle'],change['replacement']))
            dep=dependency_outputs['debug'];lib=library('mutant-'+change['name']+'-library',altered,0,folder/'library',dep)
            _,raw=production('mutant-'+change['name']+'-production',lib,0,dep,folder)
            differences=compare(raw,expected['expected']);need(differences,'Compiled mutant did not produce a logical mismatch')
            tests=ordinary('mutant-'+change['name']+'-ordinary',altered,0,dep,folder,True)
            actual_rows,wanted_rows=raw.splitlines(),expected['expected'].splitlines()
            witnesses=[{'expected':json.loads(wanted_rows[i]),'actual':json.loads(actual_rows[i])}for i in differences[:4]]
            mutants.append({'name':change['name'],'relation':change['relation'],'production_exit':0,'observations':len(actual_rows),'different_observations':len(differences),'actual_witnesses':witnesses,'ordinary':tests,'source_sha256':digest(altered)})
        cargo_env={'RUSTC':str(rustc),'RUSTDOC':str(rustc.with_name('rustdoc')),'CARGO_HOME':str(output/'cargo-home'),'CARGO_TARGET_DIR':str(output/'cargo-target'),'CARGO_NET_OFFLINE':'true',
                   'RUSTFLAGS':'-D warnings -C codegen-units=1 -C overflow-checks=on -C linker=/usr/bin/cc -C link-arg=-fuse-ld=bfd --remap-path-prefix '+str(ROOT)+'=/reconstruction'}
        execute('cargo-locked-offline-build',[cargo,'build','--jobs','1','--offline','--locked','--manifest-path',COMPONENT/'Cargo.toml'],extra_env=cargo_env)
        after=audit(ROOT,rustc,cargo,provider_path);need(before==after,'Physical inputs/pins/provider/head/tree/status/tools changed')
        result={'status':'PASS','source_before':before,'source_after':after,'tool_versions':versions,'cc_selected_bfd':{'reported':selected,'canonical':str(chosen.resolve()),'sha256':digest(chosen)},
                'oracle':expected['metadata'],'profiles':profiles,'own_signed_reproducibility':reproducibility,'semantic_mutants':mutants,'actual_library_artifacts':checks,'calls':calls,
                'native_focused_methods':11,'comparator_controls':comparison_controls,
                'child_environment':env,'cargo_environment':cargo_env,'limits':['Only own/project Rust executes; no captured execution or instruction evaluator.','Logical active fields and complete residual state only; no undefined/padding byte claim.','Primary357 is new signed recovery; previously established330-byte helpers are dependencies.','Signed rlib reproducibility is not target-byte identity or dependency rebuild reproducibility.','Input-only data flow is not an operating-system sandbox.','Expanded/full suite, hosted CI, original ABI/compiler/caller/whole-node and full-component gates unclaimed.']}
        (output/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n');return result
    except Exception as error:
        (output/'FAILURE.json').write_text(json.dumps({'error':str(error),'calls':calls},indent=2)+'\n');raise

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/94/hl-node')
    parser.add_argument('--rustc',type=Path,required=True);parser.add_argument('--cargo',type=Path,required=True)
    parser.add_argument('--provider-audit',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();result=build(args.binary,args.rustc,args.cargo,args.provider_audit,args.output)
    print(json.dumps({'status':result['status'],'stimuli':27671,'observations_per_profile':89218,'commands':len(result['calls']),'normal_mutants':len(result['semantic_mutants'])}))

if __name__=='__main__':main()
