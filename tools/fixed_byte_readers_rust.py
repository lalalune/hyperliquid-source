#!/usr/bin/env python3
"""Qualify the actual paired217 write/cursor/counter relation using own Rust.

No captured executable, instruction evaluator, network service or full suite.
The existing audited physical/provider recipe is reused for this bounded RE task.
"""
from pathlib import Path
import argparse,hashlib,json,os,re,shutil,stat,subprocess,sys,time
from libcore_fmt_correspondence import Elf,ar_members
import fixed_byte_readers_reference as reference

ROOT=Path(__file__).resolve().parents[1]
PACKET=ROOT/'research/work-items/RE-005-fixed-byte-readers-94'
COMPONENT=ROOT/'src/node94-fixed-byte-readers'
SOURCE=COMPONENT/'lib.rs'
DRIVER=COMPONENT/'input_only_driver.rs'
CRATE='node94_fixed_byte_readers'
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
    config_roots=set([root,*root.parents,COMPONENT,*COMPONENT.parents])
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
    need(first['kind']=='value' and first['output'].startswith('12'),
         'Initial independent result control differs')
    first['output']='13'+first['output'][2:]
    changed[0]=json.dumps(first,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
    need(compare(b'\n'.join(changed)+b'\n',expected)==[0],'Changed-result comparator control failed')
    results=[{'name':'altered-result-byte','different_row_indices':[0]}]
    for name,raw in [('missing-row',b'\n'.join(rows[:-1])+b'\n'),
                     ('extra-row',expected+rows[-1]+b'\n')]:
        try:compare(raw,expected)
        except ValueError as error:results.append({'name':name,'refusal':str(error)})
        else:raise ValueError('Comparator admitted '+name)
    return results

def artifacts(folder,execute,label):
    files=[folder/('lib'+CRATE+'.rlib'),folder/(CRATE+'.o'),folder/(CRATE+'.ll')]
    need(all(path.is_file()for path in files),'Actual library/object/IR omitted')
    undefined=set();definitions=[]
    for member,raw in ar_members(files[0].read_bytes()).items():
        if raw[:4]!=b'\x7fELF':continue
        elf=Elf(raw,1)
        for table in elf.sections:
            if table['type']!=2:continue
            for symbol in elf.symbols(table['index']):
                name=symbol['name']
                if not symbol['section'] and name:undefined.add(name)
                if symbol['section'] and symbol['info']&15==2 and CRATE in name and any(x in name for x in ('read_20','read_32')):
                    function=elf.function(symbol['section'],name)
                    body=elf.section_bytes(symbol['section'])
                    definitions.append({'member':member,'symbol':function,'bytes':len(body),
                                        'sha256':sha(body),'code_relocations':elf.relocations(symbol['section'])})
    need(len(definitions)==2,'Exactly two real public reader definitions required')
    obj=Elf(files[1].read_bytes(),1);ir=files[2].read_text()
    for definition in definitions:
        name=definition['symbol']['name'];matches=[]
        for table in obj.sections:
            if table['type']!=2:continue
            matches.extend(symbol for symbol in obj.symbols(table['index'])if symbol['name']==name and symbol['section'])
        need(len(matches)==1,'Own object reader definition missing/ambiguous')
        selected=matches[0];function=obj.function(selected['section'],name)
        need(sha(obj.section_bytes(selected['section']))==definition['sha256'] and
             obj.relocations(selected['section'])==definition['code_relocations'],
             'Actual rlib/object selected reader differs')
        need(any(line.startswith('define ') and name in line for line in ir.splitlines()),
             'Actual LLVM IR reader definition absent')
    execute(label+'-own-object-disassembly',['/usr/bin/objdump','-dr','-Mintel',files[1]])
    return {'files':{p.name:{'bytes':p.stat().st_size,'sha256':digest(p)}for p in files},
            'undefined_symbols':sorted(undefined),'selected_decoder_definitions':definitions,
            'rlib_object_IR_reader_binding':True,
            'scope':'Actual own compiled functions; no original compiled-byte identity claim.'}

def mutations(source):
    changes=[{'name':'rollback-limit-charge','needle':'    *charged = next;\n    next <= limit',
              'replacement':'    if next > limit { return false; }\n    *charged = next;\n    true',
              'occurrences':1,'relation':'Wrongly discard the increment on a limit error.'},
             {'name':'clear-inactive-result','needle':') -> Outcome {\n    if !charge_permitted',
              'replacement':') -> Outcome {\n    output.fill(0);\n    if !charge_permitted',
              'occurrences':2,'relation':'Wrongly clear supplied result bytes before the native write set.'},
             {'name':'thirtytwo-success-tag18','needle':'    output[0] = 0;\n    *input = &input[32..];',
              'replacement':'    output[0] = 18;\n    *input = &input[32..];',
              'occurrences':1,'relation':'Wrongly apply the twenty-byte leading success tag to the thirty-two-byte result.'}]
    for change in changes:
        need(source.count(change['needle'])==change['occurrences'],'Semantic mutant source pattern differs')
    return changes

def build(binary,rustc,cargo,provider_path,output):
    rustc,cargo,provider_path,output=[Path(x).absolute()for x in (rustc,cargo,provider_path,output)]
    need(not os.path.lexists(output),'New output directory required; preserve earlier runs')
    need(digest(rustc)==RUSTC_SHA and digest(cargo)==CARGO_SHA,'Selected compiler/Cargo differs')
    expected=reference.fresh(binary)
    before=audit(ROOT,rustc,cargo,provider_path)
    need(not before['status'],'Preserve a clean source checkpoint before compilation')
    output.mkdir(parents=True);(output/'tmp').mkdir();(output/'cargo-home').mkdir()
    (output/'inputs.txt').write_bytes(expected['inputs'])
    (output/'expected.jsonl').write_bytes(expected['expected'])
    (output/'oracle.json').write_text(json.dumps(expected['metadata'],indent=2)+'\n')
    (output/'native.json').write_text(json.dumps(expected['native_record'],indent=2)+'\n')
    calls=[];env={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C','TZ':'UTC','TMPDIR':str(output/'tmp')}
    def execute(label,argv,code=0,extra_env=None):
        started=time.monotonic()
        result=subprocess.run([str(x)for x in argv],cwd=ROOT,env={**env,**(extra_env or{})},
                              stdin=subprocess.DEVNULL,capture_output=True)
        logs={}
        for kind,raw in [('stdout',result.stdout),('stderr',result.stderr)]:
            name=label+'.'+kind;(output/name).write_bytes(raw)
            logs[kind]={'file':name,'bytes':len(raw),'sha256':sha(raw)}
        calls.append({'label':label,'argv':[str(x)for x in argv],'exit_code':result.returncode,
                      'seconds':round(time.monotonic()-started,3),'logs':logs})
        (output/'CALLS.json').write_text(json.dumps(calls,indent=2)+'\n')
        need(result.returncode==code,label+' unexpected exit; raw streams retained')
        return result.stdout,result.stderr
    try:
        versions={}
        for name,argv in [('rustc',[rustc,'-vV']),('cargo',[cargo,'--version']),
                          ('cc',['/usr/bin/cc','--version']),('ld.bfd',['/usr/bin/ld.bfd','--version']),
                          ('objdump',['/usr/bin/objdump','--version'])]:
            versions[name]=execute(name+'-identity',argv)[0].decode()
        need(versions['rustc'].startswith('rustc 1.94.1 ') and 'e408947bfd200af42db322daf0fadfe7e26d3bd1'in versions['rustc'],
             'Actual rustc version/commit differs')
        need(versions['cargo'].startswith('cargo 1.89.0 (d96b80636'),'Actual selected Cargo differs')
        selected=execute('cc-selected-ld-bfd',['/usr/bin/cc','-print-prog-name=ld.bfd'])[0].decode().strip()
        chosen=Path(selected)if Path(selected).is_absolute()else Path(shutil.which(selected,path=env['PATH'])or'/nonexistent')
        need(chosen.resolve(strict=True)==Path('/usr/bin/ld.bfd').resolve(strict=True),'Actual C driver selects another bfd')
        stdout,stderr=execute('native-focused-controls',[sys.executable,'-B','-m','unittest','tests.test_fixed_byte_readers_contract','-v'])
        need(re.search(rb'Ran 12 tests in ',stdout+stderr)is not None and b'\nOK\n'in stdout+stderr,
             'All twelve actual native/static methods did not pass')
        comparison_controls=comparator_controls(expected['expected'])
        def flags(opt):
            return ['--edition=2024','-D','warnings','-C','codegen-units=1','-C',f'opt-level={opt}',
                    '-C','overflow-checks=on','-C','linker=/usr/bin/cc','-C','link-arg=-fuse-ld=bfd',
                    '--remap-path-prefix',str(ROOT)+'=/reconstruction']
        checks=[]
        def library(label,source,opt,folder):
            folder.mkdir(parents=True,exist_ok=False)
            execute(label,[rustc,'--crate-name',CRATE,'--crate-type=rlib',source,
                           '--emit=link,obj,llvm-ir','--out-dir',folder,'-C','metadata=research-fixed217',*flags(opt)])
            checks.append({'label':label,**artifacts(folder,execute,label)})
            return folder/('lib'+CRATE+'.rlib')
        def production(label,library,opt,folder):
            program=folder/'production'
            execute(label+'-link',[rustc,DRIVER,'--crate-name','fixed217_observer',
                                   '--extern',CRATE+'='+str(library),'-o',program,*flags(opt)])
            raw=execute(label+'-run',[program,output/'inputs.txt'])[0]
            return program,raw
        def ordinary(label,source,opt,folder,failed=False):
            program=folder/'ordinary-tests'
            execute(label+'-build',[rustc,'--test',source,'--crate-name',CRATE,'-o',program,*flags(opt)])
            stdout,stderr=execute(label+'-run',[program,'--nocapture','--test-threads=1'],101 if failed else 0)
            if failed:
                need(b'FAILED'in stdout+stderr and b'panicked at'in stdout+stderr,'Genuine semantic assertion failure absent')
            else:
                need(b'test result: ok. 1 passed; 0 failed;'in stdout,'One ordinary unit method did not pass')
            return {'expected_exit':101 if failed else 0,'ordinary_methods':1,'stimuli':20,
                    'observations':50,'program_sha256':digest(program)}
        profiles=[]
        for name,opt in [('debug',0),('optimized',3)]:
            folder=output/name;lib=library(name+'-library',SOURCE,opt,folder)
            tests=ordinary(name+'-ordinary',SOURCE,opt,folder)
            program,raw=production(name+'-production',lib,opt,folder)
            need(not compare(raw,expected['expected']) and raw==expected['expected'],
                 name+' exact independent initialized-result observations differ')
            profiles.append({'name':name,'opt_level':opt,'stimuli':50391,'observations':122634,
                             'actual_sha256':sha(raw),'expected_sha256':sha(expected['expected']),
                             'program':str(program),'program_sha256':digest(program),
                             'library_sha256':digest(lib),'ordinary':tests})
        optimized=output/'optimized'/('lib'+CRATE+'.rlib')
        repeat=library('repro-b',SOURCE,3,output/'repro-b')
        reproducibility={'a_bytes':optimized.stat().st_size,'b_bytes':repeat.stat().st_size,
                         'a_sha256':digest(optimized),'b_sha256':digest(repeat),
                         'raw_equal':optimized.read_bytes()==repeat.read_bytes(),
                         'normalization':'none','target_byte_identity':False}
        need(reproducibility['raw_equal'],'Own optimized rlib rebuild differs')
        mutants=[];source_text=SOURCE.read_text()
        for change in mutations(source_text):
            folder=output/('mutant-'+change['name']);folder.mkdir()
            for file in [SOURCE,COMPONENT/'unit-vectors.tsv']:shutil.copy2(file,folder/file.name)
            altered=folder/'lib.rs';altered.write_text(source_text.replace(change['needle'],change['replacement']))
            lib=library('mutant-'+change['name']+'-library',altered,0,folder/'library')
            _,raw=production('mutant-'+change['name']+'-production',lib,0,folder)
            differences=compare(raw,expected['expected'])
            need(differences,'Normal compiled variant did not produce a logical mismatch')
            tests=ordinary('mutant-'+change['name']+'-ordinary',altered,0,folder,True)
            actual_rows,wanted_rows=raw.splitlines(),expected['expected'].splitlines()
            witnesses=[{'expected':json.loads(wanted_rows[i]),'actual':json.loads(actual_rows[i])}for i in differences[:4]]
            mutants.append({'name':change['name'],'relation':change['relation'],'production_exit':0,
                            'observations':len(actual_rows),'different_observations':len(differences),
                            'actual_witnesses':witnesses,'ordinary':tests,'source_sha256':digest(altered)})
        cargo_env={'RUSTC':str(rustc),'RUSTDOC':str(rustc.with_name('rustdoc')),
                   'CARGO_HOME':str(output/'cargo-home'),'CARGO_TARGET_DIR':str(output/'cargo-target'),
                   'CARGO_NET_OFFLINE':'true','RUSTFLAGS':'-D warnings -C codegen-units=1 -C overflow-checks=on -C linker=/usr/bin/cc -C link-arg=-fuse-ld=bfd --remap-path-prefix '+str(ROOT)+'=/reconstruction'}
        execute('cargo-locked-offline-build',[cargo,'build','--jobs','1','--offline','--locked',
                                            '--manifest-path',COMPONENT/'Cargo.toml'],extra_env=cargo_env)
        after=audit(ROOT,rustc,cargo,provider_path)
        need(before==after,'Physical source/pins/provider/head/tree/status/tools changed')
        result={'status':'PASS','source_before':before,'source_after':after,'tool_versions':versions,
                'cc_selected_bfd':{'reported':selected,'canonical':str(chosen.resolve()),'sha256':digest(chosen)},
                'oracle':expected['metadata'],'profiles':profiles,'own_reproducibility':reproducibility,
                'semantic_mutants':mutants,'actual_library_artifacts':checks,'calls':calls,
                'native_focused_methods':12,'comparator_controls':comparison_controls,
                'child_environment':env,'cargo_environment':cargo_env,
                'limits':['Only own Rust executes; no captured execution or instruction evaluator.',
                          'Full result bytes require the supplied initialized separated21/33-byte projection.',
                          '217 primary bytes are the family;529 caller-context bytes are not reconstructed.',
                          'Own rlib reproducibility is not original compiled-byte identity.',
                          'Input-only data flow is not an operating-system sandbox.',
                          'Original ABI/caller/whole-codec/node, expanded/full suite, hosted CI and component gates unclaimed.']}
        (output/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
        return result
    except Exception as error:
        (output/'FAILURE.json').write_text(json.dumps({'error':str(error),'calls':calls},indent=2)+'\n')
        raise

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/94/hl-node')
    parser.add_argument('--rustc',type=Path,required=True)
    parser.add_argument('--cargo',type=Path,required=True)
    parser.add_argument('--provider-audit',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=build(args.binary,args.rustc,args.cargo,args.provider_audit,args.output)
    print(json.dumps({'status':result['status'],'stimuli':50391,'observations_per_profile':122634,
                      'commands':len(result['calls']),'normal_mutants':len(result['semantic_mutants'])}))

if __name__=='__main__':
    main()
