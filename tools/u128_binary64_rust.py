#!/usr/bin/env python3
"""Build and qualify the independently authored unsigned128-to-binary64 bit projection.

The complete132-byte static proof and independently frozen bit authority supply expectations;
only our Rust library, input-only client and ordinary unit tests execute.
Captured target code and instruction emulators never execute here.
"""
from pathlib import Path
import argparse,hashlib,json,os,re,shutil,stat,subprocess,time
import u128_binary64_reference as reference
from libcore_fmt_correspondence import Elf, ar_members
import u128_binary64_contract as native

CRATE='node94_u128_binary64'
COMPILER_SHA256='ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d'

def need(ok,message):
    if not ok:raise ValueError(message)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def file_digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb')as f:
        for raw in iter(lambda:f.read(1<<20),b''):h.update(raw)
    return h.hexdigest()

def mismatch_ids(actual,wanted):
    rows,expected=actual.splitlines(),wanted.splitlines()
    need(len(rows)==len(expected),'Production row count differs, not a normal semantic control')
    for row in rows:
        parts=row.split(b'|')
        need(len(parts)==2 and re.fullmatch(rb'[0-9a-f]{16}',parts[1])is not None,
             'Production row is not a complete normal64-bit encoding')
    mismatches=[]
    for row,answer in zip(rows,expected):
        identifier=answer.split(b'|',1)[0]
        need(row.split(b'|',1)[0]==identifier,'Production case identities/order differ')
        if row!=answer:mismatches.append(identifier.decode('ascii'))
    return mismatches

def qualify(root,expected,source,fixture,rustc,output,harness,mutations,provider_audit,additional_sources=()):
    root,source,fixture,rustc,output=(Path(p).absolute()for p in(root,source,fixture,rustc,output))
    need(not os.path.lexists(output),'Output directory must be new; preserve previous evidence')
    need(fixture.read_bytes()==expected['fixture'],'Checked fixture differs from fresh static expectations')
    compiler_before=file_digest(rustc)
    need(compiler_before==COMPILER_SHA256,'Compiler differs from authenticated research1.94.1')
    provider_audit=Path(provider_audit).absolute()
    need(file_digest(provider_audit)=='56969b4e39acf17cf6f60f7c94d840a06bb37feb89cc577d0dcadfed7a71fdd6','Exact restored provider audit differs')
    provider=json.loads(provider_audit.read_text(encoding='utf-8'))
    sysroot=rustc.parent.parent
    def audit_provider():
        actual={}
        need(provider['payload_count']==len(provider['payloads'])==103,'Provider denominator differs')
        for row in provider['payloads']:
            relative=Path(row['path'])
            need(not relative.is_absolute() and '..' not in relative.parts,'Provider path escapes prefix')
            path=sysroot/relative
            digest=file_digest(path)
            need(path.stat().st_size==row['bytes'] and digest==row['sha256'],'Provider payload differs: '+row['path'])
            actual[row['path']]=digest
        manifests={}
        for name,digest in provider['installed_manifest_sha256'].items():
            need(Path(name).name==name,'Installed manifest name escapes prefix')
            path=sysroot/'lib/rustlib'/name
            need(file_digest(path)==digest,'Installed component manifest differs: '+name)
            manifests[name]=digest
        need(len(manifests)==2,'Installed component manifest denominator differs')
        return {'payloads':actual,'installed_manifests':manifests}
    provider_before=audit_provider()
    def git_state():
        def git(*argv):
            return subprocess.check_output(['/usr/bin/git',*argv],cwd=root,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},stdin=subprocess.DEVNULL).decode('utf-8')
        pins=git('submodule','status','--recursive')
        need(len(pins.splitlines())==7 and all(line.startswith(' ') for line in pins.splitlines()),'Seven real pins are not clean')
        return {'head':git('rev-parse','HEAD').strip(),'tree':git('rev-parse','HEAD^{tree}').strip(),'status':git('status','--porcelain=v1'),'actual_submodule_pins':pins}
    git_before=git_state()
    need(not git_before['status'],'Commit a clean source checkpoint before qualification')
    def physical_inputs():
        records={}
        def walk(directory,prefix='',child=False):
            def git(*argv):
                return subprocess.check_output(['/usr/bin/git',*argv],cwd=directory,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},stdin=subprocess.DEVNULL)
            if child:
                need(not git('status','--porcelain=v1'),'Pinned child working tree is dirty: '+prefix)
            for entry in git('ls-files','--stage','-z').split(b'\0'):
                if not entry:continue
                header,name=entry.split(b'\t',1);mode,commit,stage=header.decode('ascii').split()
                need(stage=='0','Unmerged physical input')
                name=name.decode('utf-8');relative=Path(name)
                need(not relative.is_absolute() and '..' not in relative.parts,'Tracked path escapes repository')
                path=directory/relative;key=prefix+name
                if mode=='160000':
                    need(git('-C',str(path),'rev-parse','HEAD').decode().strip()==commit,'Actual child pin differs: '+key)
                    walk(path,key+'/',True)
                elif mode=='120000':
                    raw=os.readlink(path).encode('utf-8');records[key]={'mode':mode,'physical_mode':oct(stat.S_IMODE(path.lstat().st_mode)),'bytes':len(raw),'sha256':sha(raw),'kind':'symlink-text-only'}
                else:
                    need(mode in ('100644','100755') and path.is_file() and not path.is_symlink(),'Unexpected tracked physical input: '+key)
                    records[key]={'mode':mode,'physical_mode':oct(stat.S_IMODE(path.stat().st_mode)),'bytes':path.stat().st_size,'sha256':file_digest(path),'kind':'regular-file'}
        walk(root)
        return records
    physical_before=physical_inputs()
    linker=shutil.which('cc',path='/usr/bin:/bin');need(linker is not None,'C linker driver cc is required')
    linker_before=file_digest(linker)
    actual_ld=shutil.which('ld.bfd',path='/usr/bin:/bin');need(actual_ld is not None,'Explicit GNU ld.bfd is required')
    actual_ld_before=file_digest(actual_ld)
    inputs=tuple(sorted(p for p in source.parent.iterdir()if p.is_file() and p.suffix in {'.rs','.txt','.tsv'}))+tuple(map(Path,additional_sources))
    before={str(p):file_digest(p)for p in inputs}
    output.mkdir(parents=True,exist_ok=False)
    (output/'tmp').mkdir()
    (output/'inputs.txt').write_bytes(expected['inputs']);(output/'expected.txt').write_bytes(expected['expected'])
    (output/'oracle.json').write_text(json.dumps(expected['metadata'],indent=2)+'\n',encoding='utf-8',newline='\n')
    (output/'native-proof.json').write_text(json.dumps(expected['native_proof'],indent=2)+'\n',encoding='utf-8',newline='\n')
    (output/'comparison-main.rs').write_text(harness,encoding='utf-8',newline='\n')
    calls=[];environment=dict(PATH='/usr/bin:/bin',LC_ALL='C',LANG='C',TZ='UTC',TMPDIR=str(output/'tmp'))
    def execute(label,argv,required_exit=0):
        memory=Path('/sys/fs/cgroup/memory.max')
        if memory.exists() and memory.read_text(encoding='utf-8').strip().isdigit():
            need(int(memory.read_text(encoding='utf-8'))-int(Path('/sys/fs/cgroup/memory.current').read_text(encoding='utf-8'))>256*1024*1024,
                 'Pause own Rust commands: cgroup headroom below256MiB')
        start=time.monotonic();p=subprocess.run([str(v)for v in argv],cwd=root,env=environment,stdin=subprocess.DEVNULL,capture_output=True)
        logs={}
        for kind,raw in [('stdout',p.stdout),('stderr',p.stderr)]:
            name=label+'.'+kind;(output/name).write_bytes(raw);logs[kind]={'file':name,'bytes':len(raw),'sha256':sha(raw)}
        calls.append({'label':label,'argv':[str(v)for v in argv],'exit_code':p.returncode,'seconds':round(time.monotonic()-start,3),'logs':logs})
        (output/'CALLS.json').write_text(json.dumps(calls,indent=2)+'\n',encoding='utf-8',newline='\n')
        need(p.returncode==required_exit,label+' failed; exact raw streams retained')
        return p
    try:
        version=execute('rustc-identity',[rustc,'-vV']).stdout.decode('utf-8')
        need(version.startswith('rustc 1.94.1 ')and'e408947bfd200af42db322daf0fadfe7e26d3bd1'in version,'Actual compiler full identity differs')
        linker_version=execute('linker-identity',[linker,'--version']).stdout.decode('utf-8')
        actual_ld_version=execute('ld-bfd-identity',[actual_ld,'--version']).stdout.decode('utf-8')
        selected_ld_text=execute('cc-selected-ld-bfd',[linker,'-print-prog-name=ld.bfd']).stdout.decode('utf-8').strip()
        need(selected_ld_text and '\n' not in selected_ld_text,'C driver ld.bfd selection is not one path')
        selected_ld=Path(selected_ld_text) if Path(selected_ld_text).is_absolute() else Path(shutil.which(selected_ld_text,path=environment['PATH']) or '/nonexistent-selected-ld')
        need(selected_ld.resolve(strict=True)==Path(actual_ld).resolve(strict=True)
             and file_digest(selected_ld)==actual_ld_before,'C driver selects another actual ld.bfd')
        selected_ld_record={'reported_path':selected_ld_text,'canonical_path':str(selected_ld.resolve(strict=True)),
                            'sha256':file_digest(selected_ld)}
        objdump=shutil.which('objdump',path='/usr/bin:/bin');need(objdump is not None,'GNU objdump is required for own object inspection')
        objdump_before=file_digest(objdump)
        canonical_tools={str(p):str(Path(p).resolve(strict=True)) for p in (rustc,linker,actual_ld,objdump)}
        objdump_version=execute('objdump-identity',[objdump,'--version']).stdout.decode('utf-8')
        library_checks=[]
        def flags(opt):return ['--edition=2021','-D','warnings','-C','codegen-units=1','-C',f'opt-level={opt}','-C','overflow-checks=on','-C','linker='+linker,'-C','link-arg=-fuse-ld=bfd','--remap-path-prefix',str(root)+'=/reconstruction']
        def library(label,src,opt,directory,delegation_control=False):
            directory.mkdir(parents=True,exist_ok=False);lib=directory/('lib'+CRATE+'.rlib')
            execute(label,[rustc,'--crate-name',CRATE,'--crate-type=rlib',src,
                           '--emit=link,obj,llvm-ir','--out-dir',directory,
                           '-C','metadata=node94-u128-binary64',*flags(opt)])
            observation=inspect_own_artifacts(directory,execute,label,objdump)
            try:
                reject_delegation(observation)
            except ValueError as error:
                need(delegation_control,'Production floating conversion guard rejected: '+str(error))
                need(observation['forbidden_symbols'] and observation['IR_floating_operations'],
                     'Build-only cast wrapper did not exercise both actual object and IR guard')
                observation.update(verdict='REJECTED_BEFORE_CLIENT_LINK_OR_EXECUTION',refusal=str(error))
            else:
                need(not delegation_control,'Build-only delegation wrapper was incorrectly admitted')
                observation['verdict']='PRODUCTION_INTEGER_ONLY_NO_FLOAT_CONVERSION'
            library_checks.append({'label':label,**observation})
            return lib
        def production(label,lib,opt,directory):
            program=directory/'production'
            execute(label+'-link',[rustc,'--crate-name','u128_binary64_comparison',output/'comparison-main.rs','--extern',CRATE+'='+str(lib),'-o',program,*flags(opt)])
            raw=execute(label+'-run',[program,output/'inputs.txt']).stdout
            return program,raw
        def ordinary_tests(label,src,opt,directory,failed=False):
            program=directory/'ordinary-tests'
            execute(label+'-build',[rustc,'--crate-name',CRATE,'--test',src,'-o',program,*flags(opt)])
            p=execute(label+'-run',[program,'--nocapture','--test-threads=1'],101 if failed else 0)
            raw=p.stdout+p.stderr
            if failed:
                need(b'FAILED'in raw and b'panicked at'in raw,'No retained semantic unit assertion failure')
                return {'program':str(program),'expected_exit':101,'semantic_failure_observed':True}
            m=re.search(rb'test result: ok\. (\d+) passed; 0 failed; 0 ignored;',raw)
            need(m is not None and int(m[1])>0,'Actual ordinary Rust tests did not run')
            return {'program':str(program),'actual_tests':int(m[1]),'expected_exit':0}
        control_source=output/'delegation-wrapper.rs'
        control_source.write_text('#![no_std]\n#[inline(never)]\npub fn binary64_bits(n:u128)->u64{ (n as f64).to_bits() }\n',encoding='utf-8',newline='\n')
        library('build-only-delegation-wrapper',control_source,0,output/'delegation-wrapper',True)
        profiles=[]
        for name,opt in [('debug',0),('optimized',3)]:
            directory=output/name;lib=library(name+'-library',source,opt,directory)
            tests=ordinary_tests(name+'-ordinary',source,opt,directory)
            program,raw=production(name+'-production',lib,opt,directory)
            need(not mismatch_ids(raw,expected['expected']),name+' fresh native expectation mismatch')
            need(raw==expected['expected'],name+' positive output bytes differ from exact frozen transcript')
            profiles.append({'name':name,'opt_level':opt,'ordinary_tests':tests,'production':str(program),'production_sha256':file_digest(program),'production_cases':len(raw.splitlines()),'actual_sha256':sha(raw),'expected_sha256':sha(expected['expected']),'library_sha256':file_digest(lib)})
        a=output/'optimized'/('lib'+CRATE+'.rlib');b=library('repro-b',source,3,output/'repro-b')
        rebuild={'a_bytes':a.stat().st_size,'b_bytes':b.stat().st_size,'a_sha256':file_digest(a),'b_sha256':file_digest(b),'raw_equal':a.read_bytes()==b.read_bytes(),'normalization':'none','original_target_match_claimed':False}
        need(rebuild['raw_equal'],'Own rebuilds differ')
        results=[];text=source.read_text(encoding='utf-8')
        for item in mutations:
            name=item['name'];need(text.count(item['needle'])==1,name+' no longer uniquely matches source')
            folder=output/('mutant-'+name);folder.mkdir()
            # All copied inputs are our component source/tests/fixtures, not a
            # captured image/provider. Expected fixture bytes stay unchanged.
            for p in source.parent.iterdir():
                if p.is_file():
                    need(p.stat().st_size<1<<20,'Unexpected large component input')
                    shutil.copy2(p,folder/p.name)
            altered=folder/source.name;altered.write_text(text.replace(item['needle'],item['replacement']),encoding='utf-8',newline='\n')
            lib=library('mutant-'+name+'-library',altered,0,folder/'library')
            _,raw=production('mutant-'+name+'-production',lib,0,folder)
            mismatches=mismatch_ids(raw,expected['expected']);need(mismatches,name+' did not fail semantic observations')
            if item.get('witness_stimulus_id'):need(item['witness_stimulus_id']in mismatches,name+' selected witness did not fail')
            tests=ordinary_tests('mutant-'+name+'-ordinary',altered,0,folder,True)
            actual_rows=dict(line.split(b'|') for line in raw.splitlines())
            expected_rows=dict(line.split(b'|') for line in expected['expected'].splitlines())
            stimuli=dict(line.split(b'|') for line in expected['inputs'].splitlines())
            witnesses=[{'id':i,'n_hex':stimuli[i.encode()].decode(),'expected_bits':expected_rows[i.encode()].decode(),'actual_bits':actual_rows[i.encode()].decode()} for i in mismatches[:5]]
            results.append({'name':name,'relation':item['relation'],'source_sha256':file_digest(altered),'production_exit':0,'production_cases':len(raw.splitlines()),'different_transcripts':len(mismatches),'sample_mismatch_ids':mismatches[:8],'actual_witnesses':witnesses,'ordinary_tests':tests})
        after={str(p):file_digest(p)for p in inputs}
        provider_after=audit_provider();git_after=git_state();physical_after=physical_inputs()
        need(before==after and provider_before==provider_after and git_before==git_after and physical_before==physical_after and canonical_tools=={str(p):str(Path(p).resolve(strict=True)) for p in (rustc,linker,actual_ld,objdump)} and file_digest(provider_audit)=='56969b4e39acf17cf6f60f7c94d840a06bb37feb89cc577d0dcadfed7a71fdd6' and file_digest(rustc)==compiler_before and file_digest(linker)==linker_before and file_digest(actual_ld)==actual_ld_before and file_digest(objdump)==objdump_before,'Source/provider/head/status/pins/linker/analysis-tool bytes changed')
        result={'status':'PASS','compiler':{'path':str(rustc),'sha256':compiler_before,'identity':version,'research_toolchain_not_original':True},'linker':{'path':linker,'sha256':linker_before,'identity':linker_version,'explicit_selection':'-fuse-ld=bfd','actual_ld':actual_ld,'actual_ld_sha256':actual_ld_before,'actual_ld_identity':actual_ld_version},'provider_before':provider_before,'provider_after':provider_after,'git_before':git_before,'git_after':git_after,'physical_inputs_before':physical_before,'physical_inputs_after':physical_after,'physical_input_count':len(physical_before),'oracle':expected['metadata'],'child_environment':environment,'source_before':before,'source_after':after,'profiles':profiles,'own_reproducibility':rebuild,'semantic_mutants':results,'own_library_static_checks':library_checks,'analysis_provider':{'path':objdump,'sha256':objdump_before,'identity':objdump_version},'calls':calls,'limits':['Every u128 integer as a returned-bits numerical projection under the explicit native ordinary-call/frame domain.','Input-only production data flow, not a filesystem sandbox.','Finite16614 vectors support the separately complete native and integer-rounding source proofs.','Only independently authored Rust executes; captured code and instruction interpreters never execute.','No original ABI/type/compiler/runtime/byte identity, caller-wide or recovery gate claim.']}
        result['canonical_tool_paths']=canonical_tools
        result['linker']['cc_selected_ld_bfd']=selected_ld_record
        result['comparator_controls']=comparator_controls(expected['expected'])
        (output/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8',newline='\n');return result
    except Exception as error:
        (output/'FAILURE.json').write_text(json.dumps({'error':str(error),'calls':calls,'source_before':before},indent=2)+'\n',encoding='utf-8',newline='\n');raise


def inspect_own_artifacts(directory, execute, label, objdump):
    """Inspect our actual rlib/object/IR; never link/load any supplied object."""
    lib=directory/('lib'+CRATE+'.rlib');obj=directory/(CRATE+'.o');ir=directory/(CRATE+'.ll')
    need(all(p.is_file() for p in (lib,obj,ir)),'Fixed library recipe omitted an output')
    undefined=set();definitions=[]
    for name,raw in ar_members(lib.read_bytes()).items():
        if raw[:4]!=b'\x7fELF':continue
        image=Elf(raw,1)
        for table in image.sections:
            if table['type']!=2:continue
            for symbol in image.symbols(table['index']):
                if symbol['section']==0 and symbol['name']:undefined.add(symbol['name'])
                if symbol['section'] and symbol['info']&15==2 and CRATE in symbol['name'] and 'binary64_bits' in symbol['name']:
                    function=image.function(symbol['section'],symbol['name'])
                    body=image.section_bytes(function['section'])
                    definitions.append({'member':name,'symbol':function,'body_bytes':len(body),
                                        'body_sha256':sha(body),'code_relocations':image.relocations(function['section'])})
    need(len(definitions)==1,'Own binary64_bits definition is missing or ambiguous')
    forbidden=sorted(s for s in undefined if re.search(r'__(?:float|fix|u?div|u?mod|u?rem|sdiv|smod)|compiler_builtins.*float',s))
    ir_text=ir.read_text(encoding='utf-8')
    ir_ops=sorted(set(re.findall(r'\b(?:uitofp|sitofp|fptoui|fptosi|fpext|fptrunc|fadd|fsub|fmul|fdiv|frem|fcmp|udiv|urem|sdiv|srem)\b',ir_text)))
    machine_ops=[]
    if not forbidden and not ir_ops:
        raw=execute(label+'-own-object-disassembly',[objdump,'-dr','-Mintel',obj]).stdout
        for line in raw.decode('utf-8').splitlines():
            parts=line.split('\t')
            if len(parts)>=3:
                words=parts[-1].strip().split()
                if words and (words[0] in ('div','idiv') or re.fullmatch(r'v?cvt\w+|f(?:ld|st|ist|add|sub|mul|div|com|ucom|sqrt)\w*|v?(?:add|sub|mul|div|sqrt|min|max|round|comi|ucomi)(?:ss|sd|ps|pd)',words[0])):
                    machine_ops.append(line)
    return {'files':{p.name:{'bytes':p.stat().st_size,'sha256':file_digest(p)} for p in (lib,obj,ir)},
            'undefined_symbols':sorted(undefined),'forbidden_symbols':forbidden,
            'IR_floating_operations':ir_ops,'machine_floating_or_division_instructions':machine_ops,
            'binary64_definitions':definitions,
            'scope':'Actual production rlib/object/IR only, not std-linked I/O client or unit harness'}


def reject_delegation(observation):
    need(not observation['forbidden_symbols'] and not observation['IR_floating_operations']
         and not observation['machine_floating_or_division_instructions'],
         'Production float conversion/arithmetic or division delegation is forbidden')


def comparator_controls(expected):
    changed=expected.replace(b'f00000|0000000000000000',b'f00000|0000000000000001',1)
    need(mismatch_ids(changed,expected)==['f00000'],'Value corruption comparator control failed')
    bad=[('missing-row',b'\n'.join(expected.splitlines()[:-1])+b'\n'),
         ('wrong-id',expected.replace(b'f00000|',b'other0|',1)),
         ('partial-word',expected.replace(b'f00000|0000000000000000',b'f00000|0000',1))]
    results=[{'name':'wrong-bits','actual_mismatch_ids':['f00000']}]
    for name,raw in bad:
        try:mismatch_ids(raw,expected)
        except ValueError as error:results.append({'name':name,'refusal':str(error)})
        else:raise ValueError('Malformed transcript comparator control admitted: '+name)
    return results


ROOT=Path(__file__).resolve().parents[1]
TARGET=ROOT/'artifacts/node/94/hl-node'
COMPONENT=ROOT/'src/node94-u128-binary64'
SOURCE=COMPONENT/'lib.rs'
DRIVER=COMPONENT/'input_only_driver.rs'
FIXTURE=COMPONENT/'unit-vectors.tsv'
PACKET=ROOT/'research/work-items/RE-004-u128-binary64-94'


def semantic_mutations(text):
    changes=[
        {'name':'ties-away-from-even',
         'needle':'if residue > halfway || (residue == halfway && significand & 1 != 0) {',
         'replacement':'if residue >= halfway {',
         'relation':'Incorrectly increment even retained significands at an exact midpoint.'},
        {'name':'ignore-above-half-sticky',
         'needle':'if residue > halfway || (residue == halfway && significand & 1 != 0) {',
         'replacement':'if residue == halfway && significand & 1 != 0 {',
         'relation':'Ignore residues strictly greater than the midpoint, including every sticky-bit position.'},
        {'name':'drop-top-input-bit','needle':'    if n == 0 {',
         'replacement':'    let n = n & ((1_u128 << 127) - 1);\n    if n == 0 {',
         'relation':'Discard input bit127 and incorrectly convert the lower127-bit word.'}]
    for row in changes:need(text.count(row['needle'])==1,row['name']+' no longer matches source uniquely')
    return changes


def build(binary,rustc,output,provider_audit,controls=False):
    output=Path(output).absolute()
    need(not os.path.lexists(output),'Output directory must be new; preserve evidence')
    expected=reference.fresh(Path(binary))
    additional=[Path(__file__),Path(native.__file__),Path(reference.__file__),
                ROOT/'tools/libcore_fmt_correspondence.py',ROOT/'tools/elf_index.py',
                ROOT/'tools/fde_extents.py',ROOT/'tools/node115_field_adapter_drift.py',
                ROOT/'tools/build_provenance.py',ROOT/'tools/artifacts.py',Path(binary),
                PACKET/'native/rows.json',PACKET/'native/record.json',PACKET/'PROOF.md',
                PACKET/'SOURCE-PROOF.md',*sorted((PACKET/'preparation').glob('*'))]
    need(all(p.is_file() for p in additional),'Qualification inputs include an absent/non-file path')
    return qualify(ROOT,expected,SOURCE,FIXTURE,Path(rustc),output,
                   DRIVER.read_text(encoding='utf-8'),semantic_mutations(SOURCE.read_text(encoding='utf-8')) if controls else [],provider_audit,additional)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,default=TARGET)
    parser.add_argument('--rustc',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--controls',action='store_true')
    parser.add_argument('--provider-audit',type=Path,required=True)
    args=parser.parse_args();result=build(args.binary,args.rustc,args.output,args.provider_audit,args.controls)
    print(json.dumps({'status':result['status'],'qualified_rows':result['oracle']['rows'],
                      'commands':len(result['calls']),'valued_mutants':len(result['semantic_mutants']),
                      'build_only_cast_control':'REJECTED_BEFORE_CLIENT_LINK_OR_EXECUTION'}))


if __name__=='__main__':main()
