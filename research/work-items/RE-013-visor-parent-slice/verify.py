"""Regenerate the complete static records twice and reject corrupted evidence."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from survey import Image, InvalidEvidence, collect, json_bytes, require, sha, write_new

HERE=Path(__file__).resolve().parent

def check_records(expected,directory):
    paths=list(directory.rglob('*'))
    require(not any(p.is_symlink() for p in paths),'Symlink in records')
    names={p.relative_to(directory).as_posix() for p in paths if p.is_file()}
    require(names==set(expected),'Record inventory differs')
    for name,data in expected.items():require((directory/name).read_bytes()==data,'Record differs: '+name)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--receipt',type=Path,required=True)
    args=parser.parse_args()
    try:
        require(not args.receipt.exists(),'Preserve existing receipt')
        first=collect(args.binary);second=collect(args.binary)
        require(first==second,'Two native generations differ')
        check_records(first,HERE/'observed')
        controls=[]
        with tempfile.TemporaryDirectory(prefix='visor-parent-controls-') as temporary:
            root=Path(temporary);raw=args.binary.read_bytes();image=Image(raw)
            changed=bytearray(raw)
            offsets=[o+0x694f33-v for o,v,n in image.loads if v<=0x694f33<v+n]
            require(len(offsets)==1,'Changed code needs mapping');changed[offsets[0]]^=1
            for name,data in [('truncated',raw[:-1]),('lfs-pointer',b'version https://git-lfs.github.com/spec/v1\n'),('changed-code',bytes(changed))]:
                path=root/(name+'.elf');path.write_bytes(data);dest=root/(name+'-output')
                result=subprocess.run([sys.executable,'-B',str(HERE/'survey.py'),'--binary',str(path),'--output',str(dest)],capture_output=True,text=True,timeout=60)
                require(result.returncode==1 and 'Wrong full Visor identity' in result.stderr and not dest.exists(),'Identity control failed')
                controls.append(name)
            for name in ('summary-fde','summary-relocation','native-byte','native-fde','native-relocation','missing-record'):
                dest=root/name;shutil.copytree(HERE/'observed',dest)
                if name.startswith('summary-'):
                    path=dest/'summary.json';value=json.loads(path.read_bytes())
                    if name=='summary-fde':value['ranges'][0]['end']='0x3a1b12'
                    else:value['relocations'][0]['addend']+=1
                    path.write_bytes(json_bytes(value))
                elif name=='missing-record':(dest/'records/caller.txt').unlink()
                else:
                    filename,before,after={
                        'native-byte':('caller.txt',b'3a1780:\t55',b'3a1780:\t54'),
                        'native-fde':('caller.fde.txt',b'3a1b13',b'3a1b12'),
                        'native-relocation':('relocations.txt',b'694cf0',b'694cf1')}[name]
                    path=dest/'records'/filename;data=path.read_bytes();require(before in data,'Mutation precondition failed')
                    path.write_bytes(data.replace(before,after,1))
                try:check_records(first,dest)
                except InvalidEvidence:controls.append(name)
                else:raise InvalidEvidence('Changed evidence accepted')
            dest=root/'existing';dest.mkdir();sentinel=dest/'sentinel';sentinel.write_bytes(b'keep\n')
            try:write_new(dest,first)
            except InvalidEvidence:
                require(sentinel.read_bytes()==b'keep\n' and len(list(dest.iterdir()))==1,'Existing output changed')
                controls.append('existing-output')
            else:raise InvalidEvidence('Existing output accepted')
        receipt={'nativeGenerations':2,'files':len(first),'controls':controls,
                 'recordSha256':{n:sha(d) for n,d in sorted(first.items())},
                 'capturedExecution':False,'instructionEvaluation':False,
                 'scope':'Static evidence integrity only; not runtime equivalence.'}
        args.receipt.write_bytes(json_bytes(receipt));print(json.dumps(receipt))
    except (InvalidEvidence,OSError,UnicodeError,subprocess.TimeoutExpired) as error:parser.exit(1,str(error)+'\n')

if __name__=='__main__':main()
