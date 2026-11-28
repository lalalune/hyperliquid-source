"""Change only force-frame-pointers; do not link or execute either Rust fixture."""
import argparse
import hashlib
import json
from pathlib import Path
import os
import subprocess
import tempfile

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from survey import HERE, classify, parse, require, sections


def output(command):
    return subprocess.check_output(command, cwd=HERE, env=dict(os.environ, LC_ALL='C'))


def experiment(readelf):
    version = output(['rustup', 'run', '1.95.0', 'rustc', '-vV']).decode()
    commit = '59807616e1fa2540724bfbac14d7976d7e4a3860'
    require(f'commit-hash: {commit}' in version, 'Wrong compiler')
    target = 'x86_64-unknown-linux-gnu'
    common = ['--crate-name', 'frame_probe', '--crate-type=lib', '--edition=2021', '--emit=obj',
              '-C', 'opt-level=2', '-C', 'panic=abort', '-C', 'force-unwind-tables=yes']
    cases = []
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    with tempfile.TemporaryDirectory() as temp:
        for src, func in [('rotate.rs', 'rotate_add'), ('aligned.rs', 'aligned_buffer')]:
            for flag in ('no', 'yes'):
                obj = Path(temp) / f'{func}-{flag}.o'
                args = [*common,'-C',f'force-frame-pointers={flag}','--target',target,src]
                output(['rustup','run','1.95.0','rustc',*args,'-o',str(obj)])
                image = obj.read_bytes()
                name = '.text.' + func
                text, = [s for s in sections(image) if s['name'] == name]
                body = image[text['offset']:text['offset']+text['size']]
                reloc_output = output([readelf,'-Wr',str(obj)]).decode()
                frame_relocations = reloc_output.split("Relocation section '.rela.eh_frame'",1)[1].split("\n\n",1)[0]
                require(frame_relocations.count('R_X86_64_PC32') == 1 and name+' + 0' in frame_relocations,
                        'Unexpected .eh_frame to .text binding')
                frames = obj.with_suffix('.frames')
                frames.write_bytes(output([readelf,'--debug-dump=frames-interp',str(obj)]))
                _, (fde,), _ = parse(frames,'gnu')
                require((fde['start'],fde['end'])==(0,len(body)),'FDE differs from whole section')
                category,after,_ = classify(decoder,body,0)
                cases.append(dict(source=src, rustc_arguments=args,
                                  object_sha256=hashlib.sha256(image).hexdigest(),
                                  text_hex=body.hex(),entry=category,after_setup=after,cfa_rows=fde['rows']))
    require(cases[0]['entry']=='other-entry' and cases[1]['entry']=='push-and-set-rbp',
            'Ordinary leaf no longer distinguishes flags')
    require(cases[2]['entry']==cases[3]['entry']=='push-and-set-rbp' and
            cases[2]['object_sha256']==cases[3]['object_sha256'],
            'Realignment no longer produces equal objects')
    return dict(rustc_commit=commit,target=target,cases=cases)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--readelf',default='readelf')
    parser.add_argument('--print-result',action='store_true')
    args=parser.parse_args()
    report=experiment(args.readelf)
    if args.print_result:
        print(json.dumps(report,indent=2))
    else:
        require(report==json.loads((HERE/'control.json').read_text()),'Rust fixture evidence differs')
        print('Four cross-compiled fixture objects verified against pinned receipts')
