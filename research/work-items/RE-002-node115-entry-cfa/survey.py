"""Compare actual FDE entry instructions to the CFA rows for the same FDE."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PREVIOUS = HERE.parent / 'RE-002-node115-cfa-frame-policy'
sys.path.insert(0, str(PREVIOUS))
sys.path.insert(0, str(ROOT / 'tools'))
from reconcile import TARGET, parse
from elf_index import sections
from fde_extents import eh_frame_records


def require(condition, message):
    if not condition:
        raise ValueError(message)


def classify(decoder, body, start):
    # At most three x86 instructions: optional ENDBR64, push, mov. Never cross an FDE end.
    insns = list(decoder.disasm_lite(body[:45], start, count=3))
    pos = int(bool(insns and insns[0][2:] == ('endbr64', '')))
    if len(insns) <= pos:
        return 'no-decodable-entry', None, insns
    if insns[pos][2:] != ('push', 'rbp'):
        return 'other-entry', None, insns
    if len(insns) > pos + 1 and insns[pos+1][2:] == ('mov', 'rbp, rsp'):
        pc, size, _, _ = insns[pos+1]
        return 'push-and-set-rbp', pc + size, insns
    return 'push-rbp-without-immediate-set', None, insns


def run(target, frames):
    image = target.read_bytes()
    require(hashlib.sha256(image).hexdigest() == TARGET, 'Invalid target SHA-256')
    sec = sections(image)
    frame, = [s for s in sec if s['name'] == '.eh_frame']
    code = [s for s in sec if s['flags'] & 4 and s['type'] == 1]
    _, bound = eh_frame_records(image, sec)
    _, decoded, _ = parse(frames, 'gnu')
    require(len(bound) == len(decoded) == 135313, 'FDE count mismatch')
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    cross, examples, encodings = Counter(), {}, Counter()
    old_cross, projection = Counter(), hashlib.sha256()
    for fde, source in zip(bound, decoded):
        start, end = fde['start'], fde['end']
        require((start,end,fde['fde'],fde['cie']) ==
                (source['start'],source['end'],source['offset']+frame['address'],source['cie']+frame['address']),
                'Independent FDE bounds mismatch')
        area, = [s for s in code if s['address'] <= start < end <= s['address']+s['size']]
        file_offset = area['offset'] + start - area['address']
        head = image[file_offset:file_offset+min(45,end-start)]
        category, after, insns = classify(decoder, head, start)
        states = source['rows']
        bases = {cfa.split('+')[0].split('-')[0] for _,cfa in states}
        has_rbp = 'RBP' in bases
        old_cross[(','.join(sorted(bases)),source['saved_rbp'])] += 1
        entry_rbp = states[0][1].startswith('RBP')
        if after is None:
            alignment = 'not-applicable'
        else:
            encodings[head[:after-start].hex()] += 1
            at = next((cfa for pc,cfa in reversed(states) if pc <= after), None)
            alignment = 'rbp-at-next-pc' if at and at.startswith('RBP') and after < end else 'no-rbp-row-at-next-pc'
        key=(category,has_rbp,entry_rbp,alignment)
        cross[key]+=1
        projection.update((f'{fde["fde"]:x} {start:x} {end:x} {category} {int(has_rbp)} '
                           f'{int(entry_rbp)} {alignment}\n').encode())
        if key not in examples or start < examples[key]['start']:
            examples[key]=dict(start=start,end=end,file_offset=file_offset,fde=fde['fde'],
                               instructions=[dict(pc=pc,bytes=head[pc-start:pc-start+size].hex(),
                                                  mnemonic=op,operands=args) for pc,size,op,args in insns],
                               initial_cfa=states[0][1],
                               first_rbp_row=next(([pc,cfa] for pc,cfa in states if cfa.startswith('RBP')),None))
    prior=json.loads((PREVIOUS/'summary.json').read_text())['cross_tab']
    require(old_cross == Counter({(r['cfa_bases'],r['saved_rbp']):r['fdes'] for r in prior}),
            'Prior full CFA/saved-RBP population differs')
    return dict(target_sha256=TARGET,fdes=len(bound),row_sequence_sha256=projection.hexdigest(),
                setup_encodings=dict(sorted(encodings.items())),
                strata=[dict(entry=key[0],has_rbp_cfa=key[1],starts_rbp_cfa=key[2],
                             after_setup=key[3],count=cross[key],lowest_va_example=examples[key]) for key in sorted(cross)])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--readelf',default='readelf')
    parser.add_argument('--print-result',action='store_true')
    args=parser.parse_args()
    target=ROOT/'artifacts/node/115/hl-node'
    with tempfile.TemporaryDirectory() as temp:
        frames=Path(temp)/'frames.txt'
        with frames.open('wb') as handle:
            subprocess.run([args.readelf,'--debug-dump=frames-interp',str(target)],check=True,
                           stdout=handle,env=dict(os.environ,LC_ALL='C'))
        result=run(target,frames)
    if args.print_result:
        print(json.dumps(result,indent=2))
    else:
        require(result==json.loads((HERE/'survey.json').read_text()),'Pinned survey differs')
        print(f"{result['fdes']} FDE entry/CFA comparisons verified")


if __name__=='__main__':
    main()
