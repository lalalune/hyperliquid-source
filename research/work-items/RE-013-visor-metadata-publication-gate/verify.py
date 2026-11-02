#!/usr/bin/env python3
"""Check static evidence, below-identity bindings, graph sensitivity and finite logic."""
import copy
import gzip
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

import collect as c


def logic():
    # Algebraic predicates, not a captured-instruction interpreter.
    rows=[{'f':f,'lowbit_skip':bool(f&1),'published_gate':bool(f^1)} for f in range(256)]
    c.need(all(not (r['lowbit_skip'] and r['published_gate']) for r in rows[:2]), 'binary-domain implication')
    bad=[r['f'] for r in rows if r['lowbit_skip'] and r['published_gate']]
    c.need(bad == list(range(3,256,2)), 'raw-byte counterexamples')
    # Each ANDed pair of equality lanes must be true; their 16 signs form 0xffff.
    lane_cases=0
    for left in range(2):
        for right in range(2):
            c.need(bool((255 if left else 0)&(255 if right else 0)) == bool(left and right), 'paired equality lane')
            lane_cases+=1
    for mask in range(65536):
        c.need((mask==65535) == all(mask & (1<<i) for i in range(16)), 'all lane bits')
    return {'raw_byte_cases':256,'binary_domain':[0,1],'skip_and_pass_counterexamples':bad,
            'paired_boolean_lane_cases':lane_cases,'sixteen_lane_mask_cases':65536,
            'limitation':'The finite predicate checks assume the manually bound TEST/XOR/CMP and PCMPEQB/PAND/PMOVMSKB semantics. No machine instruction execution.'}


def tree(path):
    return {p.name:p.read_bytes() for p in path.iterdir() if p.is_file()}


def main():
    data=c.TARGET.read_bytes();c.need(hashlib.sha256(data).hexdigest()==c.SHA,'baseline identity')
    im=c.Image(data);relocs=c.bindings(im);fdes=c.unwind(im)
    baseline=json.loads((c.HERE/'observed/records.json').read_text());rows={};controls=[]
    def rejects(name, operation, why):
        try:
            operation()
        except ValueError as err:
            c.need(why in str(err),name+' unexpected rejection '+str(err))
            controls.append({'name':name,'rejected_by':why})
        else:
            raise ValueError(name+' accepted')
    def flip(off,operation):
        changed=bytearray(data);changed[off]^=1;return operation(c.Image(changed))
    expected=json.loads((c.HERE/'bindings.json').read_text())
    for name,v in expected['witnesses'].items():
        rejects('below-hash/witness/'+name,lambda v=v:flip(im.offset(int(v['va'],16),1),c.bindings),'witness')
    rejects('below-hash/mode-table',lambda:flip(im.offset(c.TABLE[0],1),c.bindings),'mode table')
    for v in relocs:
        rejects('below-hash/RELA/'+v['slot'],lambda v=v:flip(v['file_offset']+16,c.bindings),'selected RELA')
    symbols=next(s for s in im.secs if s['name']=='.dynsym')
    strings=next(s for s in im.secs if s['name']=='.dynstr')
    name_offset=strings['offset']+struct.unpack_from('<I',data,symbols['offset']+6*24)[0]
    rejects('below-hash/memcpy-symbol',lambda:flip(name_offset,c.bindings),'selected imported symbol')
    for name,v in fdes.items():
        va=int(v['fields']['fde'],16)
        rejects('below-hash/FDE/'+name,lambda va=va:flip(im.offset(va+12,1),c.unwind),'FDE range')
    for name,(a,b) in c.RANGES.items():
        native={}
        for label in ['gnu','llvm']:
            meta=baseline['ranges'][name]['exports'][label];stored=(c.HERE/'observed'/meta['file']).read_bytes()
            raw=stored if label=='gnu' else gzip.decompress(stored)
            c.need(hashlib.sha256(stored).hexdigest()==meta['stored_sha256'],'stored export digest')
            c.need(hashlib.sha256(raw).hexdigest()==meta['raw_sha256'],'raw export digest')
            native[label]=c.parse(raw.decode(),a,b)
            c.need(b''.join(x[1] for x in native[label])==im.at(a,b-a),'complete export bytes')
        c.need([(a,b) for a,b,_ in native['gnu']]==[(a,b) for a,b,_ in native['llvm']],'decoder boundaries')
        rows[name]=native['gnu']
    c.need(c.certificate(rows)==baseline['structural_certificate'],'retained structural certificate')
    changed=copy.deepcopy(rows);a,b,asm=changed['metadata'][0];changed['metadata'][0]=(a,b'\xc3','ret')
    rejects('graph/nonvacuity-ret-entry',lambda:c.certificate(changed),'vacuous cutset')
    with tempfile.TemporaryDirectory(prefix='visor-metadata-verify-') as temp:
        temp=Path(temp)
        # Actual changed target bytes are freshly decoded below the hash/binding gate.
        # The branch bypasses both the flag store and error stores before normal return.
        changed=bytearray(data);va=0x41654e;off=im.offset(va,7)
        changed[off:off+7]=b'\xe9'+struct.pack('<i',0x416767-(va+5))+b'\x90\x90'
        mutant=temp/'mutant.elf';mutant.write_bytes(changed);mutant.chmod(0o400)
        text=subprocess.check_output([c.GNU,'-d','-M','intel','--insn-width=16','--start-address=0x415620','--stop-address=0x416cce',str(mutant)],text=True)
        altered=copy.deepcopy(rows);altered['metadata']=c.parse(text,*c.FULL['metadata'])
        c.need(b''.join(x[1] for x in altered['metadata'])==c.Image(changed).at(*[c.FULL['metadata'][0],c.FULL['metadata'][1]-c.FULL['metadata'][0]]),'mutant native binding')
        rejects('fresh-native-below-hash/flag-store-bypass',lambda:c.certificate(altered),'cutset bypass')
        for name in ['normal','repeat']:
            c.collect(temp/name)
            c.need(tree(temp/name)==tree(c.HERE/'observed'),'complete regenerated tree')
    return {'target_sha256':c.SHA,'evidence_bytes':sum(v['bytes'] for v in baseline['ranges'].values()),
            'rows':sum(v['rows'] for v in baseline['ranges'].values()),'regenerations':2,
            'controls':controls,'control_count':len(controls),'logic':logic(),
            'limits':'Static integrity, native decoding and structural/finite-algebra checks only. Manual semantic and helper-preservation premises remain unexecuted and conditional.'}


if __name__=='__main__':
    print(json.dumps(main(),indent=2))
