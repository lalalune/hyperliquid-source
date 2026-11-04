#!/usr/bin/env python3
from pathlib import Path
import json
from collect import TARGET,ROOT,collect,digest,dump,relation
from corpus import corpus

PACKET=Path(__file__).resolve().parent
if __name__=='__main__':
    if (ROOT/'src/node115-tcp-frame-plan/lib.rs').exists():raise ValueError('freeze must precede Rust implementation')
    evidence,exports=collect(TARGET.read_bytes(),native=True)
    inputs,expected=corpus(evidence['parameters'],relation)
    out=ROOT/'work/environment/node115-task/frozen';out.mkdir(exist_ok=False)
    (out/'inputs.tsv').write_text(inputs);(out/'expected.tsv').write_text(expected)
    frozen={'cases':len(expected.splitlines()),'input_sha256':digest(inputs.encode()),'expected_sha256':digest(expected.encode()),'generator_sha256':digest((PACKET/'corpus.py').read_bytes()),'collector_sha256':digest((PACKET/'collect.py').read_bytes())}
    (PACKET/'corpus.json').write_text(dump(frozen));(PACKET/'evidence.json').write_text(dump(evidence))
    for name,text in exports.items():(PACKET/name).write_text(text)
    print(dump(frozen))
