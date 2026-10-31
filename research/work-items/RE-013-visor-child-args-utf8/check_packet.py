#!/usr/bin/env python3
"""Regenerate complete target bindings and retained raw native exports."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools'))
from visor_child_args_utf8 import TARGET, collect, require


def verify(packet,data):
    record,exports = collect(data)
    require(json.loads((packet/'record.json').read_text())==record,'UTF8 record differs from fresh target bindings')
    for name,raw in exports.items():
        require((packet/name).read_bytes()==raw,'UTF8 native export differs from fresh target bindings')
    return {'validator_bytes':503,'validator_instructions':143,'validator_blocks':57,
            'adapter_bytes':67,'adapter_instructions':15,'table_entries':256,
            'open_adapter_error_boundary':'0x48dc43','code_executed_or_emulated':False,
            'automatic_machine_equivalence_verifier':False}


if __name__=='__main__':
    print(json.dumps(verify(Path(__file__).resolve().parent,TARGET.read_bytes()),sort_keys=True))
