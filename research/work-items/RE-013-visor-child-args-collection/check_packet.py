#!/usr/bin/env python3
"""Reproduce the target-bound conditional normal collection packet."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools'))
from visor_child_args_collection import TARGET,collect,require


def verify(packet,data):
    record,exports = collect(data)
    require(json.loads((packet/'record.json').read_text())==record,'collection record differs from fresh target bindings')
    for name,raw in exports.items():
        require((packet/name).read_bytes()==raw,'collection native export differs from fresh target bindings')
    return {'owned_bytes':860,'native_instruction_rows':220,'blocks':61,
            'normal_projection_nodes':176,'conditional_projection_nodes':144,
            'opaque_allocator_copy_contracts_assumed_not_recovered':True,
            'captured_code_executed_or_emulated':False,'automatic_machine_equivalence_verifier':False}


if __name__=='__main__':
    print(json.dumps(verify(Path(__file__).resolve().parent,TARGET.read_bytes()),sort_keys=True))
