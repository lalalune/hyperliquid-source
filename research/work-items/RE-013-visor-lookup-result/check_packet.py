#!/usr/bin/env python3
"""Authenticate and regenerate the retained bounded lookup record/native export."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools'))
from visor_lookup_result import TARGET, collect, require


def verify(packet, data):
    record,native = collect(data)
    require(json.loads((packet/'record.json').read_text()) == record, 'lookup record differs from target regeneration')
    require((packet/'lookup.objdump.txt').read_bytes() == native, 'lookup native export differs from target regeneration')
    return {'lookup_bytes':record['lookup_fde']['bytes'],
            'native_instructions':record['normal_CFG']['decoded_instructions'],
            'branches':len(record['normal_CFG']['branches']),
            'normal_calls':len(record['normal_CFG']['calls']),
            'normal_return_low32_upper_bound':record['return_cutset']['normal_return_low32_upper_bound'],
            'captured_target_executed':False}


if __name__ == '__main__':
    print(json.dumps(verify(Path(__file__).resolve().parent,TARGET.read_bytes()),sort_keys=True))
