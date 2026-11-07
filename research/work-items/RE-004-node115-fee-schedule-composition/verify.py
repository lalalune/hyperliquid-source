#!/usr/bin/env python3
"""Recheck prior target-bound fee certificates without executing target code."""
import hashlib, json, struct, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
import fee_schedule_gate_static as gate
import fee_schedule_sources_static as sources
import fee_schedule_finite_static as finite
import fee_schedule_post_static as post
from elf_index import sections

raw = gate.TARGET.read_bytes()
if len(raw) != gate.SIZE or hashlib.sha256(raw).hexdigest() != gate.SHA:
    raise ValueError('expected pinned node 115')
g = gate.analyze(raw)
s = sources.analyze(raw)
f = finite.analyze(raw)
p = post.analyze(raw)
gate.require(len(s['slice_sources']) == 9, 'source count')
gate.require(f['slices_fully_checked_finite'] == [1,2,3,4,5,6,8,9], 'finite coverage')
gate.require(p['certificate']['map_sum']['fail_if'] == 'sum ja 1.0', 'sum gate')
gate.require(len(p['certificate']['floor_calls']) == 2, 'floor call count')

def altered(va, replacement):
    data = bytearray(raw)
    section = next(v for v in sections(raw) if v['type'] != 8 and v['address'] <= va and va+len(replacement) <= v['address']+v['size'])
    offset = section['offset'] + va-section['address']
    data[offset:offset+len(replacement)] = replacement
    return bytes(data)

# Inspect decoded certificates directly, so whole-image/body hashes do not
# cause the negative controls to pass without exercising the selected fact.
gate.require(post.certificate(altered(0x36a2d8b, b'\x0f\x86'))['map_sum']['fail_if'] == 'sum jbe 1.0', 'sum control')
gate.require(post.certificate(altered(0x459b50, struct.pack('<d', 0.00005)))['cross_range']['positive_minimum'] != p['certificate']['cross_range']['positive_minimum'], 'minimum control')
gate.require(post.certificate(altered(0x36a2da5, b'\x20'))['floor_calls'][0]['fields']['0x8'] != p['certificate']['floor_calls'][0]['fields']['0x8'], 'floor argument control')
print(json.dumps({'target_sha256': gate.SHA, 'prior_certificates': 4, 'source_slices': len(s['slice_sources']), 'finite_slices': f['slices_fully_checked_finite'], 'floor_calls': 2, 'semantic_controls_changed': 3, 'captured_code_executed': False}, indent=2))
