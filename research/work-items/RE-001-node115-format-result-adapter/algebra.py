#!/usr/bin/env python3
"""Exhaust finite byte-domain identities; no target instruction evaluation."""
import json
from pathlib import Path
# This is propositional algebra over the two bytes read after an opaque call.
# It supplies no call result, memory model or target execution engine.
rows=[]
for c in range(256):
    for h in range(256):
        expression=((~h)|c)&1
        close=(c&1)==0 and (h&1)==1
        assert (expression==0)==close
        assert ((c|h)&1)==((c&1)|(h&1))
for c,h in ((0,0),(0,1),(1,0),(1,1),(2,3),(255,254)):
    rows.append(dict(c=c,h=h,close=((~h)|c)&1==0,early_result=(c|h)&1))
print(json.dumps(dict(domain_pairs=65536,claim='low-bit Boolean identities only',examples=rows,target_executed=False,target_emulated=False),indent=2))
