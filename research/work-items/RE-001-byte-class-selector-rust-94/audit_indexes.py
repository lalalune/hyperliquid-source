#!/usr/bin/env python3
"""Compare prefix-maximum overlap indexes with exhaustive interval predicates."""
import bisect
import struct
from static_evidence import TARGET,SHA,WINDOWS,sections,require,sha
from fde_extents import eh_frame_records

def main():
    data=TARGET.read_bytes();require(sha(data)==SHA,'target identity');secs=sections(data);_,frames=eh_frame_records(data,secs)
    ordered=sorted(frames,key=lambda f:f['start']);starts=[f['start'] for f in ordered];ends=[];maximum=0
    for f in ordered:maximum=max(maximum,f['end']);ends.append(maximum)
    for start,end,_ in WINDOWS.values():
        expected={f['fde'] for f in frames if f['start']<end and start<f['end']}
        i=bisect.bisect_left(starts,end);actual=set()
        while i and ends[i-1]>start:
            i-=1
            if ordered[i]['end']>start:actual.add(ordered[i]['fde'])
        require(actual==expected,'FDE index/exhaustive disagreement')
    intervals=sorted((s,e) for s,e,_ in WINDOWS.values());starts=[s for s,_ in intervals];ends=[];maximum=0
    for _,end in intervals:maximum=max(maximum,end);ends.append(maximum)
    slots=[]
    for section in secs:
        if section['type']==4:
            slots.extend(struct.unpack_from('<Q',data,o)[0] for o in range(section['offset'],section['offset']+section['size'],24))
    actual_slots=len(slots)
    for start,end in intervals:slots.extend((start-8,start-7,start,start+1,end-8,end-1,end))
    for slot in slots:
        expected=any(slot<end and start<slot+8 for start,end in intervals)
        i=bisect.bisect_left(starts,slot+8);actual=i>0 and ends[i-1]>slot
        require(actual==expected,'relocation index/exhaustive disagreement')
    print(f'PASS {len(WINDOWS)} FDE queries, {actual_slots} actual relocation destinations, {len(slots)-actual_slots} synthetic boundary destinations against exhaustive predicates')
if __name__=='__main__':main()
