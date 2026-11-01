#!/usr/bin/env python3
"""Independent compact static intake validation; no instruction execution."""
from pathlib import Path
import hashlib,json,struct

ROOT=Path(__file__).resolve().parent
INTAKE=ROOT.parent/'hex-iterator-intake'
TARGET=ROOT.parent/'main/artifacts/node/94/hl-node'
sha=lambda raw:hashlib.sha256(raw).hexdigest()
data=TARGET.read_bytes()
assert len(data)==91774280 and sha(data)=='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
header=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
assert header[0][:6]==b'\x7fELF\x02\x01' and header[2]==62 and header[9]==56 and header[11]==64
ph=[struct.unpack_from('<IIQQQQQQ',data,header[5]+i*56) for i in range(header[10])]
sections=[struct.unpack_from('<IIQQQQIIQQ',data,header[6]+i*64) for i in range(header[12])]
strings=data[sections[header[13]][4]:sections[header[13]][4]+sections[header[13]][5]]
def secname(row):
    return strings[row[0]:strings.index(b'\x00',row[0])].decode()
def at(va,size,executable=False):
    loads=[row for row in ph if row[0]==1 and row[3]<=va<va+size<=row[3]+row[5]]
    secs=[row for row in sections if row[1]!=8 and row[2]&2 and row[3]<=va<va+size<=row[3]+row[5]]
    assert len(loads)==len(secs)==1
    if executable:assert loads[0][1]&1 and secs[0][2]&4
    offset=loads[0][2]+va-loads[0][3]
    assert offset==secs[0][4]+va-secs[0][3]
    return offset,data[offset:offset+size]
record_raw=(INTAKE/'records.json').read_bytes()
records=json.loads(record_raw)
details=json.loads((INTAKE/'data.json').read_bytes())
functions=[]
for row in records['functions']:
    if row['start'] not in (0x4eb64f0,0x4eb6360):continue
    offset,body=at(row['start'],row['bytes'],True)
    assert offset==row['file_offset'] and sha(body)==row['sha256']
    cursor=row['start']
    for instruction in row['rows']:
        raw=bytes.fromhex(instruction['raw']);assert instruction['va']==cursor
        assert data[offset+cursor-row['start']:offset+cursor-row['start']+len(raw)]==raw
        cursor+=len(raw)
    assert cursor==row['end']==row['start']+row['bytes']
    frame=bytes.fromhex(row['fde_raw']);cie=bytes.fromhex(row['cie_raw'])
    assert frame==data[row['fde_file_offset']:row['fde_file_offset']+len(frame)]
    assert cie==data[row['cie_file_offset']:row['cie_file_offset']+len(cie)]
    assert struct.unpack_from('<I',frame)[0]+4==len(frame)
    cie_back=struct.unpack_from('<I',frame,4)[0]
    assert row['fde_file_offset']+4-cie_back==row['cie_file_offset']
    delta,extent=struct.unpack_from('<iI',frame,8)
    assert row['fde_va']+8+delta==row['start'] and extent==row['bytes']
    stdout=(INTAKE/(format(row['start'],'x')+'.stdout')).read_bytes()
    assert sha(stdout)==row['stdout_sha256']
    functions.append({'start':row['start'],'end':row['end'],'bytes':len(body),'sha256':sha(body),
                      'file_offset':offset,'rows':len(row['rows']),'calls':row['calls'],
                      'fde_sha256':sha(frame),'fde_bytes':len(frame),'fde_file_offset':row['fde_file_offset'],
                      'cie_sha256':sha(cie),'stdout_sha256':sha(stdout)})
assert len(functions)==2
assert sorted(row['bytes'] for row in functions)==[140,953]
relas=[]
for section in sections:
    if section[1]==4:
        assert section[9]==24
        for position in range(section[4],section[4]+section[5],24):
            slot,info,addend=struct.unpack_from('<QQq',data,position)
            for function in functions:
                assert not (slot<function['end'] and slot+8>function['start'])
            relas.append({'slot':slot,'type':info&0xffffffff,'symbol':info>>32,'addend':addend,'record_file_offset':position})
expected_slots={0x576e118:0x157b480,0x576e070:0x15793d0,0x576e470:0x157a9f0}
selected=[]
for slot,callee in expected_slots.items():
    matches=[row for row in relas if row['slot']<slot+8 and row['slot']+8>slot]
    assert len(matches)==1 and matches[0]['slot']==slot and matches[0]['type']==8
    assert matches[0]['symbol']==0 and matches[0]['addend']==callee
    selected.extend(matches)
locations=[]
for row in details['panic_locations']:
    offset,raw=at(row['va'],24)
    assert offset==row['file_offset'] and raw.hex()==row['raw_hex']
    pointer,length,line,column=struct.unpack('<QQII',raw)
    assert pointer==0 and line==row['line'] and column==row['column']
    matches=[r for r in relas if r['slot']<row['va']+8 and r['slot']+8>row['va']]
    assert len(matches)==1 and matches[0]['slot']==row['va'] and matches[0]['type']==8 and matches[0]['symbol']==0
    path_offset,path=at(matches[0]['addend'],length)
    assert path_offset==row['source_file_offset'] and path.hex()==row['source_path_hex']
    locations.append({'va':row['va'],'bytes':24,'sha256':sha(raw),'line':line,'column':column,
                      'source_bytes':length,'source_path_sha256':sha(path),'RELATIVE':matches[0]})
receipt={'schema':'hex953-scalar140-independent-native-review-v1','status':'PASS',
         'target_sha256':sha(data),'target_bytes':len(data),'intake_records_sha256':sha(record_raw),
         'intake_data_sha256':sha((INTAKE/'data.json').read_bytes()),'functions':functions,
         'exceptional_slots':selected,'source_locations':locations,
         'all_selected_bodies_raw_rows_fde_cie_executable_mappings_verified':True,
         'normal_domain_proof_sha256':sha((ROOT/'hex-iterator-proof.md').read_bytes()),
         'limits':['Static file/ELF/row validation only, no target/helper execution or instruction evaluator.',
                   'Three exceptional targets are bound but their runtime semantics are not claimed; the proof makes them unreachable in the constructed valid-string domain.',
                   'Primary953 and supporting140 stay distinct; no prefix-strip/outerASCII acceptance API, original ABI, rebuilt-byte or component-gate claim.']}
out=ROOT/'HEX-NATIVE-REVIEW.json';out.write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
print(json.dumps({'receipt_sha256':sha(out.read_bytes()),'functions':functions,'location_count':len(locations)},sort_keys=True))
