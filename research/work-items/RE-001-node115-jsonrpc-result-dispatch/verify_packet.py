#!/usr/bin/env python3
"""Owned stdlib data probe. No imports from the repository, subprocess or network.

Encoded xref/call candidates are not validated instruction boundaries. This is
preparation for a bounded hosted decode, not a semantic equivalence claim.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import struct

TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
NEEDLE = b'data did not match any variant of untagged enum JsonRpcResult'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def cie_encoding(cie):
    """Decode only supported version-1 zR/zPLR records, with bounded reads.

    Field interpretation checked against LLVM lld ELF/EhFrame.cpp; this is an
    independently authored reader, not imported/copied implementation code.
    """
    require(cie[8] == 1, 'Unsupported CIE version')
    end = cie.find(b'\0', 9)
    require(end > 9, 'CIE augmentation string bounds')
    augmentation = cie[9:end].decode('ascii')
    require(augmentation in ('zR', 'zPLR'), 'Unsupported augmentation string')
    pos = end + 1

    def leb():
        nonlocal pos
        value = shift = 0
        for _ in range(10):
            require(pos < len(cie), 'CIE LEB bounds')
            byte = cie[pos]
            pos += 1
            value |= (byte & 127) << shift
            if not byte & 128:
                return value
            shift += 7
        raise ValueError('CIE LEB too long')

    leb()  # Code alignment, value not used to decode pointer encoding.
    leb()  # Signed data alignment: only its bounded encoded length is needed.
    require(pos < len(cie), 'CIE return register bounds')
    pos += 1  # Version 1 has a one-byte return-address register.
    length = leb()
    limit = pos + length
    require(limit <= len(cie), 'CIE augmentation data bounds')
    fields = {'augmentation': augmentation}
    for char in augmentation[1:]:
        require(pos < limit, 'CIE augmentation field bounds')
        value = cie[pos]
        pos += 1
        if char == 'P':
            require(value == 0x9b and pos + 4 <= limit, 'Unsupported personality pointer encoding')
            fields['personality_pointer_encoding'] = hex(value)
            pos += 4
        elif char == 'L':
            fields['lsda_pointer_encoding'] = hex(value)
        elif char == 'R':
            fields['fde_pointer_encoding'] = value
    require(pos == limit and fields['fde_pointer_encoding'] == 0x1b, 'FDE pointer encoding or augmentation length mismatch')
    return fields


def probe(data, extra_vas=()):
    require(len(data) == 105896032 and hashlib.sha256(data).hexdigest() == TARGET, 'Target identity mismatch')
    require(data[:7] == b'\x7fELF\x02\x01\x01' and struct.unpack_from('<H', data, 18)[0] == 62, 'Not supported ELF64 x86-64')
    shoff = struct.unpack_from('<Q', data, 40)[0]
    size, count, names_index = struct.unpack_from('<HHH', data, 58)
    require(size == 64 and 0 < names_index < count and shoff + count * size <= len(data), 'Section bounds')
    rows = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * size) for i in range(count)]
    names_row = rows[names_index]
    names = data[names_row[4]:names_row[4] + names_row[5]]
    sections = {}
    for row in rows:
        end = names.find(b'\0', row[0])
        require(0 <= row[0] <= end < len(names), 'Section name bounds')
        name = names[row[0]:end].decode('ascii')
        require(name not in sections, 'Duplicate section name')
        require(row[1] == 8 or row[4] + row[5] <= len(data), 'Section data bounds')
        sections[name] = row

    def at_va(va, length):
        hits = [r for r in rows if r[1] != 8 and r[2] & 2 and r[3] <= va and va + length <= r[3] + r[5]]
        require(len(hits) == 1, 'Ambiguous or unmapped allocated VA')
        r = hits[0]
        off = r[4] + va - r[3]
        return off, data[off:off + length]

    text = sections['.text']
    require(text[2] & 6 == 6, 'Non-executable text')
    code = data[text[4]:text[4] + text[5]]
    literals = []
    offset = 0
    while (offset := data.find(NEEDLE, offset)) >= 0:
        owners = [(name, r) for name, r in sections.items() if r[1] != 8 and r[4] <= offset and offset + len(NEEDLE) <= r[4] + r[5]]
        require(len(owners) == 1, 'Literal section ownership')
        name, r = owners[0]
        require(r[2] & 2 and not r[2] & 5, 'Literal is not readonly allocated data')
        literals.append({'file_offset': hex(offset), 'va': hex(r[3] + offset - r[4]), 'section': name, 'bytes': len(NEEDLE)})
        offset += 1
    require(len(literals) == 1, 'Expected one exact diagnostic')
    target = int(literals[0]['va'], 16)
    hdr, frame = sections['.eh_frame_hdr'], sections['.eh_frame']
    hpos = hdr[4]
    require(data[hpos:hpos + 4] == b'\x01\x1b\x03\x3b', 'Unsupported unwind header')
    n = struct.unpack_from('<I', data, hpos + 8)[0]
    require(0 < n and 12 + n * 8 <= hdr[5], 'Unwind table bounds')
    entries = [tuple(hdr[3] + v for v in struct.unpack_from('<ii', data, hpos + 12 + 8 * i)) for i in range(n)]
    require(all(a[0] < b[0] for a, b in zip(entries, entries[1:])), 'Unwind starts not strictly ordered')
    starts = [row[0] for row in entries]

    def fde_candidate(va):
        ordinal = bisect.bisect_right(starts, va) - 1
        require(ordinal >= 0, 'No preceding unwind start')
        start, fde_va = entries[ordinal]
        off, raw = at_va(fde_va, 16)
        length, distance, delta, extent = struct.unpack('<IIii', raw)
        require(12 <= length < 4096 and frame[4] <= off < off + length + 4 <= frame[4] + frame[5], 'FDE bounds')
        cie_off = off + 4 - distance
        require(frame[4] <= cie_off < off, 'CIE back-reference')
        cie_length, cie_id = struct.unpack_from('<II', data, cie_off)
        require(cie_id == 0 and cie_off + 4 + cie_length <= frame[4] + frame[5], 'CIE bounds/id')
        cie = data[cie_off:cie_off + 4 + cie_length]
        encoding = cie_encoding(cie)
        require(fde_va + 8 + delta == start and start <= va < start + extent and extent > 0, 'FDE actual extent does not cover candidate')
        body_off, body = at_va(start, extent)
        return {'start_va': hex(start), 'end_va': hex(start + extent), 'bytes': extent,
                'file_offset': hex(body_off), 'body_sha256': hashlib.sha256(body).hexdigest(),
                'unwind_index_row': ordinal, 'fde_va': hex(fde_va), 'fde_file_offset': hex(off),
                'fde_hex': data[off:off + 4 + length].hex(), 'cie_file_offset': hex(cie_off),
                'cie_hex': cie.hex(), 'fde_pointer_encoding': '0x1b (pcrel signed-4-byte)',
                'cie_fields': encoding,
                'limits': 'Actual unwind record extent, not complete CFG/exception closure or source ownership'}

    xrefs = []
    for match in re.finditer(rb'[\x40-\x4f]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', code):
        i = match.start()
        if i + 7 > len(code):
            continue
        va = text[3] + i
        if va + 7 + struct.unpack_from('<i', code, i + 3)[0] == target:
            xrefs.append({'candidate_va': hex(va), 'bytes': code[i:i + 7].hex(),
                          'target_va': hex(target), 'instruction_boundary_validated': False,
                          'fde': fde_candidate(va)})
    require(xrefs, 'No direct RIP-relative LEA candidate; expand only by a reviewed plan')
    functions = {int(row['fde']['start_va'], 16) for row in xrefs}
    calls = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        if pos + 5 <= len(code):
            va = text[3] + pos
            destination = va + 5 + struct.unpack_from('<i', code, pos + 1)[0]
            if destination in functions:
                calls.append({'candidate_va': hex(va), 'bytes': code[pos:pos + 5].hex(),
                              'destination_va': hex(destination), 'instruction_boundary_validated': False,
                              'fde': fde_candidate(va)})
        pos += 1
    result = {'status': 'DATA_ONLY_REMAP_CANDIDATES_NOT_NATIVE_VALIDATED', 'target_sha256': TARGET,
            'target_bytes': len(data), 'literal': literals[0], 'diagnostic': NEEDLE.decode(),
            'text_bytes': text[5], 'unwind_index_rows': n, 'encoded_lea_candidates': xrefs,
            'encoded_direct_call_candidates': calls, 'repository_imports': False,
            'native_decoder_run': False, 'captured_execution': False,
            'limits': 'Encoded patterns can occur inside other instructions or data; hosted native decoding must qualify every edge and semantic claim.'}
    if extra_vas:
        result['selected_fde_candidates']={hex(va): fde_candidate(va) for va in extra_vas}
    return result



import sys

def verify_retained_packet(data, packet):
    for line in (packet/'MANIFEST.sha256').read_text().splitlines():
        expected,name=line.split('  ',1)
        path=Path(name)
        require(not path.is_absolute() and '..' not in path.parts,'unsafe manifest entry')
        require(hashlib.sha256((packet/path).read_bytes()).hexdigest()==expected,'packet manifest mismatch: '+name)
    current=probe(data)
    require(current==json.loads((packet/'candidates.json').read_text()),'candidate metadata drift')
    hosted=json.loads((packet/'receipts/full-input-replay.json').read_text())
    require(current==hosted,'hosted complete-input result drift')
    result=json.loads((packet/'receipts/decode-result.json').read_text())
    evidence=json.loads((packet/'evidence.json').read_text())
    require(result['target_sha256']==current['target_sha256'] and result['whole_elf_reauthenticated_in_job'],'hosted target binding')
    bodies={}; rows_by_label={}; total=0
    for label,candidate in [('constructor-candidate',current['encoded_lea_candidates'][0]),('delegate-candidate',current['encoded_direct_call_candidates'][0])]:
        record=candidate['fde'];start=int(record['start_va'],16);off=int(record['file_offset'],16)
        body=data[off:off+record['bytes']]
        require(hashlib.sha256(body).hexdigest()==record['body_sha256'],'body digest mismatch')
        rows=[];cursor=start
        for line in (packet/'receipts'/(label+'.stdout')).read_text().splitlines():
            if not re.match(r'^\s*[0-9a-f]+:',line):continue
            parts=line.split('\t');require(len(parts)>=3,'native row syntax')
            va=int(parts[0].strip().rstrip(':'),16);tokens=parts[1].split()
            require(tokens and all(re.fullmatch('[0-9a-f]{2}',token) for token in tokens),'native byte syntax')
            raw=bytes.fromhex(' '.join(tokens));text=' '.join(parts[2:]).strip()
            require(va==cursor and body[va-start:va-start+len(raw)]==raw,'native/full-input bytes differ')
            require(text and '(bad)' not in text and not text.startswith('.byte'),'undecoded native bytes')
            rows.append({'va':hex(va),'bytes':raw.hex(),'text':text});cursor+=len(raw)
        saved=next(r for r in result['regions'] if r['label']==label)
        require(rows==saved['instruction_rows'] and cursor==int(record['end_va'],16),'native extent/record drift')
        require(len(rows)==saved['instructions']==evidence['instruction_counts'][label],'native instruction count drift')
        bodies[label]=(start,body);rows_by_label[label]={int(row['va'],16):row for row in rows};total+=len(rows)
    bindings=json.loads((packet/'field-bindings.json').read_text())
    def fields(active):
        for field in bindings:
            label=field['region'];va=int(field['va'],16);raw=bytes.fromhex(field['bytes']);start,body=active[label]
            require(va in rows_by_label[label] and rows_by_label[label][va]['bytes']==field['bytes'],'field native boundary')
            require(body[va-start:va-start+len(raw)]==raw,'field bytes differ: '+field['label'])
    fields(bodies)
    controls=[]
    for field in bindings:
        active=dict(bodies);label=field['region'];start,body=bodies[label];changed=bytearray(body)
        changed[int(field['va'],16)-start+len(bytes.fromhex(field['bytes']))-1]^=1
        active[label]=(start,changed)
        try:fields(active)
        except ValueError as error:controls.append({'control':field['label'],'rejection':str(error)})
        else:raise ValueError('field evidence corruption escaped')
    for candidate in [current['encoded_lea_candidates'][0],current['encoded_direct_call_candidates'][0]]:
        record=candidate['fde'];fde=bytes.fromhex(record['fde_hex'])
        def extent(raw):
            delta,length=struct.unpack_from('<ii',raw,8)
            require(int(record['fde_va'],16)+8+delta==int(record['start_va'],16),'FDE initial-location drift')
            require(length==record['bytes'] and int(record['start_va'],16)+length==int(record['end_va'],16),'FDE actual extent drift')
        extent(fde);changed=bytearray(fde);changed[12]^=1
        try:extent(changed)
        except ValueError as error:controls.append({'control':'FDE extent '+record['start_va'],'rejection':str(error)})
        else:raise ValueError('FDE extent corruption escaped')
    return {'status':'COMPLETE_INPUT_AND_RETAINED_NATIVE_BYTES_REPRODUCED','target_sha256':current['target_sha256'],
            'target_bytes':len(data),'regions':2,'region_bytes':2296,'native_instruction_rows':total,
            'instruction_counts':evidence['instruction_counts'],'unwind_rows_checked':current['unwind_index_rows'],
            'field_bindings':len(bindings),'evidence_corruptions_rejected':len(controls),'controls':controls,
            'python':sys.version.split()[0],
            'native_decoder_run':False,'captured_execution':False,'repository_imports':False,
            'limits':'Authenticates retained static observations; controls corrupt evidence fields, not runtime parser inputs. No helper/schema/exception closure, Rust build, repository-suite pass or completion gate.'}


def verify_completion(data, packet):
    directory=packet/'completion'
    current=probe(data, extra_vas=(0x1700a10,0x17073f9))
    require(current==json.loads((directory/'candidates.json').read_text()),'completion candidate drift')
    require(current==json.loads((directory/'receipts/full-input-replay.json').read_text()),'completion hosted replay drift')
    native=json.loads((directory/'receipts/decode-result.json').read_text())
    require(native['target_sha256']==TARGET and native['whole_elf_reauthenticated_in_job'],'completion target binding')
    require(native['input_hashes_unchanged'] and not native['captured_program_executed'],'completion input/execution claim')
    bodies={};native_rows={}
    for label,key in [('completion-candidate','0x1700a10'),('delegate-candidate','0x17073f9')]:
        record=current['selected_fde_candidates'][key];start=int(record['start_va'],16);off=int(record['file_offset'],16)
        body=data[off:off+record['bytes']]
        require(hashlib.sha256(body).hexdigest()==record['body_sha256'],'completion body identity')
        cursor=start;rows=[]
        for line in (directory/'receipts'/(label+'.stdout')).read_text().splitlines():
            if not re.match(r'^\s*[0-9a-f]+:',line):continue
            pieces=line.split('\t');require(len(pieces)>=3,'completion native syntax')
            va=int(pieces[0].strip().rstrip(':'),16);tokens=pieces[1].split()
            require(tokens and all(re.fullmatch('[0-9a-f]{2}',t) for t in tokens),'completion native byte syntax')
            raw=bytes.fromhex(' '.join(tokens));text=' '.join(pieces[2:]).strip()
            require(va==cursor and body[va-start:va-start+len(raw)]==raw,'completion native/input byte mismatch')
            require(text and '(bad)' not in text and not text.startswith('.byte'),'completion undecoded row')
            rows.append(dict(va=hex(va),bytes=raw.hex(),text=text));cursor+=len(raw)
        saved=next(r for r in native['regions'] if r['label']==label)
        require(rows==saved['instruction_rows'] and len(rows)==saved['instructions'],'completion instruction rows drift')
        require(cursor==int(record['end_va'],16),'completion native extent drift')
        bodies[label]=(start,body);native_rows[label]={int(r['va'],16):r for r in rows}
    old=json.loads((packet/'receipts/decode-result.json').read_text())
    original=next(r for r in old['regions'] if r['label']=='delegate-candidate')
    renewed=next(r for r in native['regions'] if r['label']=='delegate-candidate')
    require(original['instruction_rows']==renewed['instruction_rows'],'renewed caller differs from original native evidence')
    edges=json.loads((directory/'receipts/qualified-candidate-edges.json').read_text())
    require(len(edges)==1 and edges[0]['native_instruction_boundary_validated'],'completion edge qualification')
    call=native_rows['delegate-candidate'][0x17073f9];raw=bytes.fromhex(call['bytes'])
    require(raw[0]==0xe8 and 0x17073f9+5+struct.unpack_from('<i',raw,1)[0]==0x1700a10,'completion direct call target')
    require(edges[0]['candidate_va']==call['va'] and edges[0]['bytes']==call['bytes'],'completion edge bytes')
    fields=json.loads((directory/'field-bindings.json').read_text())
    def check_fields(active):
        for field in fields:
            label=field['region'];va=int(field['va'],16);raw=bytes.fromhex(field['bytes']);start,body=active[label]
            require(native_rows[label].get(va,{}).get('bytes')==field['bytes'],'completion field native boundary')
            require(body[va-start:va-start+len(raw)]==raw,'completion field corruption: '+field['label'])
    check_fields(bodies);controls=[]
    for field in fields:
        active=dict(bodies);start,body=bodies[field['region']];changed=bytearray(body)
        changed[int(field['va'],16)-start+len(bytes.fromhex(field['bytes']))-1]^=1
        active[field['region']]=(start,changed)
        try:check_fields(active)
        except ValueError as error:controls.append(dict(control=field['label'],rejection=str(error)))
        else:raise ValueError('completion field corruption escaped')
    for record in current['selected_fde_candidates'].values():
        raw=bytes.fromhex(record['fde_hex'])
        def extent(candidate):
            delta,length=struct.unpack_from('<ii',candidate,8)
            require(int(record['fde_va'],16)+8+delta==int(record['start_va'],16),'completion FDE location')
            require(length==record['bytes'] and int(record['start_va'],16)+length==int(record['end_va'],16),'completion FDE extent')
        extent(raw);changed=bytearray(raw);changed[12]^=1
        try:extent(changed)
        except ValueError as error:controls.append(dict(control='completion FDE '+record['start_va'],rejection=str(error)))
        else:raise ValueError('completion FDE corruption escaped')
    rows=native_rows['completion-candidate']
    def instruction(va):return bytes.fromhex(rows[va]['bytes'])
    mask_raw=instruction(0x1700a2b);bound_raw=instruction(0x1700a3b)
    require(mask_raw[:2]==b'\x48\xbe' and bound_raw[:3]==b'\x49\x83\xf8','predicate operand encoding')
    mask=int.from_bytes(mask_raw[2:],'little');upper=bound_raw[3]
    whitespace=[v for v in range(256) if v<=upper and mask & (1<<v)]
    require(whitespace==[9,10,13,32] and upper==44,'whitespace predicate domain')
    require(instruction(0x1700a70)==bytes.fromhex('4983f82c'),'comma predicate')
    require(instruction(0x1700a8b)==bytes.fromhex('4183f87d'),'closing brace predicate')
    raw_tags={}
    for label,va in [('at_or_after_end',0x1700a5b),('comma',0x1700a76),('other_unexpected_byte',0x1700aa1)]:
        raw=instruction(va);require(raw[:4]==bytes.fromhex('48c70424'),'raw tag store encoding')
        raw_tags[label]=int.from_bytes(raw[4:],'little')
    require(raw_tags=={'at_or_after_end':3,'comma':21,'other_unexpected_byte':22},'raw error tag operands')
    calls=[];branches=[]
    for va,row in rows.items():
        raw=bytes.fromhex(row['bytes'])
        if raw[0]==0xe8:
            target=va+len(raw)+struct.unpack_from('<i',raw,1)[0]
            require(target==0x16ffc80,'completion opaque error callee target');calls.append(dict(va=hex(va),target=hex(target)))
        elif 0x70<=raw[0]<=0x7f:
            target=va+len(raw)+struct.unpack_from('<b',raw,1)[0]
            require(target in rows,'completion conditional branch target boundary');branches.append(dict(va=hex(va),target=hex(target)))
    require(len(calls)==3 and len(branches)==7,'completion direct control-transfer inventory')
    helper=next(r for r in native['regions'] if r['label']=='completion-candidate')
    return dict(status='COMPLETION_HELPER_STATIC_EVIDENCE_REPRODUCED',helper_instructions=helper['instructions'],
        helper_bytes=helper['bytes'],renewed_caller_rows=len(native_rows['delegate-candidate']),
        field_bindings=len(fields),evidence_corruptions_rejected=len(controls),controls=controls,
        whitespace_byte_domain=whitespace,predicate_values_enumerated=256,raw_error_tags=raw_tags,
        direct_error_calls=calls,conditional_branches=branches,
        limits='Static instruction/evidence checks, not parser execution, accepted input schemas, opaque error-helper closure or whole-input trailing-data validation.')


def extract_variant_data(data):
    assert hashlib.sha256(data).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
    off=struct.unpack_from('<Q',data,40)[0];size,count,namesidx=struct.unpack_from('<HHH',data,58);assert size==64
    rows=[struct.unpack_from('<IIQQQQIIQQ',data,off+i*size) for i in range(count)]
    namesrow=rows[namesidx];names=data[namesrow[4]:namesrow[4]+namesrow[5]]
    def at(va,length):
        hits=[r for r in rows if r[1]!=8 and r[2]&2 and r[3]<=va and va+length<=r[3]+r[5]]
        assert len(hits)==1
        row=hits[0];assert not row[2]&5
        pos=row[4]+va-row[3];raw=data[pos:pos+length]
        return dict(va=hex(va),file_offset=hex(pos),bytes=length,section=names[row[0]:names.find(b'\0',row[0])].decode(),
            data_hex=raw.hex(),sha256=hashlib.sha256(raw).hexdigest())
    result={'target_sha256':hashlib.sha256(data).hexdigest(),'tables':{},'literals':{}}
    for label,va,n in [('outer-selected',0x47dd9c,22),('key-bounded',0x47ddf4,15)]:
        record=at(va,n*4);raw=bytes.fromhex(record['data_hex'])
        record['entries']=[dict(index=i,displacement=struct.unpack_from('<i',raw,4*i)[0],target=hex(va+struct.unpack_from('<i',raw,4*i)[0])) for i in range(n)]
        record['limits']='22 selected entries, no local outer tag-bound proved' if n==22 else '15 entries bounded by raw-key-minus-one <=14 in native code'
        result['tables'][label]=record
    for label,va,n in [('result-field',0x47e529,6),('missing-format-window',0x4325c4,32),('duplicate-format-window',0x43351a,32)]:
        record=at(va,n);record['ascii_preview']=bytes.fromhex(record['data_hex']).decode('ascii',errors='backslashreplace');result['literals'][label]=record
    return result

def verify_first_variant(data, packet):
    folder=packet/'first-variant'
    current=probe(data,extra_vas=(0x16fdba0,0x175140e))
    require(current==json.loads((folder/'candidates.json').read_text()),'variant candidate drift')
    require(current==json.loads((folder/'receipts/full-input-replay.json').read_text()),'variant hosted full-input drift')
    native=json.loads((folder/'receipts/decode-result.json').read_text())
    require(native['target_sha256']==TARGET and native['whole_elf_reauthenticated_in_job'] and native['input_hashes_unchanged'],'variant target/input binding')
    bodies={};rowmaps={}
    for label,key in [('variant-candidate','0x16fdba0'),('constructor-candidate','0x175140e')]:
        record=current['selected_fde_candidates'][key];start=int(record['start_va'],16);off=int(record['file_offset'],16)
        body=data[off:off+record['bytes']];require(hashlib.sha256(body).hexdigest()==record['body_sha256'],'variant body identity')
        cursor=start;rows=[]
        for line in (folder/'receipts'/(label+'.stdout')).read_text().splitlines():
            if not re.match(r'^\s*[0-9a-f]+:',line):continue
            pieces=line.split('\t');require(len(pieces)>=3,'variant native syntax')
            va=int(pieces[0].strip().rstrip(':'),16);tokens=pieces[1].split()
            require(tokens and all(re.fullmatch('[0-9a-f]{2}',t) for t in tokens),'variant native byte syntax')
            raw=bytes.fromhex(' '.join(tokens));text=' '.join(pieces[2:]).strip()
            require(va==cursor and body[va-start:va-start+len(raw)]==raw,'variant native/input bytes')
            require(text and '(bad)' not in text and not text.startswith('.byte'),'variant native undecoded row')
            rows.append(dict(va=hex(va),bytes=raw.hex(),text=text));cursor+=len(raw)
        saved=next(r for r in native['regions'] if r['label']==label)
        require(rows==saved['instruction_rows'] and len(rows)==saved['instructions'] and cursor==int(record['end_va'],16),'variant native rows/extent')
        bodies[label]=(start,body);rowmaps[label]={int(r['va'],16):r for r in rows}
    old=json.loads((packet/'receipts/decode-result.json').read_text())
    require(next(r['instruction_rows'] for r in old['regions'] if r['label']=='constructor-candidate')==
            next(r['instruction_rows'] for r in native['regions'] if r['label']=='constructor-candidate'),'renewed constructor drift')
    edge=json.loads((folder/'receipts/qualified-candidate-edges.json').read_text())
    call=rowmaps['constructor-candidate'][0x175140e];raw=bytes.fromhex(call['bytes'])
    require(len(edge)==1 and edge[0]['native_instruction_boundary_validated'] and edge[0]['bytes']==call['bytes'],'variant edge qualification')
    require(raw[0]==0xe8 and 0x175140e+5+struct.unpack_from('<i',raw,1)[0]==0x16fdba0,'variant direct call target')
    fields=json.loads((folder/'field-bindings.json').read_text())
    def check_fields(active):
        for f in fields:
            label=f['region'];va=int(f['va'],16);raw=bytes.fromhex(f['bytes']);start,body=active[label]
            require(rowmaps[label].get(va,{}).get('bytes')==f['bytes'],'variant field boundary')
            require(body[va-start:va-start+len(raw)]==raw,'variant field corruption: '+f['label'])
    check_fields(bodies);controls=[]
    for f in fields:
        active=dict(bodies);start,body=bodies[f['region']];changed=bytearray(body)
        changed[int(f['va'],16)-start+len(bytes.fromhex(f['bytes']))-1]^=1;active[f['region']]=(start,changed)
        try:check_fields(active)
        except ValueError as error:controls.append(dict(control='first variant '+f['label'],rejection=str(error)))
        else:raise ValueError('variant field mutation escaped')
    for record in current['selected_fde_candidates'].values():
        raw=bytes.fromhex(record['fde_hex'])
        def extent(candidate):
            delta,length=struct.unpack_from('<ii',candidate,8)
            require(int(record['fde_va'],16)+8+delta==int(record['start_va'],16),'variant FDE location')
            require(length==record['bytes'] and int(record['start_va'],16)+length==int(record['end_va'],16),'variant FDE extent')
        extent(raw);changed=bytearray(raw);changed[12]^=1
        try:extent(changed)
        except ValueError as error:controls.append(dict(control='first variant FDE '+record['start_va'],rejection=str(error)))
        else:raise ValueError('variant FDE mutation escaped')
    computed=extract_variant_data(data);saved=json.loads((folder/'referenced-data.json').read_text())
    require(computed==saved,'variant readonly data drift')
    active={group+'/'+name:bytes.fromhex(r['data_hex']) for group in ['tables','literals'] for name,r in computed[group].items()}
    def check_data(values):
        for name,raw in values.items():
            group,key=name.split('/',1);require(raw.hex()==saved[group][key]['data_hex'],'variant referenced data corruption: '+name)
    check_data(active)
    for name,body in active.items():
        count=len(body)//4 if name.startswith('tables/') else 1
        for i in range(count):
            values=dict(active);changed=bytearray(body);changed[4*i if name.startswith('tables/') else len(body)//2]^=1;values[name]=changed
            try:check_data(values)
            except ValueError as error:controls.append(dict(control=name+' entry '+str(i),rejection=str(error)))
            else:raise ValueError('variant referenced data mutation escaped')
    rows=rowmaps['variant-candidate'];instruction=lambda va:bytes.fromhex(rows[va]['bytes'])
    for site,target in [(0x16fdbb4,0x47dd9c),(0x16fdbe0,0x47ddf4),(0x16fdd45,0x47e529),
                        (0x16fdf35,0x47e529),(0x16fdd70,0x4325c4),(0x16fdf60,0x43351a)]:
        raw=instruction(site)
        require(raw[:2]==bytes.fromhex('488d') and site+len(raw)+struct.unpack_from('<i',raw,3)[0]==target,'variant RIP-relative data binding')
    for table in computed['tables'].values():
        require(all(int(r['target'],16) in rows for r in table['entries']),'variant table target is not a native instruction boundary')
    require(instruction(0x16fdc14)==bytes.fromhex('83fa0e') and instruction(0x16fdc12)==bytes.fromhex('ffca'),'key table index bound')
    outer=computed['tables']['outer-selected'];keys=computed['tables']['key-bounded']
    require(outer['entries'][21]['target']=='0x16fdbc4' and len(outer['entries'])==22,'selected outer map-like path')
    require(len(keys['entries'])==15,'bounded key table length')
    routes=[dict(raw_key_tag=tag,target=keys['entries'][(tag-1)&0xffffffff]['target'] if (tag-1)&0xffffffff<=14 else '0x16fdf6c') for tag in range(256)]
    name=bytes.fromhex(computed['literals']['result-field']['data_hex']);require(name==b'result','result name literal')
    wide=instruction(0x16fdc90)[1:5]+instruction(0x16fdc9b)[2:4]
    bytewise=bytes([instruction(va)[-1] for va in [0x16fdc48,0x16fdc5f,0x16fdc65,0x16fdc6b,0x16fdc71,0x16fdc77]])
    require(wide==bytewise==name and instruction(0x16fdc5a)[-1]==name[0],'independent key comparison constants')
    for va in [0x16fdc30,0x16fdc3d,0x16fdc4f,0x16fdc7f]:require(instruction(va)[-1]==6,'six-byte key length guard')
    def matches(key):
        wide_ok=len(key)==6 and ((int.from_bytes(key[:4],'little')^int.from_bytes(wide[:4],'little')) |
            (int.from_bytes(key[4:],'little')^int.from_bytes(wide[4:],'little')))==0
        byte_ok=len(key)==6 and all(key[i]==bytewise[i] for i in range(6))
        require(wide_ok==byte_ok,'wide/bytewise key predicate disagreement');return wide_ok
    require(matches(name),'baseline field name rejected');key_mutations=0
    for i in range(6):
        for v in range(256):
            if v==name[i]:continue
            changed=bytearray(name);changed[i]=v;require(not matches(changed),'mutated field name accepted');key_mutations+=1
    require(key_mutations==1530,'field-name mutation denominator')
    direct_calls=[];branches=[]
    for va,row in rows.items():
        raw=bytes.fromhex(row['bytes']);target=None
        if raw[0]==0xe8:
            target=va+5+struct.unpack_from('<i',raw,1)[0]
            require(target in [0x16fd8b0,0x1742090,0x1704de0],'variant direct callee inventory')
            direct_calls.append(dict(va=hex(va),target=hex(target)));continue
        if raw[0] in [0xeb] or 0x70<=raw[0]<=0x7f:target=va+len(raw)+struct.unpack_from('<b',raw,1)[0]
        elif raw[0]==0xe9:target=va+len(raw)+struct.unpack_from('<i',raw,1)[0]
        elif raw[:1]==b'\x0f' and len(raw)>1 and 0x80<=raw[1]<=0x8f:target=va+len(raw)+struct.unpack_from('<i',raw,2)[0]
        if target is not None:
            require(target in rows,'variant direct branch target boundary');branches.append(dict(va=hex(va),target=hex(target)))
    require(len(direct_calls)==3,'variant direct callee count')
    # These six observed stores cover 40 bytes, not the constructor's 104-byte total.
    stores=[(0x16fdd01,11,4),(0x16fdd04,8,4),(0x16fdd0c,23,16),(0x16fdd15,39,1),(0x16fdd25,0,8),(0x16fdd28,15,8)]
    store_bytes=['89530b','894b08','0f114317','884b27','48890b','4889430f']
    coverage=set()
    for (va,offset,size),encoding in zip(stores,store_bytes):
        require(instruction(va).hex()==encoding,'variant output store encoding');coverage.update(range(offset,offset+size))
    require(coverage==set(range(40)),'observed ordinary store coverage')
    sentinel=int.from_bytes(instruction(0x16fdd18)[2:],'little')
    require(sentinel==0x8000000000000001 and instruction(0x16fdd22)==bytes.fromhex('48ffc9'),'ordinary tag construction')
    variant=next(r for r in native['regions'] if r['label']=='variant-candidate')
    return dict(status='FIRST_VARIANT_LOCAL_FIELD_EVIDENCE_REPRODUCED',variant_instructions=variant['instructions'],variant_bytes=variant['bytes'],
        field_bindings=len(fields),evidence_corruptions_rejected=len(controls),controls=controls,
        field_name=name.decode(),selected_outer_entries=22,bounded_key_entries=15,key_tag_values_enumerated=256,
        nonfallback_key_tags=[r['raw_key_tag'] for r in routes if r['target']!='0x16fdf6c'],
        baseline_field_name_cases=1,distinct_single_byte_key_mutations_rejected=key_mutations,
        direct_calls=direct_calls,direct_branches=branches,ordinary_observed_store_bytes=40,ordinary_first_word=hex(sentinel-1),
        limits='Local result-field recognition/presence/duplicate paths on raw internal records. Value converter, complete accepted JSON/value domain, outer tag validity, source/type ownership and exception closure remain unresolved.')



def main():
    parser=argparse.ArgumentParser(description='Owned stdlib complete-input/native evidence verifier; no subprocess or captured execution.')
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--packet',type=Path,default=Path(__file__).resolve().parent)
    args=parser.parse_args()
    data=args.binary.read_bytes()
    result=verify_retained_packet(data,args.packet)
    completion=verify_completion(data,args.packet)
    result['regions']=3;result['region_bytes']+=completion['helper_bytes']
    result['native_instruction_rows']+=completion['helper_instructions']
    result['instruction_counts']['completion-candidate']=completion['helper_instructions']
    result['field_bindings']+=completion['field_bindings']
    result['evidence_corruptions_rejected']+=completion['evidence_corruptions_rejected']
    result['controls']+=completion['controls']
    result['completion']=completion
    variant=verify_first_variant(data,args.packet)
    result['regions']+=1;result['region_bytes']+=variant['variant_bytes']
    result['native_instruction_rows']+=variant['variant_instructions']
    result['instruction_counts']['variant-candidate']=variant['variant_instructions']
    result['field_bindings']+=variant['field_bindings']
    result['evidence_corruptions_rejected']+=variant['evidence_corruptions_rejected']
    result['controls']+=variant['controls'];result['first_variant']=variant
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
