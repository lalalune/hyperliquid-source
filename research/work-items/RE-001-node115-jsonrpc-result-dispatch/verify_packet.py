#!/usr/bin/env python3
"""Authenticate retained node115 native evidence against the complete capture.

Standard-library data checks only: no repository imports, subprocess, network,
native decoder or captured-program execution. Observations remain scoped.
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
        limits='Local result-field recognition/presence/duplicate paths on raw internal records. Delegated value conversion contracts, complete JSON/value domain, outer tag validity, source/type ownership and exception closure remain unresolved.')



def extract_value_data(data):
    assert len(data)==105896032 and hashlib.sha256(data).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
    shoff=struct.unpack_from('<Q',data,40)[0];size,count,nameidx=struct.unpack_from('<HHH',data,58);assert size==64
    rows=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+64*i) for i in range(count)]
    sr=rows[nameidx];names=data[sr[4]:sr[4]+sr[5]]
    sections={names[r[0]:names.find(b'\0',r[0])].decode():r for r in rows}
    def at(va,n):
        hits=[(name,r) for name,r in sections.items() if r[1]!=8 and r[2]&2 and r[3]<=va and va+n<=r[3]+r[5]];assert len(hits)==1
        name,row=hits[0];off=row[4]+va-row[3];raw=data[off:off+n]
        return dict(va=hex(va),file_offset=hex(off),section=name,section_flags=row[2],bytes=n,data_hex=raw.hex(),sha256=hashlib.sha256(raw).hexdigest())
    table=at(0x47dd44,22*4);raw=bytes.fromhex(table['data_hex'])
    table['entries']=[dict(raw_tag=i,displacement=struct.unpack_from('<i',raw,4*i)[0],target=hex(0x47dd44+struct.unpack_from('<i',raw,4*i)[0])) for i in range(22)]
    table['limits']='22 retained entries; no local tag bound or complete raw/JSON tag-domain proof'
    rela=sections['.rela.dyn'];records={}
    for off in range(rela[4],rela[4]+rela[5],24):
        slot,info,addend=struct.unpack_from('<QQq',data,off)
        if slot in [0x64e1e48,0x64e0900,0x64df520]:
            assert slot not in records
            records[slot]=dict(slot=hex(slot),info=info,addend=hex(addend),relocation_file_offset=hex(off),relocation_hex=data[off:off+24].hex(),stored_pointer=at(slot,8))
    assert len(records)==3
    return dict(target_sha256=hashlib.sha256(data).hexdigest(),table=table,relocations=list(records.values()),
        descriptors=[at(va,32) for va in [0x640e390,0x640c008,0x640bff0]],
        limits='Allocated descriptor bytes are unidentified data, not recovered source types or vtable layouts. Relocations identify targets without establishing their contracts.')

def verify_value_helper(data, packet):
    folder=packet/'value-helper'
    current=probe(data,extra_vas=(0x16fd8b0,0x16fdcb9))
    require(current==json.loads((folder/'candidates.json').read_text()),'value helper candidate drift')
    require(current==json.loads((folder/'receipts/full-input-replay.json').read_text()),'value helper hosted replay drift')
    native=json.loads((folder/'receipts/decode-result.json').read_text())
    require(native['target_sha256']==TARGET and native['whole_elf_reauthenticated_in_job'] and native['input_hashes_unchanged'],'value helper input binding')
    require(not native['captured_program_executed'] and native['native_invocations']==3,'value helper execution record')
    bodies={};rowmaps={}
    for label,key in [('value-candidate','0x16fd8b0'),('variant-candidate','0x16fdcb9')]:
        record=current['selected_fde_candidates'][key];start=int(record['start_va'],16);off=int(record['file_offset'],16)
        body=data[off:off+record['bytes']]
        require(hashlib.sha256(body).hexdigest()==record['body_sha256'],'value helper body identity')
        cursor=start;rows=[]
        for line in (folder/'receipts'/(label+'.stdout')).read_text().splitlines():
            if not re.match(r'^\s*[0-9a-f]+:',line):continue
            parts=line.split('\t');require(len(parts)>=3,'value helper native syntax')
            va=int(parts[0].strip().rstrip(':'),16);tokens=parts[1].split()
            require(tokens and all(re.fullmatch('[0-9a-f]{2}',t) for t in tokens),'value helper byte syntax')
            raw=bytes.fromhex(' '.join(tokens));text=' '.join(parts[2:]).strip()
            require(va==cursor and body[va-start:va-start+len(raw)]==raw,'value helper native/full-image bytes')
            require(text and '(bad)' not in text and not text.startswith('.byte'),'value helper undecoded row')
            rows.append(dict(va=hex(va),bytes=raw.hex(),text=text));cursor+=len(raw)
        saved=next(r for r in native['regions'] if r['label']==label)
        require(rows==saved['instruction_rows'] and len(rows)==saved['instructions'] and cursor==int(record['end_va'],16),'value helper native rows/extent')
        bodies[label]=(start,body);rowmaps[label]={int(r['va'],16):r for r in rows}
    earlier=json.loads((packet/'first-variant/receipts/decode-result.json').read_text())
    require(next(r['instruction_rows'] for r in earlier['regions'] if r['label']=='variant-candidate')==
            next(r['instruction_rows'] for r in native['regions'] if r['label']=='variant-candidate'),'renewed first alternative differs')
    edge=json.loads((folder/'receipts/qualified-candidate-edges.json').read_text())
    call=rowmaps['variant-candidate'][0x16fdcb9];raw=bytes.fromhex(call['bytes'])
    require(len(edge)==1 and edge[0]['native_instruction_boundary_validated'] and edge[0]['candidate_va']==call['va'] and edge[0]['bytes']==call['bytes'],'value helper direct edge qualification')
    require(raw[0]==0xe8 and 0x16fdcb9+5+struct.unpack_from('<i',raw,1)[0]==0x16fd8b0,'value helper direct edge target')
    fields=json.loads((folder/'field-bindings.json').read_text())
    def check_fields(active):
        for field in fields:
            label=field['region'];va=int(field['va'],16);raw=bytes.fromhex(field['bytes']);start,body=active[label]
            require(rowmaps[label].get(va,{}).get('bytes')==field['bytes'],'value helper field boundary')
            require(body[va-start:va-start+len(raw)]==raw,'value helper field corruption: '+field['label'])
    check_fields(bodies);controls=[]
    for field in fields:
        active=dict(bodies);start,body=bodies[field['region']];changed=bytearray(body)
        changed[int(field['va'],16)-start+len(bytes.fromhex(field['bytes']))-1]^=1
        active[field['region']]=(start,changed)
        try:check_fields(active)
        except ValueError as error:controls.append(dict(control='value helper '+field['label'],rejection=str(error)))
        else:raise ValueError('value helper field corruption escaped')
    record=current['selected_fde_candidates']['0x16fd8b0'];fde=bytes.fromhex(record['fde_hex'])
    def check_extent(raw):
        delta,length=struct.unpack_from('<ii',raw,8)
        require(int(record['fde_va'],16)+8+delta==int(record['start_va'],16),'value helper FDE location')
        require(length==740 and int(record['start_va'],16)+length==int(record['end_va'],16),'value helper FDE extent')
    check_extent(fde);changed=bytearray(fde);changed[12]^=1
    try:check_extent(changed)
    except ValueError as error:controls.append(dict(control='value helper FDE extent',rejection=str(error)))
    else:raise ValueError('value helper FDE corruption escaped')
    computed=extract_value_data(data);saved=json.loads((folder/'referenced-data.json').read_text())
    require(computed==saved,'value helper referenced data drift')
    active={'table':bytes.fromhex(saved['table']['data_hex'])}
    active.update({'relocation '+r['slot']:bytes.fromhex(r['relocation_hex']) for r in saved['relocations']})
    active.update({'descriptor '+r['va']:bytes.fromhex(r['data_hex']) for r in saved['descriptors']})
    expected={key:value.hex() for key,value in active.items()}
    def check_data(values):
        for key,raw in values.items():require(raw.hex()==expected[key],'value helper referenced data corruption: '+key)
    check_data(active)
    for key,raw in active.items():
        offsets=range(0,len(raw),4) if key=='table' else [16 if key.startswith('relocation ') else 0]
        for offset in offsets:
            values=dict(active);changed=bytearray(raw);changed[offset]^=1;values[key]=changed
            try:check_data(values)
            except ValueError as error:controls.append(dict(control='value helper '+key+' '+str(offset),rejection=str(error)))
            else:raise ValueError('value helper data corruption escaped')
    rows=rowmaps['value-candidate'];instruction=lambda va:bytes.fromhex(rows[va]['bytes'])
    targets=[0x16fdada,0x16fdae9,0x16fdac9,0x16fdacf,0x16fdab8,0x16fdaf9,0x16fdb00,0x16fdad4,
             0x16fdb19,0x16fdabe,0x16fdb07,0x16fd8ce,0x16fd947,0x16fd951,0x16fd993,0x16fd9a4,
             0x16fda87,0x16fda87,0x16fdaaa,0x16fdab1,0x16fd8f3,0x16fdb51]
    require([int(r['target'],16) for r in computed['table']['entries']]==targets and all(t in rows for t in targets),'value helper selected dispatch table')
    for site,target in [(0x16fd8be,0x47dd44),(0x16fd96c,0x64e1e48),(0x16fda5b,0x64e1e48),
                        (0x16fdb38,0x64e0900),(0x16fdb8e,0x64df520),(0x16fdb27,0x640e390),
                        (0x16fdb6b,0x640c008),(0x16fdb87,0x640bff0)]:
        raw=instruction(site)
        require(site+len(raw)+struct.unpack_from('<i',raw,len(raw)-4)[0]==target,'value helper RIP binding')
    require([(r['slot'],r['info'],r['addend']) for r in computed['relocations']]==[
        ('0x64df520',8,'0x1681da0'),('0x64e0900',8,'0x5c54bd0'),('0x64e1e48',8,'0x167a9c0')],'value helper actual relocation targets')
    require(instruction(0x16fd993)==bytes.fromhex('48837e1820') and instruction(0x16fd9a4)==bytes.fromhex('48837e1020'),'two direct-byte length guards')
    require(instruction(0x16fd963)==instruction(0x16fda55)==bytes.fromhex('41b820000000'),'text decoder requested output bytes')
    require(instruction(0x16fd972)==instruction(0x16fda61)==bytes.fromhex('837c243003'),'text decoder success-code guards')
    require(instruction(0x16fd9ba)==bytes.fromhex('0f114b11') and instruction(0x16fd9be)==bytes.fromhex('0f114301'),'32-byte ordinary output stores')
    require(instruction(0x16fd9c2)==bytes.fromhex('31c0') and instruction(0x16fd9c4)==bytes.fromhex('8803'),'ordinary zero status byte')
    require(instruction(0x16fda9a)==bytes.fromhex('b001') and instruction(0x16fda9c)==bytes.fromhex('8803') and instruction(0x16fdb42)==bytes.fromhex('c60301'),'local error status byte')
    require(instruction(0x16fd8fb)==bytes.fromhex('48c1e105') and instruction(0x16fd922)==bytes.fromhex('803b00'),'sequence cursor stride and delegated status guard')
    require(instruction(0x16fd92c)==bytes.fromhex('482b7c2410') and instruction(0x16fdb5d)==bytes.fromhex('48c1ef05') and instruction(0x16fdb61)==bytes.fromhex('4801c7'),'remaining-record length calculation')
    calls=[];branches=[]
    for va,row in rows.items():
        raw=bytes.fromhex(row['bytes']);target=None
        if raw[0]==0xe8:
            target=va+5+struct.unpack_from('<i',raw,1)[0]
            require(target in [0x173fe30,0x1742410,0x1742120,0x173d830],'value helper direct callees')
            calls.append(dict(va=hex(va),target=hex(target)));continue
        if raw[0]==0xeb or 0x70<=raw[0]<=0x7f:target=va+len(raw)+struct.unpack_from('<b',raw,1)[0]
        elif raw[0]==0xe9:target=va+len(raw)+struct.unpack_from('<i',raw,1)[0]
        elif raw[0]==0x0f and 0x80<=raw[1]<=0x8f:target=va+len(raw)+struct.unpack_from('<i',raw,2)[0]
        if target is not None:
            require(target in rows,'value helper local branch boundary');branches.append(dict(va=hex(va),target=hex(target)))
    require(len(calls)==4,'value helper direct call count')
    value=next(r for r in native['regions'] if r['label']=='value-candidate')
    return dict(status='VALUE_HELPER_LOCAL_PATHS_REPRODUCED',helper_bytes=value['bytes'],helper_instructions=value['instructions'],
        field_bindings=len(fields),evidence_corruptions_rejected=len(controls),controls=controls,
        selected_raw_tags=22,local_tag_domain_bound_proved=False,direct_byte_record_tags=[14,15],direct_byte_required_length=32,
        shared_decoder_input_tags=[11,12,13],shared_decoder_requested_bytes=32,shared_decoder_success_code=3,
        sequence_record_tag=20,sequence_record_stride=32,locally_error_preparation_tags=list(range(11))+[16,17,18,19,21],
        ordinary_local_output_byte_offsets=list(range(33)),direct_callees=calls,local_branches=branches,
        relocation_bindings=len(computed['relocations']),unidentified_descriptor_spans=len(computed['descriptors']),
        renewed_variant_rows=len(rowmaps['variant-candidate']),
        limits='Selected raw-record paths only. Ordinary direct/text success writes one status byte plus32 data bytes. Sequence output is delegated; nonzero delegated tags are forwarded. No full text/sequence contract, raw JSON/null mapping, source/type identity, complete tag domain, ABI/initialization, exception closure or runtime equivalence is established.')



def extract_text_data(data):
    assert len(data)==105896032 and hashlib.sha256(data).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
    shoff=struct.unpack_from('<Q',data,40)[0];size,count,nameidx=struct.unpack_from('<HHH',data,58);assert size==64
    rows=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+64*i) for i in range(count)]
    sr=rows[nameidx];names=data[sr[4]:sr[4]+sr[5]]
    sections={names[r[0]:names.find(b'\0',r[0])].decode():r for r in rows}
    def at(va,n):
        hits=[(name,r) for name,r in sections.items() if r[1]!=8 and r[2]&2 and r[3]<=va and va+n<=r[3]+r[5]];assert len(hits)==1
        name,row=hits[0];off=row[4]+va-row[3];raw=data[off:off+n]
        return dict(va=hex(va),file_offset=hex(off),section=name,section_flags=row[2],bytes=n,data_hex=raw.hex(),sha256=hashlib.sha256(raw).hexdigest())
    table=at(0x46d50c,256)
    table['accepted_bytes']=[i for i,v in enumerate(bytes.fromhex(table['data_hex'])) if v!=255]
    table['decoded_values']={str(i):v for i,v in enumerate(bytes.fromhex(table['data_hex'])) if v!=255}
    rela=sections['.rela.dyn'];records={}
    for off in range(rela[4],rela[4]+rela[5],24):
        slot,info,addend=struct.unpack_from('<QQq',data,off)
        if slot in [0x64e1e48,0x64dfa60,0x64dfa68]:
            assert slot not in records
            records[slot]=dict(slot=hex(slot),info=info,addend=hex(addend),relocation_file_offset=hex(off),relocation_hex=data[off:off+24].hex(),stored_pointer=at(slot,8))
    assert len(records)==3
    feature_va=int(records[0x64dfa60]['addend'],16)
    hits=[(name,r) for name,r in sections.items() if r[2]&2 and r[3]<=feature_va and feature_va+8<=r[3]+r[5]];assert len(hits)==1
    feature_name,feature_section=hits[0];assert feature_section[1]==8
    feature=dict(va=hex(feature_va),bytes=8,section=feature_name,section_type=feature_section[1],initialization='ELF NOBITS zero-fill; runtime value is not inferred')
    return dict(target_sha256=hashlib.sha256(data).hexdigest(),table=table,relocations=list(records.values()),
        vector_constants=[at(va,16) for va in [0x455d80,0x455a20,0x4536c0,0x453ac0,0x4566a0]],
        feature_word=feature,
        limits='Local decoder data and relocation bindings only. Feature initialization, invalid-byte reporter and vector conversion helper behavior remain delegated.')

def verify_text_decoder(data, packet):
    folder=packet/'text-decoder'
    current=probe(data,extra_vas=(0x167a9c0,0x16fd96c))
    require(current==json.loads((folder/'candidates.json').read_text()),'text decoder FDE candidate drift')
    require(current==json.loads((folder/'receipts/full-input-replay.json').read_text()),'text decoder hosted full-input replay drift')
    native=json.loads((folder/'receipts/decode-result.json').read_text())
    require(native['target_sha256']==TARGET and native['whole_elf_reauthenticated_in_job'] and native['input_hashes_unchanged'],'text decoder full input binding')
    require(not native['captured_program_executed'] and native['native_invocations']==3,'text decoder execution record')
    bodies={};rowmaps={}
    for label,key in [('text-candidate','0x167a9c0'),('value-candidate','0x16fd96c')]:
        record=current['selected_fde_candidates'][key];start=int(record['start_va'],16);off=int(record['file_offset'],16)
        body=data[off:off+record['bytes']]
        require(hashlib.sha256(body).hexdigest()==record['body_sha256'],'text decoder body identity')
        cursor=start;rows=[]
        for line in (folder/'receipts'/(label+'.stdout')).read_text().splitlines():
            if not re.match(r'^\s*[0-9a-f]+:',line):continue
            parts=line.split('\t');require(len(parts)>=3,'text decoder native syntax')
            va=int(parts[0].strip().rstrip(':'),16);tokens=parts[1].split()
            require(tokens and all(re.fullmatch('[0-9a-f]{2}',t) for t in tokens),'text decoder native byte syntax')
            raw=bytes.fromhex(' '.join(tokens));text=' '.join(parts[2:]).strip()
            require(va==cursor and body[va-start:va-start+len(raw)]==raw,'text decoder native/full-image binding')
            require(text and '(bad)' not in text and not text.startswith('.byte'),'text decoder undecoded row')
            rows.append(dict(va=hex(va),bytes=raw.hex(),text=text));cursor+=len(raw)
        saved=next(r for r in native['regions'] if r['label']==label)
        require(rows==saved['instruction_rows'] and len(rows)==saved['instructions'] and cursor==int(record['end_va'],16),'text decoder complete rows/extent')
        bodies[label]=(start,body);rowmaps[label]={int(r['va'],16):r for r in rows}
    earlier=json.loads((packet/'value-helper/receipts/decode-result.json').read_text())
    require(next(r['instruction_rows'] for r in earlier['regions'] if r['label']=='value-candidate')==
            next(r['instruction_rows'] for r in native['regions'] if r['label']=='value-candidate'),'renewed value helper drift')
    edge=json.loads((folder/'receipts/qualified-candidate-edges.json').read_text())
    call=rowmaps['value-candidate'][0x16fd96c];raw=bytes.fromhex(call['bytes'])
    require(len(edge)==1 and edge[0]['native_instruction_boundary_validated'] and edge[0]['candidate_va']==call['va'] and edge[0]['bytes']==call['bytes'],'text decoder caller boundary')
    require(raw[:2]==bytes.fromhex('ff15') and 0x16fd96c+6+struct.unpack_from('<i',raw,2)[0]==0x64e1e48,'text decoder caller RIP slot')
    fields=json.loads((folder/'field-bindings.json').read_text())
    def check_fields(active):
        for field in fields:
            va=int(field['va'],16);raw=bytes.fromhex(field['bytes']);start,body=active[field['region']]
            require(rowmaps[field['region']].get(va,{}).get('bytes')==field['bytes'],'text decoder field boundary')
            require(body[va-start:va-start+len(raw)]==raw,'text decoder field corruption: '+field['label'])
    check_fields(bodies);controls=[]
    for field in fields:
        active=dict(bodies);start,body=bodies[field['region']];changed=bytearray(body)
        changed[int(field['va'],16)-start+len(bytes.fromhex(field['bytes']))-1]^=1
        active[field['region']]=(start,changed)
        try:check_fields(active)
        except ValueError as error:controls.append(dict(control='text decoder '+field['label'],rejection=str(error)))
        else:raise ValueError('text decoder field corruption escaped')
    record=current['selected_fde_candidates']['0x167a9c0'];fde=bytes.fromhex(record['fde_hex'])
    def check_extent(raw):
        delta,length=struct.unpack_from('<ii',raw,8)
        require(int(record['fde_va'],16)+8+delta==0x167a9c0 and length==571 and 0x167a9c0+length==int(record['end_va'],16),'text decoder actual FDE extent')
    check_extent(fde);changed=bytearray(fde);changed[12]^=1
    try:check_extent(changed)
    except ValueError as error:controls.append(dict(control='text decoder FDE extent',rejection=str(error)))
    else:raise ValueError('text decoder FDE corruption escaped')
    computed=extract_text_data(data);saved=json.loads((folder/'referenced-data.json').read_text())
    require(computed==saved,'text decoder referenced data drift')
    active={'nibble table':bytes.fromhex(saved['table']['data_hex'])}
    active.update({'relocation '+r['slot']:bytes.fromhex(r['relocation_hex']) for r in saved['relocations']})
    active.update({'vector '+r['va']:bytes.fromhex(r['data_hex']) for r in saved['vector_constants']})
    expected={k:bytes(v) for k,v in active.items()}
    def check_data(values):
        require(set(values)==set(expected),'text decoder data inventory')
        for key,raw in values.items():require(bytes(raw)==expected[key],'text decoder data corruption: '+key)
    check_data(active)
    for key,raw in active.items():
        changed=bytearray(raw);changed[16 if key.startswith('relocation ') else 0]^=1;values=dict(active);values[key]=changed
        try:check_data(values)
        except ValueError as error:controls.append(dict(control='text decoder '+key,rejection=str(error)))
        else:raise ValueError('text decoder data corruption escaped')
    rows=rowmaps['text-candidate'];instruction=lambda va:bytes.fromhex(rows[va]['bytes'])
    for site,target in [(0x167aa1a,0x455d80),(0x167aa22,0x455a20),(0x167aa2a,0x4536c0),
                        (0x167aa32,0x453ac0),(0x167aa3a,0x4566a0),(0x167aaae,0x46d50c),
                        (0x167aae4,0x64dfa60),(0x167abad,0x64dfa68)]:
        raw=instruction(site);require(site+len(raw)+struct.unpack_from('<i',raw,len(raw)-4)[0]==target,'text decoder RIP data/call binding')
    require([(r['slot'],r['info'],r['addend']) for r in computed['relocations']]==[
        ('0x64dfa60',8,'0x6500098'),('0x64dfa68',8,'0x5cadd50'),('0x64e1e48',8,'0x167a9c0')],'text decoder actual RELATIVE bindings')
    for site,raw in [(0x167a9cb,'f6c201'),(0x167a9d4,'4883fa01'),(0x167a9da,'803e30'),(0x167a9df,'807e0178'),
                     (0x167a9e5,'4883c602'),(0x167a9e9,'4883c2fe'),(0x167a9f0,'48d1e8'),(0x167a9f3,'4939c0'),
                     (0x167aa95,'c70701000000'),(0x167aaa0,'c70702000000'),(0x167ab95,'c70703000000'),
                     (0x167aa5f,'660ffcf0'),(0x167aa67,'660fdaf9'),(0x167aa6b,'660f74fe'),
                     (0x167aa6f,'660fdbea'),(0x167aa73,'660ffceb'),(0x167aa7b,'660fdaf4'),
                     (0x167aa7f,'660f74f5'),(0x167aa83,'660fdbf7'),(0x167aa87,'660fd7ee'),
                     (0x167ab3b,'41c0e104'),(0x167ab44,'470a0c32'),(0x167ab48,'44880c01'),
                     (0x167ab57,'41c0e104'),(0x167ab61,'470a0c32'),(0x167ab65,'44884c0101'),
                     (0x167ab86,'c0e204'),(0x167ab8e,'420a1436'),(0x167ab92,'881401')]:
        require(instruction(site)==bytes.fromhex(raw),'text decoder semantic instruction binding')
    calls=[];branches=[]
    for va,row in rows.items():
        raw=bytes.fromhex(row['bytes']);target=None
        if raw[0]==0xe8:
            target=va+5+struct.unpack_from('<i',raw,1)[0];calls.append(dict(va=hex(va),target=hex(target)));continue
        if raw[0]==0xeb or 0x70<=raw[0]<=0x7f:target=va+len(raw)+struct.unpack_from('<b',raw,1)[0]
        elif raw[0]==0xe9:target=va+len(raw)+struct.unpack_from('<i',raw,1)[0]
        elif raw[0]==0x0f and len(raw)>1 and 0x80<=raw[1]<=0x8f:target=va+len(raw)+struct.unpack_from('<i',raw,2)[0]
        if target is not None:require(target in rows,'text decoder local branch boundary');branches.append(dict(va=hex(va),target=hex(target)))
    require(calls==[dict(va='0x167aad7',target='0x167a940'),dict(va='0x167abdb',target='0x167ac00')],'text decoder direct callees')
    alphabet=b'0123456789ABCDEFabcdef';table=bytes.fromhex(saved['table']['data_hex'])
    require(saved['table']['accepted_bytes']==sorted(alphabet),'text decoder 22-byte alphabet')
    require(all(table[c]==int(chr(c),16) if c in alphabet else table[c]==255 for c in range(256)),'text decoder complete nibble lookup')
    vectors=[bytes.fromhex(r['data_hex']) for r in saved['vector_constants']]
    lane_cases=0
    # Arithmetic interpretation of the pinned byte operations/constants only.
    # This is not a target execution, emulator, SIMD provider or runtime proof.
    for lane in range(16):
        k0,k1,k2,k3,k4=(v[lane] for v in vectors)
        for c in range(256):
            a=(c+k0)&255;b=((c&k2)+k3)&255
            bad=(min(a,k1)==a) and (min(b,k4)==b)
            require(bad==(table[c]==255),'text decoder vector/table alphabet disagreement');lane_cases+=1
    pairs=0
    for high in alphabet:
        for low in alphabet:
            require((table[high]<<4)|table[low]==int(bytes([high,low]),16),'text decoder scalar pair arithmetic');pairs+=1
    def local_policy(raw,requested):
        if len(raw)&1:return 'code1',None
        tail=raw[2:] if len(raw)>1 and raw[:2]==b'0x' else raw
        if len(tail)//2!=requested:return 'code2',None
        if any(table[c]==255 for c in tail):return 'invalid-helper',None
        return 'local-gates-pass',bytes((table[tail[i]]<<4)|table[tail[i+1]] for i in range(0,len(tail),2))
    cases=[(b'00'*32,'local-gates-pass'),(b'0x'+b'00'*32,'local-gates-pass'),
        (b'aF'*32,'local-gates-pass'),(b'0x'+b'aF'*32,'local-gates-pass'),
        (b'0X'+b'00'*32,'code2'),(b'0X'+b'00'*31,'invalid-helper'),
        (b'0'*63,'code1'),(b'0x'+b'0'*63,'code1'),(b'0'*62,'code2'),
        (b'0'*66,'code2'),(b'0x','code2'),(b' '*64,'invalid-helper'),
        (b'g'*64,'invalid-helper'),(b'\xff'*64,'invalid-helper')]
    for raw,expected_kind in cases:require(local_policy(raw,32)[0]==expected_kind,'text decoder static policy boundary')
    require(local_policy(b'00'*32,32)[1]==bytes(32) and local_policy(b'aF'*32,32)[1]==bytes([175])*32,'text decoder scalar output arithmetic')
    # The prior full-input stage pins the caller's 1..4-byte scalar-text paths.
    for length in range(1,5):
        require(local_policy(b'0'*length,32)[0] in ['code1','code2'],'short scalar text cannot satisfy32 requested bytes')
    return dict(status='TEXT_DECODER_LOCAL_FORMAT_REPRODUCED',helper_bytes=571,helper_instructions=143,
        field_bindings=len(fields),evidence_corruptions_rejected=len(controls),controls=controls,
        local_branches=branches,direct_callees=calls,relocation_bindings=3,vector_constant_spans=5,
        alphabet_bytes=list(alphabet),classifier_lane_cases=lane_cases,scalar_pair_cases=pairs,
        static_policy_cases=len(cases),caller_requested_bytes=32,bare_payload_bytes=64,prefixed_payload_bytes=66,
        optional_prefix_hex='3078',odd_length_code=1,length_mismatch_code=2,normal_local_success_code=3,
        tag11_short_text_cannot_satisfy_requested_length=True,renewed_value_rows=185,
        limits='Static local checks and scalar arithmetic only. Invalid-byte reporting, CPU-feature initialization, vector conversion, valid pointer/raw-record domains, complete JSON/null grammar, ABI/exception and runtime equivalence remain unresolved. Code3 follows a normal return from the opaque vector helper; its output is not proved here.')


def extract_sequence_data(data):
    assert len(data)==105896032 and hashlib.sha256(data).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
    shoff=struct.unpack_from('<Q',data,40)[0];size,count,nameidx=struct.unpack_from('<HHH',data,58);assert size==64
    rows=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+64*i) for i in range(count)]
    sr=rows[nameidx];names=data[sr[4]:sr[4]+sr[5]]
    sections={names[r[0]:names.find(b'\0',r[0])].decode():r for r in rows}
    def at(va,n):
        hits=[(name,r) for name,r in sections.items() if r[1]!=8 and r[2]&2 and r[3]<=va and va+n<=r[3]+r[5]];assert len(hits)==1
        name,row=hits[0];off=row[4]+va-row[3];raw=data[off:off+n]
        return dict(va=hex(va),file_offset=hex(off),section=name,section_flags=row[2],bytes=n,data_hex=raw.hex(),sha256=hashlib.sha256(raw).hexdigest())
    rela=sections['.rela.dyn'];records=[]
    for off in range(rela[4],rela[4]+rela[5],24):
        slot,info,addend=struct.unpack_from('<QQq',data,off)
        if slot==0x64df4a0:
            records.append(dict(slot=hex(slot),info=info,addend=hex(addend),relocation_file_offset=hex(off),relocation_hex=data[off:off+24].hex(),stored_pointer=at(slot,8)))
    assert len(records)==1 and records[0]['info']==8
    return dict(target_sha256=hashlib.sha256(data).hexdigest(),relocations=records,
        indirect_sites=['0x173fecf','0x173fef8','0x173ff40'],
        direct_callees=['0x16fce10','0x1740fe0','0x173ff50','0x63f0a50'],
        limits='Actual indirect binding only; direct callee contracts, opaque error record ownership, memory validity and exception tables remain unrecovered. Cleanup/element-reader/length-error are inferred roles, not source identities.')

def verify_sequence_helper(data, packet):
    folder=packet/'sequence-helper'
    current=probe(data,extra_vas=(0x173fe30,0x16fd91d))
    require(current==json.loads((folder/'candidates.json').read_text()),'sequence helper FDE candidate drift')
    require(current==json.loads((folder/'receipts/full-input-replay.json').read_text()),'sequence helper hosted full-input replay drift')
    native=json.loads((folder/'receipts/decode-result.json').read_text())
    require(native['target_sha256']==TARGET and native['whole_elf_reauthenticated_in_job'] and native['input_hashes_unchanged'],'sequence helper full input binding')
    require(not native['captured_program_executed'] and native['native_invocations']==3,'sequence helper execution record')
    bodies={};rowmaps={}
    for label,key in [('sequence-candidate','0x173fe30'),('value-candidate','0x16fd91d')]:
        record=current['selected_fde_candidates'][key];start=int(record['start_va'],16);off=int(record['file_offset'],16)
        body=data[off:off+record['bytes']]
        require(hashlib.sha256(body).hexdigest()==record['body_sha256'],'sequence helper body identity')
        cursor=start;rows=[]
        for line in (folder/'receipts'/(label+'.stdout')).read_text().splitlines():
            if not re.match(r'^\s*[0-9a-f]+:',line):continue
            parts=line.split('\t');require(len(parts)>=3,'sequence helper native syntax')
            va=int(parts[0].strip().rstrip(':'),16);tokens=parts[1].split()
            require(tokens and all(re.fullmatch('[0-9a-f]{2}',t) for t in tokens),'sequence helper native byte syntax')
            raw=bytes.fromhex(' '.join(tokens));text=' '.join(parts[2:]).strip()
            require(va==cursor and body[va-start:va-start+len(raw)]==raw,'sequence helper native/full-image binding')
            require(text and '(bad)' not in text and not text.startswith('.byte'),'sequence helper undecoded row')
            rows.append(dict(va=hex(va),bytes=raw.hex(),text=text));cursor+=len(raw)
        saved=next(r for r in native['regions'] if r['label']==label)
        require(rows==saved['instruction_rows'] and len(rows)==saved['instructions'] and cursor==int(record['end_va'],16),'sequence helper complete rows/extent')
        bodies[label]=(start,body);rowmaps[label]={int(r['va'],16):r for r in rows}
    earlier=json.loads((packet/'value-helper/receipts/decode-result.json').read_text())
    require(next(r['instruction_rows'] for r in earlier['regions'] if r['label']=='value-candidate')==
            next(r['instruction_rows'] for r in native['regions'] if r['label']=='value-candidate'),'renewed value helper drift')
    edge=json.loads((folder/'receipts/qualified-candidate-edges.json').read_text())
    call=rowmaps['value-candidate'][0x16fd91d];raw=bytes.fromhex(call['bytes'])
    require(len(edge)==1 and edge[0]['native_instruction_boundary_validated'] and edge[0]['candidate_va']==call['va'] and edge[0]['bytes']==call['bytes'],'sequence helper caller boundary')
    require(raw[0]==0xe8 and 0x16fd91d+5+struct.unpack_from('<i',raw,1)[0]==0x173fe30,'sequence helper caller direct target')
    fields=json.loads((folder/'field-bindings.json').read_text())
    def check_fields(active):
        for field in fields:
            va=int(field['va'],16);raw=bytes.fromhex(field['bytes']);start,body=active[field['region']]
            require(rowmaps[field['region']].get(va,{}).get('bytes')==field['bytes'],'sequence helper field boundary')
            require(body[va-start:va-start+len(raw)]==raw,'sequence helper field corruption: '+field['label'])
    check_fields(bodies);controls=[]
    for field in fields:
        active=dict(bodies);start,body=bodies[field['region']];changed=bytearray(body)
        changed[int(field['va'],16)-start+len(bytes.fromhex(field['bytes']))-1]^=1
        active[field['region']]=(start,changed)
        try:check_fields(active)
        except ValueError as error:controls.append(dict(control='sequence helper '+field['label'],rejection=str(error)))
        else:raise ValueError('sequence helper field corruption escaped')
    record=current['selected_fde_candidates']['0x173fe30'];fde=bytes.fromhex(record['fde_hex'])
    def check_extent(raw):
        delta,length=struct.unpack_from('<ii',raw,8)
        require(int(record['fde_va'],16)+8+delta==0x173fe30 and length==286 and 0x173fe30+length==int(record['end_va'],16),'sequence helper actual FDE extent')
    check_extent(fde);changed=bytearray(fde);changed[12]^=1
    try:check_extent(changed)
    except ValueError as error:controls.append(dict(control='sequence helper FDE extent',rejection=str(error)))
    else:raise ValueError('sequence helper FDE corruption escaped')
    computed=extract_sequence_data(data);saved=json.loads((folder/'referenced-data.json').read_text())
    require(computed==saved,'sequence helper relocation/data drift')
    record=saved['relocations'][0];raw_relocation=bytes.fromhex(record['relocation_hex'])
    require((record['slot'],record['info'],record['addend'])==('0x64df4a0',8,'0x635de30'),'sequence helper actual RELATIVE target')
    def check_relocation(raw):require(bytes(raw)==raw_relocation,'sequence helper relocation corruption')
    check_relocation(raw_relocation);changed=bytearray(raw_relocation);changed[16]^=1
    try:check_relocation(changed)
    except ValueError as error:controls.append(dict(control='sequence helper cleanup-slot relocation',rejection=str(error)))
    else:raise ValueError('sequence helper relocation corruption escaped')
    rows=rowmaps['sequence-candidate'];instruction=lambda va:bytes.fromhex(rows[va]['bytes'])
    for site in [0x173fecf,0x173fef8,0x173ff40]:
        raw=instruction(site)
        require(raw[:2]==bytes.fromhex('ff15') and site+6+struct.unpack_from('<i',raw,2)[0]==0x64df4a0,'sequence helper indirect slot binding')
    for site,raw in [(0x173fe41,'0f57c0'),(0x173fe44,'0f29442420'),(0x173fe49,'0f29442410'),(0x173fe4e,'4531ff'),
        (0x173fe6b,'803c2400'),(0x173fe71,'807c240101'),(0x173fe7c,'0fb6442402'),(0x173fe81,'4288443c10'),
        (0x173fe86,'49ffc7'),(0x173fe89,'4983ff20'),(0x173fe9a,'0fb60424'),(0x173fe9e,'84c0'),
        (0x173fea2,'807c240100'),(0x173fea9,'84c0'),(0x173fead,'4c8b742408'),(0x173feb2,'498b06'),
        (0x173feb5,'4883f801'),(0x173febb,'4885c0'),(0x173fec0,'498b7610'),(0x173fec4,'4885f6'),
        (0x173fec9,'498b7e08'),(0x173fecd,'31d2'),(0x173fed7,'488b442408'),(0x173fedc,'48894308'),
        (0x173fee0,'c60301'),(0x173fee5,'498d7e08'),(0x173feee,'be28000000'),(0x173fef6,'31d2'),
        (0x173fefe,'0f28442410'),(0x173ff03,'0f284c2420'),(0x173ff08,'0f114b11'),(0x173ff0c,'0f114301'),
        (0x173ff10,'c60300'),(0x173ff22,'4c89ff'),(0x173ff27,'bf21000000'),
        (0x173ff36,'be28000000'),(0x173ff3e,'31d2')]:
        require(instruction(site)==bytes.fromhex(raw),'sequence helper semantic instruction binding')
    calls=[];branches=[]
    for va,row in rows.items():
        raw=bytes.fromhex(row['bytes']);target=None
        if raw[0]==0xe8:
            target=va+5+struct.unpack_from('<i',raw,1)[0];calls.append(dict(va=hex(va),target=hex(target)));continue
        if raw[0]==0xeb or 0x70<=raw[0]<=0x7f:target=va+len(raw)+struct.unpack_from('<b',raw,1)[0]
        elif raw[0]==0xe9:target=va+len(raw)+struct.unpack_from('<i',raw,1)[0]
        elif raw[0]==0x0f and len(raw)>1 and 0x80<=raw[1]<=0x8f:target=va+len(raw)+struct.unpack_from('<i',raw,2)[0]
        if target is not None:require(target in rows,'sequence helper local branch boundary');branches.append(dict(va=hex(va),target=hex(target)))
    require(calls==[dict(va='0x173fe66',target='0x16fce10'),dict(va='0x173fe95',target='0x16fce10'),
        dict(va='0x173fee9',target='0x1740fe0'),dict(va='0x173ff2c',target='0x173ff50'),
        dict(va='0x173ff49',target='0x63f0a50')],'sequence helper direct callee bindings')
    def trace(responses):
        # Abstract opaque-helper responses, not source-record or JSON inputs.
        # Cleanup and error-constructor calls are normal-return premises.
        out=[];reads=0
        for index in range(32):
            outer,present,payload=responses[reads];reads+=1
            if outer!=0:return dict(kind='forward-error-pointer',status=1,count=index,reads=reads,pointer=payload)
            if present!=1:return dict(kind='length-helper',status=1,count=index,reads=reads)
            out.append(payload)
        outer,present,_=responses[reads];reads+=1
        if outer==0 and present!=0:return dict(kind='length-helper',status=1,count=33,reads=reads)
        return dict(kind='cleanup-then-success' if outer!=0 else 'end-then-success',status=0,count=32,reads=reads,output=bytes(out))
    prefix=[(0,1,i) for i in range(32)];scenarios=[]
    for count in range(32):
        r=trace(prefix[:count]+[(1,0,'opaque-pointer')]);require(r==dict(kind='forward-error-pointer',status=1,count=count,reads=count+1,pointer='opaque-pointer'),'early helper-error forwarding')
        scenarios.append(dict(case='early-error',count=count,reads=r['reads']))
        r=trace(prefix[:count]+[(0,0,0)]);require(r==dict(kind='length-helper',status=1,count=count,reads=count+1),'short sequence reports successful-response count')
        scenarios.append(dict(case='short',count=count,reads=r['reads']))
    for outer in [1,2,128,255]:
        r=trace(prefix+[(outer,255,'opaque-pointer')]);require(r['kind']=='cleanup-then-success' and r['status']==0 and r['reads']==33 and r['output']==bytes(range(32)),'boundary helper-error cleanup reaches local success')
        scenarios.append(dict(case='boundary-error',outer=outer,status=r['status']))
    r=trace(prefix+[(0,0,0)]);require(r['kind']=='end-then-success' and r['output']==bytes(range(32)) and r['reads']==33,'boundary end local success')
    scenarios.append(dict(case='boundary-end',status=r['status']))
    for flag in [1,2,128,255]:
        r=trace(prefix+[(0,flag,0)]);require(r==dict(kind='length-helper',status=1,count=33,reads=33),'nonzero boundary presence reports33')
        scenarios.append(dict(case='boundary-present',flag=flag,count=r['count']))
    for flag in [2,128,255]:
        r=trace([(0,flag,0)]);require(r==dict(kind='length-helper',status=1,count=0,reads=1),'first-stage presence requires exact1')
        scenarios.append(dict(case='first-stage-other-flag',flag=flag,count=r['count']))
    return dict(status='SEQUENCE_HELPER_LOCAL_RESPONSE_PATHS_REPRODUCED',helper_bytes=286,helper_instructions=82,
        field_bindings=len(fields),evidence_corruptions_rejected=len(controls),controls=controls,direct_callees=calls,local_branches=branches,
        successful_element_responses_required=32,boundary_probe_ordinal=33,short_length_arguments=list(range(32)),excess_length_argument=33,
        first_stage_outer_error_status=1,boundary_outer_error_local_status_after_cleanup=0,ordinary_local_output_byte_offsets=list(range(33)),
        relocation_bindings=1,static_response_scenarios=len(scenarios),response_scenarios=scenarios,renewed_value_rows=185,
        limits='Abstract opaque-helper response traces only. Element acceptance, cursor/counter effects, error construction, cleanup ownership, validity of record/pointer domains and exception mapping remain unresolved. Boundary-error local success assumes all cleanup calls return normally; it does not establish accepted real inputs or a vulnerability. Outer remainder validation still applies. No runtime equivalence or component closure.')


def extract_element_data(data):
    assert len(data)==105896032 and hashlib.sha256(data).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
    shoff=struct.unpack_from('<Q',data,40)[0];size,count,nameidx=struct.unpack_from('<HHH',data,58);assert size==64
    rows=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+64*i) for i in range(count)]
    sr=rows[nameidx];names=data[sr[4]:sr[4]+sr[5]]
    sections={names[r[0]:names.find(b'\0',r[0])].decode():r for r in rows}
    def at(va,n):
        hits=[(name,r) for name,r in sections.items() if r[1]!=8 and r[2]&2 and r[3]<=va and va+n<=r[3]+r[5]];assert len(hits)==1
        name,row=hits[0];off=row[4]+va-row[3];raw=data[off:off+n]
        return dict(va=hex(va),file_offset=hex(off),section=name,section_flags=row[2],bytes=n,data_hex=raw.hex(),sha256=hashlib.sha256(raw).hexdigest())
    table=at(0x47db78,8*4);raw=bytes.fromhex(table['data_hex'])
    table['entries']=[dict(raw_tag=i+1,displacement=struct.unpack_from('<i',raw,4*i)[0],target=hex(0x47db78+struct.unpack_from('<i',raw,4*i)[0])) for i in range(8)]
    rela=sections['.rela.dyn'];records=[]
    for off in range(rela[4],rela[4]+rela[5],24):
        slot,info,addend=struct.unpack_from('<QQq',data,off)
        if slot in [0x64e0910,0x64df520]:
            records.append(dict(slot=hex(slot),info=info,addend=hex(addend),relocation_file_offset=hex(off),relocation_hex=data[off:off+24].hex(),stored_pointer=at(slot,8)))
    assert len(records)==2 and all(r['info']==8 for r in records)
    return dict(target_sha256=hashlib.sha256(data).hexdigest(),table=table,relocations=records,
        descriptors=[at(va,32) for va in [0x640be00,0x640bc40]],
        limits='Eight raw-tag dispatch entries and allocated unidentified descriptors; no recovered source enum/type or vtable. Error/default/overflow callees and their memory effects remain opaque.')

def verify_element_reader(data, packet):
    folder=packet/'element-reader'
    current=probe(data,extra_vas=(0x16fce10,0x173fe66))
    require(current==json.loads((folder/'candidates.json').read_text()),'element reader FDE candidate drift')
    require(current==json.loads((folder/'receipts/full-input-replay.json').read_text()),'element reader hosted full-input replay drift')
    native=json.loads((folder/'receipts/decode-result.json').read_text())
    require(native['target_sha256']==TARGET and native['whole_elf_reauthenticated_in_job'] and native['input_hashes_unchanged'],'element reader full input binding')
    require(not native['captured_program_executed'] and native['native_invocations']==3,'element reader execution record')
    bodies={};rowmaps={}
    for label,key in [('element-candidate','0x16fce10'),('sequence-candidate','0x173fe66')]:
        record=current['selected_fde_candidates'][key];start=int(record['start_va'],16);off=int(record['file_offset'],16)
        body=data[off:off+record['bytes']]
        require(hashlib.sha256(body).hexdigest()==record['body_sha256'],'element reader body identity')
        cursor=start;rows=[]
        for line in (folder/'receipts'/(label+'.stdout')).read_text().splitlines():
            if not re.match(r'^\s*[0-9a-f]+:',line):continue
            parts=line.split('\t');require(len(parts)>=3,'element reader native syntax')
            va=int(parts[0].strip().rstrip(':'),16);tokens=parts[1].split()
            require(tokens and all(re.fullmatch('[0-9a-f]{2}',t) for t in tokens),'element reader native byte syntax')
            raw=bytes.fromhex(' '.join(tokens));text=' '.join(parts[2:]).strip()
            require(va==cursor and body[va-start:va-start+len(raw)]==raw,'element reader native/full-image binding')
            require(text and '(bad)' not in text and not text.startswith('.byte'),'element reader undecoded row')
            rows.append(dict(va=hex(va),bytes=raw.hex(),text=text));cursor+=len(raw)
        saved=next(r for r in native['regions'] if r['label']==label)
        require(rows==saved['instruction_rows'] and len(rows)==saved['instructions'] and cursor==int(record['end_va'],16),'element reader complete rows/extent')
        bodies[label]=(start,body);rowmaps[label]={int(r['va'],16):r for r in rows}
    earlier=json.loads((packet/'sequence-helper/receipts/decode-result.json').read_text())
    require(next(r['instruction_rows'] for r in earlier['regions'] if r['label']=='sequence-candidate')==
            next(r['instruction_rows'] for r in native['regions'] if r['label']=='sequence-candidate'),'renewed sequence helper drift')
    edge=json.loads((folder/'receipts/qualified-candidate-edges.json').read_text())
    call=rowmaps['sequence-candidate'][0x173fe66];raw=bytes.fromhex(call['bytes'])
    require(len(edge)==1 and edge[0]['native_instruction_boundary_validated'] and edge[0]['candidate_va']==call['va'] and edge[0]['bytes']==call['bytes'],'element reader caller boundary')
    require(raw[0]==0xe8 and 0x173fe66+5+struct.unpack_from('<i',raw,1)[0]==0x16fce10,'element reader caller direct target')
    fields=json.loads((folder/'field-bindings.json').read_text())
    def check_fields(active):
        for field in fields:
            va=int(field['va'],16);raw=bytes.fromhex(field['bytes']);start,body=active[field['region']]
            require(rowmaps[field['region']].get(va,{}).get('bytes')==field['bytes'],'element reader field boundary')
            require(body[va-start:va-start+len(raw)]==raw,'element reader field corruption: '+field['label'])
    check_fields(bodies);controls=[]
    for field in fields:
        active=dict(bodies);start,body=bodies[field['region']];changed=bytearray(body)
        changed[int(field['va'],16)-start+len(bytes.fromhex(field['bytes']))-1]^=1
        active[field['region']]=(start,changed)
        try:check_fields(active)
        except ValueError as error:controls.append(dict(control='element reader '+field['label'],rejection=str(error)))
        else:raise ValueError('element reader field corruption escaped')
    record=current['selected_fde_candidates']['0x16fce10'];fde=bytes.fromhex(record['fde_hex'])
    def check_extent(raw):
        delta,length=struct.unpack_from('<ii',raw,8)
        require(int(record['fde_va'],16)+8+delta==0x16fce10 and length==264 and 0x16fce10+length==int(record['end_va'],16),'element reader actual FDE extent')
    check_extent(fde);changed=bytearray(fde);changed[12]^=1
    try:check_extent(changed)
    except ValueError as error:controls.append(dict(control='element reader FDE extent',rejection=str(error)))
    else:raise ValueError('element reader FDE corruption escaped')
    computed=extract_element_data(data);saved=json.loads((folder/'referenced-data.json').read_text())
    require(computed==saved,'element reader referenced data drift')
    active={'table':bytes.fromhex(saved['table']['data_hex'])}
    active.update({'relocation '+r['slot']:bytes.fromhex(r['relocation_hex']) for r in saved['relocations']})
    active.update({'descriptor '+r['va']:bytes.fromhex(r['data_hex']) for r in saved['descriptors']})
    expected={k:bytes(v) for k,v in active.items()}
    def check_data(values):
        require(set(values)==set(expected),'element reader data inventory')
        for key,raw in values.items():require(bytes(raw)==expected[key],'element reader data corruption: '+key)
    check_data(active)
    for key,raw in active.items():
        for offset in (range(0,len(raw),4) if key=='table' else [16 if key.startswith('relocation ') else 0]):
            values=dict(active);changed=bytearray(raw);changed[offset]^=1;values[key]=changed
            try:check_data(values)
            except ValueError as error:controls.append(dict(control='element reader '+key+' '+str(offset),rejection=str(error)))
            else:raise ValueError('element reader data corruption escaped')
    rows=rowmaps['element-candidate'];instruction=lambda va:bytes.fromhex(rows[va]['bytes'])
    for site,target in [(0x16fce48,0x47db78),(0x16fced0,0x640be00),(0x16fcef5,0x640be00),
                        (0x16fcee1,0x64e0910),(0x16fcf0b,0x640bc40),(0x16fcf12,0x64df520)]:
        raw=instruction(site);require(site+len(raw)+struct.unpack_from('<i',raw,len(raw)-4)[0]==target,'element reader RIP binding')
    require([(r['slot'],r['info'],r['addend']) for r in computed['relocations']]==[
        ('0x64df520',8,'0x1681da0'),('0x64e0910',8,'0x5c54c30')],'element reader actual RELATIVE targets')
    targets=[0x16fce58,0x16fce81,0x16fce70,0x16fce75,0x16fce64,0x16fce9c,0x16fcea3,0x16fce7b]
    require([int(r['target'],16) for r in computed['table']['entries']]==targets and all(t in rows for t in targets),'element reader eight-tag table')
    for site,raw in [(0x16fce15,'488b06'),(0x16fce18,'483b4608'),(0x16fce1e,'488d4820'),(0x16fce22,'48890e'),
        (0x16fce25,'488b4e10'),(0x16fce29,'4883f9ff'),(0x16fce33,'48ffc1'),(0x16fce36,'48894e10'),
        (0x16fce3a,'0fb608'),(0x16fce3d,'ffc9'),(0x16fce3f,'83f907'),(0x16fce4f,'48630c8a'),
        (0x16fce58,'0fb64001'),(0x16fce5e,'c6470100'),(0x16fce64,'480fbe4001'),(0x16fce69,'4885c0'),
        (0x16fce70,'8b4004'),(0x16fce75,'488b4008'),(0x16fce7b,'488b4008'),(0x16fce81,'0fb74002'),
        (0x16fce85,'483dff000000'),(0x16fce90,'4889442410'),(0x16fce95,'c644240801'),
        (0x16fce9c,'480fbf4002'),(0x16fcea3,'48634004'),(0x16fcea7,'483d00010000'),
        (0x16fceaf,'c6470101'),(0x16fceb3,'884702'),(0x16fceb6,'31c0'),(0x16fceb8,'8807'),
        (0x16fcec6,'4889442410'),(0x16fcecb,'c644240802'),(0x16fceea,'48894308'),(0x16fceee,'b001')]:
        require(instruction(site)==bytes.fromhex(raw),'element reader semantic instruction binding')
    calls=[];branches=[]
    for va,row in rows.items():
        raw=bytes.fromhex(row['bytes']);target=None
        if raw[0]==0xe8:
            target=va+5+struct.unpack_from('<i',raw,1)[0];calls.append(dict(va=hex(va),target=hex(target)));continue
        if raw[0]==0xeb or 0x70<=raw[0]<=0x7f:target=va+len(raw)+struct.unpack_from('<b',raw,1)[0]
        elif raw[0]==0xe9:target=va+len(raw)+struct.unpack_from('<i',raw,1)[0]
        elif raw[0]==0x0f and len(raw)>1 and 0x80<=raw[1]<=0x8f:target=va+len(raw)+struct.unpack_from('<i',raw,2)[0]
        if target is not None:require(target in rows,'element reader local branch boundary');branches.append(dict(va=hex(va),target=hex(target)))
    require(calls==[dict(va='0x16fcf04',target='0x1704de0')],'element reader direct default helper')
    for site in [0x173fe66,0x173fe95]:
        raw=bytes.fromhex(rowmaps['sequence-candidate'][site]['bytes'])
        require(raw[0]==0xe8 and site+5+struct.unpack_from('<i',raw,1)[0]==0x16fce10,'both sequence reader calls')
    widths={1:8,2:16,3:32,4:64,5:8,6:16,7:32,8:64};signed_tags={5,6,7,8};mask64=(1<<64)-1
    for tag in range(256):require((((tag-1)&0xffffffff)<=7)==(1<=tag<=8),'bounded raw-tag dispatch')
    def numeric(tag,raw):
        width=widths[tag];word=raw&((1<<width)-1)
        extended=(word-(1<<width) if tag in signed_tags and word>>(width-1) else word)&mask64
        if tag==1:accepted=True
        elif tag==5:accepted=extended<(1<<63)
        elif tag in [2,3,4]:accepted=extended<=255
        else:accepted=extended<256
        return accepted,extended&255,extended
    def reference(tag,raw):
        width=widths[tag];value=raw&((1<<width)-1)
        if tag in signed_tags and value>=(1<<(width-1)):value-=1<<width
        return 0<=value<=255,value
    exhaustive=0;wide=0
    for tag in [1,5,2,6]:
        for raw in range(1<<widths[tag]):
            accepted,byte,extended=numeric(tag,raw);wanted,value=reference(tag,raw)
            require(accepted==wanted and (not accepted or byte==value),'element reader exhaustive byte/word predicate');exhaustive+=1
    for tag in [3,7,4,8]:
        width=widths[tag]
        values={0,1,127,128,255,256,257,(1<<(width-1))-1,1<<(width-1),(1<<width)-1,(1<<width)-128,(1<<width)-256}
        for raw in sorted(values):
            accepted,byte,extended=numeric(tag,raw);wanted,value=reference(tag,raw)
            require(accepted==wanted and (not accepted or byte==value),'element reader wide boundary predicate');wide+=1
    def step(current,end,count,tag=1,raw=0):
        if current==end:return dict(kind='end',current=current,count=count,pair=[0,0],result_write_offsets=[0,1],header_write_offsets=[])
        advanced=(current+32)&mask64
        if count==mask64:return dict(kind='overflow-edge',current=advanced,count=count,header_write_offsets=list(range(8)))
        count+=1
        header=list(range(8))+list(range(16,24))
        if tag not in widths:return dict(kind='conditional-default-error',current=advanced,count=count,pair=[1,None],header_write_offsets=header)
        accepted,byte,extended=numeric(tag,raw)
        if not accepted:return dict(kind='conditional-numeric-error',current=advanced,count=count,pair=[1,None],diagnostic_code=2 if tag in signed_tags else 1,header_write_offsets=header)
        return dict(kind='byte',current=advanced,count=count,pair=[0,1],byte=byte,result_write_offsets=[0,1,2],header_write_offsets=header)
    cursor_cases=0
    for count in [0,mask64]:
        r=step(4096,4096,count);require(r['kind']=='end' and r['current']==4096 and r['count']==count and not r['header_write_offsets'],'empty before counter guard');cursor_cases+=1
    for tag in range(1,9):
        r=step(4096,4128,7,tag,127);require(r['kind']=='byte' and (r['current'],r['count'])==(4128,8) and r['result_write_offsets']==[0,1,2],'ordinary write/advance frame');cursor_cases+=1
    for tag,raw in [(2,256),(3,256),(4,256),(5,255),(6,65535),(7,(1<<32)-1),(8,mask64)]:
        r=step(4096,4128,7,tag,raw);require(r['kind']=='conditional-numeric-error' and (r['current'],r['count'])==(4128,8),'rejected numeric consumes record before opaque call');cursor_cases+=1
    for tag in [0,9,22,255]:
        r=step(4096,4128,7,tag,0);require(r['kind']=='conditional-default-error' and (r['current'],r['count'])==(4128,8),'default raw tag consumes record');cursor_cases+=1
    r=step(4096,4128,mask64);require(r['kind']=='overflow-edge' and r['current']==4128 and r['count']==mask64,'cursor advances before overflow edge');cursor_cases+=1
    r=step(4096,4128,mask64-1);require(r['kind']=='byte' and r['count']==mask64,'maximum nonoverflowing increment');cursor_cases+=1
    def composed(records):
        current=0;count=0;end=len(records)*32;out=[]
        def read():
            nonlocal current,count
            tag,raw=records[current//32] if current!=end else (1,0)
            r=step(current,end,count,tag,raw);current,count=r['current'],r['count'];return r
        for index in range(32):
            r=read()
            if r['kind'].startswith('conditional-'):return dict(outcome='conditional-early-error',count=count,current=current)
            if r['kind']=='end':return dict(outcome='conditional-short-error',reported=index,count=count,current=current)
            require(r['kind']=='byte','bounded composition cannot overflow');out.append(r['byte'])
        r=read()
        if r['kind']=='byte':return dict(outcome='conditional-excess-error',reported=33,count=count,current=current)
        require(r['kind']=='end' or r['kind'].startswith('conditional-'),'bounded boundary response')
        if current!=end:return dict(outcome='conditional-outer-remainder-error',reported=count+(end-current)//32,count=count,current=current)
        return dict(outcome='ordinary-local-success' if r['kind']=='end' else 'conditional-boundary-error-local-success',count=count,current=current,output=bytes(out))
    compositions=0
    for length in range(35):
        r=composed([(1,i) for i in range(length)])
        expected='conditional-short-error' if length<32 else 'ordinary-local-success' if length==32 else 'conditional-excess-error'
        require(r['outcome']==expected,'composed raw-record length path')
        if length==32:require(r['output']==bytes(range(32)) and r['count']==32 and r['current']==1024,'ordinary numeric32 frame')
        compositions+=1
    for bad in [(2,256),(6,65535),(22,0)]:
        for trailing in [0,1]:
            r=composed([(1,i) for i in range(32)]+[bad]+[(1,1)]*trailing)
            wanted='conditional-outer-remainder-error' if trailing else 'conditional-boundary-error-local-success'
            require(r['outcome']==wanted and r['count']==33 and r['current']==1056,'conditional boundary-record/outer remainder path')
            if trailing:require(r['reported']==34,'remaining count adds processed33 plus one')
            else:require(r['output']==bytes(range(32)),'conditional cleanup frame premise')
            compositions+=1
    return dict(status='ELEMENT_READER_LOCAL_RECORD_PATHS_REPRODUCED',helper_bytes=264,helper_instructions=73,
        field_bindings=len(fields),evidence_corruptions_rejected=len(controls),controls=controls,direct_callees=calls,local_branches=branches,
        raw_integer_tags=list(range(1,9)),dispatch_byte_cases=256,numeric_8_16_payload_cases=exhaustive,numeric_32_64_boundary_cases=wide,
        cursor_cases=cursor_cases,composed_raw_record_cases=compositions,record_stride=32,empty_result_write_offsets=[0,1],
        byte_result_write_offsets=[0,1,2],ordinary_header_write_offsets=list(range(8))+list(range(16,24)),normal_byte_and_end_paths_call_helpers=False,
        error_result_write_offsets=list(range(8,16))+[0],overflow_after_cursor_advance=True,relocation_bindings=2,unidentified_descriptors=2,renewed_sequence_rows=82,
        limits='Static numeric/cursor and conditional raw-record traces only. Valid nonaliased record/header/output memory is required. Error/default/overflow and cleanup helper effects and returns remain opaque. Ordinary byte/end paths have no opaque calls and their local stores fit the16-byte response carrier; error paths retain a memory-frame premise. Serialized JSON/wire reachability, security impact, source ABI/type, second alternative, exception closure and runtime equivalence remain unproved.')


def extract_second_data(data):
    assert len(data)==105896032 and hashlib.sha256(data).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
    shoff=struct.unpack_from('<Q',data,40)[0];size,count,nameidx=struct.unpack_from('<HHH',data,58);assert size==64
    rows=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+64*i) for i in range(count)]
    sr=rows[nameidx];names=data[sr[4]:sr[4]+sr[5]]
    sections={names[r[0]:names.find(b'\0',r[0])].decode():r for r in rows}
    def at(va,n):
        hits=[(name,r) for name,r in sections.items() if r[1]!=8 and r[2]&2 and r[3]<=va and va+n<=r[3]+r[5]];assert len(hits)==1
        name,row=hits[0];off=row[4]+va-row[3];raw=data[off:off+n]
        return dict(va=hex(va),file_offset=hex(off),section=name,section_flags=row[2],bytes=n,data_hex=raw.hex(),sha256=hashlib.sha256(raw).hexdigest())
    tables=[]
    for label,va,count,first in [('outer',0x47de30,22,0),('keys',0x47de88,15,1)]:
        table=at(va,count*4);raw=bytes.fromhex(table['data_hex']);table['label']=label
        table['entries']=[dict(raw_tag=i+first,displacement=struct.unpack_from('<i',raw,4*i)[0],target=hex(va+struct.unpack_from('<i',raw,4*i)[0])) for i in range(count)]
        tables.append(table)
    rela=sections['.rela.dyn'];records=[]
    for off in range(rela[4],rela[4]+rela[5],24):
        slot,info,addend=struct.unpack_from('<QQq',data,off)
        if slot in [0x64e0900,0x64df4a0,0x64df4c0]:
            records.append(dict(slot=hex(slot),info=info,addend=hex(addend),relocation_file_offset=hex(off),relocation_hex=data[off:off+24].hex(),stored_pointer=at(slot,8)))
    assert len(records)==3 and all(r['info']==8 for r in records)
    return dict(target_sha256=hashlib.sha256(data).hexdigest(),tables=tables,relocations=records,
        prior_first_sites=[at(va,n) for va,n in [(0x16fdd01,3),(0x16fdd04,3),(0x16fdd0c,4),(0x16fdd15,3),(0x16fdd18,10),(0x16fdd22,3),(0x16fdd25,3),(0x16fdd28,4)]],
        key_literal=at(0x47e524,5),descriptors=[at(va,32) for va in [0x640e8e8,0x640bd10]],
        formatter_pool_spans=[at(va,32) for va in [0x4325c4,0x43351a]],
        limits='Selected outer/key tables, actual relocation records and allocated data spans. Outer raw-tag domain, descriptor/formatter layout, source types, helper initialization/ownership and exception contracts remain unproved.')

def verify_second_alternative(data, packet):
    folder=packet/'second-alternative'
    current=probe(data,extra_vas=(0x16fdf90,0x1751436))
    require(current==json.loads((folder/'candidates.json').read_text()),'second alternative FDE candidate drift')
    require(current==json.loads((folder/'receipts/full-input-replay.json').read_text()),'second alternative hosted full-input replay drift')
    native=json.loads((folder/'receipts/decode-result.json').read_text())
    require(native['target_sha256']==TARGET and native['whole_elf_reauthenticated_in_job'] and native['input_hashes_unchanged'],'second alternative full input binding')
    require(not native['captured_program_executed'] and native['native_invocations']==3,'second alternative execution record')
    bodies={};rowmaps={}
    for label,key in [('second-candidate','0x16fdf90'),('constructor-candidate','0x1751436')]:
        record=current['selected_fde_candidates'][key];start=int(record['start_va'],16);off=int(record['file_offset'],16)
        body=data[off:off+record['bytes']]
        require(hashlib.sha256(body).hexdigest()==record['body_sha256'],'second alternative body identity')
        cursor=start;rows=[]
        for line in (folder/'receipts'/(label+'.stdout')).read_text().splitlines():
            if not re.match(r'^\s*[0-9a-f]+:',line):continue
            parts=line.split('\t');require(len(parts)>=3,'second alternative native syntax')
            va=int(parts[0].strip().rstrip(':'),16);tokens=parts[1].split()
            require(tokens and all(re.fullmatch('[0-9a-f]{2}',t) for t in tokens),'second alternative native byte syntax')
            raw=bytes.fromhex(' '.join(tokens));text=' '.join(parts[2:]).strip()
            require(va==cursor and body[va-start:va-start+len(raw)]==raw,'second alternative native/full-image binding')
            require(text and '(bad)' not in text and not text.startswith('.byte'),'second alternative undecoded row')
            rows.append(dict(va=hex(va),bytes=raw.hex(),text=text));cursor+=len(raw)
        saved=next(r for r in native['regions'] if r['label']==label)
        require(rows==saved['instruction_rows'] and len(rows)==saved['instructions'] and cursor==int(record['end_va'],16),'second alternative complete rows/extent')
        bodies[label]=(start,body);rowmaps[label]={int(r['va'],16):r for r in rows}
    earlier=json.loads((packet/'receipts/decode-result.json').read_text())
    require(next(r['instruction_rows'] for r in earlier['regions'] if r['label']=='constructor-candidate')==
            next(r['instruction_rows'] for r in native['regions'] if r['label']=='constructor-candidate'),'renewed constructor drift')
    edge=json.loads((folder/'receipts/qualified-candidate-edges.json').read_text())
    call=rowmaps['constructor-candidate'][0x1751436];raw=bytes.fromhex(call['bytes'])
    require(len(edge)==1 and edge[0]['native_instruction_boundary_validated'] and edge[0]['candidate_va']==call['va'] and edge[0]['bytes']==call['bytes'],'second alternative caller boundary')
    require(raw[0]==0xe8 and 0x1751436+5+struct.unpack_from('<i',raw,1)[0]==0x16fdf90,'second alternative caller direct target')
    fields=json.loads((folder/'field-bindings.json').read_text())
    def check_fields(active):
        for field in fields:
            va=int(field['va'],16);raw=bytes.fromhex(field['bytes']);start,body=active[field['region']]
            require(rowmaps[field['region']].get(va,{}).get('bytes')==field['bytes'],'second alternative field boundary')
            require(body[va-start:va-start+len(raw)]==raw,'second alternative field corruption: '+field['label'])
    check_fields(bodies);controls=[]
    for field in fields:
        active=dict(bodies);start,body=bodies[field['region']];changed=bytearray(body)
        changed[int(field['va'],16)-start+len(bytes.fromhex(field['bytes']))-1]^=1
        active[field['region']]=(start,changed)
        try:check_fields(active)
        except ValueError as error:controls.append(dict(control='second alternative '+field['label'],rejection=str(error)))
        else:raise ValueError('second alternative field corruption escaped')
    record=current['selected_fde_candidates']['0x16fdf90'];fde=bytes.fromhex(record['fde_hex'])
    def check_extent(raw):
        delta,length=struct.unpack_from('<ii',raw,8)
        require(int(record['fde_va'],16)+8+delta==0x16fdf90 and length==1346 and 0x16fdf90+length==int(record['end_va'],16),'second alternative actual FDE extent')
    check_extent(fde);changed=bytearray(fde);changed[12]^=1
    try:check_extent(changed)
    except ValueError as error:controls.append(dict(control='second alternative FDE extent',rejection=str(error)))
    else:raise ValueError('second alternative FDE corruption escaped')
    computed=extract_second_data(data);saved=json.loads((folder/'referenced-data.json').read_text())
    require(computed==saved,'second alternative data drift')
    active={r['label']+' table':bytes.fromhex(r['data_hex']) for r in saved['tables']}
    active.update({'relocation '+r['slot']:bytes.fromhex(r['relocation_hex']) for r in saved['relocations']})
    active.update({'descriptor '+r['va']:bytes.fromhex(r['data_hex']) for r in saved['descriptors']})
    active.update({'formatter '+r['va']:bytes.fromhex(r['data_hex']) for r in saved['formatter_pool_spans']})
    active.update({'prior first '+r['va']:bytes.fromhex(r['data_hex']) for r in saved['prior_first_sites']})
    active['key literal']=bytes.fromhex(saved['key_literal']['data_hex']);expected={k:bytes(v) for k,v in active.items()}
    def check_data(values):
        require(set(values)==set(expected),'second alternative data inventory')
        for key,raw in values.items():require(bytes(raw)==expected[key],'second alternative data corruption: '+key)
    check_data(active)
    for key,raw in active.items():
        for offset in (range(0,len(raw),4) if key.endswith(' table') else [16 if key.startswith('relocation ') else 0]):
            values=dict(active);changed=bytearray(raw);changed[offset]^=1;values[key]=changed
            try:check_data(values)
            except ValueError as error:controls.append(dict(control='second alternative '+key+' '+str(offset),rejection=str(error)))
            else:raise ValueError('second alternative data corruption escaped')
    rows=rowmaps['second-candidate'];instruction=lambda va:bytes.fromhex(rows[va]['bytes'])
    outer=[0x16fe24f,0x16fe261,0x16fe22b,0x16fe244,0x16fe214,0x16fe274,0x16fe289,0x16fe249,0x16fe2a5,
        0x16fe220,0x16fe290,0x16fe1e9,0x16fe21a,0x16fe27b,0x16fe1e3,0x16fe231,0x16fe188,0x16fe188,0x16fe2c2,0x16fe2cc,0x16fe2b8,0x16fdfb7]
    keys=[0x16fe037,0x16fe424,0x16fe424,0x16fe000,0x16fe424,0x16fe424,0x16fe424,0x16fe424,0x16fe424,0x16fe424,0x16fe424,0x16fe090,0x16fe041,0x16fe064,0x16fe050]
    require([int(r['target'],16) for r in computed['tables'][0]['entries']]==outer and all(t in rows for t in outer),'second outer table boundaries')
    require([int(r['target'],16) for r in computed['tables'][1]['entries']]==keys and all(t in rows for t in keys),'second key table boundaries')
    require([(r['slot'],r['info'],r['addend']) for r in computed['relocations']]==[
        ('0x64df4a0',8,'0x635de30'),('0x64df4c0',8,'0x1680cab'),('0x64e0900',8,'0x5c54bd0')],'second actual RELATIVE bindings')
    for site,target in [(0x16fdfa7,0x47de30),(0x16fdff4,0x47de88),(0x16fe192,0x47e524),(0x16fe3c4,0x47e524),
        (0x16fe1ba,0x16c7ba0),(0x16fe3ec,0x16c7ba0),(0x16fe1c6,0x4325c4),(0x16fe3f8,0x43351a),
        (0x16fe37c,0x640e8e8),(0x16fe42f,0x640bd10),(0x16fe38d,0x64e0900),(0x16fe473,0x64df4a0),(0x16fe4cc,0x64df4c0)]:
        raw=instruction(site);require(site+len(raw)+struct.unpack_from('<i',raw,len(raw)-4)[0]==target,'second RIP binding')
    for site,raw in [(0x16fdfb7,'49bf0100000000000080'),(0x16fdfc1,'4c8b6610'),(0x16fdfc5,'4c8b6e18'),(0x16fdfc9,'498d77ff'),
        (0x16fdfe3,'49c1e506'),(0x16fe010,'4983c440'),(0x16fe014,'4983c5c0'),(0x16fe01e,'410fb60424'),
        (0x16fe023,'ffc8'),(0x16fe025,'83f80e'),(0x16fe000,'49837c240800'),(0x16fe037,'41807c240100'),
        (0x16fe041,'49837c241005'),(0x16fe050,'49837c241005'),(0x16fe064,'49837c241805'),(0x16fe090,'49837c241805'),
        (0x16fe05d,'803865'),(0x16fe071,'803865'),(0x16fe076,'80780172'),(0x16fe07c,'80780272'),(0x16fe082,'8078036f'),(0x16fe088,'80780472'),
        (0x16fe0a1,'8b08'),(0x16fe0a3,'bf6572726f'),(0x16fe0aa,'0fb64004'),(0x16fe0ae,'83f072'),(0x16fe0b9,'4939f6'),
        (0x16fe0c5,'498d742420'),(0x16fe0ca,'488d7c2410'),(0x16fe0d7,'4c8b742410'),(0x16fe0dc,'488b542418'),(0x16fe0e1,'4939f6'),
        (0x16fe126,'49bf0100000000000080'),(0x16fe130,'498d47ff'),(0x16fe134,'4939c6'),
        (0x16fe142,'48894360'),(0x16fe14a,'0f114350'),(0x16fe15e,'0f115b40'),(0x16fe162,'0f115330'),(0x16fe166,'0f114b20'),(0x16fe16a,'0f114310'),
        (0x16fe16e,'4c8933'),(0x16fe171,'48895308'),(0x16fe1a1,'48c784248800000005000000'),
        (0x16fe1d7,'48894308'),(0x16fe1db,'4c893b'),(0x16fe397,'48b80100000000000080'),(0x16fe3a1,'488903')]:
        require(instruction(site)==bytes.fromhex(raw),'second semantic instruction binding')
    calls=[];branches=[]
    for va,row in rows.items():
        raw=bytes.fromhex(row['bytes']);target=None
        if raw[0]==0xe8:
            target=va+5+struct.unpack_from('<i',raw,1)[0];calls.append(dict(va=hex(va),target=hex(target)));continue
        if raw[0]==0xeb or 0x70<=raw[0]<=0x7f:target=va+len(raw)+struct.unpack_from('<b',raw,1)[0]
        elif raw[0]==0xe9:target=va+len(raw)+struct.unpack_from('<i',raw,1)[0]
        elif raw[0]==0x0f and len(raw)>1 and 0x80<=raw[1]<=0x8f:target=va+len(raw)+struct.unpack_from('<i',raw,2)[0]
        if target is not None:require(target in rows,'second local branch boundary');branches.append(dict(va=hex(va),target=hex(target)))
    require(calls==[dict(va=hex(a),target=hex(b)) for a,b in [(0x16fe0cf,0x16fe920),(0x16fe1d2,0x1742090),
        (0x16fe404,0x1742090),(0x16fe43e,0x1704de0),(0x16fe493,0x17044a0),(0x16fe4bf,0x17048c0),(0x16fe4c7,0x63f0a50)]],'second direct callee bindings')
    first_native=json.loads((packet/'first-variant/receipts/decode-result.json').read_text())
    first_rows={r['va']:r for r in next(r for r in first_native['regions'] if r['label']=='variant-candidate')['instruction_rows']}
    for r in saved['prior_first_sites']:require(first_rows[r['va']]['bytes']==r['data_hex'],'first alternative bridge row binding')
    first_byva={int(k,16):bytes.fromhex(r['bytes']) for k,r in first_rows.items()}
    require(first_byva[0x16fdd18]==bytes.fromhex('48b90100000000000080') and first_byva[0x16fdd22]==bytes.fromhex('48ffc9') and first_byva[0x16fdd25]==bytes.fromhex('48890b'),'first ordinary marker A')
    constructor=rowmaps['constructor-candidate'];ci=lambda va:bytes.fromhex(constructor[va]['bytes'])
    require(ci(0x1751413)==bytes.fromhex('49be0100000000000080') and ci(0x175141d)==ci(0x175143b)==bytes.fromhex('4c39742420'),'constructor rejects only marker B locally')
    for site,target in [(0x175140e,0x16fdba0),(0x1751436,0x16fdf90)]:
        raw=ci(site);require(raw[0]==0xe8 and site+5+struct.unpack_from('<i',raw,1)[0]==target,'constructor alternative order')
    for site,raw in [(0x175146e,'48894360'),(0x1751477,'0f114350'),(0x1751480,'0f114340'),(0x1751498,'0f115b30'),
        (0x175149c,'0f115320'),(0x17514a0,'0f114b10'),(0x17514a4,'0f1103')]:require(ci(site)==bytes.fromhex(raw),'constructor copy store binding')
    def coverage(spans):return sorted({i for offset,length in spans for i in range(offset,offset+length)})
    first_spans=[(0,8),(8,4),(11,4),(15,8),(23,16),(39,1)]
    second_spans=[(0,8),(8,8),(16,16),(32,16),(48,16),(64,16),(80,16),(96,8)]
    constructor_spans=[(0,16),(16,16),(32,16),(48,16),(64,16),(80,16),(96,8)]
    require(coverage(first_spans)==list(range(40)) and coverage(second_spans)==coverage(constructor_spans)==list(range(104)),'alternative/constructor store coverage')
    require(bytes.fromhex(saved['key_literal']['data_hex'])==b'error','error field pool bytes')
    def key_class(tag,payload=b'',number=0):
        if tag==1:return 'recognized' if number&255==0 else 'ignored'
        if tag==4:return 'recognized' if number&((1<<64)-1)==0 else 'ignored'
        if tag in [12,13,14,15]:
            if len(payload)!=5:return 'ignored'
            if tag in [12,13]:same=(int.from_bytes(payload[:4],'little')^0x6f727265)|(payload[4]^0x72)==0
            else:same=all(a==b for a,b in zip(payload,b'error'))
            return 'recognized' if same else 'ignored'
        return 'opaque-key-error'
    mutations=0
    for offset in range(5):
        for byte in range(256):
            if byte==b'error'[offset]:continue
            changed=bytearray(b'error');changed[offset]=byte
            require(all(key_class(tag,bytes(changed))=='ignored' for tag in [12,13,14,15]),'five-byte key mutation escaped');mutations+=1
    for tag in [12,13,14,15]:
        require(key_class(tag,b'error')=='recognized','exact error key')
        for payload in [b'',b'erro',b'errors',b'Error',b'ERROR',b'result']:require(key_class(tag,payload)=='ignored','error key length/case/prefix policy')
    key_cases=0
    for tag in range(256):
        wanted='recognized' if tag in [1,4,12,13,14,15] else 'opaque-key-error'
        require(key_class(tag,b'error',0)==wanted,'raw-key dispatch classes');key_cases+=1
    A=1<<63;B=A+1
    def second_model(entries):
        word=A;retained=None;converted=0
        for tag,key,number,child_word,child_payload in entries:
            kind=key_class(tag,key,number)
            if kind=='opaque-key-error':return dict(kind=kind,word=B,converted=converted,stores=16)
            if kind=='ignored':continue
            if word!=A:return dict(kind='duplicate',word=B,converted=converted,stores=16)
            converted+=1
            if child_word==A:return dict(kind='child-marker-A',word=B,converted=converted,stores=16)
            word=child_word;retained=child_payload
        if word==A:return dict(kind='missing',word=B,converted=converted,stores=16)
        return dict(kind='wide-local-return',word=word,converted=converted,stores=104,retained=retained)
    words=[0,1,2,255,A-1,A,B,A+2,(1<<64)-1];model_cases=0
    for word in words:
        r=second_model([(12,b'error',0,word,'opaque104')]);require(r['word']==(B if word==A else word) and r['converted']==1 and r['stores']==(16 if word==A else 104),'second child-word transport');model_cases+=1
        if word!=A:
            d=second_model([(12,b'error',0,word,'first'),(13,b'error',0,0,'never-converted')]);require(d['kind']=='duplicate' and d['converted']==1,'duplicate before second conversion, including word0/B');model_cases+=1
    for entries,kind,count in [([], 'missing',0), ([(12,b'unknown',0,0,'unused')],'missing',0),
        ([(2,b'',0,0,'unused')],'opaque-key-error',0), ([(1,b'',0,0,'first'),(12,b'error',0,0,'unused')],'duplicate',1),
        ([(4,b'',0,0,'numeric-zero')],'wide-local-return',1), ([(1,b'',1,0,'ignored'),(12,b'error',0,0,'used')],'wide-local-return',1)]:
        r=second_model(entries);require(r['kind']==kind and r['converted']==count,'second local map-state scenario');model_cases+=1
    def constructor_choice(first_word,second_word):return 'first-copy104' if first_word!=B else 'generic-failure' if second_word==B else 'second-copy104'
    constructor_cases=0
    for first_word in words:
        for second_word in words:
            wanted='first-copy104' if first_word!=B else 'generic-failure' if second_word==B else 'second-copy104'
            require(constructor_choice(first_word,second_word)==wanted,'constructor local whole-word choice');constructor_cases+=1
    require(constructor_choice(A,B)=='first-copy104' and constructor_choice(B,0)=='second-copy104' and constructor_choice(B,B)=='generic-failure','distinct marker namespaces')
    # Store coverage is not source definedness or a recovered active-field mask.
    require(set(coverage(constructor_spans))-set(coverage(first_spans))==set(range(40,104)),'64 first-alternative tail bytes remain unclassified')
    return dict(status='SECOND_ALTERNATIVE_AND_LOCAL_LAYOUT_REPRODUCED',helper_bytes=1346,helper_instructions=303,
        field_bindings=len(fields),evidence_corruptions_rejected=len(controls),controls=controls,direct_callees=calls,local_branches=branches,
        selected_outer_entries=22,outer_tag_domain_bound_proved=False,key_table_entries=15,key_byte_classes=key_cases,distinct_error_key_mutations_rejected=mutations,
        map_pair_stride=64,numeric_zero_identifier_tags=[1,4],five_byte_identifier_tags=[12,13,14,15],marker_A=hex(A),marker_B=hex(B),
        local_map_model_cases=model_cases,constructor_word_choice_cases=constructor_cases,first_observed_store_offsets=coverage(first_spans),
        second_observed_store_offsets=coverage(second_spans),constructor_copy_offsets=coverage(constructor_spans),first_unclassified_copy_tail=list(range(40,104)),
        second_payload_after_first_two_words=88,second_child_helper='0x16fe920',second_child_full_initialization_proved=False,
        relocation_bindings=3,unidentified_descriptors=2,unclassified_formatter_pool_spans=2,renewed_constructor_rows=79,
        limits='Conditional raw-map/helper-word and store-coverage models only. A is first ordinary marker but second absent/child-failure test; B is constructor failure marker. Admitted child-word domain, initialization of its104-byte carrier, first tail active/inactive/padding classification, cleanup/exception/serialized input/type and runtime equivalence remain unresolved. Local copying does not prove all copied bytes initialized or semantically active.')


def extract_error_data(data):
    assert len(data)==105896032 and hashlib.sha256(data).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
    shoff=struct.unpack_from('<Q',data,40)[0];size,count,nameidx=struct.unpack_from('<HHH',data,58);assert size==64
    rows=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+64*i) for i in range(count)]
    sr=rows[nameidx];names=data[sr[4]:sr[4]+sr[5]]
    sections={names[r[0]:names.find(b'\0',r[0])].decode():r for r in rows}
    def at(va,n):
        hits=[(name,r) for name,r in sections.items() if r[1]!=8 and r[2]&2 and r[3]<=va and va+n<=r[3]+r[5]];assert len(hits)==1
        name,row=hits[0];off=row[4]+va-row[3];raw=data[off:off+n]
        return dict(va=hex(va),file_offset=hex(off),section=name,section_flags=row[2],bytes=n,data_hex=raw.hex(),sha256=hashlib.sha256(raw).hexdigest())
    tables=[]
    for label,va,count,first in [('keys',0x47def4,15,1),('numeric-fields',0x47df30,4,0)]:
        table=at(va,count*4);raw=bytes.fromhex(table['data_hex']);table['label']=label
        table['entries']=[dict(raw_tag=i+first,displacement=struct.unpack_from('<i',raw,4*i)[0],target=hex(va+struct.unpack_from('<i',raw,4*i)[0])) for i in range(count)]
        tables.append(table)
    rela=sections['.rela.dyn'];records=[]
    for off in range(rela[4],rela[4]+rela[5],24):
        slot,info,addend=struct.unpack_from('<QQq',data,off)
        if slot in [0x64df4a0,0x64df4c0]:
            records.append(dict(slot=hex(slot),info=info,addend=hex(addend),relocation_file_offset=hex(off),relocation_hex=data[off:off+24].hex(),stored_pointer=at(slot,8)))
    assert len(records)==2 and all(r['info']==8 for r in records)
    return dict(target_sha256=hashlib.sha256(data).hexdigest(),tables=tables,relocations=records,
        key_literals=[at(va,n) for va,n in [(0x459e80,4),(0x47e4d1,7),(0x45a158,4)]],
        descriptors=[at(va,32) for va in [0x640bef8,0x640bf08,0x640bd30,0x640bcd0,0x640c008]],
        formatter_pool_spans=[at(va,32) for va in [0x4325c4,0x43351a]],
        limits='Selected key/numeric tables, RELATIVE records and allocated spans. Source enum types, descriptor/formatter layouts, dependent helper result domains, active-field definedness, ownership and exception contracts remain unproved.')

def verify_error_value(data, packet):
    folder=packet/'error-value'
    current=probe(data,extra_vas=(0x16fe920,0x16fe0cf))
    require(current==json.loads((folder/'candidates.json').read_text()),'error value FDE candidate drift')
    require(current==json.loads((folder/'receipts/full-input-replay.json').read_text()),'error value hosted full-input replay drift')
    native=json.loads((folder/'receipts/decode-result.json').read_text())
    require(native['target_sha256']==TARGET and native['whole_elf_reauthenticated_in_job'] and native['input_hashes_unchanged'],'error value full input binding')
    require(not native['captured_program_executed'] and native['native_invocations']==3,'error value execution record')
    bodies={};rowmaps={}
    for label,key in [('error-candidate','0x16fe920'),('second-candidate','0x16fe0cf')]:
        record=current['selected_fde_candidates'][key];start=int(record['start_va'],16);off=int(record['file_offset'],16)
        body=data[off:off+record['bytes']]
        require(hashlib.sha256(body).hexdigest()==record['body_sha256'],'error value body identity')
        cursor=start;rows=[]
        for line in (folder/'receipts'/(label+'.stdout')).read_text().splitlines():
            if not re.match(r'^\s*[0-9a-f]+:',line):continue
            parts=line.split('\t');require(len(parts)>=3,'error value native syntax')
            va=int(parts[0].strip().rstrip(':'),16);tokens=parts[1].split()
            require(tokens and all(re.fullmatch('[0-9a-f]{2}',t) for t in tokens),'error value native byte syntax')
            raw=bytes.fromhex(' '.join(tokens));text=' '.join(parts[2:]).strip()
            require(va==cursor and body[va-start:va-start+len(raw)]==raw,'error value native/full-image binding')
            require(text and '(bad)' not in text and not text.startswith('.byte'),'error value undecoded row')
            rows.append(dict(va=hex(va),bytes=raw.hex(),text=text));cursor+=len(raw)
        saved=next(r for r in native['regions'] if r['label']==label)
        require(rows==saved['instruction_rows'] and len(rows)==saved['instructions'] and cursor==int(record['end_va'],16),'error value complete rows/extent')
        bodies[label]=(start,body);rowmaps[label]={int(r['va'],16):r for r in rows}
    earlier=json.loads((packet/'second-alternative/receipts/decode-result.json').read_text())
    require(next(r['instruction_rows'] for r in earlier['regions'] if r['label']=='second-candidate')==
            next(r['instruction_rows'] for r in native['regions'] if r['label']=='second-candidate'),'renewed second alternative drift')
    edge=json.loads((folder/'receipts/qualified-candidate-edges.json').read_text())
    call=rowmaps['second-candidate'][0x16fe0cf];raw=bytes.fromhex(call['bytes'])
    require(len(edge)==1 and edge[0]['native_instruction_boundary_validated'] and edge[0]['candidate_va']==call['va'] and edge[0]['bytes']==call['bytes'],'error value caller boundary')
    require(raw[0]==0xe8 and 0x16fe0cf+5+struct.unpack_from('<i',raw,1)[0]==0x16fe920,'error value caller direct target')
    fields=json.loads((folder/'field-bindings.json').read_text())
    def check_fields(active):
        for field in fields:
            va=int(field['va'],16);raw=bytes.fromhex(field['bytes']);start,body=active[field['region']]
            require(rowmaps[field['region']].get(va,{}).get('bytes')==field['bytes'],'error value field boundary')
            require(body[va-start:va-start+len(raw)]==raw,'error value field corruption: '+field['label'])
    check_fields(bodies);controls=[]
    for field in fields:
        active=dict(bodies);start,body=bodies[field['region']];changed=bytearray(body)
        changed[int(field['va'],16)-start+len(bytes.fromhex(field['bytes']))-1]^=1
        active[field['region']]=(start,changed)
        try:check_fields(active)
        except ValueError as error:controls.append(dict(control='error value '+field['label'],rejection=str(error)))
        else:raise ValueError('error value field corruption escaped')
    record=current['selected_fde_candidates']['0x16fe920'];fde=bytes.fromhex(record['fde_hex'])
    def check_extent(raw):
        delta,length=struct.unpack_from('<ii',raw,8)
        require(int(record['fde_va'],16)+8+delta==0x16fe920 and length==2706 and 0x16fe920+length==int(record['end_va'],16),'error value actual FDE extent')
    check_extent(fde);changed=bytearray(fde);changed[12]^=1
    try:check_extent(changed)
    except ValueError as error:controls.append(dict(control='error value FDE extent',rejection=str(error)))
    else:raise ValueError('error value FDE corruption escaped')
    computed=extract_error_data(data);saved=json.loads((folder/'referenced-data.json').read_text())
    require(computed==saved,'error value data drift')
    active={r['label']+' table':bytes.fromhex(r['data_hex']) for r in saved['tables']}
    active.update({'relocation '+r['slot']:bytes.fromhex(r['relocation_hex']) for r in saved['relocations']})
    for group in ['key_literals','descriptors','formatter_pool_spans']:
        active.update({group+' '+r['va']:bytes.fromhex(r['data_hex']) for r in saved[group]})
    expected={k:bytes(v) for k,v in active.items()}
    def check_data(values):
        require(set(values)==set(expected),'error value data inventory')
        for key,raw in values.items():require(bytes(raw)==expected[key],'error value data corruption '+key)
    check_data(active)
    for key,raw in active.items():
        for offset in (range(0,len(raw),4) if key.endswith(' table') else [16 if key.startswith('relocation ') else 0]):
            values=dict(active);changed=bytearray(raw);changed[offset]^=1;values[key]=changed
            try:check_data(values)
            except ValueError as error:controls.append(dict(control='error value '+key+' '+str(offset),rejection=str(error)))
            else:raise ValueError('error value data corruption escaped')
    rows=rowmaps['error-candidate'];instruction=lambda va:bytes.fromhex(rows[va]['bytes'])
    key_targets=[0x16fead8,0x16ff17d,0x16ff17d,0x16febd7]+[0x16ff17d]*7+[0x16fec34,0x16feafb,0x16feb7d,0x16feb2e]
    number_targets=[0x16febfc,0x16fec63,0x16fecc7,0x16feab0]
    for table,targets in zip(computed['tables'],[key_targets,number_targets]):
        require([int(r['target'],16) for r in table['entries']]==targets and all(t in rows for t in targets),'error value table/boundaries')
    require([(r['slot'],r['info'],r['addend']) for r in computed['relocations']]==[
        ('0x64df4a0',8,'0x635de30'),('0x64df4c0',8,'0x1680cab')],'error value actual relocation records')
    require([bytes.fromhex(r['data_hex']) for r in computed['key_literals']]==[b'code',b'message',b'data'],'error field literals')
    for site,target in [(0x16fe985,0x47def4),(0x16feaeb,0x47df30),(0x16febec,0x47df30),
        (0x16fed50,0x47e4d1),(0x16feda0,0x459e80),(0x16ff262,0x45a158),
        (0x16fed84,0x4325c4),(0x16ff1e8,0x43351a),(0x16fed78,0x16c7ba0),
        (0x16fefaa,0x640bef8),(0x16fefb1,0x640bf08),(0x16ff18e,0x640bd30),
        (0x16ff2ac,0x640bcd0),(0x16ff2e6,0x640c008),(0x16fef07,0x64df4a0),(0x16ff3ac,0x64df4c0)]:
        raw=instruction(site);require(site+len(raw)+struct.unpack_from('<i',raw,len(raw)-4)[0]==target,'error value RIP binding')
    semantic=[(0x16fe937,'83f814'),(0x16fe941,'48bd0000000000000080'),(0x16fe94b,'83f815'),
        (0x16fe971,'49c1e506'),(0x16fe975,'4983c420'),(0x16fe97d,'c744242000000000'),
        (0x16feab0,'4983c440'),(0x16feab4,'4983c5c0'),(0x16feac6,'83f80e'),
        (0x16feade,'3c03'),(0x16feae5,'0f43c1'),(0x16febdc,'4883f803'),(0x16febe5,'480f43c1'),
        (0x16feb15,'8138636f6465'),(0x16feb21,'813864617461'),(0x16fec4a,'ba6d657373'),(0x16fec54,'ba73616765'),
        (0x16febfc,'837c242001'),(0x16fec14,'837c243001'),(0x16fec27,'c744242001000000'),
        (0x16fec63,'4939ef'),(0x16fec86,'4939ef'),(0x16feccb,'4939c6'),(0x16fecd9,'4c8d7505'),
        (0x16fecdd,'83f910'),(0x16fece6,'83f911'),(0x16feceb,'83f912'),
        (0x16fed21,'4939c6'),(0x16fed2a,'4c8d7506'),(0x16fed40,'f644242001'),
        (0x16fedf3,'4983fd02'),(0x16fee02,'b902000000'),(0x16fee19,'4883c505'),
        (0x16fee5c,'4839c8'),(0x16fefe4,'488d4306'),(0x16feff1,'4839c8'),
        (0x16ff05b,'b903000000'),(0x16ff060,'49c1e505'),(0x16ff119,'4929f6')]
    map_stores=[(0x16fef5a,'4c897d00'),(0x16fef66,'48894508'),(0x16fef6a,'48895510'),(0x16fef6e,'4c897518'),
        (0x16fef92,'0f114520'),(0x16fef96,'0f114d30'),(0x16fef9a,'0f115540'),(0x16fef9e,'0f115d50'),(0x16fefa2,'894d60')]
    sequence_stores=[(0x16ff06c,'4c8927'),(0x16ff06f,'4c897f08'),(0x16ff078,'4c894710'),(0x16ff07c,'48894718'),
        (0x16ff080,'48895720'),(0x16ff09c,'0f114728'),(0x16ff0a0,'0f114f38'),(0x16ff0a4,'0f115748'),(0x16ff0b0,'48894758'),(0x16ff0b4,'896f60')]
    for site,raw in semantic+map_stores+sequence_stores:require(instruction(site)==bytes.fromhex(raw),'error value semantic/store instruction')
    calls=[];branches=[]
    for va,row in rows.items():
        raw=bytes.fromhex(row['bytes']);target=None
        if raw[0]==0xe8:
            calls.append(dict(va=hex(va),target=hex(va+5+struct.unpack_from('<i',raw,1)[0])));continue
        if raw[0]==0xeb or 0x70<=raw[0]<=0x7f:target=va+len(raw)+struct.unpack_from('<b',raw,1)[0]
        elif raw[0]==0xe9:target=va+len(raw)+struct.unpack_from('<i',raw,1)[0]
        elif raw[0]==0x0f and len(raw)>1 and 0x80<=raw[1]<=0x8f:target=va+len(raw)+struct.unpack_from('<i',raw,2)[0]
        if target is not None:require(target in rows,'error value local branch boundary');branches.append(dict(va=hex(va),target=hex(target)))
    expected_calls=[(0x16fe9b7,0x1705900),(0x16fe9f1,0x16fe790),(0x16fec0f,0x1705900),(0x16fec77,0x16fe790),
        (0x16fecff,0x16fd260),(0x16fed13,0x16fd260),(0x16fed93,0x1742090),(0x16fede0,0x1742090),(0x16fee4e,0x16fd260),
        (0x16feedf,0x17044a0),(0x16fefba,0x173d830),(0x16fefcd,0x16fd260),(0x16ff14a,0x173d830),
        (0x16ff19d,0x1704de0),(0x16ff1f4,0x1742090),(0x16ff24b,0x1742090),(0x16ff2a2,0x1742090),
        (0x16ff2be,0x1704de0),(0x16ff2f8,0x173d830),(0x16ff30f,0x17048c0),(0x16ff321,0x17048c0),
        (0x16ff347,0x63f0a50),(0x16ff377,0x17044a0),(0x16ff38c,0x63f0a50),(0x16ff3a7,0x63f0a50)]
    require(calls==[dict(va=hex(a),target=hex(b)) for a,b in expected_calls],'error value complete direct callees')
    def key_class(tag,payload=b'',number=0):
        if tag in [1,4]:
            value=number&((1<<(8 if tag==1 else 64))-1)
            return ['code','message','data','ignored'][min(value,3)]
        if tag not in [12,13,14,15]:return 'opaque-key-error'
        if len(payload) not in [4,7]:return 'ignored'
        if tag in [12,13]:
            if len(payload)==7:same=((int.from_bytes(payload[:4],'little')^0x7373656d)|(int.from_bytes(payload[3:7],'little')^0x65676173))==0;return 'message' if same else 'ignored'
            word=int.from_bytes(payload,'little');return 'code' if word==0x65646f63 else 'data' if word==0x61746164 else 'ignored'
        return next((name for name in ['code','message','data'] if len(payload)==len(name) and all(a==b for a,b in zip(payload,name.encode()))),'ignored')
    mutations=0
    for name in [b'code',b'message',b'data']:
        for tag in [12,13,14,15]:require(key_class(tag,name)==name.decode(),'exact nested field identifier')
        for offset in range(len(name)):
            for byte in range(256):
                if byte==name[offset]:continue
                changed=bytearray(name);changed[offset]=byte
                require(all(key_class(tag,changed)=='ignored' for tag in [12,13,14,15]),'nested field mutation escaped');mutations+=1
    numeric_cases=0
    for tag in [1,4]:
        for value in ([0,1,2,3,255] if tag==1 else [0,1,2,3,255,256,(1<<63),(1<<64)-1]):
            require(key_class(tag,number=value)==(['code','message','data'][value] if value<3 else 'ignored'),'numeric nested field identifier');numeric_cases+=1
    A=1<<63;B=A+1;NONE=A+5;MISSING=A+6
    def map_model(entries):
        present={'code':False,'message':False,'data':False};calls_seen=[]
        for name,returned in entries:
            if name=='ignored':continue
            if name=='opaque-key-error':return name,calls_seen
            if present[name]:return 'duplicate-'+name,calls_seen
            calls_seen.append(name)
            if name=='code' and returned==1:return 'code-child-failure',calls_seen
            if name=='message' and returned==A:return 'message-child-failure',calls_seen
            if name=='data' and returned in [NONE,MISSING]:return 'data-child-failure',calls_seen
            present[name]=True
        return ('missing-code' if not present['code'] else 'missing-message' if not present['message'] else 'ordinary'),calls_seen
    scenarios=[([], 'missing-code'),([('message',0)],'missing-code'),([('code',0)],'missing-message'),
        ([('code',1)],'code-child-failure'),([('code',0),('message',A)],'message-child-failure'),
        ([('code',0),('message',0),('data',NONE)],'data-child-failure'),
        ([('code',0),('message',0),('data',MISSING)],'data-child-failure'),
        ([('code',0),('message',0)],'ordinary'),([('message',B),('code',0)],'ordinary'),
        ([('ignored',0),('code',0),('message',0),('data',0)],'ordinary'),([('opaque-key-error',0)],'opaque-key-error')]
    for name in ['code','message','data']:
        scenarios.append(([(name,0),(name,0)],'duplicate-'+name))
    for entries,wanted in scenarios:
        kind,seen=map_model(entries);require(kind==wanted,'nested local map model')
        if wanted.startswith('duplicate-'):require(len(seen)==1,'duplicate precedes repeated conversion')
    # Both raw-null tags are present data, so a following data key is a duplicate.
    for raw_tag in [16,18]:
        require(instruction(0x16fecd9)==bytes.fromhex('4c8d7505'),'raw null marker A+5')
        kind,seen=map_model([('data',0),('data',0)]);require(kind=='duplicate-data' and len(seen)==1,'null data duplicate still rejected')
    def sequence_shape(count):return ('short-0',0) if count==0 else ('short-1',1) if count==1 else ('ordinary',2) if count==2 else ('ordinary',3) if count==3 else ('trailing-elements',3)
    for count,wanted in [(0,('short-0',0)),(1,('short-1',1)),(2,('ordinary',2)),(3,('ordinary',3)),(4,('trailing-elements',3)),(100,('trailing-elements',3))]:
        require(sequence_shape(count)==wanted,'conditional nested sequence count model')
    coverage=lambda spans:sorted({i for offset,size in spans for i in range(offset,offset+size)})
    map_spans=[(0,8),(8,8),(16,8),(24,8),(32,16),(48,16),(64,16),(80,16),(96,4)]
    seq_spans=[(0,8),(8,8),(16,8),(24,8),(32,8),(40,16),(56,16),(72,16),(88,8),(96,4)]
    require(coverage(map_spans)==coverage(seq_spans)==list(range(100)),'nested ordinary carrier store coverage')
    require(set(range(104))-set(coverage(map_spans))==set(range(100,104)),'four copied tail bytes unclassified')
    return dict(status='ERROR_VALUE_FIELDS_AND_LOCAL_CARRIER_REPRODUCED',helper_bytes=2706,helper_instructions=553,
        field_bindings=len(fields),evidence_corruptions_rejected=len(controls),controls=controls,direct_callees=calls,local_branches=branches,
        key_table_entries=15,numeric_field_entries=4,numeric_identifier_cases=numeric_cases,distinct_nested_key_mutations_rejected=mutations,
        local_map_model_cases=len(scenarios)+2,conditional_sequence_shape_cases=6,recognized_fields=['code','message','data'],
        message_words_offsets=[0,8,16],data_word_and_carrier_offsets=[24,32,40,48,56,64,72,80,88],code_dword_offset=96,
        marker_A=hex(A),marker_B=hex(B),data_none_marker=hex(NONE),data_missing_tracker=hex(MISSING),
        ordinary_map_store_offsets=coverage(map_spans),ordinary_sequence_store_offsets=coverage(seq_spans),unclassified_copy_tail=list(range(100,104)),
        message_helper='0x16fe790',code_helper='0x1705900',data_helper='0x16fd260',renewed_second_rows=303,
        complete_first_word_domain_proved=False,complete_104_byte_initialization_proved=False,
        limits='Conditional static map/sequence models and instruction-backed stores. Source JSON/enum types, message first-word domain (including B), dependent field initialization, default-data inactive bytes, copied tail100..103, first-form tail40..103, ownership/cleanup/exception and runtime equivalence remain unproved. No captured program execution or source-language undefined-behavior claim.')


def extract_message_data(data):
    assert len(data)==105896032 and hashlib.sha256(data).hexdigest()=='a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
    shoff=struct.unpack_from('<Q',data,40)[0];size,count,nameidx=struct.unpack_from('<HHH',data,58);assert size==64
    rows=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+64*i) for i in range(count)]
    sr=rows[nameidx];names=data[sr[4]:sr[4]+sr[5]]
    sections={names[r[0]:names.find(b'\0',r[0])].decode():r for r in rows}
    def at(va,n):
        hits=[(name,r) for name,r in sections.items() if r[1]!=8 and r[2]&2 and r[3]<=va and va+n<=r[3]+r[5]];assert len(hits)==1
        name,row=hits[0];off=row[4]+va-row[3];raw=data[off:off+n]
        return dict(va=hex(va),file_offset=hex(off),section=name,section_flags=row[2],bytes=n,data_hex=raw.hex(),sha256=hashlib.sha256(raw).hexdigest())
    tables=[]
    for label,va,count,first in [('message-tags',0x47dee4,4,12)]:
        table=at(va,count*4);raw=bytes.fromhex(table['data_hex']);table['label']=label
        table['entries']=[dict(raw_tag=i+first,displacement=struct.unpack_from('<i',raw,4*i)[0],target=hex(va+struct.unpack_from('<i',raw,4*i)[0])) for i in range(count)]
        tables.append(table)
    rela=sections['.rela.dyn'];records=[]
    for off in range(rela[4],rela[4]+rela[5],24):
        slot,info,addend=struct.unpack_from('<QQq',data,off)
        if slot in [0x64df480,0x64df498,0x64df508,0x64dfca8,0x64e0910]:
            records.append(dict(slot=hex(slot),info=info,addend=hex(addend),relocation_file_offset=hex(off),relocation_hex=data[off:off+24].hex(),stored_pointer=at(slot,8)))
    assert len(records)==5
    for record in records:
        record['relocation_type']=record['info']&0xffffffff
        record['symbol_index']=record['info']>>32
        if record['relocation_type']==8:
            assert record['symbol_index']==0
        else:
            assert record['relocation_type']==6 and record['symbol_index']==7
            symbols=sections['.dynsym'];strings=sections['.dynstr'];assert symbols[9]==24
            symbol=at(symbols[3]+24*record['symbol_index'],24)
            name,info,other,shndx,value,size=struct.unpack('<IBBHQQ',bytes.fromhex(symbol['data_hex']))
            assert 0<=name<strings[5]
            remaining=at(strings[3]+name,strings[5]-name)
            raw=bytes.fromhex(remaining['data_hex']);end=raw.index(0)
            record.update(symbol_record=symbol,symbol_name_record=at(strings[3]+name,end+1),symbol_name=raw[:end].decode(),symbol_info=info,symbol_other=other,symbol_section_index=shndx,symbol_value=hex(value),symbol_size=size)
    return dict(target_sha256=hashlib.sha256(data).hexdigest(),tables=tables,relocations=records,
        descriptors=[at(va,32) for va in [0x640bb50,0x640bcb0]],
        limits='Four raw-tag table entries, four RELATIVE records and one GLOB_DAT record with its dynamic symbol and two descriptor spans. Allocator/copy/validation/error labels are inferred from call use; helper contracts, nonreturn behavior, raw record domains, source types and ownership remain unproved.')

def verify_message_helper(data, packet):
    folder=packet/'message-helper'
    current=probe(data,extra_vas=(0x16fe790,0x16fec77))
    require(current==json.loads((folder/'candidates.json').read_text()),'message helper FDE candidate drift')
    require(current==json.loads((folder/'receipts/full-input-replay.json').read_text()),'message helper hosted full-input replay drift')
    native=json.loads((folder/'receipts/decode-result.json').read_text())
    require(native['target_sha256']==TARGET and native['whole_elf_reauthenticated_in_job'] and native['input_hashes_unchanged'],'message helper full input binding')
    require(not native['captured_program_executed'] and native['native_invocations']==3,'message helper execution record')
    bodies={};rowmaps={}
    for label,key in [('message-candidate','0x16fe790'),('error-candidate','0x16fec77')]:
        record=current['selected_fde_candidates'][key];start=int(record['start_va'],16);off=int(record['file_offset'],16)
        body=data[off:off+record['bytes']]
        require(hashlib.sha256(body).hexdigest()==record['body_sha256'],'message helper body identity')
        cursor=start;rows=[]
        for line in (folder/'receipts'/(label+'.stdout')).read_text().splitlines():
            if not re.match(r'^\s*[0-9a-f]+:',line):continue
            parts=line.split('\t');require(len(parts)>=3,'message helper native syntax')
            va=int(parts[0].strip().rstrip(':'),16);tokens=parts[1].split()
            require(tokens and all(re.fullmatch('[0-9a-f]{2}',t) for t in tokens),'message helper native byte syntax')
            raw=bytes.fromhex(' '.join(tokens));text=' '.join(parts[2:]).strip()
            require(va==cursor and body[va-start:va-start+len(raw)]==raw,'message helper native/full-image binding')
            require(text and '(bad)' not in text and not text.startswith('.byte'),'message helper undecoded row')
            rows.append(dict(va=hex(va),bytes=raw.hex(),text=text));cursor+=len(raw)
        saved=next(r for r in native['regions'] if r['label']==label)
        require(rows==saved['instruction_rows'] and len(rows)==saved['instructions'] and cursor==int(record['end_va'],16),'message helper complete rows/extent')
        bodies[label]=(start,body);rowmaps[label]={int(r['va'],16):r for r in rows}
    earlier=json.loads((packet/'error-value/receipts/decode-result.json').read_text())
    require(next(r['instruction_rows'] for r in earlier['regions'] if r['label']=='error-candidate')==
            next(r['instruction_rows'] for r in native['regions'] if r['label']=='error-candidate'),'renewed error helper drift')
    edge=json.loads((folder/'receipts/qualified-candidate-edges.json').read_text())
    call=rowmaps['error-candidate'][0x16fec77];raw=bytes.fromhex(call['bytes'])
    require(len(edge)==1 and edge[0]['native_instruction_boundary_validated'] and edge[0]['candidate_va']==call['va'] and edge[0]['bytes']==call['bytes'],'message helper caller boundary')
    require(raw[0]==0xe8 and 0x16fec77+5+struct.unpack_from('<i',raw,1)[0]==0x16fe790,'message helper caller direct target')
    fields=json.loads((folder/'field-bindings.json').read_text())
    def check_fields(active):
        for field in fields:
            va=int(field['va'],16);raw=bytes.fromhex(field['bytes']);start,body=active[field['region']]
            require(rowmaps[field['region']].get(va,{}).get('bytes')==field['bytes'],'message helper field boundary')
            require(body[va-start:va-start+len(raw)]==raw,'message helper field corruption: '+field['label'])
    check_fields(bodies);controls=[]
    for field in fields:
        active=dict(bodies);start,body=bodies[field['region']];changed=bytearray(body)
        changed[int(field['va'],16)-start+len(bytes.fromhex(field['bytes']))-1]^=1
        active[field['region']]=(start,changed)
        try:check_fields(active)
        except ValueError as error:controls.append(dict(control='message helper '+field['label'],rejection=str(error)))
        else:raise ValueError('message helper field corruption escaped')
    record=current['selected_fde_candidates']['0x16fe790'];fde=bytes.fromhex(record['fde_hex'])
    def check_extent(raw):
        delta,length=struct.unpack_from('<ii',raw,8)
        require(int(record['fde_va'],16)+8+delta==0x16fe790 and length==395 and 0x16fe790+length==int(record['end_va'],16),'message helper actual FDE extent')
    check_extent(fde);changed=bytearray(fde);changed[12]^=1
    try:check_extent(changed)
    except ValueError as error:controls.append(dict(control='message helper FDE extent',rejection=str(error)))
    else:raise ValueError('message helper FDE corruption escaped')
    computed=extract_message_data(data);saved=json.loads((folder/'referenced-data.json').read_text())
    require(computed==saved,'message helper referenced data drift')
    active={'tag table':bytes.fromhex(saved['tables'][0]['data_hex'])}
    active.update({'relocation '+r['slot']:bytes.fromhex(r['relocation_hex']) for r in saved['relocations']})
    external=next(r for r in saved['relocations'] if r['relocation_type']==6)
    active['dynamic symbol']=bytes.fromhex(external['symbol_record']['data_hex'])
    active['dynamic symbol name']=bytes.fromhex(external['symbol_name_record']['data_hex'])
    active.update({'descriptor '+r['va']:bytes.fromhex(r['data_hex']) for r in saved['descriptors']})
    expected={k:bytes(v) for k,v in active.items()}
    def check_data(values):
        require(set(values)==set(expected),'message helper data inventory')
        for key,raw in values.items():require(bytes(raw)==expected[key],'message helper data corruption '+key)
    check_data(active)
    for key,raw in active.items():
        for offset in (range(0,len(raw),4) if key=='tag table' else [16 if key.startswith('relocation ') else 0]):
            values=dict(active);changed=bytearray(raw);changed[offset]^=1;values[key]=changed
            try:check_data(values)
            except ValueError as error:controls.append(dict(control='message helper '+key+' '+str(offset),rejection=str(error)))
            else:raise ValueError('message helper data corruption escaped')
    rows=rowmaps['message-candidate'];instruction=lambda va:bytes.fromhex(rows[va]['bytes'])
    targets=[0x16fe7bd,0x16fe873,0x16fe7e7,0x16fe81c]
    require([int(r['target'],16) for r in saved['tables'][0]['entries']]==targets and all(t in rows for t in targets),'message helper tag-table targets')
    require([(r['slot'],r['info'],r['addend']) for r in saved['relocations']]==[
        ('0x64df480',8,'0x6355830'),('0x64df498',8,'0x141e264'),('0x64dfca8',8,'0x16815e0'),
        ('0x64e0910',8,'0x5c54c30'),('0x64df508',(7<<32)|6,'0x0')],'message helper relocation kinds and targets')
    require(external['symbol_name']=='memcpy' and external['symbol_index']==7 and external['symbol_info']==18 and external['symbol_section_index']==0,'message helper undefined memcpy dynamic symbol')
    for site,target in [(0x16fe7ad,0x47dee4),(0x16fe7d7,0x64df480),(0x16fe7fa,0x64dfca8),
        (0x16fe82f,0x64dfca8),(0x16fe854,0x64df480),(0x16fe86b,0x64df508),(0x16fe881,0x64df498),
        (0x16fe890,0x64df480),(0x16fe8a3,0x64df498),(0x16fe8d8,0x640bb50),(0x16fe8e9,0x64e0910),(0x16fe8f1,0x640bcb0)]:
        raw=instruction(site);require(site+len(raw)+struct.unpack_from('<i',raw,len(raw)-4)[0]==target,'message helper RIP binding')
    semantics=[(0x16fe79e,'0fb606'),(0x16fe7a1,'83c0f4'),(0x16fe7a4,'83f803'),
        (0x16fe7bd,'4c8b7618'),(0x16fe7c1,'4d85f6'),(0x16fe7d0,'4c8b6610'),
        (0x16fe7e7,'4c8b7610'),(0x16fe7eb,'4c8b7e18'),(0x16fe800,'837c240801'),
        (0x16fe80b,'4c8b742418'),(0x16fe810,'4d85f6'),(0x16fe81c,'4c8b7608'),(0x16fe820,'4c8b7e10'),
        (0x16fe835,'837c240801'),(0x16fe840,'4c8b742418'),(0x16fe845,'4d85f6'),(0x16fe84c,'4c8b642410'),
        (0x16fe85f,'4989c7'),(0x16fe862,'4889c7'),(0x16fe865,'4c89e6'),(0x16fe868,'4c89f2'),
        (0x16fe873,'4c8b7610'),(0x16fe877,'4d85f6'),(0x16fe87c,'31ff'),(0x16fe87e,'4c89f6'),
        (0x16fe889,'4c8b6608'),(0x16fe89b,'bf01000000'),(0x16fe8a0,'4c89f6'),(0x16fe8a9,'41bf01000000'),
        (0x16fe8af,'4c8933'),(0x16fe8b2,'4c897b08'),(0x16fe8b6,'4c897310'),
        (0x16fe8d3,'c644242006'),(0x16fe908,'48894308'),(0x16fe90c,'48b80000000000000080'),(0x16fe916,'488903')]
    for site,raw in semantics:require(instruction(site)==bytes.fromhex(raw),'message helper semantic instruction')
    branches=[];calls=[];indirect=[]
    for va,row in rows.items():
        raw=bytes.fromhex(row['bytes']);target=None
        if raw[0]==0xe8:
            calls.append(dict(va=hex(va),target=hex(va+5+struct.unpack_from('<i',raw,1)[0])));continue
        if raw[:2]==b'\xff\x15':
            indirect.append(dict(va=hex(va),slot=hex(va+6+struct.unpack_from('<i',raw,2)[0])));continue
        if raw[0]==0xeb or 0x70<=raw[0]<=0x7f:target=va+len(raw)+struct.unpack_from('<b',raw,1)[0]
        elif raw[0]==0xe9:target=va+len(raw)+struct.unpack_from('<i',raw,1)[0]
        elif raw[0]==0x0f and len(raw)>1 and 0x80<=raw[1]<=0x8f:target=va+len(raw)+struct.unpack_from('<i',raw,2)[0]
        if target is not None:require(target in rows,'message helper local branch target');branches.append(dict(va=hex(va),target=hex(target)))
    require(calls==[dict(va='0x16fe903',target='0x1704de0')],'message helper direct call binding')
    require(indirect==[dict(va=hex(a),slot=hex(b)) for a,b in [(0x16fe7d7,0x64df480),(0x16fe7fa,0x64dfca8),
        (0x16fe82f,0x64dfca8),(0x16fe854,0x64df480),(0x16fe86b,0x64df508),(0x16fe881,0x64df498),
        (0x16fe890,0x64df480),(0x16fe8a3,0x64df498),(0x16fe8e9,0x64e0910)]],'message helper indirect call inventory')
    caller=rowmaps['error-candidate'];ci=lambda va:bytes.fromhex(caller[va]['bytes'])
    for site in [0x16fe9f1,0x16fec77]:
        raw=ci(site);require(raw[0]==0xe8 and site+5+struct.unpack_from('<i',raw,1)[0]==0x16fe790,'message helper both caller boundaries')
    for site,raw in [(0x16fe9f6,'4c8b642430'),(0x16fea00,'4939dc'),(0x16fec7c,'4c8b7c2430'),
        (0x16fec86,'4939ef'),(0x16fec8f,'488b4c2440'),(0x16fef5a,'4c897d00'),(0x16fef66,'48894508'),(0x16fef6a,'48895510')]:
        require(ci(site)==bytes.fromhex(raw),'message helper leading-word and triple-store bridge')
    A=1<<63;B=A+1
    def route(tag,n,validation_status=0,allocation_nonzero=True):
        if ((tag-12)&0xffffffff)>3:return dict(kind='unsupported-tag-error',first=A,stores=16,validation=0,allocation=0,copy=0)
        validation=int(tag in [14,15])
        if validation and validation_status==1:return dict(kind='validation-error',first=A,stores=16,validation=1,allocation=0,copy=0)
        if n>=A:return dict(kind='failure-helper-frontier',argument0=0,validation=validation,allocation=0,copy=0)
        if n==0:return dict(kind='ordinary',first=0,second=1,third=0,stores=24,validation=validation,allocation=0,copy=0)
        if not allocation_nonzero:return dict(kind='failure-helper-frontier',argument0=1,validation=validation,allocation=1,copy=0)
        return dict(kind='ordinary',first=n,second='returned-allocation',third=n,stores=24,validation=validation,allocation=1,copy=1)
    dispatch_cases=0
    for tag in range(256):
        require(route(tag,0)['kind']==('ordinary' if tag in [12,13,14,15] else 'unsupported-tag-error'),'message helper raw-byte dispatch model');dispatch_cases+=1
    boundary_cases=0;ordinary_boundary_cases=0
    for tag in [12,13,14,15]:
        for n in [0,1,255,A-1,A,B,(1<<64)-1]:
            r=route(tag,n);require(r['kind']==('ordinary' if n<A else 'failure-helper-frontier'),'message signed-length boundary')
            if n<A:
                require(r['first']==r['third']==n and r['first']!=B and r['stores']==24,'ordinary no-frontier leading word bound')
                require((r['allocation'],r['copy'])==((0,0) if n==0 else (1,1)),'message empty/positive effects');ordinary_boundary_cases+=1
            else:require(r['argument0']==0 and r['allocation']==r['copy']==0,'negative-length helper frontier')
            boundary_cases+=1
        r=route(tag,1,allocation_nonzero=False);require(r['kind']=='failure-helper-frontier' and r['argument0']==1 and r['copy']==0,'allocation-null helper frontier');boundary_cases+=1
    for tag in [14,15]:
        r=route(tag,B,validation_status=1);require(r['kind']=='validation-error' and r['allocation']==0,'validator failure precedes length guard');boundary_cases+=1
        r=route(tag,1,validation_status=2);require(r['kind']=='ordinary','local validator check rejects exactly DWORD1, admitted status domain unproved');boundary_cases+=1
    # The model stops at the call frontier. No nonreturn/flags/helper-output
    # assumption is converted into a proof about paths after that call returns.
    require(B>=A and A-1<B,'conditional marker B exclusion is the signed nonnegative domain')
    coverage=lambda spans:sorted({i for offset,size in spans for i in range(offset,offset+size)})
    ordinary=coverage([(0,8),(8,8),(16,8)]);failed=coverage([(0,8),(8,8)])
    require(ordinary==list(range(24)) and failed==list(range(16)),'message local stores')
    return dict(status='MESSAGE_HELPER_LOCAL_STORES_AND_CONDITIONAL_WORD_DOMAIN_REPRODUCED',helper_bytes=395,helper_instructions=103,
        field_bindings=len(fields),evidence_corruptions_rejected=len(controls),controls=controls,direct_callees=calls,indirect_calls=indirect,local_branches=branches,
        raw_tag_cases=dispatch_cases,supported_raw_tags=[12,13,14,15],conditional_boundary_cases=boundary_cases,ordinary_boundary_cases=ordinary_boundary_cases,
        direct_text_length_offsets={'12':24,'13':16},validation_input_pointer_offsets={'14':16,'15':8},validation_input_length_offsets={'14':24,'15':16},
        ordinary_store_offsets=ordinary,error_store_offsets=failed,ordinary_words=['n','allocated-pointer-or-empty1','n'],empty_words=[0,1,0],
        conditional_ordinary_first_word_unsigned_range=[0,hex(A-1)],conditional_marker_B_excluded=True,global_marker_B_exclusion_proved=False,
        allocation_helper='0x6355830',failure_helper='0x141e264',validation_helper='0x16815e0',failure_helper_nonreturn_proved=False,
        memcpy_dynamic_symbol='memcpy',relative_relocations=4,glob_dat_relocations=1,renewed_error_rows=553,
        complete_104_byte_initialization_proved=False,
        limits='Instruction/data-backed stores and conditional normal-helper/memory models, not capture execution. Leading word n is signed-nonnegative on paths that avoid failure helper0x141e264; nonreturn and post-call flag contracts of that helper remain open, so global B exclusion is unproved. Validation/allocation/memcpy contracts, pointer validity/ownership, source types/ABI, error-tail100..103, first-form tail40..103 and runtime equivalence remain unresolved.')


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
    value=verify_value_helper(data,args.packet)
    result['regions']+=1;result['region_bytes']+=value['helper_bytes']
    result['native_instruction_rows']+=value['helper_instructions']
    result['instruction_counts']['value-candidate']=value['helper_instructions']
    result['field_bindings']+=value['field_bindings']
    result['evidence_corruptions_rejected']+=value['evidence_corruptions_rejected']
    result['controls']+=value['controls'];result['value_helper']=value
    require((result['regions'],result['region_bytes'],result['native_instruction_rows'])==(5,4209,966),'unique range denominator')
    result['limits']='Five digest-bound native ranges and selected raw-record paths. Delegated text/sequence helpers, raw JSON/null mapping, source/type identity, second alternative, complete ABI/exception and runtime equivalence remain unresolved.'
    text=verify_text_decoder(data,args.packet)
    result['regions']+=1;result['region_bytes']+=text['helper_bytes']
    result['native_instruction_rows']+=text['helper_instructions']
    result['instruction_counts']['text-candidate']=text['helper_instructions']
    result['field_bindings']+=text['field_bindings']
    result['evidence_corruptions_rejected']+=text['evidence_corruptions_rejected']
    result['controls']+=text['controls'];result['text_decoder']=text
    require((result['regions'],result['region_bytes'],result['native_instruction_rows'])==(6,4780,1109),'six unique ranges')
    result['limits']='Six digest-bound native ranges and local fixed-size text format. Invalid reporting, CPU-feature/vector helpers, sequence conversion, JSON/null mapping, raw-record domain, second alternative, initialized ABI/exception and runtime equivalence remain unresolved.'
    sequence=verify_sequence_helper(data,args.packet)
    result['regions']+=1;result['region_bytes']+=sequence['helper_bytes']
    result['native_instruction_rows']+=sequence['helper_instructions']
    result['instruction_counts']['sequence-candidate']=sequence['helper_instructions']
    result['field_bindings']+=sequence['field_bindings']
    result['evidence_corruptions_rejected']+=sequence['evidence_corruptions_rejected']
    result['controls']+=sequence['controls'];result['sequence_helper']=sequence
    require((result['regions'],result['region_bytes'],result['native_instruction_rows'])==(7,5066,1191),'seven unique ranges')
    result['limits']='Seven digest-bound native ranges and local value/text/sequence-response paths. Opaque element-reader cursor/counter behavior, error/cleanup and text feature/vector helpers, JSON mapping, second alternative, complete ABI/exception and runtime equivalence remain unresolved.'
    element=verify_element_reader(data,args.packet)
    result['regions']+=1;result['region_bytes']+=element['helper_bytes']
    result['native_instruction_rows']+=element['helper_instructions']
    result['instruction_counts']['element-candidate']=element['helper_instructions']
    result['field_bindings']+=element['field_bindings']
    result['evidence_corruptions_rejected']+=element['evidence_corruptions_rejected']
    result['controls']+=element['controls'];result['element_reader']=element
    require((result['regions'],result['region_bytes'],result['native_instruction_rows'])==(8,5330,1264),'eight unique ranges')
    result['limits']='Eight digest-bound native ranges and local byte/text/sequence/numeric-record paths. Normal element byte/end paths close their local store frame under valid nonaliasing memory; error/default/overflow, cleanup, text feature/vector, serialized JSON mapping, source ABI/type, second alternative, exception and runtime equivalence remain unresolved.'
    second=verify_second_alternative(data,args.packet)
    result['regions']+=1;result['region_bytes']+=second['helper_bytes']
    result['native_instruction_rows']+=second['helper_instructions']
    result['instruction_counts']['second-candidate']=second['helper_instructions']
    result['field_bindings']+=second['field_bindings']
    result['evidence_corruptions_rejected']+=second['evidence_corruptions_rejected']
    result['controls']+=second['controls'];result['second_alternative']=second
    require((result['regions'],result['region_bytes'],result['native_instruction_rows'])==(9,6676,1567),'nine unique ranges')
    result['limits']='Nine digest-bound native ranges and local result/error alternatives, value conversion and store coverage. Marker contexts are distinct. Helper0x16fe920 word domain and104-byte initialization, first-form tail classification, cleanup/exception, serialized input/type and runtime equivalence remain unresolved.'
    error_value=verify_error_value(data,args.packet)
    result['regions']+=1;result['region_bytes']+=error_value['helper_bytes']
    result['native_instruction_rows']+=error_value['helper_instructions']
    result['instruction_counts']['error-candidate']=error_value['helper_instructions']
    result['field_bindings']+=error_value['field_bindings']
    result['evidence_corruptions_rejected']+=error_value['evidence_corruptions_rejected']
    result['controls']+=error_value['controls'];result['error_value']=error_value
    require((result['regions'],result['region_bytes'],result['native_instruction_rows'])==(10,9382,2120),'ten unique ranges')
    result['limits']='Ten digest-bound native ranges and local field/result store coverage. Error-value ordinary stores cover100bytes, caller copies104; tail100..103 and dependent field definedness remain unclassified. Message first-word domain including B, first-form tail40..103, source types/ABI, cleanup/exception, serialized input and runtime equivalence remain unresolved.'
    message_helper=verify_message_helper(data,args.packet)
    result['regions']+=1;result['region_bytes']+=message_helper['helper_bytes']
    result['native_instruction_rows']+=message_helper['helper_instructions']
    result['instruction_counts']['message-candidate']=message_helper['helper_instructions']
    result['field_bindings']+=message_helper['field_bindings']
    result['evidence_corruptions_rejected']+=message_helper['evidence_corruptions_rejected']
    result['controls']+=message_helper['controls'];result['message_helper']=message_helper
    require((result['regions'],result['region_bytes'],result['native_instruction_rows'])==(11,9777,2223),'eleven unique ranges')
    result['limits']='Eleven digest-bound native ranges. Message ordinary stores are [n,pointer-or1,n], and n is signed-nonnegative on paths avoiding failure helper0x141e264. Global B exclusion requires that helper contract and remains unproved. Dependent field definedness, default-data storage, error tail100..103, first-form tail40..103, source types/ABI, cleanup/exception, wire inputs and runtime equivalence remain unresolved.'
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
