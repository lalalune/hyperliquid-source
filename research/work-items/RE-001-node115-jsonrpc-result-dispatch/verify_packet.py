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
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
