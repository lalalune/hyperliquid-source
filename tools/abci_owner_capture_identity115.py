#!/usr/bin/env python3
"""Verify the two node-115 ABCI task owner capture origins without running it."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

import capstone
from capstone import x86_const as xc

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
PARENT = (0x2CB6500, 0x2CBBBDF)
CONSTRUCTOR = (0x5A6CBC0, 0x5A6CFA7)
ALLOCATOR = (0x6355830, 0x63558F2)

sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import fde_extents
from abci_compact_root115 import relative_relocations


def require(ok, message):
    if not ok:
        raise ValueError(message)


def file_bytes(secs, data, va, size):
    rows = [s for s in secs if s['type'] != 8 and s['address'] <= va
            and va + size <= s['address'] + s['size']]
    require(len(rows) == 1, f'ambiguous or absent file-backed VA {va:#x}')
    row = rows[0]
    off = row['offset'] + va - row['address']
    return off, bytes(data[off:off + size])


def analyze(data):
    require(len(data) == SIZE, 'wrong node #115 file size')
    digest = hashlib.sha256(data).hexdigest()
    require(digest == SHA, 'wrong node #115 SHA-256')
    secs = sections(data)
    _, frames, _ = fde_extents(data)
    by_start = {frame['start']: frame for frame in frames}
    require(len(by_start) == len(frames), 'duplicate FDE starts')

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    decoded = {}
    fde_rows = []
    for label, (start, end) in (('parent', PARENT), ('task_constructor', CONSTRUCTOR),
                                ('small_allocator', ALLOCATOR)):
        frame = by_start.get(start)
        require(frame is not None and frame['end'] == end,
                f'{label}: FDE extent changed')
        off, body = file_bytes(secs, data, start, end - start)
        cursor = start
        for insn in md.disasm(body, start):
            require(insn.address == cursor, f'{label}: decode gap at {cursor:#x}')
            decoded[insn.address] = insn
            cursor += insn.size
        require(cursor == end, f'{label}: incomplete FDE decode')
        fde_rows.append({'label': label, 'start': hex(start), 'end_exclusive': hex(end),
                         'file_offset': hex(off), 'size': end - start,
                         'sha256': hashlib.sha256(body).hexdigest()})

    # These anchors pin the allocation-size request, copy, and storage of the
    # newly returned allocation in the second owner field.
    expected = {
        0x2CB865D: 'bff0060000',       # edi = 0x6f0
        0x2CB8662: 'ff15186e8203',     # indirect size-request boundary
        0x2CB8671: '4989c7',           # preserve returned pointer in r15
        0x2CB867C: 'baf0060000',       # copy length = 0x6f0
        0x2CB8681: '4889c7',
        0x2CB8684: '4889ee',
        0x2CB8687: 'ff157b6e8203',     # indirect copy boundary
        0x2CB868D: '4c89bbe80a0000',   # parent +0xae8 = new allocation
        0x2CB8863: '488bb340080000',   # rsi = existing parent +0x840
        0x2CB886A: 'f048ff06',         # retain first pointer before task build
        0x2CB8887: '488b93e80a0000',   # rdx = parent +0xae8
        0x2CB8912: '4c89e7',           # rdi = task context
        0x2CB8915: 'ff153deb8203',     # call task constructor through GOT
        0x6355834: '4881ff00100000',   # allocator's small-size branch threshold
        0x6355848: '488d4707',         # size rounded up before class lookup
        0x6355853: '48c1e803',         # divide rounded request by eight
        0x635588D: '488b9060030000',   # current per-thread class cursor
        0x6355894: '488b32',           # next returned block pointer
        0x6355897: '4c8d4208',         # cursor advances one entry
        0x63558A4: '4c898060030000',   # commit advanced cursor
        0x63558BB: '4889f0',           # return selected block pointer
        0x63558BE: 'c3',
        0x63558C0: 'e9abe1ffff',        # slow refill path
        0x5A6CBDE: '4989f6',           # constructor saves rsi owner
        0x5A6CBE4: '4889742468',       # temporary first-owner copy
        0x5A6CBE9: '4889542438',       # temporary second-owner copy
        0x5A6CD71: '4c89b424f8000000', # first owner -> task +0x78
        0x5A6CE17: '488b442438',       # reload second-owner argument
        0x5A6CE1C: '4889842428010000', # second owner -> task +0xa8
        0x5A6CC20: '0f1180100b0000',   # separate task backing object init
        0x5A6CE24: 'bfb8000000',       # task allocation size = 0xb8
        0x5A6CE3B: '488db42480000000', # task source begins at stack +0x80
        0x5A6CE43: 'bab8000000',       # task copy length = 0xb8
        0x5A6CE48: '4889c7',
        0x5A6CE4B: 'ff15b726a700',     # indirect copy boundary
    }
    anchors = []
    for va, encoded in expected.items():
        raw = bytes.fromhex(encoded)
        file_offset, actual = file_bytes(secs, data, va, len(raw))
        require(actual == raw, f'anchor bytes changed at {va:#x}')
        insn = decoded.get(va)
        require(insn is not None and insn.bytes == raw,
                f'anchor is not an instruction at {va:#x}')
        anchors.append({'va': hex(va), 'file_offset': hex(file_offset), 'bytes': raw.hex()})

    # The parent loads the existing owner into RSI, then the separately
    # allocated owner into RDX. Neither argument register is overwritten before
    # the constructor call, and the constructor receives the expected GOT target.
    for va, reg in ((0x2CB8863, xc.X86_REG_RSI), (0x2CB8887, xc.X86_REG_RDX)):
        insn = decoded[va]
        require(insn.mnemonic == 'mov' and insn.operands[0].reg == reg,
                f'owner argument register changed at {va:#x}')
        call = decoded[0x2CB8915]
        for op in insn.operands[1:]:
            if op.type == xc.X86_OP_MEM:
                require(op.mem.base == xc.X86_REG_RBX, 'unexpected parent base')
    between = [insn for va, insn in decoded.items() if 0x2CB8863 < va < 0x2CB8915]
    require(not any(op.type == xc.X86_OP_REG and op.reg == xc.X86_REG_RSI
                    and op.access & xc.CS_AC_WRITE
                    for insn in between for op in insn.operands),
            'first owner argument register is overwritten before constructor')
    require(not any(op.type == xc.X86_OP_REG and op.reg == xc.X86_REG_RDX
                    and op.access & xc.CS_AC_WRITE
                    for insn in decoded.values() if 0x2CB8887 < insn.address < 0x2CB8915
                    for op in insn.operands),
            'second owner argument register is overwritten before constructor')

    call = decoded[0x2CB8915]
    require(call.operands[0].type == xc.X86_OP_MEM
            and call.operands[0].mem.base == xc.X86_REG_RIP,
            'task constructor call is no longer RIP-indirect')
    slot = call.address + call.size + call.operands[0].mem.disp
    relocation = relative_relocations(data, secs, [slot])[slot][0]
    require(relocation == CONSTRUCTOR[0], 'task constructor relocation changed')

    allocation_call = decoded[0x2CB8662]
    alloc_slot = allocation_call.address + allocation_call.size + allocation_call.operands[0].mem.disp
    alloc_target = relative_relocations(data, secs, [alloc_slot])[alloc_slot][0]
    require(alloc_target == ALLOCATOR[0], 'allocation helper relocation changed')
    copy_call = decoded[0x2CB8687]
    copy_slot = copy_call.address + copy_call.size + copy_call.operands[0].mem.disp
    rela = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    require(len(rela) == 1 and rela[0]['size'] % 24 == 0,
            'dynamic relocation table is absent or malformed')
    copy_relocations = [entry for entry in struct.iter_unpack(
        '<QQq', data[rela[0]['offset']:rela[0]['offset'] + rela[0]['size']])
        if entry[0] == copy_slot]
    require(len(copy_relocations) == 1, 'copy helper relocation is ambiguous')
    _, copy_info, _ = copy_relocations[0]
    require((copy_info & 0xFFFFFFFF) == 6, 'copy helper is not R_X86_64_GLOB_DAT')
    symbol_index = copy_info >> 32
    dynsyms = [s for s in secs if s['name'] == '.dynsym' and s['type'] == 11]
    require(len(dynsyms) == 1 and dynsyms[0]['size'] % 24 == 0,
            'dynamic symbol table is absent or unsupported')
    dynsym = dynsyms[0]
    dynstrs = [s for s in secs if s['name'] == '.dynstr' and s['type'] != 8]
    require(len(dynstrs) == 1,
            'dynamic string table is not file-backed')
    dynstr = dynstrs[0]
    symbols = data[dynsym['offset']:dynsym['offset'] + dynsym['size']]
    require(symbol_index * 24 + 24 <= len(symbols), 'copy symbol index is out of range')
    name_offset = struct.unpack_from('<I', symbols, symbol_index * 24)[0]
    strings = data[dynstr['offset']:dynstr['offset'] + dynstr['size']]
    require(name_offset < len(strings), 'copy symbol name is out of range')
    name_end = strings.find(b'\0', name_offset)
    require(name_end >= 0, 'copy symbol name is unterminated')
    copy_symbol = strings[name_offset:name_end].decode('ascii')
    require(copy_symbol == 'memcpy', 'second-owner copy helper is not memcpy')
    slow_target = (0x63558C0 + len(bytes.fromhex('e9abe1ffff'))
                   + struct.unpack('<i', bytes.fromhex('e9abe1ffff')[1:])[0])
    require(slow_target == 0x6353A70, 'allocator slow-path target changed')

    # The constructor copies its caller's two owner pointers into different
    # fields of the 0xb8-byte callback task. RSI was saved from the first input;
    # RDX's saved value is reloaded into task offset +0xa8.
    require(decoded[0x5A6CBDE].operands[0].reg == xc.X86_REG_R14
            and decoded[0x5A6CBDE].operands[1].reg == xc.X86_REG_RSI,
            'constructor first-owner capture changed')
    require(decoded[0x5A6CBE4].operands[1].reg == xc.X86_REG_RSI,
            'constructor first-owner staging changed')
    require(decoded[0x5A6CBE9].operands[1].reg == xc.X86_REG_RDX
            and decoded[0x5A6CE17].operands[1].mem.disp == 0x38,
            'constructor second-owner staging changed')
    projection_path = ROOT / 'research/work-items/RE-017-abci-compact-root-115/parent_projection.tsv'
    projection = projection_path.read_text(encoding='utf-8')
    expected_projection = (
        'stage\tinput_offset\tsource_base\tdestination_base\tcopy_size\toutput_offset\n'
        '1\t0xdd8\t0x738\t0x3210\t0x6b8\t0x38b0\n'
        '2\t0x38b0\t0x3210\t0x2740\t0x7f0\t0x2de0\n'
        '3\t0x2de0\t0x2740\t0x1f50\t0x7f0\t0x25f0\n'
        '4\t0x25f0\t0x1f50\t0x1a0\t0x6b8\t0x840\n')
    require(projection == expected_projection,
            'existing parent-owner projection changed; re-review pointer provenance')

    # The constructor copies the caller argument block into the task object.
    # The parent evidence shows RSI/RDX are the two distinct input origins;
    # these corresponding captured offsets are pinned by existing handoff bytes.
    return {
        'artifact_sha256': SHA,
        'coordinates': 'ELF link-time virtual addresses before rebasing',
        'fdes': fde_rows,
        'anchors': anchors,
        'constructor_call': {'site': hex(call.address), 'got_slot': hex(slot),
                             'relative_relocation_addend': hex(relocation)},
        'owner_origins': {
            'root_apply_owner': {
                'parent_slot': '0x840', 'constructor_argument': 'rsi',
                'origin': 'existing pointer copied from incoming +0xdd8 through the four recorded parent copies',
                'parent_site': '0x2cb8863'},
            'result_write_owner': {
                'parent_slot': '0xae8', 'constructor_argument': 'rdx',
                'origin': 'fresh 0x6f0-byte allocation copied from parent stack and saved at +0xae8',
                'allocation_request_site': '0x2cb865d',
                'copy_site': '0x2cb8687', 'save_site': '0x2cb868d'},
        },
        'allocator': {
            'call_site': hex(allocation_call.address), 'got_slot': hex(alloc_slot),
            'relative_relocation_addend': hex(alloc_target),
            'fast_path': 'size-class cursor selects a pointer and advances the cursor',
            'slow_refill_target': hex(slow_target),
        },
        'copy_helper': {'call_site': hex(copy_call.address), 'got_slot': hex(copy_slot),
                        'relocation_type': 'R_X86_64_GLOB_DAT', 'symbol': copy_symbol,
                        'dynamic_symbol_index': symbol_index},
        'conclusion': (
            'The captured owner arguments have separate origins: one is an existing '
            'pointer retained from parent +0x840, while the other is returned by the '
            'node #115 size-class allocation path and stored at parent +0xae8. The '
            'selected allocator fast path advances its per-thread size-class cursor. '
            'Pointer inequality follows under successful allocation, valid owner '
            'liveness and the allocator non-overlap contract; this packet does not '
            'prove runtime pointer values or fully analyze the slow refill path.'),
        'limitations': (
            'Static pointer provenance, not runtime observation. The selected allocator '
            'fast path is pinned, while its slow refill and copy-helper semantics remain '
            'boundaries here; no runtime identity, '
            'scheduler execution, later alias mutation, or persistence is proved. The '
            'existing owner projection is reused as context and is not re-counted as a '
            'newly mapped path.'),
        'reused_context': {
            'path': 'research/work-items/RE-017-abci-compact-root-115/parent_projection.tsv',
            'sha256': hashlib.sha256(projection.encode('utf-8')).hexdigest(),
            'role': 'existing pointer provenance; not re-counted as new work'},
    }


def generate(out):
    report = analyze(TARGET.read_bytes())
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n',
                                        encoding='utf-8')
    (out / 'anchors.tsv').write_text(
        'va\tfile_offset\tbytes\n' + ''.join(
            f"{row['va']}\t{row['file_offset']}\t{row['bytes']}\n"
            for row in report['anchors']), encoding='utf-8')
    print(f"verified {len(report['fdes'])} FDEs and {len(report['anchors'])} anchors; "
          f"constructor slot {report['constructor_call']['got_slot']} -> "
          f"{report['constructor_call']['relative_relocation_addend']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    generate(parser.parse_args().out)


if __name__ == '__main__':
    main()
