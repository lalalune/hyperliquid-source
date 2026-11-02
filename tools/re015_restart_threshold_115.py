#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Collect byte-backed restart-threshold and suspended-poll evidence for node 115.

This is a bounded static collector, not an x86 decoder. Selected instruction
windows are fixed contracts; branch displacements, relocations, FDEs and LSDA
call sites are decoded directly from the authenticated ELF bytes.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
HISTORICAL_TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/115/hl-node'
MAX_U64 = (1 << 64) - 1

# These are actual FDE start/end contracts, not claims of full function census.
FDE_SPECS = [
    ('resume_poll', 0x2aeaef0, 0x2af0654, 'd1b4e3ecb40fb4027b69240f48eacf2de2cf5f7e8c3ae5c0e6910a784fdcce29'),
    ('setting_wrapper', 0x1562300, 0x15623d5, '8de37ecaf17ca1ccbeccaa31c3686420acd478a0f1801e2ed006c309e3f8da04'),
    ('setting_reader', 0x1501b80, 0x1501f36, '6a5a13f8a678fd63761e50af230f421ed8926b24b8e5ea459f18e70136c3470b'),
    ('path_expander', 0x1500c10, 0x1500d1a, '9c3d5ea1824737db7a68eea06b71b8f4603d52ba1f42c12aebd8f2d8cce38108'),
    ('text_number', 0x1574a60, 0x1574d64, 'ba734b808bf2cf5584c1689df155e10feb4aa787759ca71b31680b4d9a065383'),
    ('digit_accumulator', 0x1575d40, 0x1575ec7, '2ebfa631e15713c4769289a3c38d8f2e1ca737ebe3e6422b105b97585e6caf1e'),
    ('number_tail', 0x15759f0, 0x1575d32, 'e205004957e648d7183453011d4bfe280985bbb7d27824148767fdb89dc31c4f'),
    ('string_adapter', 0x155c6e0, 0x155c6f4, 'bd058559f15212b031a97f7ae45d2947c67a8965c93de92d727eb98401de4427'),
    ('first_wait_poll', 0x2a91280, 0x2a915c0, '670fc5536cbea0417be82ae30b48b921c666ed77bd0e9957d6e75bb2bf2a7955'),
]

WINDOWS = [
    ("poll_dispatch", 0x2aeaf42, 0x2aeaf5e, "02d8474e754f02873410283f5026bda0bf418cc65d9fc4fdd26c607d7bd447cc"),
    ("post_completion_entry", 0x2aefb4c, 0x2aefb94, "8d757544a3b70959994f6763a2749de50e3a963f6f616191250dea563ee65ab3"),
    ("first_poll_entry", 0x2aefee7, 0x2aeff29, "92df254f9bce040a92c0b57438f5c31798a45d1ae004a60412e322a51fe24ead"),
    ("duration_comparison", 0x2aeffb8, 0x2aeffe8, "ba423662f22fc7b7131463b04bb206fa491f6289340de6ffbadbac443706aaaa"),
    ("saturating_count", 0x2aeffe8, 0x2af0004, "43bf878d542be83a9fd714a4ed04e59440ef9c7f70b72b49875725e550ddb05f"),
    ("bounded_delay_input", 0x2af0004, 0x2af002f, "d099b0c6bc0e1fbae462d993c68a4224159041fd39cda8d8cced9086a3d6ce1a"),
    ("message_and_flag", 0x2af00cf, 0x2af0113, "06c58c6c9b7aabc715358472943535e5a9de7e03ef2f99f9eab40f7d4ecd5463"),
    ("threshold_and_reset", 0x2af0113, 0x2af0157, "be64171ac31be781e37ad9d7b2048f6823dc99a44cf2137837718f10adbfe8be"),
    ("wait_poll", 0x2af0167, 0x2af018a, "3c33c59e71b9002a2fd871bf22ee3998ef23ccf5e93b25a8169b13af5822edc1"),
    ("post_wait_cleanup", 0x2af01d8, 0x2af0229, "ffa49458653aeb7f239b59ee0c89eda12f1b4abf4a4d37e48bf64f592c77a82c"),
    ("pending_states", 0x2af0229, 0x2af024f, "79ed77c2bb35f0e3ebeab017fabad714ac27ff541a497b507043aa625813278f"),
    ("setting_cell_gate", 0x1562300, 0x1562319, "ebc97e1c47feab700d88e0d1e0b519e9302251d4d873bb63fd7db90f9a4a5c2c"),
    ("setting_template", 0x1562329, 0x156233e, "69daf00f4995c77f7157c1fbb7aa36623c8c764eb333586bfa8de3050cb41a3c"),
    ("setting_reader_call", 0x1562348, 0x1562357, "a0216fb77d027c7c616eb937caef4e290355d14fb4385b8459f4c812dbd3573d"),
    ("setting_floor", 0x1562357, 0x1562382, "9de0768643e8b25c3af9fc4f4fab8fde40dc3f2efe4c4828e21f3bdc44698485"),
    ("setting_slow_cell", 0x1562382, 0x15623b5, "0dbe46bbb52bf1da13c61f4f705d0a4aaea784ad6feeff203e1e41c9018643ee"),
    ("setting_unwind", 0x15623b5, 0x15623d5, "acd5676427f2fa8ccb40c008bb5439b1975c7ce44e633919cdf4949971edd608"),
    ("path_prefix_gate", 0x1500c24, 0x1500c3f, "b3ff3be860f4630b6644041b305ec0a8086fd6cb99a251cfa098fc1cf86121a8"),
    ("path_copy_alloc", 0x1500c3f, 0x1500c7d, "f05274e0e76810dee8a95372c9180b259d0a929e8b33e894de22fff4e1efb1cd"),
    ("path_expand", 0x1500c7d, 0x1500c9e, "918c058dd1d6de8343afb1642bcb068f92ce93f22a4a47a604ea61fa3533669c"),
    ("path_format", 0x1500c9e, 0x1500cdc, "276d1d7dd42d9a820a77f4a51d0ba0dcfa2e574afc595fa9b0bcefcd68684c64"),
    ("path_slow_cell", 0x1500cdc, 0x1500d0c, "f9fc24cca64655443fa27e9ff0ab12dc67426581a9e4496347f72f8ded0a6190"),
    ("path_alloc_fail", 0x1500d0c, 0x1500d1a, "7048b495b27a21aacb729b195a5c3d5cb458e2f6079b726cbc05f0781e37c7d8"),
    ("reader_path_predicate", 0x1501b8c, 0x1501bc7, "62a9a038f7d7cdb858262b98961317d422b90e9778daa4ce7663f5f643a6d382"),
    ("reader_missing", 0x1501bc7, 0x1501c39, "63580e47eb383c0223567dd51a1829279d486a4ecd4b3d6987cdaf785a70d272"),
    ("reader_component", 0x1501c65, 0x1501cc5, "7bd5e540957d3a8b389923fa20f3ad82807fbce0c46b5a8f0298aaf59e7823a3"),
    ("reader_binary_read", 0x1501cc5, 0x1501cff, "e495407e7459f12576917e81d77f3c8dfe6644c9ff495fc9575f10359c17dc9c"),
    ("reader_text_read", 0x1501cff, 0x1501d33, "51b51904321afb8cbfec8ae0e229fb7fd58ca1fd4671d68f6f0ecc3fa8b442ef"),
    ("reader_error_return", 0x1501d33, 0x1501d64, "60a5ed416bb41450cbac7a85a964c7a7371f75b1f878465b77e97d9b4ed8663d"),
    ("reader_text_decode", 0x1501d64, 0x1501daf, "d4ca40f4528bfb8e8a929b97e9629be09b5319680900cac6c64bb9dbd03349ae"),
    ("reader_text_cleanup", 0x1501daf, 0x1501dc7, "da56b2c033b53f3b0489c998bd0367f16f5cc36dab619610f38ae577155f7df7"),
    ("reader_success", 0x1501e6e, 0x1501ead, "a19c579aafd1238dd4ac943bdc9fddb1f4b4d28cd386f13575e4a20b05cd14a0"),
    ("reader_unwind", 0x1501efa, 0x1501f36, "7cd57ca23cae00621d234fa18eed86df36e6fa2e4d00e3f05b20c21d71808acf"),
    ("text_skip_prefix", 0x1574aa8, 0x1574af1, "a82e896357a0d7ae5771487fdb9284346201d1142d973c007d66ce0fd543f93d"),
    ("text_minus_dispatch", 0x1574b3c, 0x1574b75, "3c02dd5ca781301d46414de034ac8ffcaba31c61b165ffea1e640e62d04f9c35"),
    ("text_digit_dispatch", 0x1574bbb, 0x1574be7, "3a5afb23f17eb9d66cb3bced501b3d5b22f46e983db0bb2dbd6d485853a766e3"),
    ("text_result_tags", 0x1574bf7, 0x1574c67, "2e232b3a71dc7d5c043f2081eac9537902182bad8f91dfa1186aa463e7b731c1"),
    ("text_trailing_check", 0x1574c67, 0x1574ccc, "05e91d91cb753a591a7456ae46f6e00ede362ee1b0acee2c6a0199972ce60c1b"),
    ("digit_leading_zero", 0x1575d45, 0x1575da5, "ba696538b199c16d905a21013c6af0a7d06da3a8a48a592663610e0b2f7718d7"),
    ("digit_overflow_threshold", 0x1575da5, 0x1575e21, "7d261cc08718c017cf8145ff579c7feafa4005d37b3af7ec7c34a59e811b7238"),
    ("digit_overflow_fallback", 0x1575e21, 0x1575e50, "db64e7b36def0d0990e4593162ac9bd90822ac41dd01da3d8bd3e654eacce6f9"),
    ("number_tail_and_sign", 0x15759fa, 0x1575a72, "2a4f673c86570b1875a90882db7f666248fc3c9d2ee09f26bada086b49d2d9a0"),
    ("number_result", 0x1575cb0, 0x1575cc9, "5cf139c81eda4e46c5b619205e60363f9ca9b203262708dc9cdc6ca4dafa10d0"),
    ("format_adapter", 0x155c6e0, 0x155c6f4, "bd058559f15212b031a97f7ae45d2947c67a8965c93de92d727eb98401de4427"),
    ("nested_dispatch", 0x2aeb1cd, 0x2aeb1f9, "8c2ca949e23b5140cb905753e7883fc2153888286c3b0e3ab258c3a9f042e018"),
    ("text_negative_tags", 0x1574b75, 0x1574bbb, "8206eefab1efcb357db956a83a347af57fb5ada2f290e3f17c9fe180ff1f92bd"),
    ("setting_exception", 0x2af047a, 0x2af047f, "c7638ab5c00e8f6c3a12f63fb78087502e700b4a0882db1fcdb60c23a13aafa6"),
    ("wait_exception_cleanup", 0x2af04dc, 0x2af0529, "9ab3d0985beb94f0d759ed909525784ff098f004cbb050c9238626904bae25dd"),
    ("first_poll_exception", 0x2af056a, 0x2af0577, "9bb47ac481cb09aac9c875a230c7b01a71eaf2dfd1995071f6d9ec1d4963b347"),
    ("exception_state_and_resume", 0x2af05c7, 0x2af0648, "9750bf937b71a03c00662901d5225081ae5d13bbf9a8825afad2c00304ea3fca"),
    ("unwind_second_buffer", 0x2af0529, 0x2af056a, "e4298d6ac8e9d60b2a4741af99a071b4fc8502ea432776185e3f8ef5ed3649b3"),
    ("unwind_outer_buffer", 0x2af0587, 0x2af05c7, "3ea7e2fcd0ee323c832bf1e652e0bedd385ab011dcefcba8ddd4092e9380b220"),
    ("first_wait_dispatch", 0x2a9128e, 0x2a912ab, "f1ed5bd7c314461a35361a2ff5a91f7aa07276223484525545dea584e55d5e37"),
    ("first_wait_nested_dispatch", 0x2a912d6, 0x2a912f8, "42093007e8f3283f78f52681c69f6669a41142b337e02a90c62d7d65a831c83e"),
    ("first_wait_named_constant", 0x2a91342, 0x2a9139a, "5da61431d3e354ec50e2243b332dbf2e4ee4521580e3526dc9ad23f0e56887d5"),
    ("first_wait_pending", 0x2a913b9, 0x2a913e6, "cbe0c3ab317c1b19022146ba034ccf7a2f5a08cd9953fa1758a99654d3fd688c"),
    ("first_wait_ready", 0x2a91416, 0x2a9147e, "b907d2e9f4764b11671479ad848f3fc5164c2602da902f5a679ffab4dca74513"),
    ("first_wait_unwind", 0x2a91568, 0x2a915ae, "eeb25b1d3db38e5548827e53a8fee154d57f13f5f4a70aaaebd7ffdd5105fc54"),
]

TRANSFERS = [
    ('setting_slow', 0x1562313, 0x1562382, '756d'),
    ('setting_call', 0x1562352, 0x1501b80, 'e829f8f9ff'),
    ('setting_floor_branch', 0x156235f, 0x1562372, '7411'),
    ('setting_slow_return', 0x15623b0, 0x1562315, 'e960ffffff'),
    ('path_prefix', 0x1500c3d, 0x1500c7d, '743e'),
    ('path_alloc', 0x1500c4b, 0x1500d0c, '0f84bb000000'),
    ('reader_expand', 0x1501b9a, 0x64e0948, 'ff15a8edfd04'),
    ('reader_missing', 0x1501bb8, 0x1501bc7, '740d'),
    ('reader_component', 0x1501c6a, 0x1501cff, '0f858f000000'),
    ('reader_binary', 0x1501cc3, 0x1501cff, '743a'),
    ('reader_binary_ok', 0x1501cea, 0x1501dc7, '0f81d7000000'),
    ('reader_text_ok', 0x1501d24, 0x1501d64, '713e'),
    ('reader_decode', 0x1501d8a, 0x1574a60, 'e8d12c0700'),
    ('reader_decode_ok', 0x1501d99, 0x1501e6e, '0f85cf000000'),
    ('reader_cleanup', 0x1501e8f, 0x1501d57, '0f84c2feffff'),
    ('minus_decode', 0x1574b65, 0x1575d40, 'e8d6110000'),
    ('digit_decode', 0x1574bdd, 0x1575d40, 'e85e110000'),
    ('prefix_outside', 0x1574ad8, 0x1574bbb, '0f87dd000000'),
    ('text_minus', 0x1574ae2, 0x1574b3c, '7358'),
    ('text_digit_reject', 0x1574bc8, 0x1574ce0, '0f8312010000'),
    ('text_trailing_reject', 0x1574c99, 0x1574cc3, '7728'),
    ('leading_zero', 0x1575d7e, 0x1575e5d, '0f83d9000000'),
    ('overflow_path', 0x1575e15, 0x1575de0, '76c9'),
    ('threshold_time', 0x2aeffca, 0x2aeffe1, '7715'),
    ('pending_before', 0x2aefefd, 0x2af0229, '0f8526030000'),
    ('threshold_call', 0x2af011a, 0x64e1200, 'ff15e0109f03'),
    ('threshold_cmp', 0x2af0128, 0x2af0157, '722d'),
    ('drop_empty', 0x2af013b, 0x2af014c, '740f'),
    ('pending_after', 0x2af0184, 0x2af022d, '0f85a3000000'),
    ('back_loop', 0x2af0224, 0x2aefb4c, 'e923f9ffff'),
    ('exception_flag_clear', 0x2af04f6, 0x2af051d, '7425'),
    ('exception_empty', 0x2af0507, 0x2af051d, '7414'),
    ('parent_first_wait', 0x2aefef6, 0x2a91280, 'e88513faff'),
    ('first_wait_pending_branch', 0x2a913ce, 0x2a913e6, '7416'),
]

# Exact operands on the selected path. Other calls remain opaque boundaries.
RELOCATIONS = [
    ('configuration_cell_slot', 0x64e0918, 0x64f06c0),
    ('path_expander_slot', 0x64e0948, 0x1500c10),
    ('setting_wrapper_slot', 0x64e1200, 0x1562300),
    ('context_name_pointer', 0x63f8998, 0x464716),
]
RIP_REFERENCES = [
    ('setting_template', 0x1562329, 0x4315ea),
    ('path_separator_template', 0x1500cc5, 0x43aa84),
    ('restart_message_template', 0x2af00cf, 0x445d88),
    ('outer_state_table', 0x2aeaf49, 0x6041ec),
    ('nested_state_table', 0x2aeb1e9, 0x604294),
    ('setting_cell', 0x1562307, 0x64e0918),
    ('expander_cell', 0x1500c8f, 0x64e0918),
    ('first_wait_outer_table', 0x2a9129b, 0x603388),
    ('first_wait_inner_table', 0x2a912e8, 0x603398),
    ('first_wait_label', 0x2a91356, 0x451330),
    ('elapsed_boundary', 0x2aeffc2, 0x459568),
]
TABLE_SLOTS = [
    ('outer_resume', 0x6041ec, 3, 0x2aeb1cd),
    ('nested_first_poll', 0x604294, 3, 0x2aefee7),
    ('nested_wait', 0x604294, 4, 0x2af016e),
    ('first_wait_resume', 0x603388, 3, 0x2a912d6),
    ('first_wait_inner_resume', 0x603398, 3, 0x2a9147e),
]


def require_digest(data, expected=TARGET):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('artifact SHA-256 mismatch')


def locate(secs, va, size, *, executable=False):
    """Return a unique file-backed allocated section and its file offset."""
    if type(va) is not int or type(size) is not int or va < 0 or size <= 0:
        raise ValueError('invalid VA or size')
    found = [s for s in secs if s['type'] != 8 and s['flags'] & 2
             and s['address'] <= va and va + size <= s['address'] + s['size']
             and (not executable or s['flags'] & 4)]
    if len(found) != 1:
        raise ValueError('VA is not in one file-backed allocated section')
    s = found[0]
    return s, s['offset'] + va - s['address']


def va_bytes(data, secs, va, size, *, executable=False):
    _, off = locate(secs, va, size, executable=executable)
    result = data[off:off + size]
    if len(result) != size:
        raise ValueError('mapped bytes are truncated')
    return bytes(result)


def find_fdes(data, secs, index):
    _, fdes = eh_frame_records(data, secs)
    wanted = {spec[1]: spec for spec in FDE_SPECS}
    matches = {}
    for fde in fdes:
        start = fde['start']
        if start in wanted:
            if start in matches:
                raise ValueError('duplicate selected FDE start')
            matches[start] = fde
    by_start = {row['start']: row for row in index}
    if len(matches) != len(wanted):
        raise ValueError('selected FDE absent')
    out = []
    for role, start, end, expected_hash in FDE_SPECS:
        fde = matches[start]
        row = by_start.get(start)
        if fde['end'] != end or row is None or row['fde'] != fde['fde']:
            raise ValueError('selected FDE extent or index mismatch')
        body = va_bytes(data, secs, start, end - start, executable=True)
        if hashlib.sha256(body).hexdigest() != expected_hash:
            raise ValueError('selected FDE bytes changed')
        sec, off = locate(secs, start, len(body), executable=True)
        out.append(dict(role=role, start=start, end=end, fde=fde['fde'],
                        cie=fde['cie'], lsda=fde['lsda'], index=row['index'],
                        section=sec['name'], offset=off, body=body,
                        body_sha256=expected_hash))
    return out


def find_relocations(data, secs, specs=RELOCATIONS):
    rela = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(rela) != 1 or rela[0]['size'] % 24:
        raise ValueError('unsupported RELA section')
    section = rela[0]
    requested = {slot: (role, expected) for role, slot, expected in specs}
    if len(requested) != len(specs):
        raise ValueError('duplicate requested relocation')
    found = {}
    for off in range(section['offset'], section['offset'] + section['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot not in requested:
            continue
        role, expected = requested[slot]
        if slot in found or info != 8 or addend != expected:
            raise ValueError('relative relocation mismatch')
        _, slot_off = locate(secs, slot, 8)
        found[slot] = dict(role=role, slot=slot, slot_offset=slot_off,
                           record_offset=off, info=info, addend=addend,
                           raw=bytes(data[off:off + 24]))
    if len(found) != len(specs):
        raise ValueError('selected relocation missing')
    return [found[slot] for _, slot, _ in specs]


def window_rows(data, secs, fdes):
    out = []
    for role, start, end, expected_hash in WINDOWS:
        owners = [f for f in fdes if f['start'] <= start < end <= f['end']]
        if len(owners) != 1:
            raise ValueError('window outside selected FDE')
        sec, off = locate(secs, start, end - start, executable=True)
        raw = va_bytes(data, secs, start, end - start, executable=True)
        if hashlib.sha256(raw).hexdigest() != expected_hash:
            raise ValueError('instruction window changed')
        out.append(dict(role=role, owner=owners[0]['role'], start=start, end=end,
                        offset=off, section=sec['name'], raw=raw,
                        sha256=expected_hash))
    return out


def decode_transfer(data, secs, spec):
    role, site, expected_target, expected_hex = spec
    expected = bytes.fromhex(expected_hex)
    raw = va_bytes(data, secs, site, len(expected), executable=True)
    if raw != expected:
        raise ValueError('transfer encoding changed')
    op = raw[0]
    if op in (0xe8, 0xe9) and len(raw) == 5:
        kind = 'call' if op == 0xe8 else 'jump'
        displacement = struct.unpack_from('<i', raw, 1)[0]
    elif op == 0xff and len(raw) == 6 and raw[1] == 0x15:
        kind = 'indirect_call_slot'
        displacement = struct.unpack_from('<i', raw, 2)[0]
    elif 0x70 <= op <= 0x7f and len(raw) == 2:
        kind = 'conditional_short'
        displacement = struct.unpack_from('<b', raw, 1)[0]
    elif op == 0x0f and len(raw) == 6 and 0x80 <= raw[1] <= 0x8f:
        kind = 'conditional_near'
        displacement = struct.unpack_from('<i', raw, 2)[0]
    else:
        raise ValueError('unsupported selected transfer encoding')
    target = site + len(raw) + displacement
    if target != expected_target:
        raise ValueError('transfer target changed')
    _, off = locate(secs, site, len(raw), executable=True)
    return dict(role=role, site=site, offset=off, raw=raw,
                kind=kind, target=target)


def rip_rows(data, secs):
    out = []
    for role, site, expected_target in RIP_REFERENCES:
        if role == 'elapsed_boundary':
            raw = va_bytes(data, secs, site, 8, executable=True)
            if raw[:4] != b'\x66\x0f\x2e\x0d':
                raise ValueError('unsupported selected scalar comparison')
            target = site + 8 + struct.unpack_from('<i', raw, 4)[0]
        else:
            raw = va_bytes(data, secs, site, 7, executable=True)
            if raw[:2] not in (b'\x48\x8d', b'\x48\x8b', b'\x4c\x8b') or raw[2] & 0xc7 != 5:
                raise ValueError('unsupported selected RIP instruction')
            target = site + 7 + struct.unpack_from('<i', raw, 3)[0]
        if target != expected_target:
            raise ValueError('RIP target changed')
        _, off = locate(secs, site, len(raw), executable=True)
        out.append(dict(role=role, site=site, offset=off, raw=raw, target=target))
    return out


def table_rows(data, secs):
    out = []
    for role, base, index, expected_target in TABLE_SLOTS:
        va = base + 4 * index
        raw = va_bytes(data, secs, va, 4)
        target = base + struct.unpack('<i', raw)[0]
        if target != expected_target:
            raise ValueError('selected relative table entry changed')
        _, off = locate(secs, va, len(raw))
        out.append(dict(role=role, base=base, index=index, va=va, offset=off,
                        raw=raw, target=target))
    return out


def template_row(data, secs, role, va, expected):
    raw = va_bytes(data, secs, va, len(expected))
    if raw != expected:
        raise ValueError('complete template or context bytes changed')
    _, off = locate(secs, va, len(raw))
    return dict(role=role, va=va, offset=off, raw=raw)


def data_rows(data, secs):
    suffix = b'/hyperliquid_data/n_restarts_to_page.json'
    static = b'/static_config'
    cham = b'/cham'
    message = (b'\xc0\x16 ended, restarting in \xc0\x06. See '
               b'\xc0\x0b for output\x00')
    records = [
        ('setting_full_entry', 0x4315ea, b'\xc0' + bytes([len(suffix)]) + suffix + b'\0'),
        ('path_separator_full_entry', 0x43aa84, b'\xc0\x01/\xc0\0'),
        ('restart_message_full_entry', 0x445d88, message),
        ('prior_static_config_context', 0x4401ef, b'\xc0' + bytes([len(static)]) + static + b'\0'),
        ('prior_cham_context', 0x44ab69, b'\xc0' + bytes([len(cham)]) + cham + b'\0'),
        ('prior_name_context', 0x464716, b'NvTestnet'),
        ('first_wait_name', 0x451330, b'async_wait_inner'),
    ]
    out = [template_row(data, secs, *row) for row in records]
    for role, va, length in [('ordered_elapsed_boundary_binary64', 0x459568, 8),
                              ('decimal_cutoff_immediate', 0x1575db5, 8),
                              ('text_whitespace_mask_immediate', 0x1574abe, 8),
                              ('name_descriptor_length', 0x63f89a0, 8)]:
        raw = va_bytes(data, secs, va, length)
        _, off = locate(secs, va, length)
        out.append(dict(role=role, va=va, offset=off, raw=raw))
    if struct.unpack('<d', out[-4]['raw'])[0] != 600.0:
        raise ValueError('elapsed boundary changed')
    if struct.unpack('<Q', out[-3]['raw'])[0] != MAX_U64 // 10 - 1:
        raise ValueError('decimal cutoff changed')
    if struct.unpack('<Q', out[-2]['raw'])[0] != 0x100002600:
        raise ValueError('whitespace mask changed')
    if struct.unpack('<Q', out[-1]['raw'])[0] != 9:
        raise ValueError('name descriptor length changed')
    return out


def parse_lsda(data, secs, fde):
    """Decode only the LPStart/TTYPE headers and ULEB call-site table.

    An action is retained as an offset and is not interpreted as a handler.
    """
    if fde['lsda'] is None:
        return []
    sec, off = locate(secs, fde['lsda'], 1)
    if sec['name'] != '.gcc_except_table':
        raise ValueError('LSDA outside exception section')
    limit = sec['offset'] + sec['size']
    pos = off
    if pos + 2 > limit or data[pos] != 0xff:
        raise ValueError('unsupported LSDA LPStart encoding')
    lp_encoding = data[pos]
    type_encoding = data[pos + 1]
    pos += 2
    if type_encoding != 0xff:
        if type_encoding != 0x9b:
            raise ValueError('unsupported LSDA type encoding')
        type_offset, pos = uleb(data, pos, limit)
        if pos + type_offset > limit:
            raise ValueError('LSDA type table outside section')
    if pos >= limit or data[pos] != 1:
        raise ValueError('unsupported LSDA call-site encoding')
    pos += 1
    length, pos = uleb(data, pos, limit)
    end = pos + length
    if end > limit:
        raise ValueError('LSDA call-site table outside section')
    rows = []
    while pos < end:
        start_pos = pos
        start, pos = uleb(data, pos, end)
        span, pos = uleb(data, pos, end)
        landing, pos = uleb(data, pos, end)
        action, pos = uleb(data, pos, end)
        if start + span > fde['end'] - fde['start']:
            raise ValueError('LSDA call site outside FDE')
        if landing and landing >= fde['end'] - fde['start']:
            raise ValueError('LSDA landing outside FDE')
        rows.append(dict(owner=fde['role'], lsda=fde['lsda'],
                         table_offset=start_pos, start=fde['start'] + start,
                         length=span, landing=fde['start'] + landing if landing else None,
                         action=action, raw=bytes(data[start_pos:pos]),
                         lp_encoding=lp_encoding, type_encoding=type_encoding))
    if pos != end:
        raise ValueError('LSDA call-site table mismatch')
    return rows


def decimal_integer_model(value):
    """Conditional ASCII integer-only model; other JSON forms are out of scope."""
    if not isinstance(value, bytes):
        raise TypeError('expected bytes')
    s = value.strip(b' \t\n\r')
    if not s or any(x < 0x30 or x > 0x39 for x in s):
        return None
    if len(s) > 1 and s[0] == 0x30:
        return None
    acc = 0
    for char in s:
        digit = char - 0x30
        if acc > MAX_U64 // 10 or (acc == MAX_U64 // 10 and digit > MAX_U64 % 10):
            return None
        acc = acc * 10 + digit
    return acc


def threshold_step(previous_count, reader_word):
    """Model the selected normal-return counter and flag stores, not execution."""
    if any(type(v) is not int or not 0 <= v <= MAX_U64
           for v in (previous_count, reader_word)):
        raise ValueError('expected two unsigned 64-bit words')
    threshold = max(1, reader_word)
    incremented = min(previous_count + 1, MAX_U64)
    if incremented < threshold:
        return threshold, incremented, 1
    return threshold, 0, 0


def tsv(out, name, headers, rows):
    with (out / name).open('w', encoding='utf-8', newline='') as handle:
        writer = csv.writer(handle, delimiter='\t', lineterminator='\n')
        writer.writerow(headers)
        writer.writerows(rows)


def generate(data, out):
    """Authenticate first and write only deterministic ELF-derived records."""
    require_digest(data)
    secs, index = unwind_index(data)
    fdes = find_fdes(data, secs, index)
    windows = window_rows(data, secs, fdes)
    relocations = find_relocations(data, secs)
    transfers = [decode_transfer(data, secs, row) for row in TRANSFERS]
    rips = rip_rows(data, secs)
    tables = table_rows(data, secs)
    literals = data_rows(data, secs)
    lsdas = [row for fde in fdes for row in parse_lsda(data, secs, fde)]
    out.mkdir(parents=True, exist_ok=True)
    tsv(out, 'functions.tsv',
        ['role', 'start_va', 'end_va_exclusive', 'size', 'file_offset',
         'fde_va', 'cie_va', 'lsda_va', 'unwind_index', 'sha256'],
        [(f['role'], hex(f['start']), hex(f['end']), f['end'] - f['start'],
          hex(f['offset']), hex(f['fde']), hex(f['cie']),
          '' if f['lsda'] is None else hex(f['lsda']), f['index'], f['body_sha256'])
         for f in fdes])
    tsv(out, 'bodies.tsv', ['role', 'start_va', 'file_offset', 'bytes_hex'],
        [(f['role'], hex(f['start']), hex(f['offset']), f['body'].hex()) for f in fdes])
    tsv(out, 'windows.tsv',
        ['role', 'owner', 'start_va', 'end_va_exclusive', 'file_offset', 'sha256', 'bytes_hex'],
        [(r['role'], r['owner'], hex(r['start']), hex(r['end']), hex(r['offset']),
          r['sha256'], r['raw'].hex()) for r in windows])
    tsv(out, 'transfers.tsv', ['role', 'site_va', 'file_offset', 'kind', 'target_va', 'bytes_hex'],
        [(r['role'], hex(r['site']), hex(r['offset']), r['kind'], hex(r['target']), r['raw'].hex())
         for r in transfers])
    tsv(out, 'rip-references.tsv', ['role', 'site_va', 'file_offset', 'target_va', 'bytes_hex'],
        [(r['role'], hex(r['site']), hex(r['offset']), hex(r['target']), r['raw'].hex()) for r in rips])
    tsv(out, 'relocations.tsv',
        ['role', 'slot_va', 'slot_file_offset', 'relocation_file_offset', 'type', 'addend', 'bytes_hex'],
        [(r['role'], hex(r['slot']), hex(r['slot_offset']), hex(r['record_offset']),
          r['info'], hex(r['addend']), r['raw'].hex()) for r in relocations])
    tsv(out, 'dispatch.tsv', ['role', 'base_va', 'index', 'entry_va', 'file_offset', 'bytes_hex', 'target_va'],
        [(r['role'], hex(r['base']), r['index'], hex(r['va']), hex(r['offset']), r['raw'].hex(),
          hex(r['target'])) for r in tables])
    tsv(out, 'data.tsv', ['role', 'va', 'file_offset', 'bytes_hex'],
        [(r['role'], hex(r['va']), hex(r['offset']), r['raw'].hex()) for r in literals])
    tsv(out, 'exceptions.tsv',
        ['owner', 'lsda_va', 'record_file_offset', 'start_va', 'length', 'landing_va',
         'action_offset', 'lpstart_encoding', 'type_encoding', 'bytes_hex'],
        [(r['owner'], hex(r['lsda']), hex(r['table_offset']), hex(r['start']), r['length'],
          '' if r['landing'] is None else hex(r['landing']), r['action'],
          hex(r['lp_encoding']), hex(r['type_encoding']), r['raw'].hex()) for r in lsdas])
    summary = {
        'binary_sha256': hashlib.sha256(data).hexdigest(),
        'coordinate_system': 'linked ELF virtual addresses and section-derived file offsets',
        'selected_fdes': len(fdes),
        'selected_fde_bytes': sum(f['end'] - f['start'] for f in fdes),
        'selected_windows': len(windows),
        'selected_transfers': len(transfers),
        'selected_rip_references': len(rips),
        'selected_relative_relocations': len(relocations),
        'selected_dispatch_entries': len(tables),
        'selected_data_entries': len(literals),
        'decoded_lsda_call_sites': len(lsdas),
        'limitations': ('Selected byte contracts and FDE/LSDA ranges do not prove all '
                        'instructions, functions, action semantics, runtime reachability, '
                        'helper closure or equivalent behavior.'),
    }
    (out / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return summary


def compare_historical(old_data, new_data):
    """Optional comparison. Neither retired nor current executable is run."""
    require_digest(old_data, HISTORICAL_TARGET)
    require_digest(new_data)
    old_secs = sections(old_data)
    new_secs = sections(new_data)
    suffix = b'\xc0\x29/hyperliquid_data/n_restarts_to_page.json\x00'
    old_suffix = va_bytes(old_data, old_secs, 0x1de68f, len(suffix))
    new_suffix = va_bytes(new_data, new_secs, 0x4315ea, len(suffix))
    if old_suffix != suffix or new_suffix != suffix:
        raise ValueError('historical/current setting entry mismatch')
    old_floor = va_bytes(old_data, old_secs, 0x13ca072, 8, executable=True)
    new_floor = va_bytes(new_data, new_secs, 0x1562372, 8, executable=True)
    if old_floor != bytes.fromhex('4883f8014883d000') or old_floor != new_floor:
        raise ValueError('historical/current floor instruction mismatch')
    old_context = [
        ('historical_static', 0x1ef5f5, b'\xc0\x0e/static_config\0'),
        ('historical_cham', 0x1fc0ec, b'\xc0\x05/cham\0'),
        ('historical_name', 0x2180ff, b'NvTestnet'),
    ]
    for role, va, expected in old_context:
        template_row(old_data, old_secs, role, va, expected)
    for role, va, expected in [
        ('current_static', 0x4401ef, b'\xc0\x0e/static_config\0'),
        ('current_cham', 0x44ab69, b'\xc0\x05/cham\0'),
        ('current_name', 0x464716, b'NvTestnet'),
    ]:
        template_row(new_data, new_secs, role, va, expected)
    for raw_data, sec_rows, site, target in [
        (old_data, old_secs, 0x164fbae, 0x1ef5f5),
        (old_data, old_secs, 0x164f840, 0x1fc0ec),
        (old_data, old_secs, 0x13ca029, 0x1de68f),
        (new_data, new_secs, 0x177840e, 0x4401ef),
        (new_data, new_secs, 0x17780f3, 0x44ab69),
        (new_data, new_secs, 0x1562329, 0x4315ea),
    ]:
        instruction = va_bytes(raw_data, sec_rows, site, 7, executable=True)
        if instruction[:3] != b'\x48\x8d\x35' or site + 7 + struct.unpack_from('<i', instruction, 3)[0] != target:
            raise ValueError('historical/current full-entry reference mismatch')
    old_rela = find_relocations(old_data, old_secs,
                                [('historical_name_pointer', 0x5668488, 0x2180ff)])
    new_rela = find_relocations(new_data, new_secs,
                                [('current_name_pointer', 0x63f8998, 0x464716)])
    old_length = struct.unpack('<Q', va_bytes(old_data, old_secs, 0x5668490, 8))[0]
    new_length = struct.unpack('<Q', va_bytes(new_data, new_secs, 0x63f89a0, 8))[0]
    if old_length != 9 or new_length != 9:
        raise ValueError('historical/current descriptor length mismatch')
    return {
        'historical_sha256': hashlib.sha256(old_data).hexdigest(),
        'current_sha256': hashlib.sha256(new_data).hexdigest(),
        'historical_setting_template_va': hex(0x1de68f),
        'current_setting_template_va': hex(0x4315ea),
        'setting_template_bytes_hex': old_suffix.hex(),
        'historical_floor_va': hex(0x13ca072),
        'current_floor_va': hex(0x1562372),
        'floor_bytes_hex': old_floor.hex(),
        'historical_name_descriptor_va': hex(old_rela[0]['slot']),
        'current_name_descriptor_va': hex(new_rela[0]['slot']),
        'historical_name_index_in_prior_table': (old_rela[0]['slot'] - 0x5668288) // 16,
        'current_name_index_in_prior_table': (new_rela[0]['slot'] - 0x63f8788) // 16,
        'name_bytes_hex': va_bytes(old_data, old_secs, 0x2180ff, 9).hex(),
        'historical_static_template_va': hex(0x1ef5f5),
        'historical_cham_template_va': hex(0x1fc0ec),
        'current_static_template_va': hex(0x4401ef),
        'current_cham_template_va': hex(0x44ab69),
        'historical_static_reference_va': hex(0x164fbae),
        'historical_cham_reference_va': hex(0x164f840),
        'historical_setting_reference_va': hex(0x13ca029),
        'current_static_reference_va': hex(0x177840e),
        'current_cham_reference_va': hex(0x17780f3),
        'current_setting_reference_va': hex(0x1562329),
        'scope': 'Descriptor positions are not independent proof of name classifier behavior.',
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--compare-94', type=Path)
    args = parser.parse_args(argv)
    data = BINARY.read_bytes()
    # Check the primary identity before reading any optional historical input.
    require_digest(data)
    if args.compare_94:
        comparison = compare_historical(args.compare_94.read_bytes(), data)
    else:
        comparison = None
    summary = generate(data, args.out)
    print(json.dumps(summary if comparison is None else comparison, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, struct.error) as exc:
        print('collector:', str(exc), file=sys.stderr)
        raise SystemExit(1)
