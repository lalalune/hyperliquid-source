#!/usr/bin/env python3
"""Extract the selected node 94 Vault root-field writer and map-reader decisions."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Individually reviewed FDE-described bodies, not a whole-program census.
FUNCTIONS = (
 ('writer_buffered',0x2340f40,0x2341271,'97d1a7f228cb5eec7a1b54aa256059955aff81e9e67acdba2de7f2e5660f09df'),
 ('writer_direct',0x23406d0,0x2340b6a,'682e6f6dc515ce5646e03d68be94da8029e772ecbce11bd64807961febcdeca3'),
 ('writer_buffered_copy',0x3953130,0x3953461,'35d69392bf5168ba3f99aa8aeda7c790621783bc75d49d0d8d29fb1af0ba2a07'),
 ('writer_direct_copy',0x3953470,0x395390a,'695735b2a5d9eaaa5e989ad51599f34edd2305bceab42ca83da35a301d8580bb'),
 ('user_states_field',0x23d55e0,0x23d563c,'e98b64412565a3553ab226c4e902bbb812b5a8330d28d649d5bd185e08b55aee'),
 ('float_field',0x23d9250,0x23d92c8,'b8e5cdf6874f53785a37d3898f107684a3ccd11a0726fea53f34f6c195c8bc49'),
 ('bool_field',0x23d49a0,0x23d4abd,'85652d2e8d36204df40e5893c419cb918292d3c0627be2c699addf00654dba1b'),
 ('duration_field',0x23d91d0,0x23d924e,'861ea0dcdcf722d3a14aa4e7d4c95cc28461521d17468fa228ef636e648ffc65'),
 ('relationship_field',0x23d3130,0x23d344e,'11a77aa7c6b3b93d65b77df9052bf6784d4f03d567ca256096ff152511ebe54c'),
 ('s_field',0x23d6da0,0x23d6e2b,'1b17e64be369763244e075558ba9ae00d00ed90700acc1022a9cde55b97aa63b'),
 ('map_reader',0x19f9a50,0x19fe747,'180f8c2e075ce5ddecd4830eb2f9f25501d49a5c6ceaf1bfdadd38c697fdb222'),
 ('pair_collector',0x257b7e0,0x257bae0,'feb5649605b17f058ea379f43a0508ed0b1dec8969e66c12bf53237266533603'),
 ('key_writer_buffered',0x1e11630,0x1e11795,'e6099f95cb6e449038a7b044c51d6e22da814137e0ef035d993b627effbd51d6'),
 ('key_writer_direct',0x1e10fb0,0x1e11115,'deb1d02068f0455aff820353498b15375b21c1cd1176fcd441cf1b11e1146dec'),
 ('root_serializer_bridge',0x25dbd30,0x25dbdf9,'52e4024eee23ffae72a6451ceab5b03afd9139ebf33920dd3b6996ff77d695be'),
 ('sequence_writer',0x1e45bc0,0x1e45e4b,'85895bdc9e5a89b92dbb38afe594ccded4dea3d603114aa9c011e8770cd44517'),
 ('pair_writer',0x1de2ea0,0x1de33f5,'ce6f323e4fe2f9fd8d136f556dfdfa0819999bca34d0e01628680a019faa6da4'),
 ('outer_map_reader',0x1900950,0x19010e9,'3a8c169b1a184b62aefa227328175468e50de603aafe7ecaacf0b948a6050290'),
 ('address_key_reader',0x16a54a0,0x16a57f0,'7705191e8e7892c65f957860c9cdee01bed6ac95a2401eea52ca4789bdb1747e'),
 ('map_value_reader',0x2641c60,0x2642260,'25195c353ab39da3952f25c8354c886cc7f7979946bf0b32d70e5ec7a40c1eec'),
)
# field, label LEA, input-load site, input opcode and displacement shape, value call.
FIELDS = (
 ('name',0x2340fc3,0x2340fb4,'4d8b67',1,0x2340fea,0x25aa7f0),
 ('description',0x2341008,0x2340ff9,'4d8b67',1,0x234102f,0x25aa7f0),
 ('create_time',0x2341045,0x2341063,'4d8d47',1,0x2341079,0x1e4fc10),
 ('vault_user',0x234108f,0x23410ad,'498db7',4,0x23410ba,0x1e7f7e0),
 ('leader',0x23410d0,0x23410ee,'498db7',4,0x23410fb,0x1e7f7e0),
 ('user_states',0x23d55f1,0x234110a,'498d57',1,0x2341114,0x23d55e0),
 ('leader_commission',0x2341129,0x2341123,'f2410f1047',1,0x234113b,0x23d9250),
 ('is_closed',0x2341151,0x234114a,'458b87',4,0x2341163,0x23d49a0),
 ('lockup_duration',0x23d91ef,0x2341172,'f2410f1047',1,0x234117e,0x23d91d0),
 ('allow_deposits',0x2341195,0x234118d,'450fb687',4,0x23411a7,0x23d49a0),
 ('relationship',0x23d314a,0x23411bc,'4c89fa',0,0x23411bf,0x23d3130),
 ('always_close_on_withdraw',0x23411d6,0x23411ce,'450fb687',4,0x23411e8,0x23d49a0),
 ('s',0x23d6dbf,0x23411f3,'410fb697',4,0x2341201,0x23d6da0),
)
# Direct writer: input site, operand prefix/width, value call, and failure branch.
DIRECT_FIELDS = (
 (0x2340713,'4d8b67',1,0x2340769,0x25aacb0,0x2340772,'0f85',0x23409d8),
 (0x2340778,'498b77',1,0x23407d4,0x25aacb0,0x23407dd,'0f85',0x23409d8),
 (0x23407e3,'4d8d47',1,0x234084a,0x1e4fd80,0x2340853,'0f85',0x23409f9),
 (0x234087e,'498db7',4,0x234088b,0x1e7f760,0x2340894,'0f85',0x2340a1d),
 (0x23408bf,'498db7',4,0x23408cc,0x1e7f760,0x23408d5,'0f85',0x2340a1d),
 (0x23408db,'498d57',1,0x23408e5,0x23d8c50,0x23408ee,'0f85',0x23409f9),
 (0x23408f4,'f2410f1047',1,0x234090c,0x23d4610,0x2340915,'0f85',0x23409f9),
 (0x234091b,'458b87',4,0x2340934,0x23d8810,0x234093d,'0f85',0x23409f9),
 (0x2340943,'498b57',1,0x234094d,0x23d76c0,0x2340956,'0f85',0x23409f9),
 (0x234095c,'450fb687',4,0x2340976,0x23d8810,0x234097f,'75',0x23409f9),
 (0x2340987,'4c89fa',0,0x234098a,0x23d64a0,0x2340993,'75',0x23409f9),
 (0x2340995,'450fb687',4,0x23409af,0x23d8810,0x23409b8,'75',0x23409f9),
 (0x23409ba,'410fb697',4,0x23409c8,0x23d3b60,0x23409d1,'75',0x23409f9))
# Post-value failure branches, in the same order as FIELDS.
FIELD_FAILURES = ((0x2340ff3,'0f85',0x2341211),(0x2341038,'0f85',0x2341211),
 (0x2341082,'0f85',0x2341244),(0x23410c3,'0f85',0x2341244),
 (0x2341104,'0f85',0x2341244),(0x234111d,'0f85',0x234125f),
 (0x2341144,'0f85',0x234125f),(0x234116c,'0f85',0x234125f),
 (0x2341187,'0f85',0x234125f),(0x23411b0,'0f85',0x234125f),
 (0x23411c8,'0f85',0x234125f),(0x23411f1,'75',0x234125f),
 (0x234120a,'75',0x234125f))
# Diagnostic-site LEAs and duplicate-guard branches, inspected on instruction boundaries.
MISSING = (
 (0x19f9f81,0x19fcd53,'75',0x19fcd68,'present skips diagnostic'),
 (0x19fa03b,0x19fa035,'0f85',0x19fa16f,'present skips diagnostic'),
 (0x19fa19b,0x19fa195,'0f85',0x19fa21e,'present skips diagnostic'),
 (0x19fa22f,0x19fa226,'0f85',0x19fa2f1,'present skips diagnostic'),
 (0x19fa302,0x19fa2f9,'0f85',0x19fa3c7,'present skips diagnostic'),
 (0x19fab28,0x19fa3d4,'0f84',0x19fab28,'absent enters diagnostic'),
 (0x19fabcd,0x19fabc7,'0f85',0x19fac54,'present skips diagnostic'),
 (0x19fac5f,0x19fac59,'0f85',0x19face0,'present skips diagnostic'),
 (0x19facf3,0x19facf1,'75',0x19fad71,'present skips diagnostic'),
 (0x19fad8b,0x19fad7d,'0f85',0x19fb6eb,'present skips diagnostic'))

DUPLICATES = (
 (0x19fe244,0x19fdd05),(0x19fe29b,0x19fdc5d),(0x19fe2f2,0x19fdb59),
 (0x19fe349,0x19fd9a3),(0x19fe3a0,0x19fd962),(0x19fe3f7,0x19fda85),
 (0x19fe44e,0x19fd790),(0x19fe4a0,0x19fd881),(0x19fe4f7,0x19fdae5),
 (0x19fe54e,0x19fd835),(0x19fe5a5,0x19fd915),(0x19fe5fc,0x19fd9f4),
 (0x19fe650,0x19fdc08),
)
# Fixed, bounded windows are byte evidence, not disassembler output.
WINDOWS = (
 ('collector_allocation_guard',0x257b7e8,0x257b81c),
 ('collector_empty',0x257b845,0x257b860),
 ('sequence_empty',0x1e45d70,0x1e45d89),
 ('collector_pair_layout',0x257b880,0x257b8b6),
 ('collector_bad_iterator',0x257ba95,0x257bab3),
 ('buffered_key_conversion',0x1e11704,0x1e11739),
 ('direct_key_conversion',0x1e11084,0x1e110b9),
 ('root_closure_call_context',0x2818821,0x2818845),
 ('bridge_argument_transfer',0x25dbd9f,0x25dbdad),
 ('sequence_first_pair',0x1e45c3b,0x1e45c84),
 ('sequence_buffer_config',0x1e45d26,0x1e45d70),
 ('sequence_loop_pair',0x1e45da0,0x1e45db3),
 ('writer_mode',0x2340f4e,0x2340fb4),
 ('writer_all_fields',0x2340fb4,0x2341211),
 ('direct_mode_and_header',0x23406de,0x2340713),
 ('writer_failure_join',0x2341211,0x2341271),
 ('pair_header_setup',0x1de2ec4,0x1de2f0f),
 ('pair_parent_reload',0x1de2f7a,0x1de2f90),
 ('pair_buffered_key_call',0x1de2f5c,0x1de2f7a),
 ('pair_direct_header',0x1de3057,0x1de3079),
 ('pair_direct_key_call',0x1de309d,0x1de30bb),
 ('pair_writer_calls',0x1de3028,0x1de3045),
 ('pair_direct_call',0x1de317b,0x1de3194),
 ('outer_reader_marker',0x1900b17,0x1900b49),
 ('outer_reader_fixmap',0x1900cd8,0x1900d38),
 ('reader_duplicate_key_guard',0x2641d46,0x2641d69),
 ('reader_duplicate_key_diagnostic',0x2642185,0x26421e6),
 ('reader_entry_key_and_value',0x2641d69,0x2641e1f),
 ('address_key_reader_normal',0x16a54a8,0x16a551f),
 ('reader_entry_call',0x2641dcc,0x2641dd8),
 ('reader_map_init',0x19f9e12,0x19f9eb0),
 ('reader_map_end',0x19fcd2f,0x19fcd7b),
 ('reader_allow_default',0x19fb6eb,0x19fb702),
 ('reader_default_stores',0x19fb895,0x19fb8c0),
 ('reader_allow_duplicate',0x19fd95d,0x19fd993),
 ('reader_always_duplicate',0x19fd830,0x19fd867),
 ('reader_s_duplicate',0x19fd910,0x19fd946),
 ('duration_named_mode',0x23d91e9,0x23d924e),
 ('relationship_mode',0x23d3144,0x23d3179),
 ('s_named_and_value',0x23d6db9,0x23d6e2b),
)
CALLS = (
 ('existing_root_closure_context',0x2818840,0x25dbd30),
 ('bridge_to_collector',0x25dbd9a,0x257b7e0),
 ('pair_buffered_key',0x1de2f66,0x1e11630),
 ('pair_direct_key',0x1de30a7,0x1e10fb0),
 ('bridge_to_sequence',0x25dbda8,0x1e45bc0),
 ('sequence_to_first_pair',0x1e45c7f,0x1de2ea0),
 ('sequence_to_loop_pair',0x1e45dae,0x1de2ea0),
 ('pair_buffered_header',0x1de2f0a,0x25a9bd0),
 ('pair_buffered',0x1de3035,0x2340f40),('pair_direct',0x1de3186,0x23406d0),
 ('outer_reader_entries',0x1900d26,0x2641c60),
 ('reader_key',0x2641d97,0x16a54a0),
 ('address_reader_child',0x16a550d,0x190f5b0),
 ('reader_bridge',0x2641dd3,0x19f9a50),
 ('buffered_map_header',0x2340f72,0x25a8f80),('buffered_array_header',0x2340fa5,0x25a9bd0),
)
BRANCHES = (
 ('collector_allocation_valid',0x257b80f,'74',0x257b81c),
 ('collector_empty_allocation',0x257b81f,'74',0x257b84f),
 ('collector_empty_count',0x257b85a,'0f84',0x257ba7b),
 ('sequence_empty',0x1e45d7d,'74',0x1e45dca),
 ('collector_null_allocation',0x257b83f,'0f84',0x257bab3),
 ('collector_bad_state',0x257b8cf,'0f84',0x257baa4),
 ('collector_missing_parent',0x257b9ba,'0f84',0x257ba95),
 ('sequence_unbuffered_adapter',0x1e45c5f,'0f84',0x1e45d73),
 ('pair_direct_adapter',0x1de2ecd,'71',0x1de2ee4),
 ('sequence_header_failure',0x1e45c35,'0f85',0x1e45cee),
 ('sequence_first_pair_success',0x1e45c9a,'0f84',0x1e45d73),
 ('sequence_loop_pair_failure',0x1e45dbb,'0f85',0x1e45ca0),
 ('pair_buffered_header_needed',0x1de2ed9,'75',0x1de2ef7),
 ('pair_direct_header_needed',0x1de2eea,'0f85',0x1de3057),
 ('pair_buffered_field_failure',0x1de303f,'0f85',0x1de3302),
 ('pair_direct_field_failure',0x1de3190,'0f85',0x1de3284),
 ('writer_array_mode',0x2340f65,'74',0x2340f9a),
 ('writer_map_header_success',0x2340f7f,'74',0x2340fb4),
 ('writer_array_failure',0x2340fb2,'75',0x2340f81),
 ('name_label_failure',0x2340fdb,'0f85',0x2341211),
 ('description_name_failure',0x2341020,'0f85',0x2341211),
 ('create_time_name_failure',0x234105d,'0f85',0x2341232),
 ('vault_user_name_failure',0x23410a7,'0f85',0x2341232),
 ('leader_name_failure',0x23410e8,'0f85',0x2341232),
 ('description_value_failure',0x2341038,'0f85',0x2341211),
 ('create_time_failure',0x2341082,'0f85',0x2341244),
 ('user_states_failure',0x234111d,'0f85',0x234125f),
 ('relationship_failure',0x23411c8,'0f85',0x234125f),
 ('s_failure',0x234120a,'75',0x234125f),
 ('outer_negative_marker',0x1900b3b,'0f88',0x1900cd8),
 ('outer_negative_integer',0x1900cde,'0f87',0x190097e),
 ('outer_other_marker',0x1900ce7,'0f83',0x1900e28),
 ('reader_empty_sequence',0x2641d6b,'0f84',0x2641e60),
 ('reader_duplicate_key',0x2641d5b,'0f85',0x2642185),
 ('reader_key_failure',0x2641da7,'0f85',0x26420ed),
 ('address_key_child_failure',0x16a5519,'0f85',0x16a5771),
 ('reader_value_failure',0x2641e19,'0f84',0x2642136),
 ('empty_map',0x19f9e2c,'0f84',0x19f9f18),
 ('allow_duplicate',0x19fd962,'0f85',0x19fe3a0),
 ('always_duplicate',0x19fd835,'0f85',0x19fe54e),
 ('s_duplicate',0x19fd915,'0f85',0x19fe5a5),
 ('description_present_skips_missing',0x19fa035,'0f85',0x19fa16f),
 ('create_time_present_skips_missing',0x19fa195,'0f85',0x19fa21e),
 ('commission_present_skips_missing',0x19fabc7,'0f85',0x19fac54),
 ('closed_present_skips_missing',0x19fac59,'0f85',0x19face0),
 ('lockup_present_skips_missing',0x19facf1,'75',0x19fad71),
 ('relationship_present_skips_missing',0x19fad7d,'0f85',0x19fb6eb),
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check_digest(data, expected=DIGEST):
    if sha(data) != expected:
        raise ValueError('node 94 digest mismatch')


def va_bytes(data, secs, va, size):
    if va < 0 or size <= 0:
        raise ValueError('invalid virtual range')
    found = [s for s in secs if s['type'] != 8 and s['size'] and
             s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('unmapped, non-file-backed or ambiguous range')
    sec = found[0]
    off = sec['offset'] + va - sec['address']
    if off < 0 or off + size > len(data):
        raise ValueError('file-backed range extends beyond input')
    return bytes(data[off:off+size])


def location(secs, va, size):
    found = [s for s in secs if s['type'] != 8 and s['size'] and
             s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(found) != 1 or size <= 0:
        raise ValueError('invalid location')
    return found[0]['name'], found[0]['offset'] + va - found[0]['address']


def rip_target(data,secs,va, prefixes):
    raw = va_bytes(data,secs,va,7)
    if raw[:3] not in prefixes:
        raise ValueError('unexpected RIP-relative instruction')
    return va + 7 + struct.unpack_from('<i',raw,3)[0]


def call_target(data,secs,va):
    raw = va_bytes(data,secs,va,5)
    if raw[0] != 0xe8:
        raise ValueError('expected rel32 call')
    return va + 5 + struct.unpack_from('<i',raw,1)[0]


def branch_target(data,secs,va,opcode):
    op = bytes.fromhex(opcode)
    n = len(op) + (1 if len(op) == 1 else 4)
    raw = va_bytes(data,secs,va,n)
    if raw[:len(op)] != op or not (len(op)==1 and 0x70<=op[0]<=0x7f or
                                   len(op)==2 and op[0]==0x0f and 0x80<=op[1]<=0x8f):
        raise ValueError('conditional branch opcode changed')
    return va + n + struct.unpack('<b' if len(op)==1 else '<i',raw[len(op):])[0]


def field_label(data,secs,site):
    target = rip_target(data,secs,site,(b'\x48\x8d\x35',b'\x48\x8d\x15'))
    tail = va_bytes(data,secs,site+7,18)
    # The reviewed sites use a direct mov edx/ ecx with the literal byte count.
    if tail[0] == 0xba:
        n = struct.unpack_from('<I',tail,1)[0]
        length_site = site + 7
    elif tail[:4] == b'\x48\x89\xe7\xb9':
        n = struct.unpack_from('<I',tail,4)[0]
        length_site = site + 10
    else:
        raise ValueError('unrecognized field length setup')
    if not 1 <= n <= 24:
        raise ValueError('field length out of bounds')
    try:
        label = va_bytes(data,secs,target,n).decode('ascii')
    except UnicodeDecodeError as exc:
        raise ValueError('non-ASCII field name') from exc
    return label, target, n, length_site


def input_offset(data,secs,site,prefix_hex,disp_size):
    prefix = bytes.fromhex(prefix_hex)
    raw = va_bytes(data,secs,site,len(prefix)+disp_size)
    if raw[:len(prefix)] != prefix or disp_size not in (0,1,4):
        raise ValueError('unexpected field input instruction')
    offset = 0 if not disp_size else int.from_bytes(raw[len(prefix):], 'little', signed=False)
    return offset,raw.hex()


def diagnostic(data,secs,site,template):
    target = rip_target(data,secs,site,(b'\x48\x8d\x05',))
    data_window = va_bytes(data,secs,site+7,100)
    # lea name; save pointer; mov qword [rsp+slot],imm32 length.
    if data_window[:3] != b'\x48\x89\x84' or data_window[8:12] != b'\x48\xc7\x84\x24':
        raise ValueError('diagnostic pointer/length setup changed')
    length = struct.unpack_from('<I',data_window,16)[0]
    if not 1 <= length <= 24:
        raise ValueError('diagnostic length out of bounds')
    template_sites = []
    for p in range(20,80):
        if data_window[p:p+3] == b'\x48\x8d\x35':
            va = site+7+p
            if rip_target(data,secs,va,(b'\x48\x8d\x35',)) == template:
                template_sites.append(va)
    if len(template_sites) != 1:
        raise ValueError('missing or ambiguous diagnostic template')
    return {'site_va':hex(site),'name_va':hex(target),'length':length,
            'name':va_bytes(data,secs,target,length).decode('ascii'),
            'template_site_va':hex(template_sites[0])}


def allow_default(slot):
    """Restricted model of the selected 0/1/2 map slot join."""
    if slot not in (0,1,2):
        raise ValueError('slot outside modeled domain')
    return 1 if slot == 2 else slot & 1


def fixmap_count(marker):
    """Model only the byte-marker path observed at the outer reader."""
    if not 0 <= marker <= 255:
        raise ValueError('marker outside u8')
    return marker & 15 if 0x80 <= marker < 0x90 else None


def allocation_precheck(count, limit=0x7ffffffffffffff8):
    """Model the reviewed unsigned shift/overflow/capacity comparisons."""
    if not 0 <= count < (1 << 64):
        raise ValueError('count outside u64')
    size = (count << 4) & ((1 << 64) - 1)
    return {'count':count,'wrapped_bytes':size,'high_bits_nonzero':bool(count >> 60),
            'above_limit':size > limit,'passes':not (count >> 60 or size > limit)}


def bit_default(slot):
    if slot not in (0,1,2):
        raise ValueError('slot outside modeled domain')
    return slot & 1


def relative_relocation(data, secs, target):
    """Find one ELF64 RELA entry for an exact slot; do not interpret SHT_NOBITS."""
    matches=[]
    for sec in secs:
        if sec['type'] != 4:
            continue
        if sec['size'] % 24 or sec['offset'] + sec['size'] > len(data):
            raise ValueError('invalid RELA section bounds')
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot,info,addend=struct.unpack_from('<QQq',data,off)
            if slot == target:
                matches.append((sec['name'],off,info & 0xffffffff,info >> 32,addend))
    if len(matches)!=1:
        raise ValueError('missing or ambiguous relocation')
    sec,off,kind,symbol,addend=matches[0]
    return {'section':sec,'file_offset':hex(off),'slot_va':hex(target),
            'type':kind,'symbol_index':symbol,'addend_va':hex(addend)}


def analyze(data,expected_digest=DIGEST):
    check_digest(data,expected_digest)
    secs,index = unwind_index(data)
    _,fdes = eh_frame_records(data,secs)
    indexed = {(x['start'],x['fde']) for x in index}
    functions=[]
    for name,start,end,expected in FUNCTIONS:
        rows=[x for x in fdes if x['start']==start]
        if len(rows)!=1 or rows[0]['end']!=end or (start,rows[0]['fde']) not in indexed:
            raise ValueError('FDE/index mismatch')
        raw=va_bytes(data,secs,start,end-start)
        if sha(raw)!=expected:
            raise ValueError('selected body differs')
        section,off=location(secs,start,end-start)
        functions.append({'name':name,'start_va':hex(start),'end_va_exclusive':hex(end),
                          'fde_va':hex(rows[0]['fde']),'section':section,'file_offset':hex(off),
                          'size':len(raw),'body_sha256':sha(raw)})
    fields=[]
    for ordinal,(expected,label_site,input_site,prefix,disp,call_site,call_expected) in enumerate(FIELDS):
        label,target,length,length_site=field_label(data,secs,label_site)
        if label!=expected:
            raise ValueError('field label changed')
        offset,input_raw=input_offset(data,secs,input_site,prefix,disp)
        child=call_target(data,secs,call_site)
        if child!=call_expected:
            raise ValueError('field call target changed')
        failure_va,failure_op,failure_expected=FIELD_FAILURES[ordinal]
        failure_target=branch_target(data,secs,failure_va,failure_op)
        if failure_target!=failure_expected:
            raise ValueError('field failure branch changed')
        failure_n=2 if len(failure_op)==2 else 6
        copy_site=input_site+(0x3953130-0x2340f40)
        if va_bytes(data,secs,copy_site,len(bytes.fromhex(input_raw))).hex()!=input_raw:
            raise ValueError('parallel writer field input changed')
        direct_site,direct_prefix,direct_disp,direct_call,direct_callee,direct_fail,direct_op,direct_end=DIRECT_FIELDS[ordinal]
        direct_offset,direct_raw=input_offset(data,secs,direct_site,direct_prefix,direct_disp)
        if direct_offset!=offset or call_target(data,secs,direct_call)!=direct_callee:
            raise ValueError('direct field input or call changed')
        if branch_target(data,secs,direct_fail,direct_op)!=direct_end:
            raise ValueError('direct field failure branch changed')
        direct_copy=direct_site+(0x3953470-0x23406d0)
        if va_bytes(data,secs,direct_copy,len(bytes.fromhex(direct_raw))).hex()!=direct_raw:
            raise ValueError('parallel direct field input changed')
        direct_n=2 if len(direct_op)==2 else 6
        fields.append({'ordinal':ordinal,'name':label,'name_va':hex(target),'name_length':length,
                       'name_site_va':hex(label_site),'length_site_va':hex(length_site),
                       'input_site_va':hex(input_site),'input_instruction_hex':input_raw,
                       'input_offset':offset,'copy_input_site_va':hex(copy_site),
                       'call_site_va':hex(call_site),'callee_va':hex(child),
                       'failure_branch_va':hex(failure_va),'failure_branch_hex':va_bytes(data,secs,failure_va,failure_n).hex(),
                       'failure_target_va':hex(failure_target),
                       'direct_input_site_va':hex(direct_site),'direct_input_instruction_hex':direct_raw,
                       'direct_copy_input_site_va':hex(direct_copy),'direct_call_site_va':hex(direct_call),
                       'direct_callee_va':hex(direct_callee),'direct_failure_va':hex(direct_fail),
                       'direct_failure_bytes':va_bytes(data,secs,direct_fail,direct_n).hex(),
                       'direct_failure_target_va':hex(direct_end)})
    missing=[]
    for site,guard,opcode,expected,meaning in MISSING:
        d=diagnostic(data,secs,site,0x1df8f3)
        if branch_target(data,secs,guard,opcode)!=expected:
            raise ValueError('missing field guard changed')
        n=2 if len(opcode)==2 else 6
        d.update({'guard_va':hex(guard),'guard_bytes':va_bytes(data,secs,guard,n).hex(),
                  'guard_target_va':hex(expected),'guard_meaning':meaning})
        missing.append(d)
    duplicates=[]
    for site,guard in DUPLICATES:
        d=diagnostic(data,secs,site,0x1e0fd5)
        op = '0f84' if guard in (0x19fdd05,0x19fdc08) else '0f85'
        target=branch_target(data,secs,guard,op)
        if target!=site:
            raise ValueError('duplicate guard target changed')
        d.update({'guard_va':hex(guard),'guard_bytes':va_bytes(data,secs,guard,6).hex()})
        duplicates.append(d)
    names={x['name'] for x in fields}
    if len(names)!=len(fields) or {x['name'] for x in duplicates}!=names:
        raise ValueError('writer and duplicate names disagree')
    if {x['name'] for x in missing} != names-{'allow_deposits','always_close_on_withdraw','s'}:
        raise ValueError('missing field diagnostics changed')
    templates={}
    for name,va,expected in [('missing',0x1df8f3,b'\x0fmissing field `'),
                             ('duplicate',0x1e0fd5,b'\x11duplicate field `')]:
        raw=va_bytes(data,secs,va,len(expected))
        if raw!=expected:
            raise ValueError('diagnostic template changed')
        templates[name]={'va':hex(va),'bytes_hex':raw.hex()}
    calls=[]
    for name,va,expected in CALLS:
        target=call_target(data,secs,va)
        if target!=expected:raise ValueError('call target changed')
        calls.append({'name':name,'site_va':hex(va),'bytes_hex':va_bytes(data,secs,va,5).hex(),'target_va':hex(target)})
    branches=[]
    for name,va,op,expected in BRANCHES:
        target=branch_target(data,secs,va,op)
        if target!=expected:raise ValueError('branch destination changed')
        n=2 if len(op)==2 else 6
        branches.append({'name':name,'site_va':hex(va),'bytes_hex':va_bytes(data,secs,va,n).hex(),'target_va':hex(target)})
    windows=[]
    for name,start,end in WINDOWS:
        sec,off=location(secs,start,end-start)
        raw=va_bytes(data,secs,start,end-start)
        windows.append({'name':name,'start_va':hex(start),'end_va_exclusive':hex(end),
                        'section':sec,'file_offset':hex(off),'bytes_hex':raw.hex()})
    alloc_code=va_bytes(data,secs,0x257b7e8,39)
    if alloc_code[:6]!=bytes.fromhex('4c8b66404d89') or alloc_code[7:11]!=bytes.fromhex('49c1e704') or alloc_code[11:18]!=bytes.fromhex('4c89e048c1e83c') or alloc_code[21:23]!=bytes.fromhex('48b9'):
        raise ValueError('allocation guard instructions changed')
    allocation_limit=struct.unpack_from('<Q',alloc_code,23)[0]
    if allocation_limit!=0x7ffffffffffffff8:
        raise ValueError('allocation guard limit changed')
    count_max=allocation_limit // 16
    allocation_cases=[allocation_precheck(n,allocation_limit) for n in (0,1,count_max,count_max+1,1<<60,(1<<64)-1)]
    marker_code=va_bytes(data,secs,0x1900cd8,27)
    if marker_code[:6]!=bytes.fromhex('41b1e080f9df') or marker_code[12:15]!=bytes.fromhex('80f990') or marker_code[21:24]!=bytes.fromhex('80e10f'):
        raise ValueError('outer reader marker decisions changed')
    marker_cases=[{'marker':hex(m),'fixmap_count':fixmap_count(m)} for m in (0x7f,0x80,0x8f,0x90,0xdf,0xe0)]
    duplicate_tail=va_bytes(data,secs,0x26421ab,10)
    duplicate_head=va_bytes(data,secs,0x26421b9,10)
    if duplicate_tail[:2]!=b'\x48\xb9' or duplicate_head[:2]!=b'\x48\xb9':
        raise ValueError('duplicate key diagnostic instructions changed')
    duplicate_key=bytearray(13)
    duplicate_key[:8]=duplicate_head[2:]
    duplicate_key[5:13]=duplicate_tail[2:]
    if duplicate_key!=b'duplicate key':
        raise ValueError('duplicate key diagnostic changed')
    address_name=rip_target(data,secs,0x2641d90,(b'\x48\x8d\x15',))
    if va_bytes(data,secs,address_name,7)!=b'Address' or va_bytes(data,secs,0x16a54f5,9)!=bytes.fromhex('48c744244014000000'):
        raise ValueError('address reader label or size changed')
    empty_code=va_bytes(data,secs,0x257b84f,11)
    if empty_code[:1]!=b'\xbb' or empty_code[5:]!=bytes.fromhex('4531f64d85e4'):
        raise ValueError('empty collector setup changed')
    empty_pointer=struct.unpack_from('<I',empty_code,1)[0]
    layout_code=va_bytes(data,secs,0x257b88a,42)
    if layout_code[:8]!=bytes.fromhex('4c8d14924f8d1491') or layout_code[8:11]!=bytes.fromhex('4981c2') or layout_code[15:18]!=bytes.fromhex('4869d2') or layout_code[28:31]!=bytes.fromhex('49c1e1'):
        raise ValueError('pair layout instructions changed')
    key_base=struct.unpack_from('<I',layout_code,11)[0]
    value_stride=struct.unpack_from('<I',layout_code,18)[0]
    pair_stride=1 << layout_code[31]
    key_setup=va_bytes(data,secs,0x1e11716,24)
    if key_setup[:5]!=bytes.fromhex('488d7c2420') or key_setup[5]!=0xbe or key_setup[10]!=0xb9 or key_setup[15:20]!=bytes.fromhex('4531c0ff15'):
        raise ValueError('key encoder argument setup changed')
    capacity=struct.unpack_from('<I',key_setup,6)[0]
    key_size=struct.unpack_from('<I',key_setup,11)[0]
    indirect_slot=0x1e11716+24+struct.unpack_from('<i',key_setup,20)[0]
    direct_setup=va_bytes(data,secs,0x1e11096,24)
    if direct_setup[:20]!=key_setup[:20]:
        raise ValueError('direct key encoder argument setup changed')
    direct_slot=0x1e11096+24+struct.unpack_from('<i',direct_setup,20)[0]
    if direct_slot!=indirect_slot:
        raise ValueError('key encoder slots disagree')
    reloc=relative_relocation(data,secs,indirect_slot)
    if (key_base,value_stride,pair_stride,capacity,key_size,reloc['type'],reloc['symbol_index'],reloc['addend_va']) != (0x798,0xb0,16,42,20,8,0,'0x29ed380'):
        raise ValueError('pair layout, key size or helper relocation changed')
    alphabet=va_bytes(data,secs,0x208620,16)
    if alphabet!=b'0123456789abcdef':
        raise ValueError('hex alphabet changed')
    pair_layout={'key_array_offset':key_base,'key_stride':5*4,'value_stride':value_stride,
                 'pair_stride':pair_stride,'key_pointer_in_pair':0,'value_pointer_in_pair':8,
                 'key_input_bytes':key_size,'key_buffer_bytes':capacity,'hex_alphabet':alphabet.decode('ascii'),
                 'reader_label_va':hex(address_name),'reader_label':'Address',
                 'hex_relocation':reloc}
    closure_setup=bytes.fromhex('48890424c744240800040001c644240c00488b36488dbc24080100004889e2e8eb34dcff')
    if va_bytes(data,secs,0x2818821,len(closure_setup))!=closure_setup:
        raise ValueError('previously identified root closure call context changed')
    code=va_bytes(data,secs,0x23406e7,20)
    if code[:20]!=bytes.fromhex('0fb66a1b488b72104080f50140c0e5044080cd8d'):
        raise ValueError('direct writer marker arithmetic changed')
    mark_xor, shift, base = code[11],code[15],code[19]
    markers=[{'mode':mode,'marker':hex((((mode ^ mark_xor)<<shift)|base)&255)} for mode in (0,1)]
    if markers != [{'mode':0,'marker':'0x9d'},{'mode':1,'marker':'0x8d'}]:
        raise ValueError('unexpected header markers')
    flag_checks=(
       (0x19f9e6c,'c644241002'),(0x19f9e71,'c644240802'),(0x19f9e76,'c644241802'),
       (0x19fcd2f,'4180e6014080e601'),
       (0x19fb6eb,'0fb654241889d0240180fa020fb6d0b8010000000f45c2'),
       (0x19fb895,'0fb64c2420888c24b4020000888424b5020000488b442408888424b6020000488b442410888424b7020000'),
    )
    for va,expected in flag_checks:
        if va_bytes(data,secs,va,len(bytes.fromhex(expected))).hex()!=expected:
            raise ValueError('default slot instruction changed')
    choices=[]
    for slot in (0,1,2):
        choices.append({'slot':slot,'allow_deposits':allow_default(slot),
                        'always_close_on_withdraw':bit_default(slot),'s_bit':bit_default(slot)})
    s0=va_bytes(data,secs,0x3dfbdb,1);s1=va_bytes(data,secs,0x3dfbdc,1)
    if (s0,s1)!=(b'D',b'U'):
        raise ValueError('s alternatives changed')
    return {'target_sha256':sha(data),'coordinate_system':'ELF link-time virtual address; ends exclusive',
            'functions':functions,'fields':fields,'missing_diagnostics':missing,'duplicate_diagnostics':duplicates,
            'calls':calls,'branches':branches,'windows':windows,'templates':templates,'direct_markers':markers,
            'pair_layout':pair_layout,'outer_marker_cases':marker_cases,'duplicate_key_diagnostic':duplicate_key.decode('ascii'),'empty_collector_pointer':empty_pointer,'allocation_limit':allocation_limit,'allocation_cases':allocation_cases,
            'root_closure_context':{'call_site_va':hex(0x2818840),'serializer_mode_byte':closure_setup[11],
                                    'serializer_auxiliary_byte':closure_setup[16]},
            'default_slot_cases':choices,'s_bit_zero':s0.decode('ascii'),'s_bit_one':s1.decode('ascii'),
            'limitations':['Only the selected FDEs and windows are analyzed; FDEs do not prove all code boundaries.',
                'Field names and roles follow byte-bearing writer and reader sites; source ownership remains an inference.',
                'Map defaults are conditional on successful preceding child readers and the selected parser state.',
                'Other serializer modes, nested value grammars, runtime entry reachability, and cross-version compatibility are unresolved.']}


def tsv(rows,keys):
    out=io.StringIO(newline='')
    w=csv.DictWriter(out,fieldnames=keys,delimiter='\t',lineterminator='\n')
    w.writeheader();w.writerows(rows)
    return out.getvalue().encode('utf-8')


def write_outputs(data,out,expected_digest=DIGEST):
    result=analyze(data,expected_digest)
    out.mkdir(parents=True,exist_ok=True)
    (out/'evidence.json').write_text(json.dumps(result,indent=2,ensure_ascii=True)+'\n',encoding='utf-8')
    for name,key,columns in (
        ('functions.tsv','functions',['name','start_va','end_va_exclusive','fde_va','section','file_offset','size','body_sha256']),
        ('fields.tsv','fields',['ordinal','name','name_va','name_length','name_site_va','length_site_va','input_site_va','input_instruction_hex','input_offset','copy_input_site_va','call_site_va','callee_va','failure_branch_va','failure_branch_hex','failure_target_va','direct_input_site_va','direct_input_instruction_hex','direct_copy_input_site_va','direct_call_site_va','direct_callee_va','direct_failure_va','direct_failure_bytes','direct_failure_target_va']),
        ('missing.tsv','missing_diagnostics',['site_va','name_va','length','name','template_site_va','guard_va','guard_bytes','guard_target_va','guard_meaning']),
        ('duplicates.tsv','duplicate_diagnostics',['site_va','name_va','length','name','template_site_va','guard_va','guard_bytes']),
        ('calls.tsv','calls',['name','site_va','bytes_hex','target_va']),
        ('branches.tsv','branches',['name','site_va','bytes_hex','target_va']),
        ('allocation-cases.tsv','allocation_cases',['count','wrapped_bytes','high_bits_nonzero','above_limit','passes']),
        ('default-cases.tsv','default_slot_cases',['slot','allow_deposits','always_close_on_withdraw','s_bit'])):
        (out/name).write_bytes(tsv(result[key],columns))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',required=True,type=Path)
    args=p.parse_args()
    write_outputs(BINARY.read_bytes(),args.out)


if __name__=='__main__':
    main()
