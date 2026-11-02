#!/usr/bin/env python3
"""Extract a bounded #94 standard-precompile installation path without execution.

Addresses are ELF VAs before load bias. Byte predicates are fixed reviewed x86
shapes, not a general decoder. The earlier runtime FDE is an external boundary.
"""
import argparse
import csv
import hashlib
import io
import json
import struct
from pathlib import Path

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

FUNCTIONS = (
    (0x43606b0, 'derive separate address set from provider representation'),
    (0x4463490, 'construct context and pass copied target to executor'),
    (0x4473320, 'borrowed registry provider mode 0'),
    (0x4473600, 'borrowed registry provider mode 1'),
    (0x4473710, 'borrowed registry provider mode 3'),
    (0x4473780, 'borrowed registry provider mode 5'),
    (0x4473c70, 'borrowed registry provider mode 4'),
    (0x4474990, 'borrowed registry provider mode 2'),
    (0x44bc770, 'raw revision switch and handler assembly'),
    (0x47f3090, 'registry publication and frame callback'),
    (0x4862a40, 'clone borrowed address set'),
    (0x488d0b0, 'twenty-byte-key registry membership probe'),
    (0x488e250, 'insert or recognize twenty-byte address'),
    (0x4ad9920, 'reserve and extend context address set'),
    (0x4b727c0, 'consume address set into insertion loop'),
    (0x4da4e20, 'call frame adapter and cleanup'),
    (0x4da6ff0, 'revision 12 creation-frame adapter and cleanup'),
    (0x4dd83a0, 'creation-frame precompile membership and early result'),
    (0x4dde9b0, 'revision 12 execution callback constructor'),
)

# The constructors were analyzed by earlier work; these are external targets,
# used only to label the six newly selected provider adapters.
PRIOR_CONSTRUCTORS = {
    0x4e99110: 0, 0x4e98c70: 1, 0x4e99650: 2,
    0x4e99f30: 3, 0x4e99af0: 4, 0x4e9a310: 5,
}
PROVIDERS = (0x4473320, 0x4473600, 0x4474990,
             0x4473710, 0x4473c70, 0x4473780)
PAIR_LEAS = (0x4ddec44, 0x4ddec58, 0x4ddec6c, 0x4ddec80,
             0x4ddec94, 0x4ddeca3, 0x4ddecb2, 0x4ddecc1,
             0x4ddecd3, 0x4ddece8, 0x4ddecfd)

# Each byte sequence was read at a manually reviewed instruction boundary.
# The generator emits the bytes read from the artifact after comparison.
PINS = (
    ("entry_revision", 0x446367c, "8bb424883a0000488dbc2440150000e8e0900500"),
    ("entry_handler_copy1", 0x44636af, "488dbc24a0030000488db42440150000baa0110000ffd5"),
    ("entry_target_address", 0x4463a3a, "41c6879402000001488b4424080f1000410f1187950200008b4010418987a5020000"),
    ("entry_context_copy", 0x4463a64, "488db42490020000baa81200004c89f74c8b3d65a5300141ffd7"),
    ("entry_handler_copy2", 0x4463b15, "488db42450160000488dbc24f8280000ba9811000041ffd7"),
    ("entry_executor", 0x4463c7f, "488dbc24a80000004c8db424e82700004c89f6e8f9f33800"),
    ("revision_switch", 0x44bc793, "4080fe130f87b10f0000400fb6c6488d0de46223fc486304814801c8ffe0"),
    ("case12_provider", 0x44bc978, "48c7000100000048c74008010000004c89742458488d0db54a260148894c24604c8964246848896c24704c897c24784c89ac24800000004889842488000000488d051a4b26014889842490000000"),
    ("case12_constructor", 0x44bc9c6, "488dbc2498000000e85dec9100488dbc24f8000000e8d01f9200c683981100000ce9351f0000"),
    ("handler_assembly", 0x44be921, "488dbb98010000488db424a80100004c8b35a9f62a01ba0010000041ffd6488b442410488943100f1004240f11030f104424280f104c24380f105424480f1153380f114b280f1143180f104424580f104c24680f105424780f109c24880000000f114b580f1153680f115b780f1143480f108424980000000f108c24a80000000f109424b80000000f109c24c80000000f1183880000000f108424d80000000f1183c80000000f119bb80000000f1193a80000000f118b980000000f108424e80000000f1183d80000004881c3e8000000488db424f8000000bab00000004889df41ffd6"),
    ("callback_allocation", 0x4ddea32, "bf10000000ff159bf598004885c00f84ff0200004989c448c7000100000048c74008010000004889442448488d054c7896004889442450"),
    ("callback_publication", 0x4ddec63, "488b4c241048894b20488d0d3d76960048894b28"),
    ("executor_first_guard", 0x47f30ad, "0fb6aea8120000488b8668010000488b8e70010000488b511048ffca4883e2f0488d34104883c610488dbc24200200004c89f2ff512880bc2420020000050f85d6010000"),
    ("executor_registry_install", 0x47f30f1, "498b8658010000498b8e60010000488b511048ffca4883e2f0488d34104883c6104c8da424480400004c89e7ff5128488dbc24200200004c89e6e880d5b6ff498dbe80000000488db42420020000e8dc672e004d8da6e80000004983bee80000000074084c89e7e8c3760600488b84246804000049894424200f108424480400000f108c2458040000410f114c2410410f110424"),
    ("executor_second_guard", 0x47f3185, "498b8678010000498b8e80010000488b511048ffca4883e2f0488d34104883c610488dbc24200200004c89f2ff512880bc2420020000050f8505010000"),
    ("executor_subtraction_guard", 0x47f31c2, "498b86d80000004c8ba0380200004d29ec0f82bd1a0000"),
    ("executor_third_guard", 0x47f31d9, "498b8688010000498b8e90010000488b511048ffca4883e2f0488d34104883c610488dbc24200200004c89f2ff51280fb68424200200003c050f85e9000000"),
    ("executor_frame_and_call", 0x47f3218, "488b842428020000498bbed800000080bf940200000148898424400400000f85f60000004881c7580100004c89e6ff153c13f8004885c00f84da190000498b8e180200004d8b8620020000498b501048ffca4883e2f0488d34114883c610488dbc24200200004c89f24889c141ff5028"),
    ("executor_result_branch", 0x47f3288, "488b8424200200004c8bac24280200004c8ba424300200000f108424380200000f298424300100004883f8040f8538020000"),
    ("executor_error_return", 0x47f32c7, "0f108424200200000f108c24300200000f114b180f11430848b802000000000000804889034889d84881c4e80400005b415c415d415e415f5dc3"),
    ("key_set_borrowed_test", 0x43606be, "4889fb4c8b364d85f60f84ce000000"),
    ("key_set_clone_call", 0x436079b, "488b76084883c6284889dfe895225000"),
    ("clone_allocation_bounds", 0x4862a4e, "4c8b66084c8b46204d85e47452498d442401b91400000048f7e1702a4883c00f4883e0f04d8d7424114989c74d01f70f92c148baf0ffffffffffff7f4939d70f97c208ca7428488d3dcbdda1fb488d150630e200be39000000ff15ebb5f000"),
    ("clone_bulk_copies", 0x4862b04, "4801c34c8b3e4c8b2dcfb4f0004889df4889f54c89fe4c89f241ffd54c89e048f7d048c1e002488d3c804901ff4801df4b8d04a4488d1485140000004c89fe41ffd50f104510488b7c24104c8b4424084c89472048891f4c8967080f114710"),
    ("extend_reservation_hint", 0x4ad9973, "498d74240148d1ee48837b1800490f44f4483b7310775a"),
    ("iterate_key_copy", 0x4b72820, "6685ed752a66662e0f1f84000000000066410f6f0424660fd7e84981c5c0feffff4983c41081fdffff000074e3f7d58d45fff30fbccd21e889c548f7d9488d048949ffcf418b4c85fc894c2470f3410f6f4485ec660f7f442460894c2450660f7f4424404889df4c89f6e8c1b9d1ff4d85ff758c"),
    ("set_hash", 0x488e257, "488b0d8201ee004c8b09488b560c488b4608483341084c31ca48f7e24889c14989d0488b06488b5604483347204c31ca48f7e24931d04931c84c31c04883f01449f7e14831c248837f10000f844a010000"),
    ("set_probe_candidates", 0x488e2a8, "488b0f4c8b4f084989d049c1e83966410f6ec0660f60c0f20f70c000660f70c0444c8d59ec4531f6660f76c931db4c21caf30f6f1411660f6fda660f74d866440fd7fb4585ff7460f3410fbcc74801d04c21c848f7d8488d0480f30f6f1ef3410f6f2483660f74e3660f6e5e1066410f6e6c8310660f74eb660fdbec660fd7edb00181fdffff00000f84b1000000418d47ff664421f84189c775ad666666662e0f1f840000000000"),
    ("set_publish", 0x488e390, "420fb6041184c00f89830000002401498d52f04c21ca468804114488441110f30f6f47100fb6c0660f6ec8660fc60dbc5097fb02660ffbc1f30f7f471049f7da4b8d04928b5610895481fcf30f6f06f30f7f4481ec31c0"),
    ("set_growth", 0x488e3f2, "488d47204989f6be010000004889fb4989d74889c2b901000000ff157e53ee004c89fa4889df4c89f6e988feffff"),
    ("frame_adapter", 0x4da4e20, "415653504889cb4989fe4889d64889cae86b200300488b4328488b7330488d7b40488b5338ff5020bea00000004889df31d2ff15b8919c004c89f04883c4085b415ec34989c6bea00000004889df31d2ff159a919c004c89f7e892b28b004989c64889dfe8778100004c89f7e87fb28b00ff1591929c00"),
    ("executor_drop_unwind_publish", 0x47f4e14, "4889c3488b84246804000049894424200f108424480400000f108c2458040000410f114c2410410f1104244889dfe8c9b2e600"),
    ("executor_set_unwind_cleanup", 0x47f4e47, "4889c34883bc2448040000000f8453010000488dbc2448040000e8ba590600e941010000"),
    ("entry_incoming_target", 0x44634ce, "4989d64989f448893c24"),
    ("entry_save_target", 0x44636e5, "4c89742408"),
    ("handler_provider_load", 0x44be96a, "0f10442458"),
    ("handler_provider_store", 0x44be98d, "0f114348"),
    ("entry_context_destination", 0x4463a5c, "4c8db42440150000"),
    ("handler_callback_group_base", 0x44be9eb, "4881c3e8000000"),
    ("executor_unwind_resume", 0x47f4fac, "4889dfe85cb1e600"),
    ("entry_environment_load", 0x44638fa, "4c8bbc2468030000"),
    ("create_adapter", 0x4da6ff0, "415653504889cb4989fe4889d6ba0c000000e899130300488b4328488b7330488d7b40488b5338ff5020be880000004889df31d2ff15e66f9c004c89f04883c4085b415ec34989c6be880000004889df31d2ff15c86f9c004c89f7e8c0908b004989c64889dfe8156400004c89f7e8ad908b00ff15bf709c00"),
    ("create_executor_callback", 0x47f347e, "498b86480200004d8b8650020000498b481048ffc94883e1f0488d34084883c610488dbc24c00000004c89f24c89e141ff5028"),
    ("create_nested_callback", 0x47f39e4, "498b86480200004d8b8650020000498b501048ffca4883e2f0488d34104883c61040b5014531ff41b501488dbc24200200004c89f241ff5028"),
    ("create_address_extract", 0x4dd87ca, "4889e6ba200000004c89efff15055a99000f1044240c0f294424208b44241c89442430"),
    ("create_owned_lookup", 0x4dd87ed, "4983bfe8000000004c8ba424280100000f8465020000498dbfe8000000488d742420e89c48abff84c00f8465020000"),
    ("create_collision_hit", 0x4dd881c, "498b466848c70301000000488d0dcaa9960048894b0848c74310010000000f57c00f114318488943284889433048c7433800000000c643405ec6434800e9d8040000"),
    ("create_borrowed_lookup", 0x4dd8a52, "4983bfe8000000004c8ba424280100000f859bfdffff498bbff0000000488d742420e83746abff84c00f859bfdffff"),
    ("contains_20byte", 0x488d0b0, "48837f18000f8401010000488b151e13ee004c8b124c8b460c4d31d0488b0e488b46084833420849f7e04989c04989d1488b56044c31d248334f204889c848f7e24931d14d31c14c31c84883f01449f7e24831c24889d048c1e839488b0f488b7f08660f6ec0660f60c0f20f70c000660f70c0444c8d41d04531c9660f76c94821faf30f6f1411660f6fda660f74d866440fd7d34585d27457f3410fbcc24801d04821f848f7d8488d044048c1e004f30f6f1ef3410f6f2400660f74e3660f6e5e1066410f6e6c0010660f74eb660fdbec66440fd7ddb0014181fbffff0000742d418d42ff664421d04189c275ab6690660f74d1660fd7c285c075104c01ca4883c2104983c110e973ffffff31c0c3"),
)

# Selected instruction starts, independently checked against the byte shape and
# the signed relative displacement. The named targets are admission controls.
EDGES = (
    ('entry_construct_handler', 0x446368b, 0x44bc770, 'call'),
    ('entry_call_executor', 0x4463c92, 0x47f3090, 'call'),
    ('revision_default', 0x44bc797, 0x44bd74e, 'conditional'),
    ('revision12_group_constructor', 0x44bc9db, 0x4dde9b0, 'call'),
    ('executor_first_gate', 0x47f30eb, 0x47f32c7, 'conditional'),
    ('executor_borrowed_keys', 0x47f312b, 0x43606b0, 'call'),
    ('executor_extend_keys', 0x47f313f, 0x4ad9920, 'call'),
    ('executor_old_map_borrowed', 0x47f3153, 0x47f315d, 'conditional'),
    ('executor_drop_owned_map', 0x47f3158, 0x485a820, 'call'),
    ('executor_second_gate', 0x47f31bc, 0x47f32c7, 'conditional'),
    ('executor_subtraction_borrow', 0x47f31d3, 0x47f4c96, 'conditional'),
    ('executor_third_gate', 0x47f3212, 0x47f3301, 'conditional'),
    ('executor_alternative_frame', 0x47f3236, 0x47f3332, 'conditional'),
    ('executor_frame_slot', 0x47f3246, 0x5774588, 'indirect_slot'),
    ('executor_null_frame', 0x47f324f, 0x47f4c2f, 'conditional'),
    ('executor_result_other', 0x47f32b4, 0x47f34f2, 'conditional'),
    ('old_drop_unwind_resume', 0x47f4e42, 0x5660110, 'call'),
    ('set_unwind_borrowed', 0x47f4e53, 0x47f4fac, 'conditional'),
    ('set_unwind_owned_cleanup', 0x47f4e61, 0x485a820, 'call'),
    ('set_unwind_continue', 0x47f4e66, 0x47f4fac, 'jump'),
    ('set_unwind_resume', 0x47f4faf, 0x5660110, 'call'),
    ('borrowed_set_arm', 0x43606c7, 0x436079b, 'conditional'),
    ('borrowed_set_clone', 0x43607a6, 0x4862a40, 'call'),
    ('clone_empty', 0x4862a59, 0x4862aad, 'conditional'),
    ('clone_multiply_overflow', 0x4862a68, 0x4862a94, 'conditional'),
    ('clone_bounds_accepted', 0x4862a92, 0x4862abc, 'conditional'),
    ('clone_allocation_null', 0x4862b02, 0x4862b75, 'conditional'),
    ('extend_reservation_needed', 0x4ad9988, 0x4ad99e4, 'conditional'),
    ('extend_consume', 0x4ad99d0, 0x4b727c0, 'call'),
    ('extend_reserve_slot', 0x4ad99f6, 0x5773790, 'indirect_slot'),
    ('iterate_insert', 0x4b7288a, 0x488e250, 'call'),
    ('set_reserve_needed', 0x488e2a2, 0x488e3f2, 'conditional'),
    ('set_existing_key', 0x488e330, 0x488e3e7, 'conditional'),
    ('set_empty_control', 0x488e373, 0x488e390, 'conditional'),
    ('set_probe_next', 0x488e38b, 0x488e2d6, 'jump'),
    ('set_control_nonnegative', 0x488e397, 0x488e420, 'conditional'),
    ('set_reserve_slot', 0x488e40c, 0x5773790, 'indirect_slot'),
    ('set_post_reserve', 0x488e41b, 0x488e2a8, 'jump'),
    ('frame_existing_boundary', 0x4da4e30, 0x4dd6ea0, 'call'),
    ('frame_deallocation_slot', 0x4da4e52, 0x576e010, 'indirect_slot'),
    ('create_frame_alloc_null', 0x47f345f, 0x47f4c75, 'conditional'),
    ('create_adapter_target', 0x4da7002, 0x4dd83a0, 'call'),
    ('create_first_borrowed', 0x4dd87fd, 0x4dd8a68, 'conditional'),
    ('create_owned_contains', 0x4dd880f, 0x488d0b0, 'call'),
    ('create_owned_no_match', 0x4dd8816, 0x4dd8a81, 'conditional'),
    ('create_collision_exit', 0x4dd8859, 0x4dd8d36, 'jump'),
    ('create_second_owned', 0x4dd8a62, 0x4dd8803, 'conditional'),
    ('create_borrowed_contains', 0x4dd8a74, 0x488d0b0, 'call'),
    ('create_borrowed_match', 0x4dd8a7b, 0x4dd881c, 'conditional'),
    ('contains_empty_map', 0x488d0b5, 0x488d1bc, 'conditional'),
    ('contains_no_fingerprint', 0x488d147, 0x488d1a0, 'conditional'),
    ('contains_full_key_match', 0x488d18f, 0x488d1be, 'conditional'),
    ('contains_next_candidate', 0x488d19c, 0x488d149, 'conditional'),
    ('contains_empty_control', 0x488d1aa, 0x488d1bc, 'conditional'),
    ('contains_next_group', 0x488d1b7, 0x488d12f, 'jump'),
)


def authenticate(data):
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('node 94 SHA-256 mismatch')


def must_equal(actual, expected, what):
    if actual != expected:
        raise ValueError('unexpected ' + what)
    return actual


class Image:
    def __init__(self, data, secs=None):
        self.data = data
        self.secs = sections(data) if secs is None else secs

    def offset(self, va, length, executable=False):
        if not isinstance(va, int) or not isinstance(length, int) or va < 0 or length <= 0:
            raise ValueError('invalid address or length')
        end = va + length
        if end > (1 << 64):
            raise ValueError('address overflow')
        rows = [s for s in self.secs if s['type'] != 8 and s['flags'] & 2
                and (not executable or s['flags'] & 4)
                and s['address'] <= va and end <= s['address'] + s['size']]
        if len(rows) != 1:
            raise ValueError('address is not uniquely file backed')
        s = rows[0]
        off = s['offset'] + va - s['address']
        if off < 0 or off + length > len(self.data):
            raise ValueError('file range outside input')
        return off

    def read(self, va, length, executable=False):
        off = self.offset(va, length, executable)
        return self.data[off:off + length]

    def allocated_section(self, va):
        rows = [s for s in self.secs if s['flags'] & 2 and
                s['address'] <= va < s['address'] + s['size']]
        if len(rows) != 1:
            raise ValueError('ambiguous allocated section')
        return rows[0]


def signed32(buf):
    if len(buf) != 4:
        raise ValueError('truncated signed displacement')
    return struct.unpack('<i', buf)[0]


def transfer(image, va):
    b = image.read(va, 2, True)
    if b[0] in (0xe8, 0xe9):
        raw = image.read(va, 5, True)
        kind, dest = ('call' if b[0] == 0xe8 else 'jump'), va + 5 + signed32(raw[1:])
    elif b[0] == 0x0f and 0x80 <= b[1] <= 0x8f:
        raw = image.read(va, 6, True)
        kind, dest = 'conditional', va + 6 + signed32(raw[2:])
    elif 0x70 <= b[0] <= 0x7f or b[0] == 0xeb:
        raw = b
        kind, dest = ('jump' if b[0] == 0xeb else 'conditional'), va + 2 + struct.unpack('<b', b[1:])[0]
    elif b in (b'\xff\x15', b'\xff\x25'):
        raw = image.read(va, 6, True)
        kind, dest = 'indirect_slot', va + 6 + signed32(raw[2:])
    else:
        raise ValueError('unsupported selected transfer shape')
    return kind, dest, raw.hex()


def relative_lea(image, va, prefix):
    raw = image.read(va, 7, True)
    if raw[:3] != prefix:
        raise ValueError('unexpected RIP-relative LEA')
    return va + 7 + signed32(raw[3:]), raw


def relas(image):
    matches = [s for s in image.secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(matches) != 1:
        raise ValueError('missing or duplicate relocation section')
    s = matches[0]
    if s['size'] % 24:
        raise ValueError('malformed RELA section')
    result = {}
    for off in range(s['offset'], s['offset'] + s['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', image.data, off)
        if slot in result:
            raise ValueError('duplicate relocation slot')
        result[slot] = (info, addend, off)
    return result


def relative_relocation(records, slot):
    if slot not in records:
        raise ValueError('missing relocation')
    info, addend, off = records[slot]
    if info != 8:
        raise ValueError('expected symbol-free relative relocation')
    return addend, off


def relocation_boundaries(image, records):
    targets = {
        0x576dfd8: 0x54c06b0, 0x576e010: 0x54c8cb0,
        0x576e020: 0x1345e2a, 0x576e3e0: 0x5788348,
        0x5773790: 0x4e95b80, 0x5774588: 0x4e91cb0,
        0x574f0b0: 0x4e9d2a0,
    }
    result = []
    for slot, target in sorted(targets.items()):
        addend, record_off = relative_relocation(records, slot)
        must_equal(addend, target, 'relative relocation target')
        target_sec = image.allocated_section(addend)
        result.append({'slot_va': slot, 'rela_file_offset': record_off, 'type': 8,
                       'symbol': '', 'addend_va': addend,
                       'target_section': target_sec['name']})
    slot = 0x576dfe0
    if slot not in records:
        raise ValueError('missing copy-symbol relocation')
    info, addend, record_off = records[slot]
    if (info & 0xffffffff) != 6 or addend != 0:
        raise ValueError('unexpected copy-symbol relocation')
    sym_index = info >> 32
    symbols = [s for s in image.secs if s['name'] == '.dynsym' and s['type'] == 11]
    strings = [s for s in image.secs if s['name'] == '.dynstr' and s['type'] == 3]
    if len(symbols) != 1 or len(strings) != 1:
        raise ValueError('missing dynamic symbol sections')
    symsec, strsec = symbols[0], strings[0]
    if sym_index * 24 + 24 > symsec['size']:
        raise ValueError('dynamic symbol index outside section')
    symoff = symsec['offset'] + sym_index * 24
    name_off, _, _, shndx, _, _ = struct.unpack_from('<IBBHQQ', image.data, symoff)
    if name_off >= strsec['size'] or shndx != 0:
        raise ValueError('invalid imported symbol')
    pos = strsec['offset'] + name_off
    limit = strsec['offset'] + strsec['size']
    terminator = image.data.find(b'\0', pos, limit)
    if terminator < 0:
        raise ValueError('unterminated dynamic symbol name')
    name = image.data[pos:terminator]
    must_equal(name, b'memcpy', 'copy symbol name')
    result.append({'slot_va': slot, 'rela_file_offset': record_off, 'type': 6,
                   'symbol': name.decode('ascii'), 'addend_va': None,
                   'target_section': 'external dynamic symbol'})
    return sorted(result, key=lambda x: x['slot_va'])


def provider(image, va):
    raw = image.read(va, 32, True)
    if raw[:7] != bytes.fromhex('534889fb488d3d') or raw[11] != 0xe8:
        raise ValueError('unexpected provider prologue')
    if raw[16:] != bytes.fromhex('48c70300000000488943084889d85bc3'):
        raise ValueError('unexpected provider return representation')
    cache = va + 11 + signed32(raw[7:11])
    constructor = va + 16 + signed32(raw[12:16])
    if constructor not in PRIOR_CONSTRUCTORS:
        raise ValueError('unrecognized prior constructor')
    section = image.allocated_section(cache)
    if section['type'] != 8:
        raise ValueError('provider cache is not NOBITS')
    return {'provider_va': va, 'mode': PRIOR_CONSTRUCTORS[constructor],
            'constructor_va': constructor, 'cache_va': cache,
            'cache_section': section['name'], 'bytes': raw.hex()}


def parse_revision_cases(image, records, provider_map):
    # The selector's upper bound and default edge are verified by the fixed pin.
    must_equal(image.read(0x44bc793, 4, True), bytes.fromhex('4080fe13'), 'revision bound')
    _, default, _ = transfer(image, 0x44bc797)
    must_equal(default, 0x44bd74e, 'revision default')
    table = 0x6f2a8c
    targets = [table + signed32(image.read(table + 4 * i, 4)) for i in range(20)]
    cases = sorted(set(targets) | {default})
    if len(cases) != 15 or any(not 0x44bc770 <= x < 0x44be921 for x in cases):
        raise ValueError('unexpected switch destinations')
    detail = {}
    for i, start in enumerate(cases):
        end = cases[i + 1] if i + 1 < len(cases) else 0x44be921
        code = image.read(start, end - start, True)
        marker = bytes.fromhex('c68398110000')
        positions = [j for j in range(len(code)) if code.startswith(marker, j)]
        if len(positions) != 1:
            raise ValueError('expected one canonical revision store')
        j = positions[0]
        if j < 5 or j + 7 > len(code) or code[j - 5] != 0xe8:
            raise ValueError('unexpected case constructor and store')
        call_va, store_va = start + j - 5, start + j
        _, constructor, call_bytes = transfer(image, call_va)
        if store_va + 7 == 0x44be921:
            exit_va = store_va + 7  # the last case falls through
        else:
            if j + 12 > len(code) or code[j + 7] != 0xe9:
                raise ValueError('unexpected case exit')
            _, exit_va, _ = transfer(image, store_va + 7)
        must_equal(exit_va, 0x44be921, 'case exit')
        provider_leas = [k for k in range(len(code) - 11)
                         if code[k:k + 3] == bytes.fromhex('488d0d')
                         and code[k + 7:k + 12] == bytes.fromhex('48894c2460')]
        if len(provider_leas) != 1:
            raise ValueError('expected one provider descriptor store')
        lea = start + provider_leas[0]
        descriptor, lea_bytes = relative_lea(image, lea, bytes.fromhex('488d0d'))
        method, relocation_offset = relative_relocation(records, descriptor + 0x28)
        if method not in provider_map:
            raise ValueError('provider descriptor has unexpected target')
        detail[start] = {
            'case_va': start, 'case_end_va': end, 'canonical': code[j + 6],
            'constructor_call_va': call_va, 'constructor_va': constructor,
            'constructor_call_bytes': call_bytes, 'exit_va': exit_va,
            'provider_lea_va': lea, 'provider_lea_bytes': lea_bytes.hex(),
            'provider_descriptor_va': descriptor, 'provider_slot_va': descriptor + 0x28,
            'provider_rela_file_offset': relocation_offset, 'provider_va': method,
            'provider_mode': provider_map[method]['mode'],
        }
    rows = []
    for raw in range(256):
        case = targets[raw] if raw < len(targets) else default
        rows.append({'raw_revision': raw, **detail[case]})
    if [rows[x]['canonical'] for x in (12, 13, 14)] != [12, 12, 12]:
        raise ValueError('revision 12 family differs')
    return rows, detail


def execution_pairs(image, records):
    rows = []
    for i, va in enumerate(PAIR_LEAS):
        prefix = bytes.fromhex('488d05' if i == 10 else '488d0d')
        desc, raw = relative_lea(image, va, prefix)
        expected_disp = 8 + 16 * i
        if i < 8:
            tail = image.read(va + 7, 4, True)
            if tail[:3] != bytes.fromhex('48894b') or tail[3] != expected_disp:
                raise ValueError('callback output displacement mismatch')
        else:
            tail = image.read(va + 7, 7, True)
            expected_prefix = bytes.fromhex('488983' if i == 10 else '48898b')
            if tail[:3] != expected_prefix or struct.unpack('<I', tail[3:])[0] != expected_disp:
                raise ValueError('callback output displacement mismatch')
        methods = []
        for displacement in (0x18, 0x20, 0x28):
            dest, record_off = relative_relocation(records, desc + displacement)
            methods.append({'offset': displacement, 'slot_va': desc + displacement,
                            'addend': dest, 'rela_file_offset': record_off})
        rows.append({'index': i, 'lea_va': va, 'output_pointer_offset': expected_disp,
                     'descriptor_va': desc, 'lea_store_bytes': (raw + tail).hex(),
                     'methods': methods})
    must_equal(rows[2]['methods'][2]['addend'], 0x4da4e20, 'frame adapter')
    must_equal(rows[5]['methods'][2]['addend'], 0x4da6ff0, 'creation frame adapter')
    return rows


def allocation_checks(image):
    """Decode the 11 reviewed allocation/null-check shapes in one constructor."""
    start, end = 0x4dde9b0, 0x4ddef15
    data = image.read(start, end - start, True)
    rows = []
    for i in range(len(data) - 20):
        if (data[i:i + 5] != bytes.fromhex('bf10000000') or
                data[i + 5:i + 7] != b'\xff\x15' or
                data[i + 11:i + 16] != bytes.fromhex('4885c00f84')):
            continue
        req = start + i
        _, slot, _ = transfer(image, req + 5)
        _, failure, _ = transfer(image, req + 14)
        if slot != 0x576dfd8 or not start <= failure < end:
            raise ValueError('unexpected allocation target')
        raw_failure = image.read(failure, 16, True)
        if raw_failure[:1] != b'\xbf' or raw_failure[5:6] != b'\xbe':
            raise ValueError('unexpected allocation failure setup')
        alignment = struct.unpack('<I', raw_failure[1:5])[0]
        size = struct.unpack('<I', raw_failure[6:10])[0]
        must_equal((alignment, size), (8, 16), 'allocation failure arguments')
        _, error_slot, _ = transfer(image, failure + 10)
        must_equal(error_slot, 0x576e020, 'allocation failure slot')
        rows.append({'ordinal': len(rows), 'request_va': req,
                     'size': struct.unpack_from('<I', data, i + 1)[0],
                     'call_va': req + 5, 'allocator_slot_va': slot,
                     'null_branch_va': req + 14, 'failure_va': failure,
                     'failure_alignment': alignment, 'failure_size': size,
                     'failure_slot_va': error_slot})
    if len(rows) != 11:
        raise ValueError('unexpected allocation/null-check count')
    return rows


def flow_facts(image, pairs):
    """Extract the selected stack/field offsets, then check their composition."""
    one = image.read(0x44636af, 23, True)
    two = image.read(0x4463a64, 26, True)
    two_dest = image.read(0x4463a5c, 8, True)
    three = image.read(0x4463b15, 24, True)
    call = image.read(0x4463c7f, 24, True)
    provider = image.read(0x47f30f1, 14, True)
    callback = image.read(0x47f3255, 14, True)
    create_callback = image.read(0x47f347e, 14, True)
    nested_callback = image.read(0x47f39e4, 14, True)
    address = image.read(0x4463a3a, 34, True)
    environment = image.read(0x44638fa, 8, True)
    frame_env = image.read(0x47f3220, 7, True)
    provider_load = image.read(0x44be96a, 5, True)
    provider_store = image.read(0x44be98d, 4, True)
    callback_base = image.read(0x44be9eb, 7, True)
    # Validate the shapes before decoding their little-endian displacements.
    must_equal(one[:4], bytes.fromhex('488dbc24'), 'first handler copy')
    must_equal(one[8:12], bytes.fromhex('488db424'), 'first handler source')
    must_equal(two[:4], bytes.fromhex('488db424'), 'context copy source')
    must_equal(two_dest[:4], bytes.fromhex('4c8db424'), 'context copy destination')
    must_equal(three[:4], bytes.fromhex('488db424'), 'second handler source')
    must_equal(three[8:12], bytes.fromhex('488dbc24'), 'second handler destination')
    must_equal(call[8:12], bytes.fromhex('4c8db424'), 'engine stack base')
    must_equal(provider[:3] + provider[7:10], bytes.fromhex('498b86498b8e'), 'provider loads')
    must_equal(callback[:3] + callback[7:10], bytes.fromhex('498b8e4d8b86'), 'callback loads')
    must_equal(create_callback[:3] + create_callback[7:10], bytes.fromhex('498b864d8b86'), 'creation callback loads')
    must_equal(nested_callback[:3] + nested_callback[7:10], bytes.fromhex('498b864d8b86'), 'nested creation callback loads')
    must_equal(address[:3], bytes.fromhex('41c687'), 'target discriminator store')
    must_equal(environment[:4], bytes.fromhex('4c8bbc24'), 'environment pointer load')
    must_equal(frame_env[:3], bytes.fromhex('498bbe'), 'frame environment load')
    must_equal(address[16:20], bytes.fromhex('410f1187'), 'target first sixteen bytes')
    must_equal(address[27:30], bytes.fromhex('418987'), 'target last four bytes')
    must_equal(provider_load[:4], bytes.fromhex('0f104424'), 'provider stack load')
    must_equal(provider_store[:3], bytes.fromhex('0f1143'), 'provider handler store')
    must_equal(callback_base[:3], bytes.fromhex('4881c3'), 'callback group base')
    def word(raw, pos):
        return struct.unpack_from('<I', raw, pos)[0]
    first_dest, first_src, first_len = word(one, 4), word(one, 12), word(one, 17)
    context_src, context_dest, context_len = word(two, 4), word(two_dest, 4), word(two, 9)
    handler_src, handler_dest, handler_len = word(three, 4), word(three, 12), word(three, 17)
    engine_base = word(call, 12)
    provider_data, provider_desc = word(provider, 3), word(provider, 10)
    callback_data, callback_desc = word(callback, 3), word(callback, 10)
    create_data, create_desc = word(create_callback, 3), word(create_callback, 10)
    tag, tag_value = word(address, 3), address[7]
    first_addr, last_addr = word(address, 20), word(address, 30)
    env_in_context = word(environment, 4) - context_src
    if env_in_context != word(frame_env, 3):
        raise ValueError('environment pointer offset does not compose')
    callback_group = word(callback_base, 3)
    if (first_src != context_dest or first_dest - context_src != 0x110 or
            handler_src - context_dest != first_dest - context_src or
            handler_dest - engine_base != first_dest - context_src or
            context_len != handler_len + (handler_dest - engine_base) or
            first_len != handler_len + 8):
        raise ValueError('handler-copy arithmetic does not compose')
    handler_base = handler_dest - engine_base
    if (provider_load[4] != 0x58 or provider_store[3] != 0x48 or
            provider_data != handler_base + provider_store[3] or
            provider_desc != provider_data + 8):
        raise ValueError('provider descriptor offset does not compose')
    if (callback_desc != handler_base + callback_group + pairs[2]['output_pointer_offset'] or
            callback_data + 8 != callback_desc):
        raise ValueError('execution descriptor offset does not compose')
    if (create_desc != handler_base + callback_group + pairs[5]['output_pointer_offset'] or
            create_data + 8 != create_desc or
            word(nested_callback, 3) != create_data or word(nested_callback, 10) != create_desc):
        raise ValueError('creation descriptor offset does not compose')
    if tag_value != 1 or first_addr != tag + 1 or last_addr != first_addr + 16:
        raise ValueError('target address offsets do not compose')
    return {'first_copy_source_stack': first_src, 'first_copy_dest_stack': first_dest,
            'first_copy_size': first_len, 'context_copy_source_stack': context_src,
            'context_copy_dest_stack': context_dest,
            'context_copy_size': context_len, 'second_copy_source_stack': handler_src,
            'second_copy_dest_stack': handler_dest, 'second_copy_size': handler_len,
            'engine_stack': engine_base, 'handler_in_engine_offset': handler_base,
            'provider_in_handler_data': provider_store[3],
            'provider_in_engine_data': provider_data, 'provider_in_engine_descriptor': provider_desc,
            'callback_group_in_handler': callback_group,
            'callback_in_engine_data': callback_data, 'callback_in_engine_descriptor': callback_desc,
            'creation_in_engine_data': create_data, 'creation_in_engine_descriptor': create_desc,
            'target_tag_offset': tag, 'target_tag_value': tag_value,
            'environment_pointer_in_context': env_in_context,
            'target_first_offset': first_addr, 'target_last_offset': last_addr}


def checked_functions(image):
    _, idx = unwind_index(image.data)
    _, frames = eh_frame_records(image.data, image.secs)
    starts = {start for start, _ in FUNCTIONS}
    if len(starts) != len(FUNCTIONS):
        raise ValueError('duplicate selected start')
    selected = {}
    for frame in frames:
        start = frame['start']
        if start in starts:
            if start in selected:
                raise ValueError('duplicate selected FDE')
            selected[start] = frame
    if set(selected) != starts:
        raise ValueError('missing selected FDE')
    indexed = {r['start']: r['fde'] for r in idx if r['start'] in starts}
    if len(indexed) != len(starts):
        raise ValueError('missing selected unwind index entry')
    rows, bodies = [], []
    for start, role in FUNCTIONS:
        f = selected[start]
        if f['fde'] != indexed[start] or not start < f['end']:
            raise ValueError('FDE and index disagree')
        size = f['end'] - start
        body = image.read(start, size, True)
        row = {'start_va': start, 'end_va': f['end'], 'size': size,
               'file_offset': image.offset(start, size, True), 'fde_va': f['fde'],
               'cie_va': f['cie'], 'lsda_va': f['lsda'],
               'sha256': hashlib.sha256(body).hexdigest(), 'role': role}
        rows.append(row)
        bodies.append({'start_va': start, 'end_va': f['end'], 'bytes': body.hex()})
    return selected, rows, bodies


def raw_frame_record(image, va):
    frame_sections = [s for s in image.secs if s['name'] == '.eh_frame' and s['type'] != 8]
    if len(frame_sections) != 1:
        raise ValueError('missing or duplicate frame section')
    sec = frame_sections[0]
    prefix = image.read(va, 4)
    size = struct.unpack('<I', prefix)[0]
    if size in (0, 0xffffffff) or not sec['address'] <= va < va + 4 + size <= sec['address'] + sec['size']:
        raise ValueError('invalid raw frame record')
    return image.read(va, size + 4).hex()


def lsda_record(image, frame):
    va = frame['lsda']
    if va is None:
        return None
    matches = [s for s in image.secs if s['name'] == '.gcc_except_table' and s['type'] != 8]
    if len(matches) != 1:
        raise ValueError('missing exception table')
    sec = matches[0]
    pos = image.offset(va, 1)
    end = sec['offset'] + sec['size']
    begin = pos
    data = image.data
    if data[pos] != 0xff:
        raise ValueError('unsupported landing-pad encoding')
    pos += 1
    if pos >= end:
        raise ValueError('truncated LSDA header')
    typ = data[pos]
    pos += 1
    type_table = None
    if typ == 0x9b:
        delta, pos = uleb(data, pos, end)
        type_table = sec['address'] + (pos - sec['offset']) + delta
        if type_table > sec['address'] + sec['size']:
            raise ValueError('type table outside exception section')
    elif typ != 0xff:
        raise ValueError('unsupported LSDA type encoding')
    if pos >= end or data[pos] != 1:
        raise ValueError('unsupported call-site encoding')
    pos += 1
    size, pos = uleb(data, pos, end)
    table_start, table_end = pos, pos + size
    if table_end > end:
        raise ValueError('truncated call-site table')
    entries = []
    while pos < table_end:
        start, pos = uleb(data, pos, table_end)
        length, pos = uleb(data, pos, table_end)
        landing, pos = uleb(data, pos, table_end)
        action, pos = uleb(data, pos, table_end)
        first = frame['start'] + start
        if first < frame['start'] or first + length > frame['end']:
            raise ValueError('LSDA call site outside selected FDE')
        if landing and not frame['start'] <= frame['start'] + landing < frame['end']:
            raise ValueError('LSDA landing outside selected FDE')
        entries.append({'start_va': first, 'length': length,
                        'landing_va': frame['start'] + landing if landing else None,
                        'action': action})
    return {'function_va': frame['start'], 'lsda_va': va,
            'file_offset': begin, 'type_encoding': typ, 'type_table_va': type_table,
            'call_site_bytes': data[table_start:table_end].hex(),
            'prefix_bytes': data[begin:table_start].hex(), 'entries': entries}


def lane_equal(left, right):
    """Synthetic projection of the selected 16-byte plus 4-byte comparisons."""
    if len(left) != 20 or len(right) != 20:
        raise ValueError('address comparison requires 20 bytes')
    return left[:16] == right[:16] and left[16:] == right[16:]


def membership_probe(controls, keys, address, hash_value):
    """Bounded synthetic model of the 16-lane probe, with caller-supplied hash.

    Controls and keys describe one logical power-of-two table, not process
    memory. At least one empty control must be encountered unless a key matches.
    """
    size = len(controls)
    if (size < 16 or size & (size - 1) or len(keys) != size or
            len(address) != 20 or type(hash_value) is not int or
            not 0 <= hash_value < 2**64 or
            any(type(c) is not int or not 0 <= c <= 255 for c in controls)):
        raise ValueError('invalid synthetic table')
    mask = size - 1
    pos = hash_value & mask
    fingerprint = hash_value >> 57
    stride = 0
    for _ in range(size // 16):
        group = [(pos + n) & mask for n in range(16)]
        for index in group:
            if controls[index] == fingerprint:
                if keys[index] is None or len(keys[index]) != 20:
                    raise ValueError('invalid occupied synthetic bucket')
                if lane_equal(keys[index], address):
                    return True
        if any(controls[index] == 0xff for index in group):
            return False
        stride += 16
        pos = (pos + stride) & mask
    raise ValueError('synthetic table has no empty control')


def reserve_hint(remaining, occupied):
    """Synthetic projection of the selected unsigned reserve-hint arithmetic."""
    if type(remaining) is not int or type(occupied) is not int or not 0 <= remaining < 2**64 or not 0 <= occupied < 2**64:
        raise ValueError('invalid unsigned word')
    return remaining if occupied == 0 else ((remaining + 1) & (2**64 - 1)) >> 1


def write_tsv(path, columns, rows):
    buf = io.StringIO(newline='')
    writer = csv.DictWriter(buf, fieldnames=columns, delimiter='\t', lineterminator='\n')
    writer.writeheader()
    for row in rows:
        writer.writerow({col: (hex(row[col]) if isinstance(row[col], int) and
                                 (col == 'va' or col.endswith('_va') or col.endswith('_offset')) else
                                 '' if row[col] is None else row[col]) for col in columns})
    path.write_text(buf.getvalue(), encoding='ascii')


def write_json(path, obj):
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + '\n', encoding='ascii')


def extract(data):
    authenticate(data)
    image = Image(data)
    selected, functions, bodies = checked_functions(image)
    relocations = relas(image)
    slots = relocation_boundaries(image, relocations)
    providers = {va: provider(image, va) for va in PROVIDERS}
    if sorted(x['mode'] for x in providers.values()) != list(range(6)):
        raise ValueError('provider modes are not unique')
    cases, details = parse_revision_cases(image, relocations, providers)
    pairs = execution_pairs(image, relocations)
    allocations = allocation_checks(image)
    flow = flow_facts(image, pairs)
    pins = []
    for name, va, expected in PINS:
        raw = image.read(va, len(bytes.fromhex(expected)), True)
        must_equal(raw.hex(), expected, 'semantic window')
        if not any(f['start'] <= va and va + len(raw) <= f['end'] for f in selected.values()):
            raise ValueError('semantic window outside selected corpus')
        pins.append({'name': name, 'va': va, 'file_offset': image.offset(va, len(raw), True),
                     'size': len(raw), 'bytes': raw.hex()})
    edges = []
    for name, va, target, expected_kind in EDGES:
        kind, dest, raw = transfer(image, va)
        must_equal(kind, expected_kind, 'selected transfer kind')
        must_equal(dest, target, 'selected transfer destination')
        if not any(f['start'] <= va < f['end'] for f in selected.values()):
            raise ValueError('transfer outside selected corpus')
        edges.append({'name': name, 'site_va': va, 'kind': kind,
                      'target_va': dest, 'bytes': raw})
    lsda = [x for x in (lsda_record(image, selected[a]) for a, _ in FUNCTIONS) if x is not None]
    unwind = [{'start_va': a, 'fde_va': selected[a]['fde'],
               'fde_bytes': raw_frame_record(image, selected[a]['fde']),
               'cie_va': selected[a]['cie'],
               'cie_bytes': raw_frame_record(image, selected[a]['cie'])}
              for a, _ in FUNCTIONS]
    object_key = image.read(0x574f0c0, 20)
    must_equal(object_key, bytes(19) + b'\x09', 'prior address-09 object key')
    callback, obj_rela_off = relative_relocation(relocations, 0x574f0b0)
    must_equal(callback, 0x4e9d2a0, 'prior wrapper pointer')
    frame_constructor, frame_rela_off = relative_relocation(relocations, 0x5774588)
    must_equal(frame_constructor, 0x4e91cb0, 'prior frame constructor')
    reserved, reserve_rela_off = relative_relocation(relocations, 0x5773790)
    constant = image.read(0x203480, 16)
    must_equal(constant, bytes.fromhex('0000000000000000ffffffffffffffff'), 'counter constant')
    prior = {'address_va': 0x574f0c0, 'address_bytes': object_key.hex(),
             'wrapper_slot_va': 0x574f0b0, 'wrapper_addend': callback,
             'wrapper_rela_file_offset': obj_rela_off,
             'frame_slot_va': 0x5774588, 'frame_addend': frame_constructor,
             'frame_rela_file_offset': frame_rela_off,
             'reserve_slot_va': 0x5773790, 'reserve_addend': reserved,
             'reserve_rela_file_offset': reserve_rela_off,
             'counter_constant_va': 0x203480, 'counter_constant_bytes': constant.hex()}
    summary = {'target_sha256': SHA256, 'selected_fdes': len(functions),
               'selected_fde_bytes': sum(r['size'] for r in functions),
               'reviewed_windows': len(pins), 'selected_transfers': len(edges),
               'selected_lsda_tables': len(lsda),
               'lsda_call_sites': sum(len(x['entries']) for x in lsda),
               'lsda_with_landing': sum(bool(e['landing_va']) for x in lsda for e in x['entries']),
               'provider_adapters': len(providers), 'raw_revision_values': len(cases),
               'distinct_case_destinations': len(details), 'execution_pairs': len(pairs),
               'constructor_allocations': len(allocations),
               'limitations': 'Selected static byte shapes and FDEs, not a complete CFG or an execution receipt.'}
    return {'functions': functions, 'bodies': bodies, 'providers': list(providers.values()),
            'revision_cases': cases, 'execution_pairs': pairs, 'windows': pins,
            'allocations': allocations, 'flow': flow,
            'relocations': slots,
            'transfers': edges, 'exceptions': lsda, 'unwind': unwind, 'prior_boundaries': prior,
            'summary': summary}


def generate(data, out):
    evidence = extract(data)
    out.mkdir(parents=True, exist_ok=True)
    write_tsv(out / 'functions.tsv', ('start_va', 'end_va', 'size', 'file_offset', 'fde_va', 'cie_va', 'lsda_va', 'sha256', 'role'), evidence['functions'])
    write_tsv(out / 'windows.tsv', ('name', 'va', 'file_offset', 'size', 'bytes'), evidence['windows'])
    write_tsv(out / 'transfers.tsv', ('name', 'site_va', 'kind', 'target_va', 'bytes'), evidence['transfers'])
    write_tsv(out / 'revision-cases.tsv', ('raw_revision', 'case_va', 'case_end_va', 'canonical', 'constructor_call_va', 'constructor_va', 'constructor_call_bytes', 'exit_va', 'provider_lea_va', 'provider_lea_bytes', 'provider_descriptor_va', 'provider_slot_va', 'provider_rela_file_offset', 'provider_va', 'provider_mode'), evidence['revision_cases'])
    write_tsv(out / 'allocation-failures.tsv', ('ordinal', 'request_va', 'size', 'call_va', 'allocator_slot_va', 'null_branch_va', 'failure_va', 'failure_alignment', 'failure_size', 'failure_slot_va'), evidence['allocations'])
    write_tsv(out / 'relocations.tsv', ('slot_va', 'rela_file_offset', 'type', 'symbol', 'addend_va', 'target_section'), evidence['relocations'])
    write_json(out / 'function-bytes.json', evidence['bodies'])
    write_json(out / 'providers.json', evidence['providers'])
    write_json(out / 'execution-pairs.json', evidence['execution_pairs'])
    write_json(out / 'flow.json', evidence['flow'])
    write_json(out / 'unwind-records.json', evidence['unwind'])
    write_json(out / 'exception-sites.json', evidence['exceptions'])
    write_json(out / 'prior-boundaries.json', evidence['prior_boundaries'])
    write_json(out / 'summary.json', evidence['summary'])
    return evidence['summary']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    summary = generate(TARGET.read_bytes(), args.out)
    print(json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    main()
