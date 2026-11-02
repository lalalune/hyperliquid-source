"""Extract selected static state-codec evidence from the authenticated node #94 ELF."""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import fde_extents

SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/94/hl-node'
FUNCTIONS = {
    'messagepack_reader': 0x19bb570, 'json_reader': 0x1caa410,
    'nested_messagepack_reader': 0x181c4a0,
    'nested_json_reader': 0x1d06dc0,
    'messagepack_key_classifier': 0x26bff40, 'json_key_classifier': 0x26bffd0,
    'json_writer': 0x275dff0, 'messagepack_writer': 0x275e5c0,
    'outer_json_field_writer': 0x27b11b0, 'nested_default_predicate': 0x282fcc0,
    'outer_expected_formatter': 0x276bb50, 'nested_expected_formatter': 0x28e82a0,
    'nested_json_writer': 0x28e6540, 'nested_messagepack_writer': 0x28e6fa0,
    'time_pair_writer': 0x2201310, 'time_pair_key_adapter': 0x297a230,
    'time_pair_json_reader': 0x1cae020,
    'five_word_json_reader': 0x1cdf140, 'five_word_json_writer': 0x2978870,
    'five_word_compact_writer': 0x297a740,
}
# The eight sites in each writer are LEAs of the key, in wire order. The
# table address and sites were selected by instruction inspection, not a
# linear sweep or a claim to enumerate every serializer.
JSON_KEYS = (0x275e13d, 0x275e1dd, 0x275e224, 0x275e268,
             0x275e2ac, 0x275e2eb, 0x275e32a, 0x275e3ae)
MP_KEYS = (0x275e6c7, 0x275e71a, 0x275e763, 0x275e7b1,
           0x275e7fd, 0x275e84b, 0x275e89d, 0x275e8e6)
NESTED_JSON = (0x28e6798, 0x28e683f, 0x28e68e4, 0x28e6989, 0x28e6a3a,
               0x28e6a6a, 0x28e6a9a, 0x28e6afa, 0x28e6bc2)
NESTED_MP = (0x28e71fb, 0x28e7249, 0x28e7297, 0x28e72f8, 0x28e734a,
             0x28e7381, 0x28e73bb, 0x28e7421, 0x28e7499)
GROUP_JSON = (0x29789a5, 0x2978a48, 0x2978ae6, 0x2978b8f, 0x2978c35)
GROUP_MP = (0x297a821, 0x297a871, 0x297a8b7, 0x297a902, 0x297a940)
# These are disassembled instruction starts for the skip gates. Values and
# targets are decoded from the bytes, while the shapes must match exactly.
GATES = (
    (0x275e6bb, '4885db7444'),
    (0x275e704, '4885ed48bb00000000000000807444'),
    (0x275e757, '4d85ed7444'),
    (0x275e7a0, '4c8b6c24304d85ed7444'),
    (0x275e7ee, '48837c2428007446'),
    (0x275e83c, '48837c2420007446'),
    (0x275e88a, '4c89ffe82e140d0084c07544'),
    (0x275e8da, '4d85e4743c'),
)
# Complete small byte sequences supporting decisions that are not reducible
# to a single key LEA. No operands are masked.
PINS = {
 'outer_type_error_vtable': (0x1cab5cb, '488d158e249e03488d7424474c89f7e8f141e8ff'),
 'nested_type_error_vtable': (0x1d07e81, '488d15d8679803488db424870000004c89f7e83879e2ff'),
 'outer_value_forward': (0x27b1204, '4889df4c89f6e8e1cdfaff'),
 'json_nested_value_forward': (0x275e379, '4889df4c89f6e8bc811800'),
 'mp_nested_value_forward': (0x275e8bb, '488d7c24084c89fe4c89f2e8d5861800'),
 'json_nested_input_forward': (0x1caaa5d, '488d7c24684c89f6e856c30500'),
 'mp_nested_input_forward': (0x19bcf98, '488d7c24704989f631d2e8f9f4e5ff'),
 'scalar_count_setup': (0x275e5d8, '488b9ec8000000488baed00000004531e44885ed410f95c44883fb014183dcff4c8baed80000004983fd014183dcff488b86e000000048894424304883f8014183dcff488b86e800000048894424284883f8014183dcff488b86f000000048894424204883f8014183dcff4889f7e875160d0034010fb6d04401e24d8ba7f80000004983fc0183daff'),
 'named_or_sequence': (0x275e661, '41807e0b00743b'),
 'json_outer_key_dispatch': (0x1caa620, 'e8ab59a100807c2410010f84860a00000fb6442411488d0db8c270fe486304814801c8ffe0'),
 'mp_outer_key_dispatch': (0x19bd40b, '440fb67424104180fe090f85c30200000fb6442411488d0d15fb9bfe486304814801c8ffe0'),
 'json_map_flags_init': (0x1caa4d2, '48c74424080000000048c78424600100000000000048c74424300000000048c74424480000000048c78424500100000000000048c784245801000000000000c74424040000000048c784244801000000000000'),
 'json_map_scalar_defaults': (0x1caadfa, '31c0f644240801488b4c2428480f44c848894c2428f684246001000001488b8c2440020000480f44c8f644243001488b542450480f44d04889542450f644244801488b542460480f44d04889542460f684245001000001480f44e8f684245801000001488b542458480f44d04889542458837c24040048896c24487450'),
 'json_success_scalar_stores': (0x1cab21e, '4c89a3c80000004c89bbd000000048898bd8000000488b442460488983e0000000488b442448488983e8000000488b442458488983f0000000488b442430488983f8000000'),
 'mp_map_scalar_defaults': (0x19bc9ca, '31c0f644245001488b4c2448480f44c848894c2448f644243801488b8c24b0010000480f44c848898c24b0010000f684247001000001488b8c2490010000480f44c848898c2490010000f644244001488b8c24c0010000480f44c848898c24c0010000f644243001488b8c24a0010000480f44c848898c24a0010000f68424b002000001488b8c2480010000480f44c848898c2480010000f68424d0010000014c8bac24480300004c0f44e885ed'),
 'nested_default_header': (0x282fcc3, '4889fbbf3bf90a00ff15bfebf30285c00f842001000089c5bf3bf90a00ff15aaebf30285c00f840b01000089c131c0'),
 'nested_default_tail': (0x282fdc0, '48833b00752c396b087527837b0c00752131c0837b1000751948837b18007512394b20750d837b24007507837b28000f94c04883c4085b5dc3'),
 'json_last_scalar_default': (0x1caaf66, '31c0f684244801000001490f45c74889442430'),
 'json_zero_tn': (0x275e127, '4d85ed0f848c000000'),
 'json_zero_vn': (0x275e1c4, '4885ff74ae'),
 'json_zero_tc': (0x275e20a, '4885d20f846dffffff'),
 'json_zero_sc': (0x275e24e, '4d85ff0f8432ffffff'),
 'json_zero_to': (0x275e292, '4885c90f84f7feffff'),
 'json_zero_so': (0x275e2d1, '4d85e40f84c1feffff'),
 'json_skip_nested': (0x275e313, 'e8a8190d0084c00f858bfeffff'),
 'json_zero_ad': (0x275e395, '48837c2440007439'),
 'nested_writer_loads': (0x28e6fc1, '488b46304889442428488b46384889442448488b46404889442440488b46484889442438488b4658480b4650480b4660480b46680f94442407488b8680000000480b4678480b8688000000480b8690000000488b467048894424700f94442406488b86980000004889442468488b86a8000000480b86a0000000480b86b0000000480b86b80000000f94442405488b86c00000004889442460'),
 'nested_count_and_composite': (0x28e705a, 'bf3bf90a00ff152b78e80285c00f84e804000089c3498b2e458b7e08458b660c458b6e10bf3bf90a00ff150778e80285c00f84c404000044896424584585e40f95c248896c24784885ed0f95c131f648837c244800400f95c648837c24280183deff48837c24400183deff48837c24380183deff0fb67c24074080f70148837c247000410f95c04108f8410fb6f801f70fb67424064080f60148837c246800410f95c04108f0450fb6c00fb67424054080f60148837c246000410f95c14108f1410fb6f14401c601fe4489fd4139df400f95c708d14008f944896c245c4585ed0f95c208ca4d8b66184d85e40f95c1458b6e204139c50f95c0418b5e2485db400f95c7458b462844894424544585c0410f95c04008cf4008c70fb6c24408c7400fb6d701c201f2'),
 'nested_p_guard': (0x28e71e9, '48837c2428004189ed7446'),
 'nested_m_guard': (0x28e723a, '48837c2448007446'),
 'nested_l_guard': (0x28e7288, '48837c2440007446'),
 'nested_L_guard': (0x28e72e5, '48837c2438008b6c245c7446'),
 'nested_s_guard': (0x28e73df, 'bf3bf90a00ff15a674e80285c00f8463010000837c2458000f94c148837c2478000f94c24139c50f94c020ca20c285ed0f94c084c28b6c24347545'),
 'nested_t_guard': (0x28e745f, 'bf3bf90a00ff152674e80285c00f84e300000085db0f94c148837c2428000f94c239c50f94c020ca20c2837c2454000f94c084c27527'),
 'nested_p_result': (0x28e720a, 'e8e135ccff4883f8020f85b6020000488d7c24084c89fe488b542428e8a54eccff488b4424084883f8020f8590020000'),
 'nested_m_result': (0x28e7258, 'e89335ccff4883f8020f8568020000488d7c24084c89fe488b542448e8574eccff488b4424084883f8020f8542020000'),
 'nested_l_result': (0x28e72a6, 'e84535ccff4883f8020f851a020000488d7c24084c89fe488b542440e8094eccff488b4424084883f8020f85f4010000'),
 'nested_L_result': (0x28e7307, 'e8e434ccff4883f8020f8505020000488d7c24084c89fe488b542438e8a84dccff488b4424084883f8020f85df010000'),
 'nested_M_result': (0x28e7359, 'e8e2330900498d44240448394424080f8590010000'),
 'nested_b_result': (0x28e7390, 'e8ab330900498d44240448394424080f8559010000'),
 'nested_c_result': (0x28e73ca, 'e871330900498d44240448394424080f851f010000'),
 'nested_s_result': (0x28e7430, 'e8bb33ccff4883f8020f85e6000000488d7c24084c89f64c89fae8c19e91ff498d44240448394424080f85d5000000'),
 'nested_t_result': (0x28e74ab, 'e8802d0900498d44240448394424087542'),
 'group_json_dispatch': (0x1cdf324, '48837c2418010f85a0000000410fb6450083c09d83f8120f878f000000488d0d80786dfe486304814801c8ffe0'),
 'group_json_loads': (0x29788dc, '4c8b2b4c8b6308488b7310488b5318488b4320'),
 'group_json_t_gate': (0x297899c, '4d85ed0f849a000000'),
 'group_json_s_gate': (0x2978a3f, '4d85e40f8492000000'),
 'group_json_c_gate': (0x2978ada, '48837c2428000f849d000000'),
 'group_json_u_gate': (0x2978b83, '48837c2420000f849a000000'),
 'group_json_l_gate': (0x2978c29, '48837c2418000f849a000000'),
 'group_json_parent_M': (0x28e6a24, '4883bc2488000000000f94c08444240d751e488d5350488d35affdb0fd488d7c2410e8251e09004885c00f85b2020000'),
 'group_json_parent_b': (0x28e6a54, '4883bc2480000000000f94c08444240c751e488d5378488d3590fbb0fd488d7c2410e8f51d09004885c00f8582020000'),
 'group_json_parent_c': (0x28e6a84, '48837c2478000f94c08444240b7521488d93a0000000488d3550fdb0fd488d7c2410e8c51d09004885c00f8552020000'),
 'group_json_parent_b_read': (0x1d07441, 'e8fa7cfdff488b4424104889442478837c2408010f84ff080000'),
 'group_json_parent_M_read': (0x1d074a6, 'e8957cfdff488b442410837c2408010f8404050000'),
 'group_json_parent_c_read': (0x1d07568, 'e8d37bfdff488b442410837c2408010f8442040000'),
 'group_compact_count': (0x297a78d, '4d8b3c24498b6c240831d24885ed0f95c24983ff0183daff4d8b6c24104983fd0183daff498b4c241848894c24104883f90183daff4d8b6424204983fc0183daff'),
 'group_compact_fields': (0x297a815, '4d85ff744141807e0b01751e488d3597bda7fdba010000004c89f7e8bbffc2ff4883f8020f854b0100004889e74c89f64c89fae88318c3ff488b04244883f8020f852a0100004885ed49bf0000000000000080744141807e0b01751e488d3590bca7fdba010000004c89f7e86bffc2ff4883f8020f85f10000004889e74c89f64889eae83318c3ff488b04244883f8020f85d00000004d85ed744141807e0b01751e488d3533bfa7fdba010000004c89f7e825ffc2ff4883f8020f85ab0000004889e74c89f64c89eae8ed17c3ff488b04244883f8020f858a0000004c8b6c24104d85ed743941807e0b01751a488d356ebea7fdba010000004c89f7e8dafec2ff4883f80275644889e74c89f64c89eae8a617c3ff488b04244883f80275474d85e4743941807e0b01751a488d351ebca7fdba010000004c89f7e89cfec2ff4883f80275264889e74c89f64c89e2e86817c3ff488b04244883f8027509'),
 'time_pair_setup': (0x2201331, '4c8b26b81a40f6003346080b460c0f9444240f8b6e1031d209e80f95c24983fc0183daff'),
 'time_pair_n_gate': (0x22013a1, '4d85e47440'),
 'time_pair_t_gate': (0x22013e6, '85ed0f94c08444240f754c'),
 'time_pair_s_call': (0x28e743f, '488d7c24084c89f64c89fae8c19e91ff'),
 'time_pair_t_call': (0x28e7495, '4983c618488d151ff1b0fd488d7c24084c89fe4c89f1e8802d0900'),
 'time_pair_adapter': (0x297a230, '41574156534889cb4989f6807e0b00741f4889d0ba010000004989ff4c89f74889c6e89905c3ff4c89ff4883f80275104889de4c89f25b415e415fe9a07088ff'),
 'time_pair_json_dispatch': (0x1cae1d3, '48837c2410017575410fb6450083f86e0f84e400000083f8747562'),
 'time_pair_json_default': (0x1cae47b, '85ed4c8b7c24387518bf3bf90a00ff150104ac0385c00f841002000089c54531ff4531edf6442430014c0f456c2440'),
 'time_pair_json_s_result': (0x1d07513, '8b4c2440488b44243848890424894c245885c90f848f070000'),
 'time_pair_json_t_result': (0x1d075d5, '8b4c2440488b442438894c245485c90f84d5030000'),
 'time_pair_json_s_transition': (0x1d074ef, '4883fe3a0f85b50900004885c00f84640a000049894628488d7c24384c89f6e80d6bfaff'),
 'time_pair_json_t_transition': (0x1d075b1, '4883fe3a0f859d0900004885c00f84a209000049894628488d7c24384c89f6e84b6afaff'),
 'nested_M_guard': (0x28e7337, '48837c2470000f94c0844424077528498d4e50'),
 'nested_b_guard': (0x28e736e, '48837c2468000f94c0844424067528498d4e78'),
 'nested_c_guard': (0x28e73a5, '48837c2460000f94c084442405752b498d8ea0000000'),
 'nested_mp_key_dispatch': (0x181dea5, '4883fa010f85520300000fb60183c0b483f8280f8743030000488d0dcf5badfe486304814801c8ffe0'),
 'nested_mp_unknown': (0x181e201, '488dbc24080100004989f6ba01000000e8baa01400'),
 'nested_json_key_dispatch': (0x1d06fc6, '48837c2418010f859e0000000fb60083c0b483f8280f878f000000488d0da8fe6afe486304814801c8ffe0'),
 'nested_json_default_words_and_groups': (0x1d0778f, '4531fff68424c000000001488b442468490f44c7488944246841f6c501488b542470490f44d740f6c501488b442460490f44c7f68424c800000001488bac2440010000490f44eff68424b0000000014c8bac24380100004d0f44ef75130f57c00f298424200100000f29842410010000f68424a800000001488b742478490f44f7448b642458488b8c243001000075400f57c00f298424000100000f298424f0000000f68424b8000000014c0f45f9742d4585e4744048895424704889442460837c2454000f856c010000e993000000f68424b8000000014c0f45f975d30f57c00f298424e00000000f298424d0000000'),
 'nested_json_default_s': (0x1d0789b, 'bf3bf90a00ff15ea6fa60385c00f84ee06000089c1'),
 'nested_json_default_t': (0x1d078fa, 'bf3bf90a00ff158b6fa6038944245485c00f848b060000'),
 'json_ac_child_result': (0x1caaa65, 'e856c305008b442470488b4c24688944240485c00f84070b0000'),
 'json_nested_default_calls': (0x1caaecd, 'bf3bf90a00ff15b839ac038944240485c00f84d1070000bf3bf90a00ff15a139ac0385c00f84be070000'),
 'mp_unknown_value': (0x19bd47b, '488d7c24704989f6ba01000000e843aefaff807c247009'),
}
EDGES = {
 'outer_to_json_writer': 0x27b120a,
 'json_to_nested_writer': 0x275e37f,
 'mp_to_nested_writer': 0x275e8c6,
 'json_classifier': 0x1caa620,
 'mp_classifier': 0x19bd237,
 'json_nested_reader': 0x1caaa65,
 'mp_nested_reader': 0x19bcfa2,
 'mp_default_predicate': 0x275e646,
 'json_default_predicate': 0x275e03d,
 's_time_pair_writer': 0x28e744a, 't_time_pair_adapter': 0x28e74ab,
 's_time_pair_json_reader': 0x1d0750e, 't_time_pair_json_reader': 0x1d075d0,
 'M_group_json_reader': 0x1d074a6, 'b_group_json_reader': 0x1d07441,
 'c_group_json_reader': 0x1d07568,
 'M_group_json_writer': 0x28e6a46, 'b_group_json_writer': 0x28e6a76,
 'c_group_json_writer': 0x28e6aa6,
}
EXPECTED_EDGES = {
 'outer_to_json_writer': 0x275dff0, 'json_to_nested_writer': 0x28e6540,
 'mp_to_nested_writer': 0x28e6fa0, 'json_classifier': 0x26bffd0,
 'mp_classifier': 0x26bff40, 'json_nested_reader': 0x1d06dc0,
 'mp_nested_reader': 0x181c4a0, 'mp_default_predicate': 0x282fcc0,
 'json_default_predicate': 0x282fcc0,
 's_time_pair_writer': 0x2201310, 't_time_pair_adapter': 0x297a230,
 's_time_pair_json_reader': 0x1cae020, 't_time_pair_json_reader': 0x1cae020,
 'M_group_json_reader': 0x1cdf140, 'b_group_json_reader': 0x1cdf140,
 'c_group_json_reader': 0x1cdf140,
 'M_group_json_writer': 0x2978870, 'b_group_json_writer': 0x2978870,
 'c_group_json_writer': 0x2978870,
}


def authenticate(data, expected=SHA256):
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        raise ValueError('node #94 SHA-256 mismatch')
    return digest


class Image:
    def __init__(self, data):
        self.data = bytes(data)
        self.sections = sections(self.data)

    def offset(self, va, size):
        if va < 0 or size < 0:
            raise ValueError('negative address or size')
        found = [s for s in self.sections if s['type'] != 8 and
                 s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(found) != 1:
            raise ValueError('address does not map to exactly one file-backed section')
        return found[0]['offset'] + va - found[0]['address']

    def read(self, va, n):
        o = self.offset(va, n)
        return bytes(self.data[o:o+n])

    def check(self, va, raw, description):
        raw = bytes.fromhex(raw) if isinstance(raw, str) else raw
        got = self.read(va, len(raw))
        if got != raw:
            raise ValueError('unexpected bytes: ' + description)
        return got

    def rip(self, va, opcode):
        ins = self.read(va, 7)
        if ins[:3] != opcode:
            raise ValueError('unexpected RIP-relative instruction')
        return va + 7 + struct.unpack_from('<i', ins, 3)[0]

    def branch(self, va, opcode):
        if opcode in (b'\x74', b'\x75'):
            ins = self.read(va, 2)
            if ins[:1] != opcode:
                raise ValueError('unexpected short branch')
            return va + 2 + struct.unpack_from('<b', ins, 1)[0]
        ins = self.read(va, 6)
        if ins[:2] != opcode:
            raise ValueError('unexpected near branch')
        return va + 6 + struct.unpack_from('<i', ins, 2)[0]

    def jump(self, va):
        ins = self.read(va, 5)
        if ins[0] != 0xe9:
            raise ValueError('unexpected direct jump')
        return va + 5 + struct.unpack_from('<i', ins, 1)[0]

    def call(self, va):
        ins = self.read(va, 5)
        if ins[0] != 0xe8:
            raise ValueError('unexpected direct call')
        return va + 5 + struct.unpack_from('<i', ins, 1)[0]


def parse_classifier(im, start, result_tag):
    im.check(start, '4889f8b1084883fa027546', 'classifier length guard')
    names = []
    for i in range(8):
        site = start + 11 + i * 7
        instr = im.read(site, 5)
        if instr[:3] != b'\x66\x81\x3e':
            raise ValueError('classifier compare opcode')
        name = instr[3:5].decode('ascii')
        names.append(name)
        if i < 7:
            target = im.branch(site + 5, b'\x74')
            if i == 0:
                im.check(target, '31c9884801c600', 'classifier zero arm')
            else:
                im.check(target, bytes((0xb1, i, 0x88, 0x48, 0x01, 0xc6, 0x00)), 'classifier arm')
            if im.read(target + (7 if i else 7), 1)[0] != result_tag:
                raise ValueError('classifier result tag')
        else:
            im.check(site + 5, '0f94c2b10828d1884801c600', 'classifier final arm')
            if im.read(site + 17, 1)[0] != result_tag:
                raise ValueError('classifier final result tag')
    if len(set(names)) != 8:
        raise ValueError('duplicate classifier names')
    return names


def keys(im, sites, n):
    out = []
    for site in sites:
        # rsi and rdx are both used in the nested writer.
        first = im.read(site, 3)
        if first not in (b'\x48\x8d\x35', b'\x48\x8d\x15'):
            raise ValueError('key reference opcode')
        ptr = im.rip(site, first)
        out.append({'site': hex(site), 'literal_va': hex(ptr),
                    'key': im.read(ptr, n).decode('ascii')})
    return out


def table(im, table_va, function_start, function_end):
    result = []
    for i in range(9):
        delta = struct.unpack('<i', im.read(table_va + 4*i, 4))[0]
        dest = table_va + delta
        if not function_start <= dest < function_end:
            raise ValueError('dispatch target outside reader FDE')
        result.append(dest)
    return result


def duplicate_arm(im, at, key):
    head = im.read(at, 9)
    duplicate_if_equal = True
    if head[:4] == b'\x48\x83\x7c\x24' and head[5] == 1:
        size = 6
    elif head[:4] == b'\x48\x83\xbc\x24' and head[8] == 1:
        size = 9
    elif head[:3] == b'\x83\x7c\x24' and head[4] == 0:
        size = 5
        duplicate_if_equal = False
    elif head[:4] in (b'\x49\x83\xfd\x01', b'\x48\x83\xfd\x01'):
        size = 4
    elif head[:2] == b'\x85\xed':
        size = 2
        duplicate_if_equal = False
    elif head[:3] == b'\x45\x85\xed':
        size = 3
        duplicate_if_equal = False
    elif head[:3] == b'\x83\xbc\x24' and head[7] == 0:
        size = 8
        duplicate_if_equal = False
    else:
        raise ValueError('unexpected duplicate presence test')
    at_branch = at + size
    lead = im.read(at_branch, 2)
    if lead[:1] in (b'\x74', b'\x75'):
        if (lead[0] == 0x74) != duplicate_if_equal:
            raise ValueError('unexpected duplicate branch condition')
        dest = im.branch(at_branch, lead[:1])
    elif lead in (b'\x0f\x84', b'\x0f\x85'):
        if (lead[1] == 0x84) != duplicate_if_equal:
            raise ValueError('unexpected duplicate branch condition')
        dest = im.branch(at_branch, lead)
    else:
        raise ValueError('unexpected duplicate branch')
    ptr = im.rip(dest, b'\x48\x8d\x05')
    if im.read(ptr, len(key)).decode('ascii') != key:
        raise ValueError('duplicate diagnostic key mismatch')
    return {'arm': hex(at), 'presence_test': im.read(at, size).hex(),
            'branch': hex(at_branch), 'duplicate_target': hex(dest),
            'diagnostic_va': hex(ptr)}


def nested_zero_offsets(im):
    pos = 0x282fcf2
    offsets, branches = [], []
    while pos < 0x282fdc0:
        if pos == 0x282fdb4:
            im.check(pos, '31c0', 'nested accumulator reset')
            pos += 2
        prefix = im.read(pos, 3)
        if prefix == b'\x48\x83\x7b':
            ins = im.read(pos, 5)
            if ins[4] != 0:
                raise ValueError('nested zero comparison')
            offset, size = ins[3], 5
        elif prefix == b'\x48\x83\xbb':
            ins = im.read(pos, 8)
            if ins[7] != 0:
                raise ValueError('nested zero comparison')
            offset, size = struct.unpack_from('<I', ins, 3)[0], 8
        else:
            raise ValueError('nested zero comparison opcode')
        br = pos + size
        lead = im.read(br, 2)
        if lead == b'\x0f\x85':
            target, length = im.branch(br, lead), 6
        elif lead[0] == 0x75:
            target, length = im.branch(br, b'\x75'), 2
        else:
            raise ValueError('nested zero comparison branch')
        if target != 0x282fdf2:
            raise ValueError('nested default branch target')
        offsets.append(offset)
        branches.append({'site': hex(br), 'target': hex(target)})
        pos = br + length
    if offsets != list(range(0x30, 0xc8, 8)) or pos != 0x282fdc0:
        raise ValueError('nested zero comparison span')
    return offsets, branches


def relocation(im, slot):
    rels = [s for s in im.sections if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(rels) != 1 or rels[0]['size'] % 24:
        raise ValueError('unexpected relocation section')
    s = rels[0]
    hits = []
    for off in range(s['offset'], s['offset'] + s['size'], 24):
        addr, info, addend = struct.unpack_from('<QQq', im.data, off)
        if addr == slot:
            hits.append((info, addend))
    if len(hits) != 1 or hits[0][0] != 8:
        raise ValueError('expected one R_X86_64_RELATIVE relocation')
    return hits[0][1]


def expected_type(im, lea_site, formatter, expected_text):
    # A selected error path supplies this vtable to the generic formatter.
    vtable = im.rip(lea_site, b'\x48\x8d\x15')
    if struct.unpack('<QQQ', im.read(vtable, 24)) != (0, 0, 1):
        raise ValueError('unexpected expected-value vtable header')
    slot = vtable + 24
    if relocation(im, slot) != formatter:
        raise ValueError('expected-value formatter relocation mismatch')
    im.check(formatter, '488b3e488b4608488b4018', 'expected-value formatter head')
    string_va = im.rip(formatter + 11, b'\x48\x8d\x35')
    length_instruction = im.read(formatter + 18, 5)
    if length_instruction[0] != 0xba:
        raise ValueError('expected-value formatter length opcode')
    length = struct.unpack_from('<I', length_instruction, 1)[0]
    im.check(formatter + 23, 'ffe0', 'expected-value formatter tail jump')
    literal = im.read(string_va, length).decode('ascii')
    if literal != expected_text:
        raise ValueError('expected-value text mismatch')
    return {'reader_lea': hex(lea_site), 'vtable': hex(vtable),
            'formatter_slot': hex(slot), 'formatter': hex(formatter),
            'literal_va': hex(string_va), 'length': length, 'text': literal}


def evaluate_classifier(names, key):
    if not isinstance(key, bytes):
        raise TypeError('key must be bytes')
    if len(key) != 2:
        return 8
    return next((i for i, name in enumerate(names) if key == name.encode('ascii')), 8)


def nested_default(qwords, first, date_word_1, second, date_word_2):
    """Model the selected predicate, conditional on two nonzero helper returns.

    first/second are (u64, u32, u32, u32); date_word values are the two
    observed helper returns. qwords correspond to offsets +0x30..+0xc0.
    """
    if len(qwords) != 19 or len(first) != 4 or len(second) != 4:
        raise ValueError('unexpected nested input shape')
    values = [*qwords, *first, *second, date_word_1, date_word_2]
    if any(type(v) is not int or v < 0 or v >= 1 << 64 for v in values):
        raise ValueError('out-of-range nested input')
    if any(v >= 1 << 32 for v in (*first[1:], *second[1:], date_word_1, date_word_2)):
        raise ValueError('out-of-range 32-bit input')
    if date_word_1 == 0 or date_word_2 == 0:
        raise ValueError('predicate reaches helper-failure branch')
    return (not any(qwords) and tuple(first) == (0, date_word_1, 0, 0)
            and tuple(second) == (0, date_word_2, 0, 0))


def name_written(test, flag):
    if not 0 <= flag <= 255:
        raise ValueError('flag out of range')
    immediate, jump = test
    if jump == 0x75:
        return flag == immediate
    if jump == 0x74:
        return flag != immediate
    raise ValueError('unsupported name-test branch')


def time_pair_presence(word, word_8, word_c, word_10, default_date):
    values = (word, word_8, word_c, word_10, default_date)
    if any(type(v) is not int or v < 0 for v in values):
        raise ValueError('negative or non-integer time pair input')
    if word >= 1 << 64 or any(v >= 1 << 32 for v in values[1:]):
        raise ValueError('time pair input out of range')
    return [name for name, include in (('n', word != 0),
            ('t', word_8 != default_date or word_c != 0 or word_10 != 0)) if include]


def five_word_presence(words):
    if len(words) != 5 or any(type(v) is not int or not 0 <= v < 1 << 64 for v in words):
        raise ValueError('expected five unsigned 64-bit words')
    return [name for name, value in zip(('t', 's', 'c', 'u', 'l'), words) if value]


def selected_fields(values, is_nested_default):
    if len(values) != 7 or any(type(v) is not int or not 0 <= v < 1 << 64 for v in values):
        raise ValueError('expected seven unsigned 64-bit values')
    if type(is_nested_default) is not bool:
        raise ValueError('nested default flag must be boolean')
    flags = [v != 0 for v in values[:6]] + [not is_nested_default, values[6] != 0]
    return [i for i, flag in enumerate(flags) if flag]


def analyze(data, expected=SHA256):
    # Authenticate and parse one immutable snapshot, including for callers
    # that supply a writable bytearray.
    data = bytes(data)
    digest = authenticate(data, expected)
    im = Image(data)
    _, all_fdes, _ = fde_extents(data)
    fdes = {f['start']: f for f in all_fdes if f['start'] in FUNCTIONS.values()}
    if set(fdes) != set(FUNCTIONS.values()):
        raise ValueError('missing selected FDE')
    functions = []
    for role, start in FUNCTIONS.items():
        f = fdes[start]
        body = im.read(start, f['end'] - start)
        functions.append({'role': role, 'start': hex(start), 'end': hex(f['end']),
                          'fde': hex(f['fde']), 'file_offset': hex(im.offset(start, len(body))),
                          'body_sha256': hashlib.sha256(body).hexdigest()})
    pins = []
    for role, (va, expected_bytes) in PINS.items():
        data_at = im.check(va, expected_bytes, role)
        pins.append({'role': role, 'va': hex(va), 'file_offset': hex(im.offset(va, len(data_at))),
                     'bytes': data_at.hex()})
    for va, raw in GATES:
        im.check(va, raw, 'writer omission gate')
    calls = []
    for role, va in EDGES.items():
        dst = im.call(va)
        if dst != EXPECTED_EDGES[role]:
            raise ValueError('direct call target mismatch: ' + role)
        calls.append({'role': role, 'site': hex(va), 'target': hex(dst), 'bytes': im.read(va, 5).hex()})
    expected_types = [
        expected_type(im, 0x1cab5cb, 0x276bb50, 'struct ExchangeCounters'),
        expected_type(im, 0x1d07e81, 0x28e82a0, 'struct AbstractionCounters'),
    ]
    outer_ptr = im.rip(0x27b11c4, b'\x48\x8d\x35')
    outer_name = im.read(outer_ptr, 3).decode('ascii')
    if outer_name != 'ctr':
        raise ValueError('unexpected outer field')
    a = parse_classifier(im, FUNCTIONS['messagepack_key_classifier'], 9)
    c = parse_classifier(im, FUNCTIONS['json_key_classifier'], 0)
    j = keys(im, JSON_KEYS, 2)
    m = keys(im, MP_KEYS, 2)
    if a != c or [x['key'] for x in j] != a or [x['key'] for x in m] != a:
        raise ValueError('key copies disagree')
    nested_j, nested_m = keys(im, NESTED_JSON, 1), keys(im, NESTED_MP, 1)
    if [x['key'] for x in nested_j] != [x['key'] for x in nested_m]:
        raise ValueError('nested writer keys disagree')
    # Read the 8-bit subtraction and unsigned upper bound from both pinned
    # dispatch sequences; their table indices are byte - minimum.
    json_min = (-im.read(0x1d06fd7, 1)[0]) & 0xff
    json_slots = im.read(0x1d06fda, 1)[0] + 1
    mp_min = (-im.read(0x181deb4, 1)[0]) & 0xff
    mp_slots = im.read(0x181deb7, 1)[0] + 1
    if (json_min, json_slots) != (mp_min, mp_slots):
        raise ValueError('nested reader dispatch bounds disagree')
    nested_base = im.rip(0x1d06fe1, b'\x48\x8d\x0d')
    nested_targets = []
    for i in range(json_slots):
        delta = struct.unpack('<i', im.read(nested_base + 4*i, 4))[0]
        dest = nested_base + delta
        if not fdes[0x1d06dc0]['start'] <= dest < fdes[0x1d06dc0]['end']:
            raise ValueError('nested JSON dispatch target outside reader FDE')
        nested_targets.append(dest)
    nested_names = [x['key'] for x in nested_j]
    nested_reader_arms = [duplicate_arm(im, nested_targets[ord(k) - json_min], k) for k in nested_names]
    other = [nested_targets[i] for i in range(json_slots) if chr(i + json_min) not in nested_names]
    if len(set(other)) != 1:
        raise ValueError('nested unknown-key dispatch disagreement')
    nested_mp_base = im.rip(0x181debe, b'\x48\x8d\x0d')
    nested_mp_targets = []
    for i in range(mp_slots):
        dest = nested_mp_base + struct.unpack('<i', im.read(nested_mp_base + 4*i, 4))[0]
        if not fdes[0x181c4a0]['start'] <= dest < fdes[0x181c4a0]['end']:
            raise ValueError('nested MessagePack dispatch target outside reader FDE')
        nested_mp_targets.append(dest)
    nested_mp_reader_arms = [duplicate_arm(im, nested_mp_targets[ord(k) - mp_min], k) for k in nested_names]
    mp_other = [nested_mp_targets[i] for i in range(mp_slots) if chr(i + mp_min) not in nested_names]
    if len(set(mp_other)) != 1:
        raise ValueError('nested MessagePack unknown-key dispatch disagreement')
    jt = table(im, 0x3b68f4, fdes[0x1caa410]['start'], fdes[0x1caa410]['end'])
    mt = table(im, 0x37cf3c, fdes[0x19bb570]['start'], fdes[0x19bb570]['end'])
    # The classifier gives 0..7 for keys and 8 for unknown. Each known arm
    # starts with its own presence test and duplicate diagnostic branch.
    rows = []
    for i, key in enumerate(a):
        jr = duplicate_arm(im, jt[i], key)
        mr = duplicate_arm(im, mt[i], key)
        off = None
        if i < 6:
            va = JSON_KEYS[i] - 7
            ins = im.read(va, 7)
            if ins[:3] != b'\x48\x8d\x8b':
                raise ValueError('scalar field address shape')
            off = struct.unpack_from('<I', ins, 3)[0]
        elif i == 7:
            im.check(0x275e3a7, '4881c3f8000000', 'last scalar offset')
            off = struct.unpack('<I', im.read(0x275e3aa, 4))[0]
        json_call_site = JSON_KEYS[i] + (20 if i == 7 else 17)
        json_target = im.call(json_call_site)
        if json_target != (0x2974190 if i == 6 else 0x2958170):
            raise ValueError('JSON writer field call mismatch')
        if i == 6:
            im.check(json_call_site + 5, '807c240801', 'JSON name writer status')
            json_fail = im.branch(json_call_site + 10, b'\x0f\x84')
            if json_fail != 0x275e543:
                raise ValueError('JSON nested field failure target')
        else:
            im.check(json_call_site + 5, '4885c0', 'JSON field result test')
            branch_at = json_call_site + 8
            if i == 0:
                im.check(branch_at, '4c8b7c2428', 'first JSON field reload')
                branch_at += 5
            json_fail = im.branch(branch_at, b'\x0f\x85')
            if json_fail != 0x275e4a3:
                raise ValueError('JSON field failure target')
        mp_call_site = MP_KEYS[i] + 15
        if im.call(mp_call_site) != 0x25aa7f0:
            raise ValueError('MessagePack field-name call mismatch')
        im.check(mp_call_site + 5, '4883f802', 'field-name call result test')
        fail_site = mp_call_site + 9
        fail_prefix = im.read(fail_site, 2)
        fail_target = im.branch(fail_site, b'\x75' if fail_prefix[0] == 0x75 else b'\x0f\x85')
        if fail_target != (0x275e93b, 0x275e92d, 0x275e92d, 0x275e92d,
                           0x275e92d, 0x275e92d, 0x275e966, 0x275e92d)[i]:
            raise ValueError('field-name failure target mismatch')
        name_gate = im.read(MP_KEYS[i] - 7, 7)
        if name_gate[:4] != b'\x41\x80\x7e\x0b' or name_gate[5] not in (0x74, 0x75):
            raise ValueError('messagepack field-name test')
        test = (name_gate[4], name_gate[5])
        skip = im.branch(MP_KEYS[i] - 2, bytes((test[1],)))
        fail_len = 2 if fail_prefix[0] == 0x75 else 6
        if skip != fail_site + fail_len:
            raise ValueError('field-name skip target mismatch')
        if [name_written(test, f) for f in (0, 1)] != [False, True]:
            raise ValueError('messagepack canonical flag behavior')
        rows.append({'index': i, 'key': key, 'name_gate_bytes': name_gate.hex(),
                     'name_written_for_flags_0_1_2': [name_written(test, f) for f in (0, 1, 2)],
                     'json_field_call': hex(json_call_site), 'json_field_target': hex(json_target), 'json_field_failure': hex(json_fail),
                     'mp_name_call': hex(mp_call_site), 'mp_name_failure': hex(fail_target), 'mp_name_skip': hex(skip), 'state_offset': None if off is None else hex(off),
                     'json_write': j[i], 'messagepack_write': m[i],
                     'json_reader': jr, 'messagepack_reader': mr,
                     'presence_rule': 'nested predicate returns zero' if i == 6 else '64-bit word is nonzero'})
    if [r['name_written_for_flags_0_1_2'][2] for r in rows] != [False,False,False,False,True,True,False,True]:
        raise ValueError('messagepack noncanonical flag behavior')
    if [r['state_offset'] for r in rows] != ['0xc8','0xd0','0xd8','0xe0','0xe8','0xf0',None,'0xf8']:
        raise ValueError('unexpected scalar offset order')
    scalar_calls = (0x275e6f0, 0x275e743, 0x275e78c, 0x275e7da, 0x275e828, 0x275e876, 0x275e90b)
    scalar_failures = []
    for i, va in enumerate(scalar_calls):
        if im.call(va) != 0x25ac0d0:
            raise ValueError('MessagePack scalar writer mismatch')
        im.check(va + 5, '488b4424084883f802', 'scalar writer result test')
        op = im.read(va + 14, 2)
        dest = im.branch(va + 14, b'\x75' if op[0] == 0x75 else b'\x0f\x85')
        if dest != (0x275e936 if i == 0 else 0x275e928):
            raise ValueError('scalar writer failure target mismatch')
        scalar_failures.append({'call': hex(va), 'failure': hex(dest)})
    im.check(0x275e8cb, '488d43044839442408', 'nested writer result test')
    if im.branch(0x275e8d4, b'\x0f\x85') != 0x275e975:
        raise ValueError('nested writer failure target mismatch')
    if im.jump(0x297a26b) != 0x2201310:
        raise ValueError('time pair adapter target mismatch')
    packed_default = struct.unpack('<I', im.read(0x2201335, 4))[0]
    tuple_key_n = im.read(im.rip(0x22013ad, b'\x48\x8d\x35'), 1).decode('ascii')
    tuple_key_t = im.read(im.rip(0x22013f8, b'\x48\x8d\x35'), 1).decode('ascii')
    time_type = im.read(im.rip(0x2201416, b'\x48\x8d\x15'), 4).decode('ascii')
    if (tuple_key_n, tuple_key_t, time_type) != ('n', 't', 'Time'):
        raise ValueError('time pair field literals')
    if (im.branch(0x22013a4, b'\x74') != 0x22013e6 or
            im.branch(0x22013ef, b'\x75') != 0x220143d):
        raise ValueError('time pair omission branch')
    if (im.call(0x22013d6) != 0x25ac0d0 or im.call(0x220142d) != 0x1e4fc10):
        raise ValueError('time pair child call')
    if (im.branch(0x22013c5, b'\x0f\x85') != 0x220144b or
            im.branch(0x22013e4, b'\x75') != 0x2201446 or
            im.branch(0x2201410, b'\x75') != 0x2201458 or
            im.branch(0x220143b, b'\x75') != 0x2201467):
        raise ValueError('time pair error branch')
    if (im.branch(0x1cae1d9, b'\x75') != 0x1cae250 or
            im.branch(0x1cae1e3, b'\x0f\x84') != 0x1cae2cd or
            im.branch(0x1cae1ec, b'\x75') != 0x1cae250):
        raise ValueError('time pair JSON dispatch branch')
    pair_reader_arms = [duplicate_arm(im, 0x1cae2cd, 'n'),
                        duplicate_arm(im, 0x1cae1ee, 't')]
    if (im.call(0x1cae387) != 0x1b2fae0 or im.call(0x1cae352) != 0x1be9a20 or
            im.branch(0x1cae38e, b'\x0f\x85') != 0x1cae5ab or
            im.branch(0x1cae35b, b'\x0f\x84') != 0x1cae5cc):
        raise ValueError('time pair JSON value error branch')
    im.check(0x1cae38c, 'a801', 'n child result test')
    im.check(0x1cae357, '833c2401', 't child result test')
    if (im.branch(0x1cae491, b'\x0f\x84') != 0x1cae6a7 or
            im.branch(0x1d07526, b'\x0f\x84') != 0x1d07cbb or
            im.branch(0x1d075e4, b'\x0f\x84') != 0x1d079bf):
        raise ValueError('time pair JSON default or parent error branch')
    if (im.branch(0x1d072dc, b'\x0f\x83') != 0x1d074ef or
            im.branch(0x1d07403, b'\x0f\x83') != 0x1d075b1):
        raise ValueError('time pair JSON parent arm transition')
    offsets, checks = nested_zero_offsets(im)
    # The nested writer loads these same consecutive words and gates each
    # three five-word groups as a unit; the fixed-load and gate pins above
    # validate that correspondence. The final two fields use tuple bases.
    nested_layout = [[offsets[i]] for i in range(4)] + [offsets[4:9], offsets[9:14], offsets[14:19], [0], [im.read(0x282fddc, 1)[0]]]
    if nested_layout[-1] != [0x18]:
        raise ValueError('second nested tuple base')
    nested_gates = [(0x28e71f2, 0x28e723a), (0x28e7240, 0x28e7288),
                    (0x28e728e, 0x28e72d6), (0x28e72ef, 0x28e7337),
                    (0x28e7344, 0x28e736e), (0x28e737b, 0x28e73a5),
                    (0x28e73b2, 0x28e73df), (0x28e7418, 0x28e745f),
                    (0x28e7493, 0x28e74bc)]
    for i, (site, target) in enumerate(nested_gates):
        if im.branch(site, b'\x74' if i < 4 else b'\x75') != target:
            raise ValueError('nested writer omission branch')
    for site in (0x28e7067, 0x28e708b, 0x28e73ec, 0x28e746c):
        if im.branch(site, b'\x0f\x84') != 0x28e7555:
            raise ValueError('nested writer default helper failure')
    nested_failures = []
    for name_site, value_site, name_failure, value_failure in (
            (0x28e720a, 0x28e7226, 0x28e74cf, 0x28e74ca),
            (0x28e7258, 0x28e7274, 0x28e74cf, 0x28e74ca),
            (0x28e72a6, 0x28e72c2, 0x28e74cf, 0x28e74ca),
            (0x28e7307, 0x28e7323, 0x28e751b, 0x28e7516)):
        if (im.call(name_site) != 0x25aa7f0 or im.call(value_site) != 0x25ac0d0 or
                im.branch(name_site + 9, b'\x0f\x85') != name_failure or
                im.branch(value_site + 14, b'\x0f\x85') != value_failure):
            raise ValueError('nested scalar writer error branch')
        nested_failures.append({'name_call': hex(name_site), 'name_failure': hex(name_failure),
                                'value_call': hex(value_site), 'value_failure': hex(value_failure)})
    for site in (0x28e7359, 0x28e7390, 0x28e73ca):
        if im.call(site) != 0x297a740 or im.branch(site + 15, b'\x0f\x85') != 0x28e74fe:
            raise ValueError('nested group writer error branch')
        nested_failures.append({'value_call': hex(site), 'value_failure': hex(0x28e74fe)})
    if (im.call(0x28e7430) != 0x25aa7f0 or
            im.branch(0x28e7439, b'\x0f\x85') != 0x28e7525 or
            im.branch(0x28e7459, b'\x0f\x85') != 0x28e7534 or
            im.branch(0x28e74ba, b'\x75') != 0x28e74fe):
        raise ValueError('nested tuple writer error branch')
    nested_failures.extend([
        {'name_call': hex(0x28e7430), 'name_failure': hex(0x28e7525),
         'value_call': hex(0x28e744a), 'value_failure': hex(0x28e7534)},
        {'value_call': hex(0x28e74ab), 'value_failure': hex(0x28e74fe)},
    ])
    group_j, group_m = keys(im, GROUP_JSON, 1), keys(im, GROUP_MP, 1)
    group_names = [row['key'] for row in group_j]
    if group_names != ['t', 's', 'c', 'u', 'l'] or group_names != [row['key'] for row in group_m]:
        raise ValueError('five-word writer keys disagree')
    group_min = (-im.read(0x1cdf337, 1)[0]) & 0xff
    group_count = im.read(0x1cdf33a, 1)[0] + 1
    group_base = im.rip(0x1cdf341, b'\x48\x8d\x0d')
    group_targets = []
    for i in range(group_count):
        dest = group_base + struct.unpack('<i', im.read(group_base + 4*i, 4))[0]
        if not fdes[0x1cdf140]['start'] <= dest < fdes[0x1cdf140]['end']:
            raise ValueError('five-word JSON target outside reader FDE')
        group_targets.append(dest)
    group_other = [group_targets[i] for i in range(group_count) if chr(i + group_min) not in group_names]
    if (group_min, group_count) != (ord('c'), 19) or len(set(group_other)) != 1:
        raise ValueError('five-word JSON dispatch')
    group_arms = [duplicate_arm(im, group_targets[ord(k) - group_min], k) for k in group_names]
    group_rows = []
    for i, (jrow, mrow, arm, skip, skip_target, name_site, value_site) in enumerate(zip(
            group_j, group_m, group_arms,
            (0x297a818, 0x297a868, 0x297a8ae, 0x297a8f9, 0x297a937),
            (0x297a85b, 0x297a8ab, 0x297a8f1, 0x297a934, 0x297a972),
            (0x297a830, 0x297a880, 0x297a8c6, 0x297a911, 0x297a94f),
            (0x297a848, 0x297a898, 0x297a8de, 0x297a925, 0x297a963))):
        if (im.branch(skip, b'\x74') != skip_target or im.call(name_site) != 0x25aa7f0 or
                im.call(value_site) != 0x25ac0d0 or im.call(GROUP_JSON[i] + 15) != 0x2974190):
            raise ValueError('five-word writer branch or call')
        name_failure = im.branch(name_site + 9, b'\x0f\x85' if i < 3 else b'\x75')
        value_failure = im.branch(value_site + 13, b'\x0f\x85' if i < 3 else b'\x75')
        json_failure = im.branch(GROUP_JSON[i] + 24, b'\x0f\x84')
        if (name_failure != (0x297a98a if i == 0 else 0x297a980) or
                value_failure != (0x297a985 if i == 0 else 0x297a97b) or json_failure != 0x2978dc8):
            raise ValueError('five-word writer failure branch')
        group_rows.append({'key': group_names[i], 'offset': hex(8*i), 'json': jrow, 'compact': mrow,
                           'json_reader': arm, 'compact_omission_branch': hex(skip),
                           'compact_omission_target': hex(skip_target),
                           'name_failure': hex(name_failure), 'value_failure': hex(value_failure),
                           'json_name_failure': hex(json_failure)})
    for site, expected in ((0x1d07455, 0x1d07d5a), (0x1d074b5, 0x1d079bf),
                           (0x1d07577, 0x1d079bf)):
        if im.branch(site, b'\x0f\x84') != expected:
            raise ValueError('five-word parent reader error branch')
    for site, expected in ((0x1d0713d, 0x1d07422), (0x1d0720c, 0x1d07487),
                           (0x1d07338, 0x1d07549)):
        if im.branch(site, b'\x0f\x83') != expected:
            raise ValueError('five-word parent reader arm')
    for site in (0x28e6a4e, 0x28e6a7e, 0x28e6aae):
        if im.branch(site, b'\x0f\x85') != 0x28e6d06:
            raise ValueError('five-word parent writer error branch')
    helper_args = []
    for va in (0x282fcc6, 0x282fcdb):
        ins = im.read(va, 11)
        if ins[0] != 0xbf or ins[5:7] != b'\xff\x15':
            raise ValueError('nested helper call shape')
        arg = struct.unpack_from('<I', ins, 1)[0]
        slot = va + 11 + struct.unpack_from('<i', ins, 7)[0]
        helper_args.append({'site': hex(va), 'argument': arg, 'slot': hex(slot),
                            'relocation_addend': hex(relocation(im, slot))})
    if helper_args[0]['argument'] != helper_args[1]['argument'] or helper_args[0]['slot'] != helper_args[1]['slot']:
        raise ValueError('nested helper calls disagree')
    gates = [{'site': hex(va), 'bytes': im.read(va, len(bytes.fromhex(raw))).hex()} for va, raw in GATES]
    scenarios = []
    for label, values, default in [
        ('all_default', [0]*7, True),
        ('all_scalars', [1]*7, True),
        ('nested_only', [0]*7, False),
        ('all_present', [1]*7, False),
        ('u64_max_first_last', [(1<<64)-1,0,0,0,0,0,(1<<64)-1], True),
    ]:
        indexes = selected_fields(values, default)
        scenarios.append({'case': label, 'words': [hex(v) for v in values], 'nested_default': default,
                          'emitted_keys': [a[i] for i in indexes]})
    return {'binary_sha256': digest, 'coordinate': 'linked ELF virtual address; exclusive FDE end',
            'functions': functions, 'expected_types': expected_types, 'outer_field': {'key': outer_name, 'literal_va': hex(outer_ptr)},
            'calls': calls, 'fields': rows, 'nested_writer_fields': [
                {'index': i, 'key': row['key'], 'state_offsets': [hex(x) for x in nested_layout[i]],
                 'omission_branch': hex(nested_gates[i][0]), 'omission_target': hex(nested_gates[i][1]),
                 'compact_failure': nested_failures[i], 'json': row, 'messagepack': nested_m[i],
                 'json_reader': nested_reader_arms[i], 'messagepack_reader': nested_mp_reader_arms[i]}
                for i, row in enumerate(nested_j)],
            'nested_messagepack_dispatch': {'table': hex(nested_mp_base), 'minimum_byte': mp_min, 'slot_count': len(nested_mp_targets), 'unknown_target': hex(mp_other[0]), 'targets': [hex(x) for x in nested_mp_targets]},
            'nested_json_dispatch': {'table': hex(nested_base), 'minimum_byte': json_min, 'slot_count': len(nested_targets), 'unknown_target': hex(other[0]), 'targets': [hex(x) for x in nested_targets]},
            'reader_unknown_arms': {'json': hex(jt[8]), 'messagepack': hex(mt[8])},
            'five_word_fields': group_rows,
            'five_word_json_dispatch': {'table': hex(group_base), 'minimum_byte': group_min,
                'slot_count': group_count, 'unknown_target': hex(group_other[0]),
                'targets': [hex(x) for x in group_targets]},
            'time_pair': {'keys': [tuple_key_n, tuple_key_t], 'type_literal': time_type,
                          'packed_default': hex(packed_default),
                          'default_immediate_site': hex(0x2201335),
                          'writer': hex(0x2201310), 'adapter': hex(0x297a230),
                          's_call': hex(0x28e744a), 't_call': hex(0x28e74ab),
                          'json_reader': hex(0x1cae020), 'json_reader_duplicate_arms': pair_reader_arms,
                          'json_reader_default_call': hex(0x1cae489),
                          'json_reader_default_failure': hex(0x1cae6a7)},
            'nested_default': {'zero_qword_offsets': [hex(o) for o in offsets],
                               'zero_branches': checks, 'helper_calls': helper_args},
            'writer_gates': gates, 'mp_scalar_calls': scalar_failures, 'pins': pins, 'synthetic_scenarios': scenarios}


def tsv(rows, columns):
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(columns)
    writer.writerows(rows)
    return out.getvalue().encode()


def generate(data, out):
    evidence = analyze(data)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'evidence.json').write_text(json.dumps(evidence, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    rows = evidence['fields']
    (out / 'fields.tsv').write_bytes(tsv([
        (r['index'], r['key'], r['state_offset'] or 'nested at base', r['presence_rule'],
         ''.join('1' if x else '0' for x in r['name_written_for_flags_0_1_2']), r['json_write']['site'], r['messagepack_write']['site'], r['json_reader']['arm'],
         r['json_reader']['duplicate_target'], r['messagepack_reader']['arm'],
         r['messagepack_reader']['duplicate_target']) for r in rows],
        ('index','key','state_offset','writer_presence','name_at_flags_0_1_2','json_writer_lea','msgpack_writer_lea',
         'json_reader_arm','json_duplicate','msgpack_reader_arm','msgpack_duplicate')))
    (out / 'nested-fields.tsv').write_bytes(tsv([
        (r['index'], r['key'], ','.join(r['state_offsets']), r['json']['site'],
         r['messagepack']['site'], r['omission_branch'], r['omission_target'],
         r['compact_failure'].get('name_failure', ''), r['compact_failure']['value_failure'],
         r['json_reader']['arm'], r['json_reader']['duplicate_target'],
         r['messagepack_reader']['arm'], r['messagepack_reader']['duplicate_target'])
        for r in evidence['nested_writer_fields']],
        ('index','key','state_offsets','json_writer_lea','msgpack_writer_lea',
         'compact_omission_branch','compact_omission_target','compact_name_failure','compact_value_failure',
         'json_reader_arm','json_duplicate','msgpack_reader_arm','msgpack_duplicate')))
    (out / 'five-word-fields.tsv').write_bytes(tsv([
        (r['key'], r['offset'], r['json']['site'], r['compact']['site'],
         r['compact_omission_branch'], r['compact_omission_target'],
         r['name_failure'], r['value_failure'], r['json_name_failure'],
         r['json_reader']['arm'], r['json_reader']['duplicate_target'])
        for r in evidence['five_word_fields']],
        ('key','group_offset','json_writer_lea','compact_writer_lea',
         'compact_omission_branch','compact_omission_target','compact_name_failure',
         'compact_value_failure','json_name_failure','json_reader_arm','json_duplicate')))
    default = int(evidence['time_pair']['packed_default'], 16)
    pairs = [
        ('default', 0, default, 0, 0),
        ('n_only', 1, default, 0, 0),
        ('word_8_changed', 0, default ^ 1, 0, 0),
        ('word_c_nonzero', 0, default, 1, 0),
        ('word_10_nonzero', 0, default, 0, 1),
        ('both', 1, default, 0, 1),
    ]
    (out / 'time-pair-scenarios.tsv').write_bytes(tsv([
        (label, hex(word), hex(date), hex(sec), hex(ns),
         ','.join(time_pair_presence(word, date, sec, ns, default)))
        for label, word, date, sec, ns in pairs],
        ('case','n_word','word_8','word_c','word_10','selected_keys')))
    (out / 'scenarios.tsv').write_bytes(tsv([
        (r['case'], ','.join(r['words']), str(r['nested_default']).lower(), ','.join(r['emitted_keys']))
        for r in evidence['synthetic_scenarios']], ('case','scalar_words','nested_default','emitted_keys')))
    return evidence


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    generate(BINARY.read_bytes(), args.out)


if __name__ == '__main__':
    main()
