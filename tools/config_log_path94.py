#!/usr/bin/env python3
"""Collect node 94 configuration-rooted log construction evidence offline.

All addresses are linked ELF virtual addresses. This is a closed set of
instruction contracts, not a general x86 decoder or an instruction census.
"""
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

TOOL_DIR = Path(__file__).resolve().parent
if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))
from elf_index import sections
from fde_extents import eh_frame_records, uleb

ROOT = TOOL_DIR.parent
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280

# The ranges are FDE extents; the body digests protect unlisted instructions,
# but the packet interprets only the fixed contracts and edges below.
FUNCTIONS = (
    ('log_configuration_builder', 0x13e28c0, 0x13e4cd4, 'c1491428f2125a070d8b70ab5e4a47023eb7a6e9092ca8c125871649a46121e2'),
    ('optional_prefix_builder', 0x13ecf10, 0x13ed094, '300aed74d69cf6bb538adf6ebe9f6c54990804c3b112a52305a34a57e5d68545'),
    ('category_formatter', 0x1444710, 0x144473a, 'cb7ba028c9250603f942e222342a78cc2229a64c932c076d2128cdf081c2e4a6'),
    ('severity_name_formatter', 0x1449050, 0x144907f, '7328479ece5b97fd781aa470d279cfe13b78dece9c2ee1ce0fdc8c0016afc3bb'),
    ('severity_formatter_adapter', 0x1456cc0, 0x1456cfa, 'cd2fa61001502281ae580cf6c95df4b906e4771c599388b49e53d3938dff49f4'),
    ('appender_result_builder', 0x1471480, 0x14718dc, '33ffa903e1ff4825bbbb1820508ed9ac61cbdc9293d59148228124af13c9862f'),
    ('path_map_insert', 0x14cad30, 0x14caf32, 'fffd3834f23f78fa691b849d950649a3e92a761f6f1a037d3bb4604c3e8c268f'),
    ('appender_map_insert', 0x14cb970, 0x14cbb74, '93622bf1752fbdcd5b862cbdfb40d5ab0a7b5674e15a5ef394b5a8a136ef8bb1'),
    ('pattern_mask_helper', 0x3ccd1b0, 0x3ccd2a0, '76d2b7b814722c8c202960f2a5abc5b9cd7fa964545e8c141ad824da7b4d9a33'),
    ('rolling_pattern_builder', 0x3ccdc50, 0x3cce16f, '34b63c53cf4d91b22e1d6c6f189976f7754120efd2be5273d72dc343c50bb608'),
)

# Exact instruction sequences examined by the analyst; no disassembler text is
# parsed. The chosen spans are not claimed to cover every instruction or edge.
CONTRACTS = (
 ('mode_selector',0x13e28f3,'0fb60576823904fec83c020f92c022056a823904'),
 ('absent_sentinel',0x13e2907,'49bc0000000000000080'),
 ('warn_input_reference',0x13e2950,'488d46184889842490020000'),
 ('optional_prefix_reference',0x13e295c,'488d463031c9483b4e30480f40c1'),
 ('disable_flag_reference',0x13e2972,'0fb6464d88442412'),
 ('warn_input_sentinel',0x13e2985,'488b46184889842480020000'),
 ('error_input_sentinel',0x13e29b4,'488b064889842478020000'),
 ('counter_initial',0x13e29d7,'b901000000'),
 ('global_config_slot',0x13e29dc,'488b1545bf3804'),
 ('first_index',0x13e29e8,'31c0eb43'),
 ('counter_step_and_exit',0x13e2a10,'488b8c24980200004889c848ffc14883f90e488b15ffbe38040f84ff150000'),
 ('category_array_operand',0x13e2a37,'488d0d374ee3fe0fb62c08'),
 ('warn_arguments',0x13e2a7c,'4c8d7a184c897c2420488d05541906004889442428488d8424b00100004889442430488b05b3bf38044889442438488d8424a00000004889442440488b05a2bf38044889442448488dbc24d0000000488d352094e1fe4c89ea'),
 ('warn_template_operand',0x13e2acb,'488d352094e1fe'),
 ('error_arguments',0x13e2b18,'4c897c2420488d05bc1806004889442428488d8424e00100004889442430488b051bbf38044889442438488d8424b00100004889442440488b050abf38044889442448488dbc24a0000000488d355023e1fe488d542420'),
 ('error_template_operand',0x13e2b63,'488d355023e1fe'),
 ('warn_key_one',0x13e2c20,'c644240601'),
 ('warn_selection',0x13e2c64,'0fb64424074c39a424800200004c8dbc24d00000007555f6d00a442412a8017474'),
 ('warn_custom_live_guard',0x13e2cd0,'a8010f8571150000'),
 ('error_key_zero',0x13e2dcf,'c644240600'),
 ('error_selection',0x13e2e28,'0fb64424074c39a42478020000754cf6d00a442412a8017476'),
 ('error_custom_live_guard',0x13e2e83,'a8010f8525140000'),
 ('key_iteration_order',0x13e2f88,'48c78424b80100000200000066c78424c00100000100'),
 ('warn_old_path_cleanup',0x13e2d95,'488bb424d000000048b802000000000000804839c67c154885f67410488bbc24d800000031d2ff154fb23804'),
 ('error_old_path_cleanup',0x13e2f4b,'488bb424d000000048b802000000000000804839c67c0e4885f60f85530f0000'),
 ('path_sentinel_branch',0x13e3078,'4c3965000f854e010000'),
 ('rolling_argument_setup',0x13e32c3,'0f1045080f11842408030000488d84240803000048898424e0010000488d05caa70f0048898424e8010000'),
 ('rolling_template_setup',0x13e32ee,'488dbc24d0000000488d35fd2fe1fe488d9424e0010000ff1535ad3804'),
 ('rolling_builder_arguments',0x13e3313,'4c8bbc24d00000004c8ba424d8000000488b8c24e0000000488d7c242031f64c89e2448b442408ff1568b83804'),
 ('file_builder_result_tag',0x13e333a,'ff1568b838044c8b74242048b800000000000000804939c6'),
 ('appender_builder_result_tag',0x13e3436,'e845e008004c8dbc24d00000004c396424200f84490d0000'),
 ('appender_old_value_cleanup',0x13e352d,'4889c34885c04c8b2d76b638040f8470faffff4989d6488b024885c074054889dfffd0498b76084885f60f8453faffff498b4610f3480fbcc84839f089cabf000000000f46d74883f8110f43d14889dfff158daa3804'),
 ('category_vector_store',0x13e3bc2,'4889d948c1e1060f104424200f104c24300f105424400f105c24500f115c08300f115408200f114c08100f11040848ffc348899c24d8010000'),
 ('final_result',0x13e4066,'ff1564ab3804837c2420060f845c0200000f10442460488b8424600200000f1140400f104424200f104c24300f105424400f105c24500f1158300f1150200f1148100f11004881c4180300005b415c415d415e415f5dc3'),
 ('file_builder_error',0x13e415d,'488b44242848898424d0000000488d3d4436e3fe488d0d683928044c8d0501382804488d9424d0000000be2b000000ff15b69e3804e905020000'),
 ('appender_builder_error',0x13e4197,'488b44242848898424d0000000488d3d0a36e3fe488d0d0e3928044c8d057f372804488d9424d0000000be2b000000ff157c9e3804e9cb010000'),
 ('final_builder_error',0x13e42d3,'488b44243848898424e00000000f104424280f298424d0000000488d3dc134e3fe488d0d253828044c8d050e352804488d9424d0000000be2b000000ff15339d3804e982000000'),
 ('assertion_operand',0x13e42b5,'488d3d7a34e3fe'),
 ('assertion_length',0x13e42c3,'be1a000000'),
 ('unwrap_length',0x13e430a,'be2b000000'),
 ('unwrap_operand',0x13e42ed,'488d3dc134e3fe'),
 ('prefix_argument_branch',0x13ecf1e,'4889d34989fe4885f60f84f6000000'),
 ('prefix_first_argument',0x13ecf30,'4889342448894c2408488b05201d38044889442410'),
 ('prefix_one_argument_template',0x13ecf45,'488d3501d5dffe'),
 ('prefix_three_arguments',0x13ecf8f,'4889e04889442420488d050259ffff488944242848896c2430488d05f112000048894424384c897c2440488b05a01a38044889442448'),
 ('prefix_three_argument_template',0x13ecfc5,'488d351935e0fe'),
 ('prefix_candidate_release',0x13ed005,'488b33488d0475000000004885c0741d488b7b0831d2ff15ef0f3804eb0f'),
 ('prefix_absent_move',0x13ed023,'488b4310498946100f1003410f1106'),
 ('category_formatter_body',0x1444710,'488b06488b4e08488d15b450ddfe488d35a350ddfe803f00480f45f2488b4918ba050000004889c7ffe1'),
 ('severity_table_formatter',0x1449050,'488b070fb600488d0d6334dcfe488b14c1488d0d3010ddfe486304814801c8488b3e488b4e08488b49184889c6ffe1'),
 ('severity_formatter_adapter',0x1456cc0,'4883ec1848893c244889e04889442408488d057923ffff4889442410488b3e488b7608488d156337d9fe488d4c2408ff15137331044883c418c3'),
 ('path_map_replace',0x14cadc3,'498b421048894310410f10020f11030f1001410f1102488b411049894210'),
 ('path_map_new_length_and_sentinel',0x14caeb7,'48ff411048b80100000000000080488903'),
 ('appender_map_replace',0x14cba07,'498b40f8498b104d8970f8498918'),
 ('appender_map_new_length',0x14cbaa5,'48ff411031c0'),
 ('appender_input_helpers',0x14714a7,'488d7c2430ff1566cb2f04488d7c2418488d742430e8af3afdff'),
 ('appender_component_tag_gate',0x1471652,'0fb68424e000000004f93c037347'),
 ('appender_operation_flags',0x1471673,'c78424a0000000ff010000c68424a400000001'),
 ('appender_external_error_return',0x1471697,'4885c0740b498944240849891c24eb42'),
 ('appender_lock_and_error',0x14716a7,'4c8d6c2468b10131c0f00fb04c24680f85d6000000488d742470488d7c2430ff1544e12f04a801742f498954240849891c24'),
 ('appender_success_copy',0x14716ff,'31c9b001f00fb04c24680f85a60000000f10842490000000410f114424600f10842480000000410f114424500f10442470410f114424400f104424300f104c24400f105424500f105c2460410f115c2430410f11542420410f114c2410410f110424'),
 ('appender_lock_slow_timeout',0x1471792,'4c89efba00ca9a3bff1590d72f04'),
 ('appender_unlock_slow',0x14717a5,'4c89ef31f6ff1588d72f04'),
 ('appender_allocation_failure',0x14717c5,'bf08000000be30000000ff154bc82f040f0b'),
 ('mask_helper_one_byte',0x3ccd240,'b0014885ff0f846bfffffff30fbcca440fb60c0e453a0875d74883ff010f8453ffffff440fb64c0e01453a480175c14883ff02'),
 ('rolling_pattern_length_gates',0x3ccdc70,'4883f90276584983fe107763'),
 ('rolling_short_search',0x3ccdc90,'6681397b7d0f844601000048ffc148ffc84883f80373e9'),
 ('rolling_pattern_error',0x3ccdca7,'488d3da8cb8efcbe1d000000e8d8a0ffff4889430848b80000000000000080488903e900020000'),
 ('rolling_two_byte_case',0x3ccdcce,'75d76641813c247b7d0f8404010000ebc8'),
 ('rolling_vector_threshold',0x3ccdd07,'4983fe420f83d201000031ed4531ed'),
 ('rolling_tail_pair_mask',0x3ccdda1,'f3430f6f4434eff3430f6f4c34f0660f7405097753fc660f740db19153fc660fdbc8660fd7d185d20f854d030000'),
 ('rolling_extension_gate',0x3ccde1a,'80bc24b000000009755a488b8c24c0000000488b8424b80000004883f90275076681382e2e743d4889ce6666662e0f1f8400000000004885f67429488d56ff807c30ff2e4889d675ed4885d274164883c1fd4839d1750d66817c1001677a0f84cd020000'),
 ('rolling_result_store',0x3ccdebc,'4c89334c897b084c89731044896b18896b1c4889d8'),
 ('rolling_tail_match_verify',0x3cce11c,'498d76ef450fb6ed488d7c24504489e9e87ff0ffff4108c54584ed8b6c240c448b6c24080f859bfcffffe95cfbffff'),
 ('rolling_gzip_error',0x3cce14b,'488d3d21c78efcbe2c000000e8045bfeffe957fbffff'),
)

# (label, instruction VA, fixed opcode form, expected linked destination).
# The list is selected and explicit; it is not a whole-body branch census.
EDGES = (
 ('mode_lazy_nonzero',0x13e28ed,'0f85',0x13e4262),
 ('first_loop',0x13e29ea,'eb',0x13e2a2f),
 ('loop_done',0x13e2a29,'0f84',0x13e402e),
 ('config_lazy_warn',0x13e2a76,'0f85',0x13e3faa),
 ('config_lazy_error',0x13e2b12,'0f85',0x13e3feb),
 ('warn_candidate_present',0x13e2bef,'75',0x13e2c20),
 ('warn_input_present',0x13e2c79,'75',0x13e2cd0),
 ('warn_default',0x13e2c83,'74',0x13e2cf9),
 ('warn_custom_live_panic',0x13e2cd2,'0f85',0x13e4249),
 ('warn_custom_alloc_failure',0x13e2cee,'0f84',0x13e436d),
 ('warn_no_default_helper',0x13e2cb4,'e8',0x13ecf10),
 ('warn_default_helper',0x13e2d1b,'e8',0x13ecf10),
 ('warn_path_insert',0x13e2d90,'e8',0x14cad30),
 ('error_input_present',0x13e2e35,'75',0x13e2e83),
 ('error_default',0x13e2e3f,'74',0x13e2eb7),
 ('error_custom_live_panic',0x13e2e85,'0f85',0x13e42b0),
 ('error_custom_alloc_failure',0x13e2ea4,'0f84',0x13e4374),
 ('error_no_default_helper',0x13e2e70,'e8',0x13ecf10),
 ('error_default_helper',0x13e2ed9,'e8',0x13ecf10),
 ('error_path_insert',0x13e2f46,'e8',0x14cad30),
 ('missing_path_map_root',0x13e2fd6,'0f84',0x13e4250),
 ('non_sentinel_appender',0x13e307c,'0f85',0x13e31d0),
 ('file_builder',0x13e333a,'ff15',0x576eba8),
 ('file_builder_error',0x13e3352,'0f84',0x13e415d),
 ('appender_builder',0x13e3436,'e8',0x1471480),
 ('appender_builder_error',0x13e3448,'0f84',0x13e4197),
 ('appender_map_insert',0x13e3528,'e8',0x14cb970),
 ('no_replaced_appender',0x13e353a,'0f84',0x13e2fb0),
 ('iteration_continue',0x13e3ceb,'0f84',0x13e2a10),
 ('final_builder',0x13e4066,'ff15',0x576ebd0),
 ('final_builder_error',0x13e4071,'0f84',0x13e42d3),
 ('prefix_absent',0x13ecf27,'0f84',0x13ed023),
 ('prefix_format',0x13ecf56,'ff15',0x576e040),
 ('prefix_three_part_format',0x13ecfd6,'ff15',0x576e040),
 ('prefix_transform',0x13ecf76,'ff15',0x576e050),
 ('prefix_temporary_empty',0x13ecf7f,'74',0x13ecf8f),
 ('prefix_result_empty',0x13ecff6,'74',0x13ed005),
 ('prefix_candidate_empty',0x13ed013,'74',0x13ed032),
 ('prefix_candidate_free',0x13ed01b,'ff15',0x576e010),
 ('prefix_unwind_empty',0x13ed04c,'74',0x13ed070),
 ('severity_adapter_sink',0x1456cef,'ff15',0x576e008),
 ('path_map_empty',0x14cad47,'0f84',0x14cade6),
 ('path_map_equal',0x14cada5,'74',0x14cadc3),
 ('path_map_replacement_return',0x14cade1,'e9',0x14caec8),
 ('path_map_alloc_failure',0x14cae5f,'74',0x14caeda),
 ('path_map_capacity_failure',0x14cae88,'73',0x14caeec),
 ('appender_map_empty',0x14cb986,'0f84',0x14cba1a),
 ('appender_map_equal',0x14cb9e5,'74',0x14cba07),
 ('appender_map_replacement_return',0x14cba15,'e9',0x14cbaab),
 ('appender_map_alloc_failure',0x14cba4e,'0f84',0x14cbb15),
 ('appender_map_capacity_failure',0x14cba7e,'0f83',0x14cbb27),
 ('appender_input_decoder',0x14714bc,'e8',0x1444f70),
 ('appender_component_reader',0x147164c,'ff15',0x576e850),
 ('appender_tag_bypass',0x147165e,'73',0x14716a7),
 ('appender_operation_first',0x1471668,'ff15',0x576ef20),
 ('appender_operation_first_null',0x1471671,'74',0x14716a7),
 ('appender_operation_second',0x1471691,'ff15',0x576ef28),
 ('appender_operation_success',0x147169a,'74',0x14716a7),
 ('appender_lock_contended',0x14716b6,'0f85',0x1471792),
 ('appender_locked_builder',0x14716c6,'ff15',0x576f810),
 ('appender_builder_ok',0x14716ce,'74',0x14716ff),
 ('appender_unlock_error_contended',0x14716e3,'0f85',0x14717a5),
 ('appender_unlock_ok_contended',0x1471709,'0f85',0x14717b5),
 ('appender_wait_slow',0x147179a,'ff15',0x576ef30),
 ('appender_unlock_slow_call',0x14717aa,'ff15',0x576ef38),
 ('appender_allocation_failure_call',0x14717cf,'ff15',0x576e020),
 ('rolling_small_length',0x3ccdc74,'76',0x3ccdcce),
 ('rolling_vector_length',0x3ccdc7a,'77',0x3ccdcdf),
 ('rolling_scalar_match',0x3ccdc95,'0f84',0x3ccdde1),
 ('rolling_scalar_repeat',0x3ccdca5,'73',0x3ccdc90),
 ('rolling_short_reject',0x3ccdcce,'75',0x3ccdca7),
 ('rolling_exact_pair_match',0x3ccdcd7,'0f84',0x3ccdde1),
 ('rolling_unrolled_threshold',0x3ccdd0b,'0f83',0x3ccdee3),
 ('rolling_tail_mask_nonzero',0x3ccddc9,'0f85',0x3cce11c),
 ('rolling_no_match',0x3ccdddb,'0f84',0x3ccdca7),
 ('rolling_component_other',0x3ccde22,'75',0x3ccde7e),
 ('rolling_extension_gzip',0x3ccde78,'0f84',0x3cce14b),
 ('rolling_gzip_to_error',0x3cce15c,'e9',0x3ccdcb8),
 ('rolling_tail_helper',0x3cce12c,'e8',0x3ccd1b0),
 ('rolling_tail_match',0x3cce140,'0f85',0x3ccdde1),
 ('rolling_tail_reject',0x3cce146,'e9',0x3ccdca7),
)

# Only relative relocations are included; dynamic imports remain boundaries.
RELOCS = {
 0x576dfd8: 0x54c06b0, 0x576e008: 0x1571d90, 0x576e010: 0x54c8cb0,
 0x576e018: 0x1345e40, 0x576e020: 0x1345e2a,
 0x576e040: 0x1344760, 0x576e050: 0x1344900, 0x576e850: 0x4f11400,
 0x576e928: 0x577b288, 0x576ea58: 0x1444710,
 0x576ea60: 0x1454a00, 0x576eba0: 0x3cb3e60,
 0x576eba8: 0x3ccdc50, 0x576ebd0: 0x3cc24e0,
 0x576ec60: 0x1456cc0, 0x5668488: 0x2180ff,
 0x576ef20: 0x4ee9cb0, 0x576ef28: 0x4ed84c0,
 0x576ef30: 0x4e0f640, 0x576ef38: 0x4e0f2c0, 0x576f810: 0x3cc9a10,
}


def verify_identity(data):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('node 94 size or SHA-256 mismatch')


class View:
    def __init__(self, data, secs=None):
        self.data = data
        self.sections = sections(data) if secs is None else secs

    def offset(self, va, size):
        if type(va) is not int or type(size) is not int or va < 0 or size <= 0 or va + size > 1 << 64:
            raise ValueError('invalid VA or byte count')
        matches = [s for s in self.sections if s['type'] != 8 and s['size']
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(matches) != 1:
            raise ValueError('VA does not have exactly one file-backed section')
        sec = matches[0]
        off = sec['offset'] + va - sec['address']
        if off < 0 or off + size > len(self.data):
            raise ValueError('file-backed section is truncated')
        return off

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]


def require(view, label, va, expected):
    expected = bytes.fromhex(expected) if isinstance(expected, str) else expected
    actual = bytes(view.read(va, len(expected)))
    if actual != expected:
        raise ValueError('instruction contract changed: ' + label)
    return {'label': label, 'va': hex(va), 'file_offset': hex(view.offset(va, len(actual))),
            'length': len(actual), 'bytes': actual.hex()}


def rip_target(va, raw):
    if len(raw) != 7 or raw[0] not in (0x48, 0x4c) or raw[1] not in (0x8b, 0x8d) or raw[2] & 0xc7 != 5:
        raise ValueError('unsupported RIP-relative form')
    return va + 7 + struct.unpack_from('<i', raw, 3)[0]


def edge_target(va, raw, form):
    prefix = bytes.fromhex(form)
    if not raw.startswith(prefix):
        raise ValueError('edge opcode changed')
    if form in ('eb', '73', '74', '75', '76', '77'):
        if len(raw) != 2:
            raise ValueError('truncated short edge')
        return va + 2 + struct.unpack_from('<b', raw, 1)[0]
    if form in ('e8', 'e9'):
        if len(raw) != 5:
            raise ValueError('truncated direct edge')
        return va + 5 + struct.unpack_from('<i', raw, 1)[0]
    if form in ('0f84', '0f85', '0f83', 'ff15'):
        if len(raw) != 6:
            raise ValueError('truncated long edge')
        return va + 6 + struct.unpack_from('<i', raw, 2)[0]
    raise ValueError('unsupported edge form')


def selected_edges(view):
    rows = []
    for label, va, form, target in EDGES:
        length = 2 if form in ('eb', '73', '74', '75', '76', '77') else (5 if form in ('e8', 'e9') else 6)
        raw = bytes(view.read(va, length))
        actual = edge_target(va, raw, form)
        if actual != target:
            raise ValueError('edge target changed: ' + label)
        matches = [x for x in FUNCTIONS if x[1] <= va and va + length <= x[2]]
        if len(matches) != 1:
            raise ValueError('edge outside selected FDEs')
        rows.append({'label': label, 'function': hex(matches[0][1]), 'site_va': hex(va),
                     'file_offset': hex(view.offset(va, length)), 'bytes': raw.hex(),
                     'destination_kind': 'relative_slot' if form == 'ff15' else 'direct_va',
                     'destination': hex(actual), 'fallthrough': hex(va + length)})
    return rows


# Closed byte-pattern x86 length reader adapted from the independent MIT
# configuration temporary-path collector in PR 1588. No decoder text is parsed.
def _need(body, pos, count):
    if pos < 0 or count < 0 or pos + count > len(body):
        raise ValueError('truncated instruction')


def decode_one(body, off, base):
    """Decode one length and control-transfer form; no full mnemonic claim."""
    start = off
    prefix66 = False
    rex = 0
    while True:
        _need(body, off, 1)
        p = body[off]
        if p in (0x66, 0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65):
            prefix66 |= p == 0x66
            off += 1
        elif 0x40 <= p <= 0x4f:
            rex = p
            off += 1
        else:
            break
        if off - start > 8:
            raise ValueError('too many prefixes')
    op = body[off]
    off += 1
    kind = 'instruction'
    target = None
    rel_width = 0
    modrm_needed = False
    imm = 0
    op2 = None
    if op == 0x0f:
        _need(body, off, 1)
        op2 = body[off]
        off += 1
        if 0x80 <= op2 <= 0x8f:
            kind, rel_width = 'conditional', 4
        elif op2 == 0x0b:
            kind = 'trap'
        elif (op2 in (0x10, 0x11, 0x1f, 0x28, 0x29, 0x2e, 0x2f, 0x57,
                      0x60, 0x6e, 0x6f, 0x70, 0x74, 0x7e, 0x7f, 0xa3, 0xaf, 0xb6, 0xb7,
                      0xb0, 0xbc, 0xbe, 0xbf, 0xd6, 0xd7, 0xdb, 0xdf, 0xeb, 0xef)
              or 0x40 <= op2 <= 0x4f or 0x90 <= op2 <= 0x9f):
            modrm_needed = True
        else:
            raise ValueError(f'unsupported 0f opcode {op2:02x} at {base + start:#x}')
    elif op in (0xe8, 0xe9):
        kind, rel_width = ('call' if op == 0xe8 else 'jump'), 4
    elif op == 0xeb or 0x70 <= op <= 0x7f:
        kind, rel_width = ('jump' if op == 0xeb else 'conditional'), 1
    elif op in (0xc3, 0xcb):
        kind = 'return'
    elif op == 0xc2:
        kind, imm = 'return', 2
    elif op in (0xcc, 0xf4):
        kind = 'trap'
    elif 0x50 <= op <= 0x5f or op in (0x90, 0x98, 0x99, 0xc9):
        pass
    elif 0xb8 <= op <= 0xbf:
        imm = 8 if rex & 8 else (2 if prefix66 else 4)
    elif 0xb0 <= op <= 0xb7 or op in (0x6a, 0xa8, 0x04, 0x0c, 0x24, 0x2c, 0x34, 0x3c):
        imm = 1
    elif op in (0x68, 0xa9, 0x05, 0x0d, 0x25, 0x2d, 0x35, 0x3d):
        imm = 2 if prefix66 else 4
    elif op in (0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b,
                0x20, 0x21, 0x22, 0x23, 0x28, 0x29, 0x2a, 0x2b,
                0x30, 0x31, 0x32, 0x33, 0x38, 0x39, 0x3a, 0x3b,
                0x63, 0x69, 0x6b, 0x80, 0x81, 0x83, 0x84, 0x85,
                0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8d, 0x8f,
                0xc0, 0xc1, 0xc6, 0xc7, 0xd0, 0xd1, 0xd2, 0xd3,
                0xf6, 0xf7, 0xfe, 0xff):
        modrm_needed = True
    else:
        raise ValueError(f'unsupported opcode {op:02x} at {base + start:#x}')

    rip_disp_pos = None
    modrm = None
    if modrm_needed:
        _need(body, off, 1)
        modrm = body[off]
        off += 1
        mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
        sib_base = None
        if mod != 3 and rm == 4:
            _need(body, off, 1)
            sib_base = body[off] & 7
            off += 1
        if mod == 0 and rm == 5:
            rip_disp_pos = off
            off += 4
        elif mod == 0 and sib_base == 5:
            off += 4
        elif mod == 1:
            off += 1
        elif mod == 2:
            off += 4
        if op == 0x0f and op2 == 0x70:
            imm = 1
        elif op in (0x80, 0x83, 0x6b, 0xc0, 0xc1, 0xc6):
            imm = 1
        elif op in (0x81, 0x69, 0xc7):
            imm = 2 if prefix66 else 4
        elif op == 0xf6 and reg in (0, 1):
            imm = 1
        elif op == 0xf7 and reg in (0, 1):
            imm = 2 if prefix66 else 4
        if op == 0xff and reg in (2, 4):
            kind = 'indirect_call' if reg == 2 else 'indirect_jump'
    if rel_width:
        _need(body, off, rel_width)
        delta = int.from_bytes(body[off:off + rel_width], 'little', signed=True)
        off += rel_width
        target = base + off + delta
    else:
        _need(body, off, imm)
        off += imm
        if rip_disp_pos is not None:
            _need(body, rip_disp_pos, 4)
            target = base + off + struct.unpack_from('<i', body, rip_disp_pos)[0]
    if off - start > 15:
        raise ValueError('instruction exceeds x86 maximum')
    _need(body, start, off - start)
    return {'va': base + start, 'end': base + off, 'kind': kind,
            'target': target, 'bytes': bytes(body[start:off]),
            'opcode': (op, op2), 'modrm': modrm,
            'rip_relative': rip_disp_pos is not None}


def decode_body(body, base):
    result = []
    offset = 0
    while offset < len(body):
        row = decode_one(body, offset, base)
        result.append(row)
        offset = row['end'] - base
    if offset != len(body):
        raise ValueError('function decoding exceeded extent')
    starts = {r['va'] for r in result}
    end = base + len(body)
    for row in result:
        if row['kind'] in ('jump', 'conditional') and base <= row['target'] < end:
            if row['target'] not in starts:
                raise ValueError(f'branch into an instruction at {row["va"]:#x}')
        if row['kind'] == 'conditional' and row['end'] < end and row['end'] not in starts:
            raise ValueError('fallthrough is not an instruction boundary')
    return result




def reachable(decoded, source, destination, forbidden=()):
    """Over-approximate normal flow: all conditions feasible and calls return."""
    by_va = {ins['va']: ins for ins in decoded}
    if source not in by_va or destination not in by_va:
        raise ValueError('CFG query is not at an instruction boundary')
    forbidden = set(forbidden)
    if any(va not in by_va for va in forbidden):
        raise ValueError('CFG forbidden VA is not an instruction boundary')
    pending, seen = [source], set()
    while pending:
        va = pending.pop()
        if va in forbidden or va in seen or va not in by_va:
            continue
        if va == destination:
            return True
        seen.add(va)
        ins = by_va[va]
        kind = ins['kind']
        if kind in ('return', 'trap', 'indirect_jump'):
            continue
        if kind == 'jump':
            pending.append(ins['target'])
        elif kind == 'conditional':
            pending.extend((ins['target'], ins['end']))
        else:
            pending.append(ins['end'])
    return False


def check_cfg(decodes):
    # These are structural reachability propositions, not feasible-input proofs.
    tests = (
      ('warn_default_reaches_insert',0x13e28c0,0x13e2d1b,0x13e2d90,(),True),
      ('warn_absent_reaches_insert',0x13e28c0,0x13e2cb4,0x13e2d90,(),True),
      ('warn_live_reaches_assertion',0x13e28c0,0x13e4249,0x13e42c8,(),True),
      ('warn_assertion_bypasses_insert',0x13e28c0,0x13e4249,0x13e2d90,(),False),
      ('error_default_reaches_insert',0x13e28c0,0x13e2ed9,0x13e2f46,(),True),
      ('error_absent_reaches_insert',0x13e28c0,0x13e2e70,0x13e2f46,(),True),
      ('error_live_reaches_assertion',0x13e28c0,0x13e42b0,0x13e42c8,(),True),
      ('error_assertion_bypasses_insert',0x13e28c0,0x13e42b0,0x13e2f46,(),False),
      ('warn_can_reach_error_insert',0x13e28c0,0x13e2d90,0x13e2f46,(),True),
      ('normal_finish_returns',0x13e28c0,0x13e4077,0x13e40bc,(),True),
      ('final_error_reaches_diagnostic',0x13e28c0,0x13e42d3,0x13e430f,(),True),
      ('final_error_bypasses_copy',0x13e28c0,0x13e42d3,0x13e4077,(),False),
      ('path_replace_reaches_return',0x14cad30,0x14cadc3,0x14caec8,(0x14caeb7,),True),
      ('path_replace_bypasses_increment',0x14cad30,0x14cadc3,0x14caeb7,(),False),
      ('appender_replace_reaches_return',0x14cb970,0x14cba07,0x14cbaab,(0x14cbaa5,),True),
      ('appender_replace_bypasses_increment',0x14cb970,0x14cba07,0x14cbaa5,(),False),
      ('prefix_absent_moves_value',0x13ecf10,0x13ed023,0x13ed040,(),True),
      ('prefix_absent_bypasses_format',0x13ecf10,0x13ed023,0x13ecfd6,(),False),
      ('prefix_present_reaches_format',0x13ecf10,0x13ecf2d,0x13ecfd6,(),True),
      ('prefix_present_can_release_candidate',0x13ecf10,0x13ecfd6,0x13ed01b,(),True),
      ('rolling_short_no_match_is_error',0x3ccdc50,0x3ccdca7,0x3ccdece,(),True),
      ('rolling_short_error_bypasses_success',0x3ccdc50,0x3ccdca7,0x3ccdebc,(),False),
      ('rolling_short_match_reaches_component',0x3ccdc50,0x3ccdc90,0x3ccdde1,(),True),
      ('rolling_component_can_reach_gzip_error',0x3ccdc50,0x3ccdde1,0x3cce14b,(),True),
      ('rolling_gzip_bypasses_success',0x3ccdc50,0x3cce14b,0x3ccdebc,(),False),
      ('rolling_success_reaches_return',0x3ccdc50,0x3ccdebc,0x3ccded1,(),True),
      ('appender_tag_bypass_reaches_lock',0x1471480,0x14716a7,0x14716c6,(),True),
      ('appender_operation_error_bypasses_copy',0x1471480,0x147169c,0x1471717,(),False),
      ('appender_call_error_reaches_sentinel',0x1471480,0x14716d0,0x14716d5,(),True),
      ('appender_call_error_bypasses_copy',0x1471480,0x14716d0,0x1471717,(),False),
      ('appender_call_ok_reaches_copy',0x1471480,0x14716ff,0x1471717,(),True),
      ('appender_call_ok_bypasses_error_store',0x1471480,0x14716ff,0x14716d5,(),False),
    )
    rows=[]
    for label, fn, source, dest, forbidden, expected in tests:
        actual = reachable(decodes[fn], source, dest, forbidden)
        if actual != expected:
            raise ValueError('CFG proposition failed: ' + label)
        rows.append({'label':label, 'function':hex(fn), 'from_va':hex(source),
                     'to_va':hex(dest), 'forbidden_va':','.join(hex(x) for x in forbidden),
                     'reachable':int(actual)})
    return rows


def parse_relocations(view):
    candidates = [s for s in view.sections if s['name'] == '.rela.dyn' and s['type'] == 4]
    if len(candidates) != 1 or candidates[0]['size'] % 24:
        raise ValueError('invalid relative relocation section')
    sec = candidates[0]
    rows = {}
    for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', view.data, off)
        if where in RELOCS:
            if where in rows:
                raise ValueError('duplicate selected relocation slot')
            if info != 8 or addend != RELOCS[where]:
                raise ValueError('selected relocation changed')
            rows[where] = {'slot_va': hex(where), 'relocation_file_offset': hex(off),
                           'type': info & 0xffffffff, 'symbol': info >> 32,
                           'addend': hex(addend)}
    if set(rows) != set(RELOCS):
        raise ValueError('missing selected relocation')
    return [rows[k] for k in sorted(rows)]



def parse_lsda(view, start, end, lsda_va):
    """Read this target's ULEB call-site table; do not interpret actions/types."""
    containing = [s for s in view.sections if s['name'] == '.gcc_except_table'
                  and s['type'] != 8 and s['address'] <= lsda_va < s['address'] + s['size']]
    if len(containing) != 1:
        raise ValueError('LSDA outside file-backed exception table')
    sec = containing[0]
    pos = view.offset(lsda_va, 2)
    section_end = sec['offset'] + sec['size']
    data = view.data
    lp_encoding, type_encoding = data[pos], data[pos+1]
    pos += 2
    if lp_encoding != 0xff or type_encoding not in (0xff, 0x9b):
        raise ValueError('unsupported LSDA header encoding')
    type_base = None
    if type_encoding != 0xff:
        relative, pos = uleb(data, pos, section_end)
        type_base = pos + relative
        if type_base > section_end:
            raise ValueError('LSDA type table outside section')
    if pos >= section_end or data[pos] != 1:
        raise ValueError('unsupported LSDA call-site encoding')
    pos += 1
    size, pos = uleb(data, pos, section_end)
    stop = pos + size
    if stop > section_end or (type_base is not None and stop > type_base):
        raise ValueError('LSDA call-site table outside bounds')
    begin = pos
    rows = []
    previous_end = 0
    while pos < stop:
        entry_off = pos
        region, pos = uleb(data, pos, stop)
        length, pos = uleb(data, pos, stop)
        landing, pos = uleb(data, pos, stop)
        action, pos = uleb(data, pos, stop)
        if not length or region < previous_end or region + length > end - start:
            raise ValueError('LSDA protected range invalid')
        if landing and landing >= end - start:
            raise ValueError('LSDA landing pad outside selected FDE')
        previous_end = region + length
        rows.append({'function': hex(start), 'lsda_va': hex(lsda_va),
                     'entry_file_offset': hex(entry_off), 'start_va': hex(start + region),
                     'end_va': hex(start + region + length),
                     'landing_va': hex(start + landing) if landing else '', 'action_index': action})
    header = {'function': hex(start), 'lsda_va': hex(lsda_va),
              'header_file_offset': hex(view.offset(lsda_va, 2)),
              'lpstart_encoding': hex(lp_encoding), 'type_encoding': hex(type_encoding),
              'callsite_encoding': '0x1', 'callsite_file_offset': hex(begin),
              'callsite_size': size, 'entries': len(rows)}
    return header, rows


def template(view, va, expected):
    data = bytearray()
    parts = []
    pos = va
    while len(data) < 64:
        tag = view.read(pos, 1)[0]
        pos += 1
        data.append(tag)
        if tag == 0:
            break
        if tag == 0xc0:
            parts.append({'argument': True})
        elif 1 <= tag <= 0x7f:
            literal = bytes(view.read(pos, tag))
            data.extend(literal)
            pos += tag
            try:
                parts.append({'literal': literal.decode('ascii')})
            except UnicodeDecodeError as error:
                raise ValueError('non-ASCII selected literal') from error
        else:
            raise ValueError('unsupported template token')
    else:
        raise ValueError('template did not terminate')
    if bytes(data) != bytes.fromhex(expected):
        raise ValueError('template bytes changed')
    return {'entry_va': hex(va), 'file_offset': hex(view.offset(va, len(data))),
            'length': len(data), 'bytes': data.hex(), 'tokens': parts}



def severity_names(view):
    lengths = rip_target(0x1449056, view.read(0x1449056, 7))
    offsets = rip_target(0x1449061, view.read(0x1449061, 7))
    if (lengths, offsets) != (0x20c4c0, 0x21a098):
        raise ValueError('severity table references changed')
    rows = []
    for key, expected in enumerate((b'Error', b'Warn')):
        length_va = lengths + 8*key
        rel_va = offsets + 4*key
        size = struct.unpack('<Q', view.read(length_va, 8))[0]
        relative = struct.unpack('<i', view.read(rel_va, 4))[0]
        if not 0 < size <= 32:
            raise ValueError('severity length out of range')
        target = offsets + relative
        name = bytes(view.read(target, size))
        if name != expected:
            raise ValueError('severity name changed')
        rows.append({'key': key, 'length_va': hex(length_va), 'length': size,
                     'relative_slot_va': hex(rel_va), 'relative': relative,
                     'name_va': hex(target), 'name_file_offset': hex(view.offset(target, size)),
                     'bytes': name.hex(), 'text': name.decode('ascii')})
    return rows



def rolling_constants(view):
    left = bytes(view.read(0x2054c0,16))
    right = bytes(view.read(0x206f70,16))
    if left != b'{'*16 or right != b'}'*16:
        raise ValueError('rolling search vector constants changed')
    result = {'left_va':hex(0x2054c0), 'left_bytes':left.hex(),
              'right_va':hex(0x206f70), 'right_bytes':right.hex(),
              'short_max':view.read(0x3ccdc79,1)[0],
              'unrolled_min':view.read(0x3ccdd0a,1)[0]}
    if (result['short_max'], result['unrolled_min']) != (16,66):
        raise ValueError('rolling search thresholds changed')
    return result


def scalar_pair_search(pattern):
    # The selected scalar loop compares a little-endian two-byte pair.
    if not isinstance(pattern, bytes) or len(pattern) > 16:
        raise ValueError('scalar case outside selected domain')
    return any(pattern[i:i+2] == b'{}' for i in range(max(0,len(pattern)-1)))


def trailing_pair_mask(pattern, left, right):
    # The selected last two unaligned 16-byte loads are at n-17 and n-16.
    if not isinstance(pattern, bytes) or len(pattern) < 17 or not (0 <= left < 256 and 0 <= right < 256):
        raise ValueError('trailing vector case outside selected domain')
    begin = len(pattern) - 17
    return sum((1 << lane) for lane in range(16)
               if pattern[begin+lane] == left and pattern[begin+lane+1] == right)


def extension_decision(tag, component):
    # This models only the local test after the external component reader.
    if type(tag) is not int or not 0 <= tag <= 255 or not isinstance(component, bytes):
        raise ValueError('invalid component test input')
    if tag != 9 or component == b'..':
        return 'continue'
    dot = component.rfind(b'.')
    if dot > 0 and dot == len(component)-3 and component[dot+1:] == b'gz':
        return 'gzip_feature_error'
    return 'continue'


def appender_tag_constants(view):
    raw = bytes(view.read(0x147165a, 4))
    if raw != b'\x04\xf9\x3c\x03':
        raise ValueError('appender tag gate changed')
    return {'addend': raw[1], 'unsigned_limit': raw[3]}


def appender_tag_enters(tag, constants):
    if type(tag) is not int or not 0 <= tag < 256:
        raise ValueError('component tag must be a byte')
    return ((tag + constants['addend']) & 0xff) < constants['unsigned_limit']


def classify(mode, mode_flag, disabled, present, prefix):
    if type(mode) is not int or type(mode_flag) is not int or not 0 <= mode < 256 or not 0 <= mode_flag < 256:
        raise ValueError('mode values must be bytes')
    if any(type(v) is not bool for v in (disabled, present, prefix)):
        raise ValueError('presence and disable inputs must be bool')
    live = (((mode - 1) & 0xff) < 2) and bool(mode_flag & 1)
    if present:
        outcome = 'assertion' if live else 'clone_custom'
    else:
        default = live and not disabled
        outcome = ('prefix_helper_' if prefix else 'move_') + ('default' if default else 'absent')
    return live, outcome


def tsv(path, rows, columns):
    with path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, delimiter='\t', lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)


def collect(data):
    verify_identity(data)
    view = View(data)
    _, fdes = eh_frame_records(data, view.sections)
    functions = []
    decodes = {}
    for name, start, end, digest in FUNCTIONS:
        matches = [row for row in fdes if row['start'] == start and row['end'] == end]
        if len(matches) != 1:
            raise ValueError('selected FDE missing or duplicated: ' + name)
        row = matches[0]
        body = view.read(start, end - start)
        body_digest = hashlib.sha256(body).hexdigest()
        if body_digest != digest:
            raise ValueError('selected FDE body changed: ' + name)
        decodes[start] = decode_body(body, start)
        functions.append({'role': name, 'start_va': hex(start), 'end_va': hex(end),
                          'file_offset': hex(view.offset(start, end-start)), 'size': end-start,
                          'fde_va': hex(row['fde']), 'cie_va': hex(row['cie']),
                          'lsda_va': '' if row['lsda'] is None else hex(row['lsda']),
                          'sha256': body_digest})
    lsda_headers, lsda_sites = [], []
    for fn in functions:
        if fn['lsda_va']:
            header, sites = parse_lsda(view, int(fn['start_va'],16), int(fn['end_va'],16), int(fn['lsda_va'],16))
            lsda_headers.append(header)
            lsda_sites.extend(sites)
    contracts = [require(view, name, va, expected) for name, va, expected in CONTRACTS]
    edges = selected_edges(view)
    relocs = parse_relocations(view)
    instruction_rows, transfer_rows = [], []
    for start in sorted(decodes):
        decoded = decodes[start]
        for ins in decoded:
            target = ins['target']
            row = {'function': hex(start), 'va': hex(ins['va']),
                   'file_offset': hex(view.offset(ins['va'], ins['end']-ins['va'])),
                   'size': ins['end']-ins['va'], 'bytes': ins['bytes'].hex(),
                   'class': ins['kind'],
                   'rip_relative': int(ins['rip_relative']),
                   'target': '' if target is None else hex(target)}
            instruction_rows.append(row)
            if ins['kind'] != 'instruction':
                transfer_rows.append(row)
    instruction_by_va = {int(row['va'],16): row for row in instruction_rows}
    for edge in edges:
        row = instruction_by_va.get(int(edge['site_va'],16))
        if row is None or row['bytes'] != edge['bytes'] or row['target'] != edge['destination']:
            raise ValueError('selected edge not aligned with decoded instruction')
    instruction_boundaries = {fn: {ins['va'] for ins in decoded} | {decoded[-1]['end']}
                              for fn, decoded in decodes.items()}
    for contract in contracts:
        va = int(contract['va'],16)
        ends = va + contract['length']
        owners = [fn for _, fn, end, _ in FUNCTIONS if fn <= va < ends <= end]
        if len(owners) != 1 or va not in instruction_boundaries[owners[0]] or ends not in instruction_boundaries[owners[0]]:
            raise ValueError('contract is not aligned to selected instruction boundaries: ' + contract['label'])
    for row in lsda_sites:
        fn = int(row['function'],16)
        boundaries = instruction_boundaries[fn]
        if any(row[key] and int(row[key],16) not in boundaries for key in ('start_va','end_va','landing_va')):
            raise ValueError('LSDA boundary is not a decoded instruction boundary')
    cfg_claims = check_cfg(decodes)
    cell_va = RELOCS[0x576e928]
    cell_sections = [sec for sec in view.sections if sec['address'] <= cell_va < sec['address'] + sec['size']]
    if len(cell_sections) != 1 or cell_sections[0]['type'] != 1 or cell_sections[0]['name'] != '.data':
        raise ValueError('configuration cell section changed')
    cell_summary = {'va': hex(cell_va), 'section': cell_sections[0]['name'],
                    'section_type': cell_sections[0]['type'], 'file_offset': hex(view.offset(cell_va, 1))}
    if rip_target(0x13e29dc, view.read(0x13e29dc, 7)) != 0x576e928:
        raise ValueError('configuration slot operand changed')
    category_va = rip_target(0x13e2a37, view.read(0x13e2a37, 7))
    warn_va = rip_target(0x13e2acb, view.read(0x13e2acb, 7))
    error_va = rip_target(0x13e2b63, view.read(0x13e2b63, 7))
    trade_va = rip_target(0x1444717, view.read(0x1444717, 7))
    infra_va = rip_target(0x144471e, view.read(0x144471e, 7))
    if (category_va, warn_va, error_va, infra_va, trade_va) != (0x217875,0x1fbef2,0x1f4eba,0x2197c8,0x2197d2):
        raise ValueError('selected data reference changed')
    infra, trade = bytes(view.read(infra_va, 5)), bytes(view.read(trade_va, 5))
    if (infra, trade) != (b'infra', b'trade'):
        raise ValueError('category strings changed')
    count_limit = view.read(0x13e2a21, 1)[0]
    if count_limit != 14:
        raise ValueError('loop limit changed')
    rolling_vectors = rolling_constants(view)
    appender_tag_gate = appender_tag_constants(view)
    tag_cases = [{'tag': tag, 'enters_two_call_gate': int(appender_tag_enters(tag, appender_tag_gate))}
                 for tag in range(256)]
    raw_categories = bytes(view.read(category_va, count_limit - 1))
    if raw_categories != bytes.fromhex('00000000000100000000000000'):
        raise ValueError('category array changed')
    category_rows = [{'index': i, 'entry_va': hex(category_va+i), 'file_offset': hex(view.offset(category_va+i, 1)),
                      'byte': value, 'formatter_slice': (trade if value else infra).decode('ascii'),
                      'formatter_slice_va': hex(trade_va if value else infra_va)}
                     for i, value in enumerate(raw_categories)]
    severity = severity_names(view)
    if rip_target(0x13e32f6, view.read(0x13e32f6,7)) != 0x1f62fa:
        raise ValueError('rolling suffix template reference changed')
    templates = {
      'warn': template(view, warn_va, 'c00a2f646174612f6c6f672fc0062f7761726e2fc000'),
      'error': template(view, error_va, 'c00a2f646174612f6c6f672fc0072f6572726f722fc000'),
      'rolling_suffix': template(view, 0x1f62fa, 'c00b5f6f766572666c6f777b7d00'),
      'prefix_join': template(view, 0x1f04e5, 'c0012fc0012fc000'),
      'prefix_single': template(view, 0x1ea44d, 'c000'),
      'seed_cham': template(view, 0x1fc0ec, 'c0052f6368616d00'),
      'seed_static_config': template(view, 0x1ef5f5, 'c00e2f7374617469635f636f6e66696700'),
    }
    assertion_va = rip_target(0x13e42b5, view.read(0x13e42b5, 7))
    unwrap_va = rip_target(0x13e42ed, view.read(0x13e42ed, 7))
    assertion_len = struct.unpack('<I', view.read(0x13e42c4, 4))[0]
    unwrap_len = struct.unpack('<I', view.read(0x13e430b, 4))[0]
    diagnostics = {}
    for label, va, length, expected in (
        ('custom_live_assertion', assertion_va, assertion_len, b'assertion failed: !is_live'),
        ('builder_unwrap', unwrap_va, unwrap_len, b'called `Result::unwrap()` on an `Err` value'),
        ('pattern_missing', rip_target(0x3ccdca7, view.read(0x3ccdca7,7)),
         struct.unpack('<I', view.read(0x3ccdcaf,4))[0], b'pattern does not contain `{}`'),
        ('gzip_feature_missing', rip_target(0x3cce14b, view.read(0x3cce14b,7)),
         struct.unpack('<I', view.read(0x3cce153,4))[0], b'gzip compression requires the `gzip` feature'),
    ):
        raw = bytes(view.read(va, length))
        if raw != expected:
            raise ValueError('diagnostic literal changed: ' + label)
        diagnostics[label] = {'va': hex(va), 'file_offset': hex(view.offset(va, length)),
                              'length': length, 'bytes': raw.hex(), 'text': raw.decode('ascii')}
    suffix = b'_overflow{}'
    if templates['rolling_suffix']['tokens'] != [{'argument':True},{'literal':suffix.decode('ascii')}]:
        raise ValueError('rolling suffix tokens changed')
    rolling_cases = []
    for length in (11,12,15,16,17,18,31,32,33,64,65,66,67,127,128,129,130,256):
        for kind, tail in (('fixed_suffix',suffix), ('corrupt_last_byte',suffix[:-1]+b'|')):
            pattern = b'x'*(length-len(tail))+tail
            if len(pattern) <= rolling_vectors['short_max']:
                result = scalar_pair_search(pattern)
                method, mask = 'scalar_all_pairs', ''
            else:
                value = trailing_pair_mask(pattern,0x7b,0x7d)
                result = bool(value)
                method, mask = 'last_16_pairs_prior_match_zero', hex(value)
            rolling_cases.append({'length':len(pattern), 'case':kind, 'method':method,
                                  'tail_mask':mask, 'local_match':int(result)})
    extension_cases = []
    for tag, component in ((9,b''),(9,b'.'),(9,b'..'),(9,b'.gz'),(9,b'x.gz'),
                           (9,b'x.GZ'),(9,b'x.gzip'),(9,b'x.gz.tmp'),(9,b'x..gz'),
                           (9,b'x.tar.gz'),(9,b'x.'),(8,b'x.gz'),(10,b'x.gz')):
        extension_cases.append({'tag':tag, 'component_hex':component.hex(),
                                'decision':extension_decision(tag,component)})
    nv = bytes(view.read(0x2180ff, 9))
    nv_len = struct.unpack('<Q', view.read(0x5668490, 8))[0]
    if nv != b'NvTestnet' or nv_len != len(nv):
        raise ValueError('context name slice changed')
    modes = (0, 1, 2, 3, 255)
    scenarios = []
    for channel, key in (('warn', 1), ('error', 0)):
        for mode in modes:
            for mode_flag in (0, 1):
                for disabled in (False, True):
                    for present in (False, True):
                        for prefix in (False, True):
                            live, outcome = classify(mode, mode_flag, disabled, present, prefix)
                            scenarios.append({'channel': channel, 'map_key': key, 'mode': mode,
                                'mode_flag': mode_flag, 'disabled_bit': int(disabled),
                                'custom_present': int(present), 'prefix_present': int(prefix),
                                'derived_live_bit': int(live), 'local_selection': outcome})
    summary = {'schema': 1, 'target': 'node94', 'sha256': DIGEST,
               'coordinate_system': 'linked ELF virtual addresses; section-mapped file offsets',
               'fde_count': len(functions), 'fde_total_bytes': sum(x['size'] for x in functions),
               'selected_contracts': len(contracts), 'selected_edges': len(edges),
               'decoded_instructions': len(instruction_rows), 'decoded_transfers': len(transfer_rows),
               'transfer_classes': dict(sorted(Counter(x['class'] for x in transfer_rows).items())),
               'cfg_propositions': len(cfg_claims),
               'selected_relative_relocations': len(relocs), 'lsda_tables': len(lsda_headers),
               'lsda_callsite_rows': len(lsda_sites), 'outer_indices': len(category_rows),
               'infra_indices': sum(x['formatter_slice'] == 'infra' for x in category_rows),
               'trade_indices': sum(x['formatter_slice'] == 'trade' for x in category_rows),
               'scenario_rows': len(scenarios), 'templates': len(templates),
               'selected_severity_names': len(severity), 'rolling_vectors': rolling_vectors,
               'rolling_case_rows': len(rolling_cases), 'extension_case_rows': len(extension_cases),
               'appender_tag_constants': appender_tag_gate,
               'appender_tag_rows': len(tag_cases),
               'appender_admitted_tags': [row['tag'] for row in tag_cases if row['enters_two_call_gate']],
               'diagnostic_literals': len(diagnostics),
               'global_config_cell': cell_summary,
               'context_nv_name': {'va': hex(0x2180ff), 'length': nv_len, 'text': nv.decode('ascii'),
                                   'slice_slot': hex(0x5668488)},
               'limitations': ['selected static byte contracts only', 'not a whole-function CFG census',
                   'unwind extents do not establish all function boundaries',
                   'formatting sink, transform, allocation, component reader, final logger builder, I/O, installation and exception semantics are external boundaries',
                   'scenario rows are static local deductions, not captured executions']}
    return {'functions': functions, 'contracts': contracts, 'edges': edges, 'relocations': relocs,
            'categories': category_rows, 'scenarios': scenarios, 'templates': templates, 'summary': summary,
            'lsda_headers': lsda_headers, 'lsda_sites': lsda_sites, 'diagnostics': diagnostics,
            'severity': severity, 'instructions': instruction_rows, 'transfers': transfer_rows,
            'cfg_claims': cfg_claims, 'rolling_cases': rolling_cases, 'extension_cases': extension_cases,
            'appender_tag_cases': tag_cases}


def generate(data, out):
    result = collect(data)
    out.mkdir(parents=True, exist_ok=True)
    specs = (
      ('instructions.tsv','instructions',('function','va','file_offset','size','bytes','class','rip_relative','target')),
      ('transfers.tsv','transfers',('function','va','file_offset','size','bytes','class','rip_relative','target')),
      ('cfg-claims.tsv','cfg_claims',('label','function','from_va','to_va','forbidden_va','reachable')),
      ('rolling-cases.tsv','rolling_cases',('length','case','method','tail_mask','local_match')),
      ('extension-cases.tsv','extension_cases',('tag','component_hex','decision')),
      ('appender-tag-cases.tsv','appender_tag_cases',('tag','enters_two_call_gate')),
      ('functions.tsv','functions',('role','start_va','end_va','file_offset','size','fde_va','cie_va','lsda_va','sha256')),
      ('contracts.tsv','contracts',('label','va','file_offset','length','bytes')),
      ('edges.tsv','edges',('label','function','site_va','file_offset','bytes','destination_kind','destination','fallthrough')),
      ('relocations.tsv','relocations',('slot_va','relocation_file_offset','type','symbol','addend')),
      ('categories.tsv','categories',('index','entry_va','file_offset','byte','formatter_slice','formatter_slice_va')),
      ('severity.tsv','severity',('key','length_va','length','relative_slot_va','relative','name_va','name_file_offset','bytes','text')),
      ('scenarios.tsv','scenarios',('channel','map_key','mode','mode_flag','disabled_bit','custom_present','prefix_present','derived_live_bit','local_selection')),
      ('lsda-headers.tsv','lsda_headers',('function','lsda_va','header_file_offset','lpstart_encoding','type_encoding','callsite_encoding','callsite_file_offset','callsite_size','entries')),
      ('lsda-sites.tsv','lsda_sites',('function','lsda_va','entry_file_offset','start_va','end_va','landing_va','action_index')),
    )
    for filename, key, columns in specs:
        tsv(out / filename, result[key], columns)
    for key in ('templates', 'diagnostics', 'summary'):
        (out / (key + '.json')).write_text(json.dumps(result[key], indent=2, ensure_ascii=True) + '\n', encoding='utf-8', newline='\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    result = generate(TARGET.read_bytes(), args.out)
    print('node94 static log evidence:', result['summary']['fde_count'], 'FDEs,',
          result['summary']['selected_edges'], 'selected edges')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as error:
        print('config_log_path94:', error, file=sys.stderr)
        raise SystemExit(1)
