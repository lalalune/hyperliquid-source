#!/usr/bin/env python3
"""Extract a bounded alternate node-94 precompile-provider handoff statically.

All VAs are linked ELF virtual addresses. Fixed x86 byte shapes are reviewed
locally and are not a general decoder; no captured instruction is executed.
"""
import argparse
import csv
import hashlib
import json
import struct
from pathlib import Path

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Previously researched constructor entry points: used only as labeled
# dependency targets, never selected or re-exported as new bodies here.
PRIOR_CONSTRUCTORS = {
    0x4e99110: 0, 0x4e98c70: 1, 0x4e99650: 2,
    0x4e99f30: 3, 0x4e99af0: 4, 0x4e9a310: 5,
}
PROVIDERS = (0x32885e0, 0x3288f00, 0x328c570,
             0x3286df0, 0x328a750, 0x3288c80)
EXTRA_FUNCTIONS = {
    0x324d170: 'final-output status translation',
    0x32ac4c0: 'output-state move and context reset',
    0x3286bf0: 'post-call capped-word adjustment',
    0x3286e10: 'result status-dependent word adjustment',
    0x3286e80: 'final output adapter',
    0x3287080: 'frame callback adapter',
    0x32876d0: 'second account update adapter',
    0x3287b50: 'first account update adapter',
    0x32bded0: 'revision 9 postexecution pair constructor',
    0x32cace0: 'revision 9 execution-pair constructor',
    0x32d1d80: 'first four-limb account update',
    0x32d2e70: 'second four-limb account update',
    0x32d36c0: 'final output and context-error handoff',
    0x34d74a0: 'owned-map destruction',
    0x37f98f0: 'registry publication and call-frame executor',
    0x37fb9e0: 'revision selector and handler builder',
}
PAIR_LEAS = (0x32caf74, 0x32caf88, 0x32caf9c, 0x32cafb0,
             0x32cafc4, 0x32cafd3, 0x32cafe2, 0x32caff1,
             0x32cb003, 0x32cb018, 0x32cb02d)
POST_LEAS = (0x32be01a, 0x32be029, 0x32be038,
             0x32be047, 0x32be056, 0x32be065)
CASE_PREFIXES = (
    bytes.fromhex('488d7c2420e8'),
    bytes.fromhex('488d7c2450e8'),
    bytes.fromhex('488dbc2490000000e8'),
    bytes.fromhex('488dbc24f0000000e8'),
)

# Each range starts at a manually reviewed instruction boundary and is
# authenticated independently to permit meaningful lower-level mutation tests.
PINS = (
    ('revision_switch', 0x37fbbab, 33, '094b28180316a3eca111d84f22562d39ce2d77c9bf34dbe48b0e0f5993a9e463'),
    ('case9_constructors', 0x37fc048, 111, 'd81247667bc157e37ab17e546a39670354f1cccdc673656957bfa11afbb689e9'),
    ('case9_provider_copy', 0x37fc110, 55, '2ac3e3502419cf6e0ba030452ba6044c20a22a54293bf34c210802a498f2999f'),
    ('case9_postexecution_copy', 0x37fc147, 96, '17307aefed829df2553dd10eb09cbc35c1367ee4852f87b8158262174a9bb0f5'),
    ('case9_execution_copy', 0x37fc1a7, 32, '734ae8745dcb90aa9964caff8baf3899be44f6bb1cf490e2878bc5338409fdd9'),
    ('builder_final_copy', 0x37fd237, 56, 'a900ef63214f9a4d79ce6370b4e91a2f3fc2133882ea4e9ac7ea706bbe74f153'),
    ('provider_publish', 0x32b8599, 14, 'c3b2e4dc4cb18bff689e28fc6cdcdd0b91486a6eedd99035a8c6f426d7663335'),
    ('callback_publish', 0x32caf93, 20, 'a9492883272fc5ba798d1fd08f3af6f240fcf306dd1f3020e46185face8eceb6'),
    ('executor_guard1', 0x37f990d, 68, 'c01dbf12c3452a0d4a675a4fa67fd6aa13c83c6b306d27f7d70be08ec2555ed4'),
    ('executor_provider', 0x37f9951, 63, '4f5691d48222dc35b41140d598502f87a3e2560452060dffc3d3e0deeb373bd7'),
    ('executor_extract_keys', 0x37f9980, 56, '31beb5547d6b1610c603454e0e00e38f06a9125e5f42bba8951cff57be39091e'),
    ('executor_extend_keys', 0x37f9a5e, 13, '51a14af7b01b20d1ef2abfdab9036b676ffbfaddd07f4595190e3a61cce4fd0c'),
    ('executor_map_replace', 0x37f9a6b, 129, '6c6ba0a7602eb19373237334cdb0e4ccc774a1053c59dddcdb5b3e8c910edc87'),
    ('executor_guard2', 0x37f9aec, 61, '7b54ab92d5b7d437944a05eeb2515c04d777bc34436b503b09ba46e1d6949689'),
    ('executor_subtract', 0x37f9b29, 23, '6827dd606b407c54d95bf5df941ef5635ae159e3879b3359f9f148abaeff740e'),
    ('executor_guard3', 0x37f9b40, 63, 'af88798af1cb2821b92a758ff4a4914904150337ab9d135fb932b35ecf1b7e5c'),
    ('executor_frame', 0x37f9b7f, 112, '600bb1c014dcd62791c93ce95892056bcf73e1d3d2a18a1c9fecc9c1cc85037c'),
    ('result_check', 0x37f9bef, 63, 'b6a260078cd45c390f4b8647284e425c809944286e4dd46f73c436129fa092ce'),
    ('fatal_copy', 0x37f9e25, 31, '173e7b0c702eeefa570398e4c4e416480c7c73cc7d6d1b022292472b2fcc9ec3'),
    ('result_loop_gate', 0x37f9ede, 45, '652c6d6467d8383fe90863fe0e596b5a8eaa3423760db366c5a60774f7655cbc'),
    ('post_check1', 0x37fb282, 70, '0ee50bd767c7ff7dd0a86022f2defdd4bf7852d33002ff25a8637079dc014e0c'),
    ('post_accounting', 0x37fb2c8, 92, '13a3c3ce9d2e04ab1ee9ed7764a5782a43b05b269999e2316f0597a2b664db74'),
    ('post_callback2', 0x37fb324, 48, '3cce803c02c15e2098a1d7fb4fa9820b8ff97d0f3c35964e7ab444e1ca2d2922'),
    ('post_check3', 0x37fb369, 62, 'd435bd5b983f63dca6f74dfd30202e57704cc84eba9e819b6ffeb9839e80d5fa'),
    ('post_check4', 0x37fb3bc, 65, '3bd53c82af1f4a6c40836e5720887f5c86a95f37378904abe2ec3ea38ff3365f'),
    ('final_result_handoff_copy', 0x37fb3fd, 104, '269e4cef9dd8860eb41e9211a827a1bf39233b03ed910b9459edae69897160c3'),
    ('unwind_publish', 0x37fb836, 49, 'b399e6747c2fcd122b361f30b1c1bad2da972202d3d2f2c4c634cbaf393b0d3d'),
    ('adapter', 0x3287080, 67, 'ee89f9e556aad67db50c679adb90e1bb1444e048a3661817eee21dd6f3eeeac6'),
    ('drop_iter', 0x34d74ae, 174, 'abe5bdc05615240841f17150b49b6c7a8f07e330b8fc3bd0740b94d6c2711e2b'),
    ('drop_tags', 0x34d755c, 188, '0312ddbc77bf0ffac0d91c6a13a6e31a0a6926c9255aa03f096293c186debb45'),
    ('drop_allocation', 0x34d7618, 72, '06f6ca4ec2e98236f9f1247d61618e4420b64848717ec2bbdae29d0ce05cc9a5'),
    ('post_result', 0x37fb465, 53, '78bc82b495fb1d4c1c951f63eb715334b4c934189713f38136be59e3d94d3afa'),
    ('result_return', 0x37fb49a, 124, 'f461e575d572ede08c8661d598ba7a09098f0c9ced315a534ad2c72ecf566f98'),
    ('post_constructor_pairs', 0x32be017, 89, '9762b7d2d163f587763d83b00904df0b868477422bc4f3a97fc49e1c12cc2f6a'),
    ('post_status_transform', 0x3286e10, 98, '679371297cea5eddc918d23ead7ea7e923b2e4177ddbe33cdf9e291e9ac58201'),
    ('post_refund_cap', 0x3286bf0, 62, '057376d81f048f5aed673853be88b58621b480e6497a694aa0df809d9cf7e146'),
    ('credit_a_adapter', 0x3287b50, 28, '64307b2f7a87a563b6466581afbee98959c35f1504f173dea57f68f504f0d556'),
    ('credit_b_adapter', 0x32876d0, 20, 'bd118ad29544613e1bcbe48711061d3698905f1858a3c63f74db07e17e7220db'),
    ('final_adapter', 0x3286e80, 91, '9a245a07d5418778cc5bd638118ffa9ac058d4ac20a6469eba29575e85139656'),
    ('credit_a_select', 0x32d1d99, 279, '55470e3e3ecb070efff596cdf2ea9dbd12d4d9ea996369bb4727b500405a58a8'),
    ('credit_a_arithmetic', 0x32d1eb0, 166, 'ac97f71be34f2f8f42eaf75b44736c109193fc5fcfc7a3728c08fcbec0438e25'),
    ('credit_b_select', 0x32d2e84, 276, 'da9295d9bd314ea7c76a342d125baf079a95e6fb77ad424a2229c68d870c0d6b'),
    ('credit_b_arithmetic', 0x32d2f98, 186, '15669c5b5b0a0cee21aedb8d4b52ab44d25048476ebc229be4e4f922f458c4db'),
    ('final_error_and_subtractions', 0x32d36d7, 63, 'd228f2758adc49b7845ffb5a7273c18ca709c9fee4953c13ba8fc0fde316909d'),
    ('final_error_return', 0x32d375c, 104, '45c5fb167c78f744348e0f54eb1cdeb253ca733f2b2c5dd71bc4ee2833cf89d9'),
    ('final_status_source', 0x32d3807, 82, '1580d9c3263e6da92eabbc7c7edad7cc45fa44a6c855920e1a605b41ab402560'),
    ('final_success_output', 0x32d38cc, 156, '5c21203aa6caa46d510a3a2070bf87f48de5f5d201f1e7e6dff2f65702522c21'),
    ('final_alternate_output', 0x32d3968, 205, '9ebdb4ab3024bdda812be1a5a7eeaaf3eeacb4d1726bba503e94a56dadb504a1'),
    ('final_output_cleanup', 0x32d3aa9, 108, '649d993a2c4c326421651d53f0c579e033a2cbdd825be8f414d7d9050a5df75e'),
    ('final_format_failure', 0x32d3b15, 121, '043da7e83f011b6b418863208a8ae79eb5c315106aafdb080369d4e46481128f'),
    ('output_status_translation', 0x324d170, 284, 'e374ac21b3df4b640a75f24a091860dc307a6b2444b24364a1c5ea038e5474d8'),
    ('output_status_dispatch', 0x32d38ad, 31, 'bd6cbd0c828b03f284664ee6fe0d27231b9318239fe89006145689284032c138'),
    ('state_reset_cleanup', 0x32ac4c0, 198, 'cdf66a797fe916225cf123d4727dd954b954174d1f7999c2cbb09096bdb38e3d'),
    ('state_reset_allocation', 0x32ac586, 170, '1389db58d5167ef3397cb3481de470428412229d6a8cf84674e3fb442fe5be81'),
    ('state_reset_move', 0x32ac630, 200, '23aad90feeec185c2bfb6bb6550646a45ed1ba1ff8a68c79b39d8558e73d8b2f'),
    ('state_reset_failures', 0x32ac6f8, 59, '1a9d0cf78090e9c82b183912e699b4bc985dbb5d15db7d6723c98bfb12830e45'),
)

# Selected transfers, not a complete control-flow census. Destinations are
# independently calculated from signed displacements before comparison.
EDGES = (
    ('revision_default', 0x37fbbb6, 0x37fc644, 'conditional'),
    ('case9_preexecution', 0x37fc098, 0x32b84c0, 'call'),
    ('case9_execution', 0x37fc0b2, 0x32cace0, 'call'),
    ('case9_join', 0x37fc1c2, 0x37fd237, 'jump'),
    ('executor_guard1', 0x37f994b, 0x37f99de, 'conditional'),
    ('derive_key_set', 0x37f998b, 0x34389a0, 'call'),
    ('extend_key_set', 0x37f9a66, 0x36e3590, 'call'),
    ('old_borrowed_map', 0x37f9ab2, 0x37f9abc, 'conditional'),
    ('drop_old_owned_map', 0x37f9ab7, 0x34d74a0, 'call'),
    ('executor_guard2', 0x37f9b23, 0x37f9c2e, 'conditional'),
    ('subtraction_borrow', 0x37f9b3a, 0x37fb68e, 'conditional'),
    ('executor_guard3', 0x37f9b79, 0x37f9c4e, 'conditional'),
    ('alternate_frame', 0x37f9b9d, 0x37f9c85, 'conditional'),
    ('frame_constructor_slot', 0x37f9bad, 0x5774588, 'indirect_slot'),
    ('null_frame', 0x37f9bb6, 0x37fb627, 'conditional'),
    ('frame_result_nonfour', 0x37f9c1b, 0x37f9e44, 'conditional'),
    ('frame_fatal_return', 0x37f9e3f, 0x37fb501, 'jump'),
    ('non_interpreter_result', 0x37f9ef1, 0x37fab96, 'conditional'),
    ('post_first_nonfive', 0x37fb2c2, 0x37fb49a, 'conditional'),
    ('post_subtraction_borrow', 0x37fb300, 0x37fb6d1, 'conditional'),
    ('post_third_nonfive', 0x37fb3a1, 0x37fb49a, 'conditional'),
    ('post_fourth_nonfive', 0x37fb3f7, 0x37fb49a, 'conditional'),
    ('post_final_return', 0x37fb498, 0x37fb501, 'jump'),
    ('old_map_unwind', 0x37fb862, 0x5660110, 'call'),
    ('adapter_runtime_boundary', 0x3287090, 0x32aceb0, 'call'),
    ('refund_signed_overflow', 0x3286bf5, 0x3286c14, 'conditional'),
    ('refund_subtract_borrow', 0x3286c02, 0x3286c21, 'conditional'),
    ('status_range_fallback', 0x3286e5d, 0x3286e66, 'conditional'),
    ('status_zeroed_payload', 0x3286e69, 0x3286e62, 'conditional'),
    ('credit_a_call', 0x3287b62, 0x32d1d80, 'call'),
    ('credit_b_call', 0x32876da, 0x32d2e70, 'call'),
    ('final_output_call', 0x3286ecd, 0x32d36c0, 'call'),
    ('credit_a_load', 0x32d1e9e, 0x32aa630, 'call'),
    ('credit_a_load_error', 0x32d1eaa, 0x32d1f56, 'conditional'),
    ('credit_a_sum_carry', 0x32d1eb5, 0x32d1f98, 'conditional'),
    ('credit_b_load', 0x32d2f87, 0x32aa630, 'call'),
    ('credit_b_load_error', 0x32d2f92, 0x32d3052, 'conditional'),
    ('credit_b_subtract1', 0x32d2fac, 0x32d3094, 'conditional'),
    ('credit_b_subtract2', 0x32d2fb6, 0x32d30a1, 'conditional'),
    ('final_context_error', 0x32d36e7, 0x32d375c, 'conditional'),
    ('final_subtract1', 0x32d3702, 0x32d3b76, 'conditional'),
    ('final_subtract2', 0x32d3710, 0x32d3b7f, 'conditional'),
    ('final_status_translation', 0x32d38b4, 0x324d170, 'call'),
    ('final_prepare_output', 0x32d3854, 0x32ac4c0, 'call'),
    ('final_format_helper', 0x32d3b6e, 0x576e098, 'indirect_slot'),
    ('final_format_return_trap', 0x32d3b74, 0x32d3b8c, 'jump'),
    ('reset_first_lazy_init', 0x32ac529, 0x32ac6f8, 'conditional'),
    ('reset_empty_old_table', 0x32ac53a, 0x32ac56a, 'conditional'),
    ('reset_allocation_null', 0x32ac594, 0x32ac713, 'conditional'),
    ('reset_empty_record_list', 0x32ac5c4, 0x32ac600, 'conditional'),
    ('reset_no_list_allocation', 0x32ac607, 0x32ac61c, 'conditional'),
    ('reset_second_lazy_init', 0x32ac689, 0x32ac723, 'conditional'),
    ('reset_allocation_failure_slot', 0x32ac71d, 0x576e020, 'indirect_slot'),
)
EDGE_BYTES = {
    0x37fbbb6: '0f87880a0000', 0x37fc098: 'e823c4abff',
    0x37fc0b2: 'e829ecacff', 0x37fc1c2: 'e970100000',
    0x37f994b: '0f858d000000', 0x37f998b: 'e810f0c3ff',
    0x37f9a66: 'e8259beeff', 0x37f9ab2: '7408',
    0x37f9ab7: 'e8e4d9cdff', 0x37f9b23: '0f8505010000',
    0x37f9b3a: '0f824e1b0000', 0x37f9b79: '0f85cf000000',
    0x37f9b9d: '0f85e2000000', 0x37f9bad: 'ff15d5a9f701',
    0x37f9bb6: '0f846b1a0000', 0x37f9c1b: '0f8523020000',
    0x37f9e3f: 'e9bd160000', 0x37f9ef1: '0f859f0c0000',
    0x37fb2c2: '0f85d2010000', 0x37fb300: '0f82cb030000',
    0x37fb3a1: '0f85f3000000', 0x37fb3f7: '0f859d000000',
    0x37fb498: 'eb67', 0x37fb862: 'e8a948e601',
    0x3287090: 'e81b5e0200',
    0x3286bf5: '701d', 0x3286c02: '721d', 0x3286e5d: '7307',
    0x3286e69: '77f7', 0x3287b62: 'e819a20400', 0x32876da: 'e891b70400',
    0x3286ecd: 'e8eec70400', 0x32d1e9e: 'e88d87fdff',
    0x32d1eaa: '0f85a6000000', 0x32d1eb5: '0f82dd000000',
    0x32d2f87: 'e8a476fdff', 0x32d2f92: '0f85ba000000',
    0x32d2fac: '0f82e2000000', 0x32d2fb6: '0f82e5000000',
    0x32d36e7: '7573', 0x32d3702: '0f826e040000', 0x32d3710: '0f8269040000',
    0x32d38b4: 'e8b798f7ff',
    0x32d3854: 'e8678cfdff', 0x32d3b6e: 'ff1524a54902', 0x32d3b74: 'eb16',
    0x32ac529: '0f85c9010000', 0x32ac53a: '742e', 0x32ac594: '0f8479010000',
    0x32ac5c4: '743a', 0x32ac607: '7413', 0x32ac689: '0f8594000000',
    0x32ac71d: 'ff15fd184c02',
}


def authenticate(data):
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('node 94 SHA-256 mismatch')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def s32(data):
    require(len(data) == 4, 'truncated displacement')
    return struct.unpack('<i', data)[0]


class Image:
    def __init__(self, data, secs=None):
        self.data = data
        self.secs = sections(data) if secs is None else secs

    def offset(self, va, length, executable=False):
        require(type(va) is int and type(length) is int and va >= 0 and length > 0,
                'invalid address or length')
        require(va + length <= 1 << 64, 'address overflow')
        found = [s for s in self.secs if s['type'] != 8 and s['flags'] & 2
                 and (not executable or s['flags'] & 4)
                 and s['address'] <= va and va + length <= s['address'] + s['size']]
        require(len(found) == 1, 'address is not uniquely file-backed')
        sec = found[0]
        off = sec['offset'] + va - sec['address']
        require(off >= 0 and off + length <= len(self.data), 'file range outside input')
        return off

    def read(self, va, length, executable=False):
        off = self.offset(va, length, executable)
        return self.data[off:off + length]

    def allocated_section(self, va):
        found = [s for s in self.secs if s['flags'] & 2
                 and s['address'] <= va < s['address'] + s['size']]
        require(len(found) == 1, 'address is not uniquely allocated')
        return found[0]


def transfer(image, va):
    head = image.read(va, 2, True)
    if head[0] in (0xe8, 0xe9):
        raw = image.read(va, 5, True)
        kind = 'call' if head[0] == 0xe8 else 'jump'
        target = va + 5 + s32(raw[1:])
    elif head[0] == 0x0f and 0x80 <= head[1] <= 0x8f:
        raw = image.read(va, 6, True)
        kind, target = 'conditional', va + 6 + s32(raw[2:])
    elif 0x70 <= head[0] <= 0x7f or head[0] == 0xeb:
        raw = head
        kind = 'jump' if head[0] == 0xeb else 'conditional'
        target = va + 2 + struct.unpack('<b', raw[1:])[0]
    elif head in (b'\xff\x15', b'\xff\x25'):
        raw = image.read(va, 6, True)
        kind, target = 'indirect_slot', va + 6 + s32(raw[2:])
    else:
        raise ValueError('unsupported transfer shape')
    return kind, target, raw


def lea(image, va, prefix):
    raw = image.read(va, 7, True)
    require(raw[:3] == prefix, 'unexpected RIP-relative LEA')
    return va + 7 + s32(raw[3:]), raw


def relocation_index(image):
    matches = [s for s in image.secs if s['type'] == 4]
    require(sorted(s['name'] for s in matches) == ['.rela.dyn', '.rela.plt']
            and not any(s['type'] in (9, 19) for s in image.secs),
            'unsupported relocation sections')
    result = {}
    for sec in matches:
        require(sec['size'] % 24 == 0, 'malformed RELA section')
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', image.data, off)
            require(slot not in result, 'duplicate relocation slot')
            result[slot] = (info, addend, off)
    return result


def relative(records, slot):
    require(slot in records, 'missing relative relocation')
    info, addend, off = records[slot]
    require(info == 8, 'unexpected relative relocation type or symbol')
    return addend, off


def provider(image, va):
    raw = image.read(va, 32, True)
    require(raw[:7] == bytes.fromhex('534889fb488d3d') and raw[11] == 0xe8,
            'unexpected provider prefix')
    require(raw[16:] == bytes.fromhex('48c70300000000488943084889d85bc3'),
            'unexpected provider return')
    cache = va + 11 + s32(raw[7:11])
    constructor = va + 16 + s32(raw[12:16])
    require(constructor in PRIOR_CONSTRUCTORS, 'unknown prior constructor')
    require(image.allocated_section(cache)['type'] == 8, 'cache is not NOBITS')
    return {'provider_va': hex(va), 'file_offset': hex(image.offset(va, 32, True)),
            'cache_va': hex(cache), 'constructor_va': hex(constructor),
            'mode': PRIOR_CONSTRUCTORS[constructor], 'raw': raw.hex()}


def case_groups(image, start):
    code = image.read(start, 0x180, True)
    require(code[:8] == bytes.fromhex('488dbc2450140000'),
            'case target is not its reviewed entry')
    rows = []
    positions = []
    for prefix in CASE_PREFIXES:
        pos = code.find(prefix)
        require(pos >= 0 and code.find(prefix, pos + 1) < 0, 'invalid case call shape')
        call_va = start + pos + len(prefix) - 1
        kind, target, raw = transfer(image, call_va)
        require(kind == 'call', 'case is not a direct call')
        rows.append((call_va, target, raw))
        positions.append(pos)
    require(positions == sorted(positions), 'case constructor order changed')
    tail = code[positions[-1]:]
    candidates = []
    for pos in range(len(tail) - 3):
        if tail[pos:pos+2] == b'\x40\xb5':
            candidates.append((positions[-1] + pos, tail[pos+2], 3))
        elif tail[pos:pos+2] == b'\x31\xed':
            candidates.append((positions[-1] + pos, 0, 2))
    require(len(candidates) == 1, 'missing or ambiguous canonical-byte assignment')
    p, canonical, size = candidates[0]
    after = start + p + size
    if after != 0x37fd237:
        kind, target, _ = transfer(image, after)
        require(kind == 'jump' and target == 0x37fd237, 'case does not join common tail')
    return rows, canonical, start + p


def provider_descriptor(image, start):
    # Match the constructor's descriptor publication, not an arbitrary LEA.
    code = image.read(start, 0x220, True)
    candidates = []
    for p in range(len(code) - 11):
        if code[p:p+3] == b'\x48\x8d\x0d' and code[p+7:p+11] == b'\x48\x89\x4b\x08':
            candidates.append(p)
    require(len(candidates) == 1, 'missing or ambiguous provider descriptor')
    p = candidates[0]
    desc = start + p + 7 + s32(code[p+3:p+7])
    return start + p, desc, code[p:p+11]


def revision_cases(image, records, provider_rows):
    require(image.read(0x37fbbab, 11, True) == bytes.fromhex('0fb683a01200004883f813'),
            'revision input or bound changed')
    kind, default, _ = transfer(image, 0x37fbbb6)
    require(kind == 'conditional' and default == 0x37fc644, 'unexpected revision default')
    table, _ = lea(image, 0x37fbbbc, b'\x48\x8d\x0d')
    require(table == 0x59a830, 'unexpected revision table')
    raw_table = image.read(table, 80)
    require(hashlib.sha256(raw_table).hexdigest() ==
            'c049bcc6a6d85791401046f168bc3209353eb66a9c406381acb414c9e805c3c8',
            'revision table bytes changed')
    entries = [table + s32(raw_table[i*4:i*4+4]) for i in range(20)]
    detail = {}
    for start in sorted(set(entries) | {default}):
        groups, canonical, store = case_groups(image, start)
        site, desc, pub = provider_descriptor(image, groups[1][1])
        adapter, _ = relative(records, desc + 0x28)
        require(adapter in provider_rows, 'unexpected provider adapter')
        detail[start] = {'case_va': hex(start), 'canonical': canonical,
                         'canonical_site': hex(store),
                         'groups': [{'call_va': hex(call), 'target_va': hex(target),
                                     'bytes': raw.hex()} for call, target, raw in groups],
                         'provider_descriptor_va': hex(desc),
                         'descriptor_store_va': hex(site), 'descriptor_store_bytes': pub.hex(),
                         'provider_va': hex(adapter), 'mode': provider_rows[adapter]['mode']}
    expected = [0, 0, 2, 2, 4, 5, 6, 8, 8, 9, 9, 11, 12, 12, 12, 15, 16, 17, 18, 19]
    require([detail[x]['canonical'] for x in entries] == expected and detail[default]['canonical'] == 255,
            'revision canonical map changed')
    modes = [0] * 6 + [1] * 3 + [2] * 2 + [3] * 6 + [4] + [5] * 2
    require([detail[x]['mode'] for x in entries] == modes and detail[default]['mode'] == 5,
            'revision provider-mode map changed')
    rows = []
    for raw_byte in range(256):
        case = entries[raw_byte] if raw_byte < 20 else default
        x = detail[case]
        rows.append({'input_byte': raw_byte, 'case_va': x['case_va'],
                     'canonical': x['canonical'], 'provider_descriptor_va': x['provider_descriptor_va'],
                     'provider_va': x['provider_va'], 'mode': x['mode'],
                     'address09_from_prior_lineage': x['mode'] >= 2,
                     'table_entry_va': hex(table + 4 * raw_byte) if raw_byte < 20 else '',
                     'table_bytes': raw_table[4*raw_byte:4*raw_byte+4].hex() if raw_byte < 20 else ''})
    return rows, detail, table, raw_table


def pair_rows(image, records, sites):
    rows = []
    for index, site in enumerate(sites):
        prefix = b'\x48\x8d\x05' if index == len(sites)-1 else b'\x48\x8d\x0d'
        desc, _ = lea(image, site, prefix)
        following = image.read(site + 7, 7, True)
        if following[:3] in (b'\x48\x89\x4b', b'\x48\x89\x43'):
            offset, store_raw = following[3], following[:4]
        elif following[:3] in (b'\x48\x89\x8b', b'\x48\x89\x83'):
            offset, store_raw = struct.unpack('<I', following[3:7])[0], following[:7]
        else:
            raise ValueError('unexpected callback descriptor store')
        require(offset == 8 + index * 16, 'callback output offset changed')
        methods = []
        for slot_offset in (0x18, 0x20, 0x28):
            target, record_offset = relative(records, desc + slot_offset)
            methods.append({'offset': slot_offset, 'slot_va': hex(desc + slot_offset),
                            'addend_va': hex(target), 'rela_file_offset': hex(record_offset)})
        rows.append({'index': index, 'site_va': hex(site), 'descriptor_va': hex(desc),
                     'descriptor_output_offset': offset, 'store_bytes': store_raw.hex(),
                     'methods': methods})
    return rows


def callback_pairs(image, records):
    rows = pair_rows(image, records, PAIR_LEAS)
    require(rows[0]['descriptor_va'] == '0x56e63a0'
            and rows[0]['methods'][2]['addend_va'] == '0x3286e10'
            and rows[2]['descriptor_va'] == '0x56e6400'
            and rows[2]['methods'][2]['addend_va'] == '0x3287080',
            'revision 9 execution descriptor changed')
    return rows


def post_pairs(image, records):
    rows = pair_rows(image, records, POST_LEAS)
    expected = ['0x3286bf0', '0x3287b50', '0x32876d0',
                '0x3286e80', '0x3286c30', '0x3289e70']
    require([r['methods'][2]['addend_va'] for r in rows] == expected,
            'postexecution callback targets changed')
    return rows


def status_classes(image):
    raw = image.read(0x3286e57, 0x1b, True)
    require(raw[:2] == b'\x8d\x4e' and raw[3:5] == b'\x83\xf9'
            and raw[6:8] == b'\x73\x07' and raw[15:17] == b'\x83\xfe',
            'unexpected status comparison shapes')
    first = -struct.unpack('<b', raw[2:3])[0]
    count, small_max = raw[5], raw[17]
    require((first, count, small_max) == (16, 6, 4), 'status comparisons changed')
    rows = []
    for byte in range(256):
        keep = 8 if first <= byte < first + count else 16 if byte <= small_max else 0
        rows.append({'status_byte': byte, 'preserved_bytes': keep,
                     'classification': 'one_word' if keep == 8 else 'two_words' if keep == 16 else 'zeroed'})
    return rows


def status_result_shape(image, target, input_byte):
    """Match the finite return/trap byte shapes in the selected helper FDE."""
    p, result_class, result_byte = target, 4, input_byte
    for _ in range(5):
        require(0x324d170 <= p and p + 2 <= 0x324d28c,
                'status target outside selected FDE')
        head = image.read(p, 2, True)
        if head == b'\x0f\x0b':
            return 'trap', None, None, image.read(target, p + 2 - target, True)
        if head == b'\x89\xfa':
            require(p + 3 <= 0x324d28c and image.read(p + 2, 1, True) == b'\xc3',
                    'changed status return shape')
            return 'return', result_class, result_byte, image.read(target, p + 3 - target, True)
        if head[0] == 0xb0:
            result_class, p = head[1], p + 2
        elif head == b'\x40\xb7':
            require(p + 3 <= 0x324d28c, 'truncated status constant')
            result_byte, p = image.read(p + 2, 1, True)[0], p + 3
        elif head == b'\x31\xc0':
            result_class, p = 0, p + 2
        elif head == b'\x31\xff':
            result_byte, p = 0, p + 2
        else:
            raise ValueError('unsupported status result shape')
    raise ValueError('status result shape too long')


def output_status_map(image):
    require(image.read(0x324d170, 6, True) == bytes.fromhex('b004400fb6cf'),
            'changed status translation prefix')
    table, _ = lea(image, 0x324d176, b'\x48\x8d\x15')
    dispatch, _ = lea(image, 0x32d38bc, b'\x48\x8d\x35')
    require((table, dispatch) == (0x580fd4, 0x582234), 'status table location changed')
    # Take the consecutive prefix whose relative destinations lie in the
    # selected helper FDE. The byte-wide input bounds this scan to 256 entries;
    # the first destination outside the FDE is a boundary, left unclassified.
    candidates = image.read(table, 256 * 4)
    selected = []
    for value in range(256):
        entry = candidates[value*4:value*4+4]
        target = table + s32(entry)
        if not 0x324d170 <= target < 0x324d28c:
            break
        selected.append((value, entry, target))
    require(0 < len(selected) < 256, 'missing status prefix boundary')
    raw = candidates[:len(selected)*4]
    require(hashlib.sha256(raw).hexdigest() ==
            '4d44afb776b5ec1d3be8bf2f8c8177503a7c0bb84c9a78424f5dff0820477ffc',
            'status table bytes changed')
    rows = []
    for value, entry, target in selected:
        kind, result_class, result_byte, body = status_result_shape(image, target, value)
        rows.append({'input_byte': value, 'entry_va': hex(table + value * 4),
                     'entry_bytes': entry.hex(), 'target_va': hex(target),
                     'target_bytes': body.hex(), 'kind': kind,
                     'returned_class': result_class if kind == 'return' else '',
                     'returned_low_byte': result_byte if kind == 'return' else ''})
    classes = [r['returned_class'] for r in rows if r['kind'] == 'return']
    require(classes and min(classes) == 0 and max(classes) < 256, 'invalid status classes')
    out_raw = image.read(dispatch, (max(classes) + 1) * 4)
    require(hashlib.sha256(out_raw).hexdigest() ==
            'eedcdfd3d951393c781a8366f310c699aeed1309ab239724316cced32e2ee872',
            'output dispatch bytes changed')
    arms = [dispatch + s32(out_raw[i*4:i*4+4]) for i in range(max(classes) + 1)]
    require(arms == [0x32d38cc, 0x32d3973, 0x32d3968, 0x32d3b15, 0x32d3b15],
            'output dispatch targets changed')
    for row in rows:
        row['output_arm_va'] = hex(arms[row['returned_class']]) if row['kind'] == 'return' else ''
    following = image.read(table + len(raw), 4)
    following_target = table + s32(following)
    require(not 0x324d170 <= following_target < 0x324d28c,
            'selected status prefix no longer ends at the same boundary')
    counts = {'trap': sum(r['kind'] == 'trap' for r in rows)}
    counts.update({str(c): sum(r['returned_class'] == c for r in rows) for c in range(len(arms))})
    metadata = {'helper_va': hex(0x324d170), 'table_va': hex(table),
                'table_file_offset': hex(image.offset(table, len(raw))), 'table_bytes': raw.hex(),
                'dispatch_va': hex(dispatch), 'dispatch_file_offset': hex(image.offset(dispatch, len(out_raw))),
                'dispatch_bytes': out_raw.hex(), 'dispatch_arms': [hex(x) for x in arms],
                'first_unselected_entry_bytes': following.hex(),
                'first_unselected_target_va': hex(following_target), 'counts': counts,
                'scope': 'The selected contiguous byte inputs are 0 through '
                         + str(len(rows) - 1) + '. Other values and the runtime-valid '
                         'input domain are not established.'}
    return rows, metadata


def credit_selection_inputs(image):
    """Recover the operands of the two reviewed four-limb selectors."""
    descriptions = (
        (0x32d1d80, 0x32d1db6, 0x32d1dbd, 0x32d1e71, 0x32d1e5c,
         ('488baf', '4c8baf', '4c8bbf', '4c8ba7'),
         '4d39c8480f42e94c0f42ea4c0f42f84c0f42e7', 0x32d1dc3),
        (0x32d2e70, 0x32d2ea1, 0x32d2ea8, 0x32d2f5c, 0x32d2f47,
         ('488baf', '4c8baf', '4c8ba7', '4c8bbf'),
         '4d39c8480f42e94c0f42ea4c0f42e04c0f42ff', 0x32d2eae),
    )
    rows = []
    for function, guard, branch, direct, compare, cap_prefixes, comparison, base in descriptions:
        raw_guard = image.read(guard, 7, True)
        require(raw_guard[:2] == b'\x83\xbf' and raw_guard[6] == 1,
                'changed credit selection guard')
        guard_offset = struct.unpack('<I', raw_guard[2:6])[0]
        kind, target, raw_branch = transfer(image, branch)
        require(guard_offset == 0x178 and kind == 'conditional' and target == direct
                and raw_branch == bytes.fromhex('0f85ae000000'),
                'changed credit selection branch')

        # Sites below are the reviewed loads/operations in low-to-high limb
        # order, which is different from their instruction order.
        cap_sites = [base + 7 * i for i in range(4)]
        left_sites = [base + i for i in (28, 49, 35, 67)]
        right_sites = [base + i for i in (60, 74, 42, 92)]
        groups = (
            ('cap', cap_sites, cap_prefixes, (0x240, 0x248, 0x250, 0x258)),
            ('left', left_sites, ('488b8f', '488b97', '488b87', '4c8b8f'),
             (0x90, 0x98, 0xa0, 0xa8)),
            ('right', right_sites, ('48038f', '481397', '480387', '4c038f'),
             (0x180, 0x188, 0x190, 0x198)),
        )
        operands = {}
        for name, sites, prefixes, expected in groups:
            limbs = []
            for site, prefix, want in zip(sites, prefixes, expected):
                raw = image.read(site, 7, True)
                require(raw[:3] == bytes.fromhex(prefix), 'changed credit operand opcode')
                offset = struct.unpack('<I', raw[3:7])[0]
                require(offset == want, 'changed credit operand offset')
                limbs.append({'site_va': hex(site), 'offset': offset, 'bytes': raw.hex()})
            operands[name] = limbs
        comparison_raw = image.read(compare, len(bytes.fromhex(comparison)), True)
        require(comparison_raw.hex() == comparison, 'changed credit selection comparison')
        rows.append({'function_va': hex(function), 'guard_va': hex(guard),
                     'guard_bytes': raw_guard.hex(), 'guard_offset': guard_offset,
                     'guard_required': raw_guard[6], 'branch_va': hex(branch),
                     'branch_bytes': raw_branch.hex(), 'direct_va': hex(target),
                     'compare_va': hex(compare), 'compare_bytes': comparison_raw.hex(),
                     'operands_low_limb_first': operands})
    return rows


def state_reset_details(image, records):
    """Bind reset constants, their relocations and the null-allocation branch."""
    loads = []
    for site, expected in ((0x32ac56a, 0x56df2a8), (0x32ac576, 0x56df298),
                           (0x32ac6a8, 0x56df2a8), (0x32ac6b3, 0x56df298)):
        raw = image.read(site, 7, True)
        require(raw[:3] == bytes.fromhex('0f1005'), 'changed reset constant load')
        target = site + 7 + s32(raw[3:7])
        require(target == expected, 'changed reset constant target')
        data = image.read(target, 16)
        require(data == bytes(16), 'reset constant file bytes changed')
        overlapping = sorted(slot for slot in records if slot < target + 16 and slot + 8 > target)
        expected_slots = [target] if target == 0x56df298 else []
        require(overlapping == expected_slots, 'unexpected reset constant relocation')
        relocations = []
        for slot in overlapping:
            addend, off = relative(records, slot)
            require(addend == 0x202e90, 'changed reset constant relocation addend')
            relocations.append({'slot_va': hex(slot), 'addend_va': hex(addend),
                                'rela_file_offset': hex(off)})
        loads.append({'site_va': hex(site), 'instruction_bytes': raw.hex(),
                      'constant_va': hex(target), 'constant_file_offset': hex(image.offset(target, 16)),
                      'constant_file_bytes': data.hex(), 'relative_relocations': relocations})
    size_raw = image.read(0x32ac586, 5, True)
    require(size_raw[0] == 0xbf, 'changed reset allocation size instruction')
    size = struct.unpack('<I', size_raw[1:])[0]
    call_kind, call_slot, call_raw = transfer(image, 0x32ac58b)
    branch_kind, failure, branch_raw = transfer(image, 0x32ac594)
    require(size == 24 and (call_kind, call_slot) == ('indirect_slot', 0x576dfd8)
            and (branch_kind, failure) == ('conditional', 0x32ac713)
            and branch_raw == bytes.fromhex('0f8479010000'),
            'changed reset allocation or failure path')
    return {'function_va': hex(0x32ac4c0), 'reset_constant_loads': loads,
            'allocation_size_site_va': hex(0x32ac586), 'allocation_size_bytes': size_raw.hex(),
            'requested_bytes': size, 'allocation_call_va': hex(0x32ac58b),
            'allocation_call_bytes': call_raw.hex(), 'allocator_slot_va': hex(call_slot),
            'null_branch_va': hex(0x32ac594), 'null_branch_bytes': branch_raw.hex(),
            'null_target_va': hex(failure)}


def project_credit_selection(discriminator, cap, left, right):
    """Synthetic limb projection of the selected operands, not target execution."""
    wide, word = (1 << 256) - 1, (1 << 64) - 1
    require(type(discriminator) is int and 0 <= discriminator <= (1 << 32) - 1
            and all(type(v) is int and 0 <= v <= wide for v in (cap, left, right)),
            'invalid selection operands')
    if discriminator != 1:
        return cap
    limbs, carry = [], 0
    for shift in (0, 64, 128, 192):
        combined = ((left >> shift) & word) + ((right >> shift) & word) + carry
        limbs.append(combined & word)
        carry = combined >> 64
    for index in (3, 2, 1, 0):
        current = limbs[index]
        limit = (cap >> (64 * index)) & word
        if current != limit:
            if current > limit:
                return cap
            break
    return sum(limb << (64 * index) for index, limb in enumerate(limbs))


def project_cap(total, remaining, prior, adjustment):
    """Synthetic projection of the selected 64-bit cap; not target execution.

    Return the branch and the value left in the field. The checked signed sum
    is stored before the later unsigned subtraction-borrow check.
    """
    limit = (1 << 64) - 1
    require(all(type(x) is int and 0 <= x <= limit
                for x in (total, remaining, prior, adjustment)), 'not a 64-bit word')
    signed = lambda x: x if x < 1 << 63 else x - (1 << 64)
    summed = signed(prior) + signed(adjustment)
    if not -(1 << 63) <= summed < 1 << 63:
        return 'signed_add_overflow', prior
    stored = summed & limit
    if remaining > total:
        return 'subtract_borrow', stored
    return 'ok', min(stored, (total - remaining) >> 1)


def project_credit(balance, price, amount):
    """Synthetic low-256 product and saturating account addition projection."""
    word = (1 << 64) - 1
    wide = (1 << 256) - 1
    require(type(balance) is int and 0 <= balance <= wide
            and type(price) is int and 0 <= price <= wide
            and type(amount) is int and 0 <= amount <= word, 'invalid credit operands')
    product, carry = [], 0
    for shift in (0, 64, 128, 192):
        part = ((price >> shift) & word) * amount + carry
        product.append(part & word)
        carry = part >> 64
    out, carry = 0, 0
    for i, part in enumerate(product):
        value = ((balance >> (64 * i)) & word) + part + carry
        out |= (value & word) << (64 * i)
        carry = value >> 64
    return (wide, True) if carry else (out, False)


def project_second_credit(total, remaining, refund, flags, balance, price):
    """Model the selected second credit after a successful account load."""
    word = (1 << 64) - 1
    wide = (1 << 256) - 1
    require(all(type(v) is int and 0 <= v <= word for v in (total, remaining, refund))
            and type(flags) is int and 0 <= flags <= 255
            and all(type(v) is int and 0 <= v <= wide for v in (balance, price)),
            'invalid second credit inputs')
    updated_flags = flags | 4
    if remaining > total:
        return 'first_subtract_borrow', updated_flags, balance, False
    remainder = total - remaining
    if refund > remainder:
        return 'second_subtract_borrow', updated_flags, balance, False
    value, saturated = project_credit(balance, price, remainder - refund)
    return 'ok', updated_flags, value, saturated


def checked_windows(image):
    rows = []
    for name, va, size, expected in PINS:
        raw = image.read(va, size, True)
        require(hashlib.sha256(raw).hexdigest() == expected, 'changed semantic window: ' + name)
        rows.append({'name': name, 'va': hex(va), 'file_offset': hex(image.offset(va, size, True)),
                     'size': size, 'sha256': expected, 'bytes': raw.hex()})
    return rows


def checked_edges(image):
    rows = []
    for name, site, expected, expected_kind in EDGES:
        kind, target, raw = transfer(image, site)
        require((kind, target) == (expected_kind, expected)
                and raw.hex() == EDGE_BYTES[site], 'changed selected edge: ' + name)
        rows.append({'name': name, 'site_va': hex(site), 'file_offset': hex(image.offset(site, len(raw), True)),
                     'kind': kind, 'target_va': hex(target), 'bytes': raw.hex()})
    return rows


def allocation_checks(image, functions):
    prefix = bytes.fromhex('bf10000000ff15')
    rows = []
    for frame in functions:
        if not frame['role'].endswith('constructor'):
            continue
        start, end = frame['start'], frame['end']
        data = image.read(start, end-start, True)
        found = []
        for pos in range(len(data)-20):
            if data.startswith(prefix, pos) and data[pos+11:pos+16] == bytes.fromhex('4885c00f84'):
                call = start + pos + 5
                branch = start + pos + 14
                ck, slot, _ = transfer(image, call)
                bk, dest, branch_raw = transfer(image, branch)
                require((ck, slot, bk) == ('indirect_slot', 0x576dfd8, 'conditional')
                        and start <= dest < end, 'invalid allocation null branch')
                found.append({'owner_va': hex(start), 'call_va': hex(call), 'slot_va': hex(slot),
                              'requested_size': struct.unpack('<I', data[pos+1:pos+5])[0],
                              'branch_va': hex(branch), 'target_va': hex(dest), 'branch_bytes': branch_raw.hex()})
        expected = 11 if start == 0x32cace0 else 6 if start == 0x32bded0 else 4
        require(len(found) == expected, 'allocation branch count changed')
        rows.extend(found)
    return rows


def select_functions(image, detail):
    _, table = unwind_index(image.data)
    _, fdes = eh_frame_records(image.data, image.secs)
    fde_by_start = {}
    for f in fdes:
        fde_by_start.setdefault(f['start'], []).append(f)
    index = {x['start']: x['fde'] for x in table}
    selected = dict(EXTRA_FUNCTIONS)
    for addr in PROVIDERS:
        selected[addr] = 'borrowed registry provider'
    for row in detail.values():
        addr = int(row['groups'][1]['target_va'], 16)
        selected[addr] = 'preexecution pair constructor'
    require(len(selected) == 37, 'unexpected selected FDE count')
    frames, rows, bodies = [], [], []
    for start, role in sorted(selected.items()):
        matches = fde_by_start.get(start, [])
        require(len(matches) == 1, 'missing or duplicate selected FDE')
        f = matches[0]
        require(index.get(start) == f['fde'] and f['end'] > start, 'unwind index mismatch')
        raw = image.read(start, f['end']-start, True)
        frames.append(dict(f, role=role))
        rows.append({'start_va': hex(start), 'end_va': hex(f['end']), 'bytes': len(raw),
                     'file_offset': hex(image.offset(start, len(raw), True)),
                     'fde_va': hex(f['fde']), 'cie_va': hex(f['cie']),
                     'lsda_va': hex(f['lsda']) if f['lsda'] is not None else '',
                     'sha256': hashlib.sha256(raw).hexdigest(), 'role': role})
        bodies.append({'start_va': hex(start), 'end_va': hex(f['end']), 'bytes': raw.hex()})
    return frames, rows, bodies


def frame_record(image, va):
    frame = [s for s in image.secs if s['name'] == '.eh_frame' and s['type'] != 8]
    require(len(frame) == 1, 'missing frame section')
    size = struct.unpack('<I', image.read(va, 4))[0]
    require(size not in (0, 0xffffffff) and frame[0]['address'] <= va
            and va + 4 + size <= frame[0]['address'] + frame[0]['size'], 'invalid frame record')
    return image.read(va, size + 4).hex()


def lsda_record(image, frame):
    va = frame['lsda']
    if va is None:
        return None
    tables = [s for s in image.secs if s['name'] == '.gcc_except_table' and s['type'] != 8]
    require(len(tables) == 1, 'missing exception section')
    sec = tables[0]
    pos, end = image.offset(va, 1), sec['offset'] + sec['size']
    begin, data = pos, image.data
    require(pos < end and data[pos] == 0xff, 'unsupported landing encoding')
    pos += 1
    require(pos < end, 'truncated exception header')
    typ = data[pos]
    pos += 1
    type_va = None
    if typ == 0x9b:
        delta, pos = uleb(data, pos, end)
        type_va = sec['address'] + pos - sec['offset'] + delta
        require(type_va <= sec['address'] + sec['size'], 'type table outside section')
    else:
        require(typ == 0xff, 'unsupported type encoding')
    require(pos < end and data[pos] == 1, 'unsupported call-site encoding')
    pos += 1
    size, pos = uleb(data, pos, end)
    first, limit = pos, pos + size
    require(limit <= end, 'truncated call-site table')
    entries = []
    while pos < limit:
        start, pos = uleb(data, pos, limit)
        length, pos = uleb(data, pos, limit)
        landing, pos = uleb(data, pos, limit)
        action, pos = uleb(data, pos, limit)
        start += frame['start']
        require(frame['start'] <= start and start + length <= frame['end'], 'call site outside FDE')
        require(not landing or frame['start'] <= frame['start'] + landing < frame['end'],
                'landing outside FDE')
        entries.append({'start_va': hex(start), 'length': length,
                        'landing_va': hex(frame['start'] + landing) if landing else '', 'action': action})
    return {'function_va': hex(frame['start']), 'lsda_va': hex(va),
            'file_offset': hex(begin), 'type_encoding': typ,
            'type_table_va': hex(type_va) if type_va is not None else '',
            'prefix_bytes': data[begin:first].hex(), 'call_site_bytes': data[first:limit].hex(),
            'entries': entries}


def covering(lsda, site):
    rows = [x for x in lsda['entries'] if int(x['start_va'], 16) <= site
            < int(x['start_va'], 16) + x['length']]
    require(len(rows) == 1, 'missing or ambiguous exception interval')
    return rows[0]


def collect(image):
    records = relocation_index(image)
    provider_rows = {va: provider(image, va) for va in PROVIDERS}
    revisions, detail, table, table_raw = revision_cases(image, records, provider_rows)
    pairs, post = callback_pairs(image, records), post_pairs(image, records)
    statuses = status_classes(image)
    output_status, output_status_meta = output_status_map(image)
    selection = credit_selection_inputs(image)
    reset = state_reset_details(image, records)
    windows, edges = checked_windows(image), checked_edges(image)
    frames, functions, bodies = select_functions(image, detail)
    allocations = allocation_checks(image, frames)
    exception = [x for x in (lsda_record(image, f) for f in frames) if x is not None]
    exception_by_va = {int(x['function_va'], 16): x for x in exception}
    landing = covering(exception_by_va[0x37f98f0], 0x37f9ab7)
    require(landing['landing_va'] == '0x37fb836', 'old-map unwind landing changed')
    slot, slot_off = relative(records, 0x5774588)
    require(slot == 0x4e91cb0, 'frame constructor relocation changed')
    key = image.read(0x574f0c0, 20)
    require(key == b'\0' * 19 + b'\x09', 'prior address key changed')
    callback, callback_off = relative(records, 0x574f0b0)
    require(callback == 0x4e9d2a0, 'prior address callback changed')
    result = {
        'target_sha256': SHA256,
        'revision_table_va': hex(table), 'revision_table_file_offset': hex(image.offset(table, 80)),
        'revision_table_bytes': table_raw.hex(), 'cases': [detail[x] for x in sorted(detail)],
        'providers': [provider_rows[x] for x in sorted(provider_rows)],
        'prior_address_key': key.hex(), 'prior_key_va': hex(0x574f0c0),
        'prior_callback_slot_va': hex(0x574f0b0), 'prior_callback_va': hex(callback),
        'prior_callback_rela_file_offset': hex(callback_off),
        'frame_constructor_slot_va': hex(0x5774588), 'frame_constructor_va': hex(slot),
        'frame_constructor_rela_file_offset': hex(slot_off),
        'old_map_drop_interval': landing,
        'limitations': 'Provider lineage and the earlier runtime boundary are dependencies. '
                       'No captured execution, source identity, live reachability or whole-component closure is claimed.',
    }
    unwind = [{'start_va': hex(f['start']), 'end_va': hex(f['end']),
               'fde_va': hex(f['fde']), 'fde_bytes': frame_record(image, f['fde']),
               'cie_va': hex(f['cie']), 'cie_bytes': frame_record(image, f['cie']),
               'lsda_va': hex(f['lsda']) if f['lsda'] is not None else ''} for f in frames]
    summary = {'target_sha256': SHA256, 'selected_fdes': len(frames),
               'selected_bytes': sum(r['bytes'] for r in functions), 'reviewed_windows': len(windows),
               'selected_transfers': len(edges), 'raw_revision_entries': 20,
               'expanded_revision_inputs': len(revisions), 'distinct_revision_cases': len(detail),
               'provider_adapters': len(provider_rows), 'execution_pairs': len(pairs),
               'postexecution_pairs': len(post), 'status_byte_cases': len(statuses),
               'output_status_prefix_cases': len(output_status),
               'output_status_traps': output_status_meta['counts']['trap'],
               'allocation_checks': len(allocations), 'lsda_tables': len(exception),
               'lsda_call_sites': sum(len(x['entries']) for x in exception),
               'no_native_execution': True}
    return {'summary.json': summary, 'flow.json': result, 'functions.tsv': functions,
            'function-bytes.json': bodies, 'unwind.json': unwind,
            'exception-sites.json': exception, 'windows.tsv': windows,
            'transfers.tsv': edges, 'revisions.tsv': revisions,
            'callback-pairs.json': pairs, 'post-pairs.json': post,
            'credit-selection.json': selection, 'state-reset.json': reset,
            'output-status.tsv': output_status, 'output-status.json': output_status_meta,
            'status-classes.tsv': statuses, 'allocation-checks.tsv': allocations}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def write_tsv(path, rows):
    require(bool(rows), 'empty TSV')
    with path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), delimiter='\t', lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)


def generate(data, out):
    authenticate(data)
    values = collect(Image(data))
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    for name in sorted(values):
        if name.endswith('.json'):
            write_json(out / name, values[name])
        else:
            write_tsv(out / name, values[name])
    return values['summary.json']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    generate(TARGET.read_bytes(), args.out)


if __name__ == '__main__':
    main()
