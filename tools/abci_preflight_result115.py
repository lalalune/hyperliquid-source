#!/usr/bin/env python3
"""Extract selected node-115 block/precheck/result evidence without execution."""

import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

from elf_index import sections
from fde_extents import fde_extents, uleb

ROOT = Path(__file__).resolve().parent.parent
BINARY = ROOT / 'artifacts/node/115/hl-node'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
HISTORICAL_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
HISTORICAL_SIZE = 91774280
U64_MAX = (1 << 64) - 1

# Exclusive ends are selected, unwind-described extents, not full function proof.
FUNCTIONS = [
    ('owner_entry', 0x4fcac10, 0x4fcb113),
    ('owner_bridge', 0x59ec200, 0x59ed8e5),
    ('upper', 0x5443930, 0x5444cb0),
    ('adapter', 0x56185e0, 0x56186c0),
    ('block', 0x5a04e40, 0x5a065f8),
    ('begin', 0x5483850, 0x5483f43),
    ('collect', 0x5486610, 0x5486717),
    ('collect_result', 0x5961480, 0x59615c8),
    ('group', 0x58679a0, 0x5867d11),
    ('precheck', 0x560dca0, 0x560dd89),
    ('batch', 0x5b31fc0, 0x5b320c6),
    ('item_loop', 0x5867480, 0x586799e),
    ('location_handler', 0x54848e0, 0x548519f),
    ('key_index', 0x4eff000, 0x4eff13c),
]

WINDOWS = [
    ('owner_input', 0x4fcac10, 0x4fcac21, 0x4fcac30, 'ebf8749b7c22674987651d8d54fc6587d24a93ae7de56319c71bf2ad170ba992'),
    ('owner_context_to_bridge', 0x4fcac10, 0x4fcade0, 0x4fcae4d, 'f816e1efef44ed070b69711d213ff1956286c8be37fee0cd4db05cade9f51ef4'),
    ('owner_result_preservation', 0x4fcac10, 0x4fcaef4, 0x4fcaf76, '3472cffeb1cc34607e3760c62cc3a6b2851dda4ab54cc3fc98474cdff718441b'),
    ('owner_result_projection', 0x4fcac10, 0x4fcafd8, 0x4fcaffa, '15f1e6cbb15f7d8e5a6ef8c16468a2973f6a6cfcd9a02f4d6df8b93e14b56e45'),
    ('bridge_tls_and_context', 0x59ec200, 0x59ec211, 0x59ec2bb, '917aab57598a4809eae23d23ccf299d734d29b0bd4218494d958ca1646c1ec88'),
    ('bridge_result_guard', 0x59ec200, 0x59ec2bb, 0x59ec2d5, 'cffe5ae9f27f813ade3d9b04de49c3b60f7be1476004ab65ff30cd083099780d'),
    ('bridge_result_nonzero', 0x59ec200, 0x59ec2d5, 0x59ec389, 'bc45d1ec9292f8b987eb861fd16a82d8eff60936d88c2f502e6a6febb03d6bf2'),
    ('bridge_post_result_gate', 0x59ec200, 0x59ec389, 0x59ec3b5, '99148342c084fa36f186ba220c8d914cfd5ea71544911009efb3dd6304964659'),
    ('bridge_past_failure', 0x59ec200, 0x59ed3db, 0x59ed3fc, '57c38a33f6d2608bdd8d84f4f506ce7bc14e11befe53f00057d0292e2592d157'),
    ('bridge_failure_terminal', 0x59ec200, 0x59ed5cd, 0x59ed5cf, '54468dbf4fa476a33fda462613e3906e78c91c71147953fd83a2a92b2fcc2e32'),
    ('bridge_tls_alternatives', 0x59ec200, 0x59ed3fc, 0x59ed480, '08612c836be1709e57fb0a4c4d3ad290d690dea438a6f36ab4cb544316021da0'),
    ('bridge_return', 0x59ec200, 0x59ed143, 0x59ed15a, 'f4b5e2e29f6b5ed029b6d95b3a594c471a786bc6506567fd93b42a8ea742c4dd'),
    ('bridge_output', 0x59ec200, 0x59ecfdd, 0x59ecffe, '6fb2d88bd4952637fcc7f4ed65b3d0551844c11eab27200f1a9694c4df046b90'),
    ('entry_input', 0x5443930, 0x5443953, 0x54439b2, '8a295bb803b693ae3a4250886d6a3d5488cc84548615decc59042659254a88b8'),
    ('entry_result_state', 0x5443930, 0x54439b2, 0x54439d4, '1516fd1096e39707333b156e29b751b94d48c05216d1f3d29f3a1efa5013ae41'),
    ('adapter', 0x56185e0, 0x5618613, 0x561864f, '079880716dff387dcc4e3e78e2e1c2ec62940af2a995fe29563b69a44a5b1718'),
    ('engine_guards', 0x5a04e40, 0x5a04e71, 0x5a04f6f, '5fbde987f2c7ed888ec4ed6eae219614dc82a7b044a6cfb102658a7a57027217'),
    ('engine_begin_call', 0x5a04e40, 0x5a04fc6, 0x5a04fee, 'e7469ff5e70c8c48440d317b816e8dccd27c20e7c4329d46fa212b98247585e7'),
    ('engine_group_call', 0x5a04e40, 0x5a052ba, 0x5a05348, '71ea285c7675066c21f66158803aa1a58083b25776b54f92b615d197d0a97314'),
    ('engine_group_join', 0x5a04e40, 0x5a05348, 0x5a0540d, 'bde4f178f86cc84ebb042261bd49381a3f0c0008faecefe84e9d8d5d906738f0'),
    ('engine_mode2_height_check', 0x5a04e40, 0x5a055de, 0x5a05649, 'a882dcd27262a912b8ba6a8dfc7b986ad59b4ecab897bccfbd8e47d4bbc6de72'),
    ('engine_end_return', 0x5a04e40, 0x5a05fc1, 0x5a060eb, 'b1c35ffe4a8d99609728d5706f0f221349875c40efe0870fe48615104de35dde'),
    ('engine_failure_arms', 0x5a04e40, 0x5a0621d, 0x5a062f2, '7cc0cf40682630922b8380671c76431f0ba0e54aa389061712f0091fa8a0748b'),
    ('engine_failure_terminal', 0x5a04e40, 0x5a0637c, 0x5a063a1, 'ce863650714c6dec90aaacfcc44bed4c1072d3224f82ccba87bb87f1886f96e9'),
    ('engine_group_unwind', 0x5a04e40, 0x5a06413, 0x5a0641b, 'bebbd28c185ff4e16ca1e57740434a87ba24cdb013282d46e0f75746c5afa6cf'),
    ('engine_cleanup_unwind', 0x5a04e40, 0x5a06533, 0x5a065f2, '57a29093dd4089d968c4429f45dd616a2b87585a79b98453e797db8721c9eea4'),
    ('begin_clock', 0x5483850, 0x5483861, 0x54838d3, '708151001f997d1178dc39e1b655f482c37aa6919e53125ef148f8b345527473'),
    ('begin_mutations', 0x5483850, 0x54838d3, 0x5483924, '07ad2570507171186157e952b53d98b7bc11c79e69781dfb934cfea63b453f95'),
    ('begin_final_state', 0x5483850, 0x5483e0e, 0x5483e8c, '09facf7c17fd7062c4ad7a7f614608331c48edd463ee76187789df089975fd9a'),
    ('begin_failure', 0x5483850, 0x5483edf, 0x5483ef8, 'a5be335428cd20bbc12f5dae5be52a5542c26746cb061c6560c3cdd0fe188a2d'),
    ('collection_setup', 0x5486610, 0x5486619, 0x54866c3, 'a51951addfa31eafb2d2f8c0cff26e6d1d11ad9fd86f32bc07d476f6eca7820b'),
    ('collection_return', 0x5486610, 0x54866c3, 0x54866da, '47097aaee2cd96042a151e388049465b8bf0d831dc161e30f6a974dd9b1dbdf7'),
    ('collect_unwind', 0x5486610, 0x54866da, 0x5486711, 'debfac6c085509466272e685c35b522ef6fa9d9567cb0554630f84cc8ba54823'),
    ('collection_output', 0x5961480, 0x596148e, 0x59614f0, '34602f0a30b82106bbbdc4991f6e1612640817c18ae7b81e7139c494e2e25090'),
    ('collection_realloc', 0x5961480, 0x5961523, 0x59615a0, '82322e28a954f772f1249bd8ba4dc0c4313562b52b5ec101573fefabd42f34e3'),
    ('result_unwind', 0x5961480, 0x59615a0, 0x59615c2, '414a5212098441307ede81f8388d23995f0b4ff0926f4f49d64fe2f9346ec615'),
    ('group_capture', 0x58679a0, 0x58679cf, 0x5867a94, 'f2f4153263b0bf562b86f981ef5c0bee4580cd31a8e4a50de8d09115e789853b'),
    ('group_precheck', 0x58679a0, 0x5867a94, 0x5867b62, 'e7f7259f91fba1309568296163b894ab4ee86286d7ba0a93fd4a8661daf84c3a'),
    ('group_dispatch', 0x58679a0, 0x5867b62, 0x5867bd4, '764d92968a683119acee3174f7fe89d04fd63a05e69130fd01d05c5c512c2892'),
    ('group_output', 0x58679a0, 0x5867bd4, 0x5867cbf, '0faf39587b4c21bb1f8836e5e0600f9d59ae37efcd4ec8d569eba90049fa82a3'),
    ('group_unwind', 0x58679a0, 0x5867cce, 0x5867d0b, '002b54e4d932d884fa90637365cb161180303b3e83b276cc6fad22ea66a4d8fb'),
    ('precheck_entire', 0x560dca0, 0x560dca0, 0x560dd89, '92def428568aec6d91abd708e7ef2a6d587c77d72c162db45eba481eee2c300c'),
    ('batch_capture', 0x5b31fc0, 0x5b31fce, 0x5b32071, '038b45713490d737d8004023f4e9cbb4ac08544e19d5980fccd431e3b5ebf070'),
    ('batch_return', 0x5b31fc0, 0x5b32071, 0x5b320a0, 'd3a439244565b0f8b4e9bd20731e2056476134310cdef03dae111b25785771ba'),
    ('batch_unwind', 0x5b31fc0, 0x5b320b3, 0x5b320c6, '448ff9126eaa8bd10f9bd361955e7a0adfd990aa61d725d064c4592e5ea4088d'),
    ('item_loop_setup', 0x5867480, 0x5867480, 0x58674f0, '964ca14964975381eb42293a0fde5ea652785bc5ceddbe01662a828532bf7ed5'),
    ('item_output_record', 0x5867480, 0x58674f0, 0x586755b, '54aef255a06f92eae8eacbd5bb4ae996b8e3847380b95e46207f735a6613da5b'),
    ('item_input_step', 0x5867480, 0x586755b, 0x586760c, '0add0d60041274addf8a50fafd7fd671a374df7bd81f8fc6baa02b6fa7b0d146'),
    ('item_first_tag', 0x5867480, 0x586760c, 0x586764c, '0fb62e65443576f3acdd4f83b8c1e291de711feb46f87928174b55f096afd545'),
    ('item_flag_false', 0x5867480, 0x586764c, 0x58676e7, '20cdb82d40dce178c9ac1c461d6ae6708ea67d2bd41c06014882cedfc9737f3f'),
    ('item_flag_true', 0x5867480, 0x58676f0, 0x586775d, 'ac97449008ebd18a5055a241f798adc699b34c10955c18643d0dbbdd200dfcfb'),
    ('item_return_convert', 0x5867480, 0x586775d, 0x586781f, 'dc766a823020cc2c94d130bfe489076da12f6e791666f4cf85d1f091ae5ce370'),
    ('item_commit_return', 0x5867480, 0x586781f, 0x5867918, '57274e12d5fe7935dd9fcbf328e682657ca0e5ccf4c091d6f6b59e8f242abb97'),
    ('item_unwind', 0x5867480, 0x586794f, 0x5867992, '991e8a314c36b67e35cb57211c68998e8387b262208b5bb9d22f4c186fefc830'),
    ('handler_tag_and_key', 0x54848e0, 0x54848f1, 0x54849bf, '7bc822661aee11219bf6bdc7ec28fa347b791a4d747b21b47712f308d21dd9b4'),
    ('handler_other_tag', 0x54848e0, 0x54849bf, 0x5484a26, '8502654dda735d1a8c697a46baa6bf2e4e6969f3d29d22d1bdf7e98966267830'),
    ('handler_table_lookup', 0x54848e0, 0x5484a26, 0x5484a7e, 'bf77435b61194ec9f51938df5507c7e64c8dfb0b48696455dfa431b0fb4165cf'),
    ('handler_tree_lookup', 0x54848e0, 0x5484a7e, 0x5484b40, '2865886f2810960e95a34dfe71d801ae404da1268be46590c432476a64088ae8'),
    ('handler_fallback', 0x54848e0, 0x5484b40, 0x5484b6b, '2da33b4bbc044aba929163c59d4d29e1bda2a9d8b01eaf06e3c41e0eae19f7b1'),
    ('handler_counters', 0x54848e0, 0x5484b6b, 0x5484c21, '441eecfbe7e46c4fb1d3d1409972ccc23d0f2924eff9c12eb9113081b38264b3'),
    ('handler_expiry', 0x54848e0, 0x5484c21, 0x5484d02, 'a5a6b9080c16cca57ac3d52a58e2cc57ef41562063b823a48a4721cbe89bc528'),
    ('handler_penalty', 0x54848e0, 0x5484cf4, 0x5484d94, 'a7005f6eb5f41f4b1a67d050d4e860d78be2e92a25147c76060e196e39db154f'),
    ('handler_return_code', 0x54848e0, 0x5484d94, 0x5484e05, '7a7ccade1278ab9daebb42482c0e70bbbe71ae3ef8888b37f03f86482554d964'),
    ('handler_result_update', 0x54848e0, 0x5484e05, 0x5484f52, '90f43835684f9aa2fd16b3fb6d755097c293a4bc81527b24cc3f269a9eafac2c'),
    ('handler_callback', 0x54848e0, 0x5484f56, 0x5485035, 'c834a402f24666a34b05d869397c9996a1b3f18505dfe78bdd74cee1a8c7b1b0'),
    ('handler_late_update', 0x54848e0, 0x5485035, 0x54850a7, '62488bbab2ae2607f408490deb9ae73cc2b6a33ac75c48380bad3acdfa4e708c'),
    ('handler_location_fail', 0x54848e0, 0x54850a7, 0x5485145, 'e47153a8e0f45623d8a326ad58902719f33853ba77c9e34879197fe128ca00c7'),
    ('handler_overflow', 0x54848e0, 0x5485145, 0x5485154, '2b73ccde5fd1716cd15b59168d3cc2030669fa929942f7727a39553c5d115f80'),
    ('handler_unwind', 0x54848e0, 0x548516c, 0x5485193, 'a26d885868ea6ceffa40f7f45823a44f3c5f6c3c29456e9730e9a94817c83626'),
    ('index_lookup', 0x4eff000, 0x4eff000, 0x4eff13c, '4ee25d7953bfebdc6d5fd04d652e760a9871f0f1e47e946bd356ea5adb612307'),
]
TRANSFERS = [
    ('owner_bridge_call', 0x4fcae48, 'e8b313a200', 0x59ec200, 'call'),
    ('bridge_missing_tls', 0x59ec227, '0f84cf110000', 0x59ed3fc, 'jcc'),
    ('bridge_tls_mismatch', 0x59ec23b, '0f852a120000', 0x59ed46b, 'jcc'),
    ('bridge_adapter_call', 0x59ec2a8, 'e833c3c2ff', 0x56185e0, 'call'),
    ('bridge_no_change', 0x59ec2cf, '0f84b4000000', 0x59ec389, 'jcc'),
    ('bridge_past_target', 0x59ec3a9, '0f822c100000', 0x59ed3db, 'jcc'),
    ('bridge_other_target', 0x59ec3af, '0f8587010000', 0x59ec53c, 'jcc'),
    ('bridge_missing_tls_fallback', 0x59ed461, 'e84a0252ff', 0x4f0d6b0, 'call'),
    ('bridge_tls_mismatch_fallback', 0x59ed473, 'e888d9ffff', 0x59eae00, 'call'),
    ('bridge_failure_call', 0x59ed3f1, 'ff153923af00', 0x64df730, 'slot_call'),
    ('bridge_failure_exit', 0x59ed3f7, 'e9d1010000', 0x59ed5cd, 'jmp'),
    ('upper_to_adapter', 0x54439ad, 'e82e4c1d00', 0x56185e0, 'call'),
    ('adapter_to_engine', 0x5618630, 'e80bc83e00', 0x5a04e40, 'call'),
    ('freeze_past', 0x5a04ede, '0f82f0130000', 0x5a062d4, 'jcc'),
    ('freeze_equal', 0x5a04ee4, '0f844b130000', 0x5a06235, 'jcc'),
    ('order_invalid', 0x5a04eed, '0f862a130000', 0x5a0621d, 'jcc'),
    ('round_mismatch', 0x5a04eff, '0f8545130000', 0x5a0624a, 'jcc'),
    ('context_a_mismatch', 0x5a04f1a, '0f854d130000', 0x5a0626d, 'jcc'),
    ('context_b_mismatch', 0x5a04f23, '0f8544130000', 0x5a0626d, 'jcc'),
    ('count_mismatch', 0x5a04f4c, '0f853e130000', 0x5a06290, 'jcc'),
    ('mode_invalid', 0x5a04f59, '0f8557130000', 0x5a062b6, 'jcc'),
    ('begin_call', 0x5a04fe9, 'e862e8a7ff', 0x5483850, 'call'),
    ('group_call', 0x5a052ed, 'e81e13a8ff', 0x5486610, 'call'),
    ('join_boundary', 0x5a05343, 'e8a8fb43ff', 0x4e44ef0, 'call'),
    ('mode2_other', 0x5a055f7, '7550', 0x5a05649, 'jcc'),
    ('mode2_height_equal', 0x5a0561d, '0f849e090000', 0x5a05fc1, 'jcc'),
    ('mode2_height_failure', 0x5a0563e, 'ff1524c8ad00', 0x64e1e68, 'slot_call'),
    ('mode2_failure_exit', 0x5a05644, 'e9510d0000', 0x5a0639a, 'jmp'),
    ('end_boundary', 0x5a05fc9, 'e8f21e0000', 0x5a07ec0, 'call'),
    ('result_tag_fallback', 0x5a05fe9, '7414', 0x5a05fff, 'jcc'),
    ('order_failure_join', 0x5a06230, 'e994000000', 0x5a062c9, 'jmp'),
    ('frozen_failure_join', 0x5a06248, 'eb7f', 0x5a062c9, 'jmp'),
    ('engine_assertion_call', 0x5a062c9, 'ff156194ad00', 0x64df730, 'slot_call'),
    ('engine_assertion_exit', 0x5a062cf, 'e9c6000000', 0x5a0639a, 'jmp'),
    ('engine_past_call', 0x5a062e7, 'ff154394ad00', 0x64df730, 'slot_call'),
    ('engine_past_exit', 0x5a062ed, 'e9a8000000', 0x5a0639a, 'jmp'),
    ('engine_alloc_failure', 0x5a06384, 'ff150e91ad00', 0x64df498, 'slot_call'),
    ('engine_alloc_failure_join', 0x5a0638a, 'eb0e', 0x5a0639a, 'jmp'),
    ('clock_major', 0x5483893, '7519', 0x54838ae, 'jcc'),
    ('clock_middle', 0x54838a0, '750c', 0x54838ae, 'jcc'),
    ('clock_minor', 0x54838aa, '7706', 0x54838b2, 'jcc'),
    ('clock_equal', 0x54838ac, 'eb25', 0x54838d3, 'jmp'),
    ('clock_less', 0x54838b0, '7521', 0x54838d3, 'jcc'),
    ('begin_flag_zero', 0x548390b, '7417', 0x5483924, 'jcc'),
    ('begin_height_differs', 0x5483914, '750e', 0x5483924, 'jcc'),
    ('begin_mode_fail', 0x548391e, '0f85bb050000', 0x5483edf, 'jcc'),
    ('collector_prepare', 0x548666b, 'e8804f1c00', 0x564b5f0, 'call'),
    ('collector_group', 0x54866be, 'e8bdad4d00', 0x5961480, 'call'),
    ('collector_shrink', 0x596155a, '7516', 0x5961572, 'jcc'),
    ('collector_alloc_fail', 0x5961564, 'ff1526dfb700', 0x64df490, 'slot_call'),
    ('collector_each', 0x59614c4, 'e8d764f0ff', 0x58679a0, 'call'),
    ('predicate_slot', 0x5867a8e, 'ff159ce9c700', 0x64e6430, 'slot_call'),
    ('predicate_false', 0x5867a9a, '0f84c2000000', 0x5867b62, 'jcc'),
    ('precheck_call', 0x5867ade, 'e8bd61daff', 0x560dca0, 'call'),
    ('precheck_tag', 0x5867aed, '7473', 0x5867b62, 'jcc'),
    ('item_batch', 0x5867bcf, 'e8eca32c00', 0x5b31fc0, 'call'),
    ('result_short', 0x5867bef, '737a', 0x5867c6b, 'jcc'),
    ('result_large', 0x5867c6f, '731d', 0x5867c8e, 'jcc'),
    ('precheck_helper_a', 0x560dce2, 'ff1500a2ed00', 0x64e7ee8, 'slot_call'),
    ('precheck_helper_b', 0x560dd0c, 'ff15dea1ed00', 0x64e7ef0, 'slot_call'),
    ('precheck_inner_tag', 0x560dd19, '751c', 0x560dd37, 'jcc'),
    ('precheck_return_success', 0x560dd35, 'eb3e', 0x560dd75, 'jmp'),
    ('batch_empty', 0x5b31fdc, '742c', 0x5b3200a, 'jcc'),
    ('batch_alloc', 0x5b31fe7, 'ff1593d49a00', 0x64df480, 'slot_call'),
    ('batch_alloc_null', 0x5b31ff0, '0f849a000000', 0x5b32090, 'jcc'),
    ('batch_iterate', 0x5b3206c, 'e80f54d3ff', 0x5867480, 'call'),
    ('batch_allocation_fail', 0x5b32098, 'ff15fad39a00', 0x64df498, 'slot_call'),
    ('iteration_empty', 0x58674ab, '0f843c040000', 0x58678ed, 'jcc'),
    ('item_tag_other', 0x5867616, '0f85d4000000', 0x58676f0, 'jcc'),
    ('item_flag_nonzero', 0x5867646, '0f85bc000000', 0x5867708, 'jcc'),
    ('item_flag_zero', 0x5867702, '0f8444ffffff', 0x586764c, 'jcc'),
    ('item_rejected_existing_state', 0x58676d0, '0f849f010000', 0x5867875, 'jcc'),
    ('item_state_initial_count', 0x58676e2, 'e9a0010000', 0x5867887, 'jmp'),
    ('handler_call', 0x5867742, 'e899d1c1ff', 0x54848e0, 'call'),
    ('item_result_variant', 0x5867757, '0f85a3000000', 0x5867800, 'jcc'),
    ('item_encoded_result', 0x58677c8, 'e8c34e5eff', 0x4e4c690, 'call'),
    ('item_return_new_state', 0x586786f, '0f8561feffff', 0x58676d6, 'jcc'),
    ('item_status_true', 0x58678c2, '0f8528fcffff', 0x58674f0, 'jcc'),
    ('item_result_skip_drop', 0x58678d5, '0f8415fcffff', 0x58674f0, 'jcc'),
    ('handler_other_tag', 0x5484901, '0f85b8000000', 0x54849bf, 'jcc'),
    ('handler_count_zero', 0x548496b, '0f840d010000', 0x5484a7e, 'jcc'),
    ('handler_count_many', 0x5484975, '0f85ab000000', 0x5484a26, 'jcc'),
    ('handler_key_mismatch', 0x54849b4, '0f85c4000000', 0x5484a7e, 'jcc'),
    ('handler_key_match', 0x54849ba, 'e9ac010000', 0x5484b6b, 'jmp'),
    ('handler_hash', 0x5484a3e, 'e81dfba6ff', 0x4ef4560, 'call'),
    ('handler_index', 0x5484a70, 'e88ba5a7ff', 0x4eff000, 'call'),
    ('handler_index_found', 0x5484a78, '0f85ed000000', 0x5484b6b, 'jcc'),
    ('handler_tree_empty', 0x5484a8d, '0f84ad000000', 0x5484b40, 'jcc'),
    ('handler_tree_no_entries', 0x5484ae3, '743b', 0x5484b20, 'jcc'),
    ('handler_tree_next', 0x5484b0e, '74d0', 0x5484ae0, 'jcc'),
    ('handler_tree_equal', 0x5484b1a, '744f', 0x5484b6b, 'jcc'),
    ('handler_tree_end', 0x5484b31, '720d', 0x5484b40, 'jcc'),
    ('handler_tree_recurse', 0x5484b3b, 'e96bffffff', 0x5484aab, 'jmp'),
    ('handler_fallback_slot', 0x5484b56, 'ff15bc030601', 0x64e4f18, 'slot_call'),
    ('handler_fallback_failure', 0x5484b65, '0f857b020000', 0x5484de6, 'jcc'),
    ('handler_helper_a', 0x5484ba8, 'ff153a330601', 0x64e7ee8, 'slot_call'),
    ('handler_helper_b', 0x5484be0, 'ff150a330601', 0x64e7ef0, 'slot_call'),
    ('handler_inner_tag', 0x5484bf0, '0f859e010000', 0x5484d94, 'jcc'),
    ('handler_mode', 0x5484c1b, '0f85e4010000', 0x5484e05, 'jcc'),
    ('handler_penalty_overflow', 0x5484cfc, '0f8043040000', 0x5485145, 'jcc'),
    ('handler_lookup_second', 0x5484d74, 'e887a2a7ff', 0x4eff000, 'call'),
    ('handler_lookup_missing', 0x5484d7c, '0f84b3020000', 0x5485035, 'jcc'),
    ('handler_account_boundary', 0x5484eca, 'e881733a00', 0x582c250, 'call'),
    ('handler_action_boundary', 0x5484f4d, 'e80efe1600', 0x55f4d60, 'call'),
    ('handler_callback_slot', 0x5484f79, 'ff15a9ff0501', 0x64e4f28, 'slot_call'),
    ('handler_callback_bad_tag', 0x5484f89, '0f8518010000', 0x54850a7, 'jcc'),
    ('handler_location_failure', 0x548513d, 'ff155da50501', 0x64df6a0, 'slot_call'),
    ('handler_unwind_skip', 0x548516f, 'eb10', 0x5485181, 'jmp'),
    ('handler_diag_cleanup', 0x548517c, 'e87fae1a00', 0x5630000, 'call'),
    ('handler_result_cleanup', 0x5485186, 'e815b91900', 0x5620aa0, 'call'),
    ('handler_unwind_resume', 0x548518e, 'e8bdb8f600', 0x63f0a50, 'call'),
    ('item_cleanup_flag', 0x5867957, '741c', 0x5867975, 'jcc'),
    ('item_cleanup_variant', 0x5867966, '740d', 0x5867975, 'jcc'),
    ('item_variant_cleanup', 0x5867970, 'e8fb980e00', 0x5951270, 'call'),
    ('item_iterator_cleanup', 0x5867985, 'e886b41600', 0x59d2e10, 'call'),
    ('item_unwind_resume', 0x586798d, 'e8be90b800', 0x63f0a50, 'call'),
    ('batch_landing_cleanup', 0x5b320b9, 'e81282fdff', 0x5b0a2d0, 'call'),
    ('batch_unwind_resume', 0x5b320c1, 'e88ae98b00', 0x63f0a50, 'call'),
    ('group_pre_cleanup', 0x5867cd9, 'e8a26e0e00', 0x594eb80, 'call'),
    ('group_pre_landing_join', 0x5867cde, 'eb09', 0x5867ce9, 'jmp'),
    ('group_landing_cleanup', 0x5867cfe, 'e89d1b0f00', 0x59598a0, 'call'),
    ('group_unwind_resume', 0x5867d06, 'e8458db800', 0x63f0a50, 'call'),
    ('result_landing_join', 0x59615a3, 'eb0d', 0x59615b2, 'jmp'),
    ('result_landing_cleanup', 0x59615b5, 'e8461effff', 0x5953400, 'call'),
    ('result_unwind_resume', 0x59615bd, 'e88ef4a800', 0x63f0a50, 'call'),
    ('collect_landing_cleanup', 0x54866e2, 'e82910dcff', 0x5247710, 'call'),
    ('collect_landing_join', 0x54866e7, 'eb20', 0x5486709, 'jmp'),
    ('collect_unwind_resume', 0x548670c, 'e83fa3f600', 0x63f0a50, 'call'),
    ('engine_group_landing_join', 0x5a06416, 'e918010000', 0x5a06533, 'jmp'),
    ('engine_landing_cleanup', 0x5a0653b, 'e850f20300', 0x5a45790, 'call'),
    ('engine_end_cleanup', 0x5a06596, 'e865790400', 0x5a4df00, 'call'),
    ('engine_cleanup_next', 0x5a065a6, 'e885e30300', 0x5a44930, 'call'),
    ('engine_cleanup_final', 0x5a065b5, 'e8e6870400', 0x5a4eda0, 'call'),
    ('engine_cleanup_mode_slot', 0x5a065ce, 'ff15d4a5ad00', 0x64e0ba8, 'slot_call'),
    ('engine_unwind_resume', 0x5a065ed, 'e85ea49e00', 0x63f0a50, 'call'),
]


# Each operand is decoded only after its exact instruction prefix and suffix
# match. Sizes describe the encoded field, not a guessed Rust layout.
OPERANDS = [
    ('owner_input_pointer', 0x4fcac2c, '4c8b7e', 1, ''),
    ('owner_context', 0x4fcae24, '498d8f', 4, ''),
    ('owner_context_stack', 0x4fcae36, '48898c24', 4, ''),
    ('owner_argument_stack', 0x4fcae43, '488d5424', 1, ''),
    ('bridge_context_input', 0x59ec27f, '4c8b69', 1, ''),
    ('bridge_context_stack', 0x59ec283, '4c896c24', 1, ''),
    ('bridge_argument_stack', 0x59ec2a3, '488d7424', 1, ''),
    ('bridge_result_stack', 0x59ec29b, '488dbc24', 4, ''),
    ('bridge_change_byte_stack', 0x59ec2c7, '80bc24', 4, '00'),
    ('adapter_context_input', 0x5618624, '488b76', 1, ''),
    ('upper_result_stack', 0x54439a2, '488dbc24', 4, ''),
    ('upper_change_byte_stack', 0x54439cc, '80bc24', 4, '00'),
    ('context_state_slot', 0x5a04ebb, '498b8c24', 4, ''),
    ('context_state_slot_second', 0x5a055de, '498b8424', 4, ''),
    ('mode2_state_height', 0x5a055e6, '488b40', 1, ''),
    ('mode2_gate', 0x5a055f2, '41833c24', 1, ''),
    ('mode2_counter_ptr_first', 0x5a055f9, '498b8c24', 4, ''),
    ('mode2_counter_inc_offset', 0x5a05601, 'f048ff41', 1, ''),
    ('mode2_counter_ptr_second', 0x5a05606, '498b8c24', 4, ''),
    ('mode2_counter_read_offset', 0x5a0560e, '488b49', 1, ''),
    ('engine_old_tag', 0x5a04ec3, '4c8b89', 4, ''),
    ('engine_old_target', 0x5a04eca, '4c8b91', 4, ''),
    ('engine_mode_field', 0x5a04f52, '80b9', 4, '03'),
    ('begin_height_store', 0x54838e5, '498955', 1, ''),
    ('begin_first_round', 0x54838f1, '49894d', 1, ''),
    ('begin_second_round', 0x54838f5, '49898d', 4, ''),
    ('begin_third_round', 0x54838fc, '49898d', 4, ''),
    ('begin_height_flag', 0x5483903, '41f685', 4, '01'),
    ('collector_slot_stack', 0x54866ac, '4c897424', 1, ''),
    ('collector_argument_stack', 0x54866b6, '488d7424', 1, ''),
    ('group_capture_offset', 0x59614b7, '488d4e', 1, ''),
    ('group_state_context', 0x5867a75, '498db8', 4, ''),
    ('group_state_mode', 0x5867a7c, '410fb6b0', 4, ''),
    ('group_state_flag', 0x5867a84, '4981c0', 4, ''),
    ('group_slot_stack', 0x5867bb1, '48894424', 1, ''),
    ('group_argument_stack', 0x5867bca, '488d7424', 1, ''),
    ('batch_copy_source', 0x5b3203b, '410f1046', 1, ''),
    ('batch_copy_stack', 0x5b3204a, '0f114424', 1, ''),
    ('batch_argument_stack', 0x5b32067, '488d7424', 1, ''),
    ('item_slot_input', 0x58674d4, '488b46', 1, ''),
    ('item_slot_stack', 0x58674d8, '48894424', 1, ''),
    ('handler_slot_stack', 0x586772a, '488b7424', 1, ''),
    ('item_descriptor_saved_stack', 0x58674a6, '48897424', 1, ''),
    ('item_unwind_descriptor_stack', 0x5867975, '488b4424', 1, ''),
    ('item_initial_result_length', 0x58674b1, '4c8b66', 1, ''),
    ('item_rejected_state_tag', 0x58676cd, '8338', 1, ''),
    ('item_return_state_tag', 0x586786c, '8338', 1, ''),
    ('item_state_tag_reset', 0x58676d6, '48c700', 4, ''),
    ('item_state_count_initial', 0x58676dd, 'b9', 4, ''),
    ('item_state_count_read', 0x5867875, '488b48', 1, ''),
    ('item_state_count_write', 0x5867887, '488948', 1, ''),
    ('item_external_key_pointer', 0x58674c7, '488b46', 1, ''),
    ('item_external_key_offset', 0x58674cb, '4883c0', 1, ''),
    ('item_external_key_stack', 0x58674cf, '48894424', 1, ''),
    ('item_external_key_reload', 0x5867708, '488b4c24', 1, ''),
    ('handler_external_key_stack', 0x54848f1, '4c894424', 1, ''),
    ('handler_external_key_reload', 0x5484aee, '488b7c24', 1, ''),
    ('handler_inline_key_offset', 0x548490c, '488d41', 1, ''),
    ('pre_counter_read', 0x560dcbc, '488b86', 4, ''),
    ('pre_counter_write', 0x560dcd1, '488986', 4, ''),
    ('pre_success_read', 0x560dd1b, '498b86', 4, ''),
    ('pre_success_write', 0x560dd29, '498986', 4, ''),
    ('handler_count', 0x5484961, '488b98', 4, ''),
    ('handler_table', 0x5484980, '488b80', 4, ''),
    ('handler_tree', 0x5484a83, '4c8bb8', 4, ''),
    ('handler_tree_depth', 0x5484a9d, '4c8ba0', 4, ''),
    ('handler_counter_read', 0x5484b7d, '498b86', 4, ''),
    ('handler_counter_write', 0x5484b92, '498986', 4, ''),
    ('handler_success_read', 0x5484bfd, '498b86', 4, ''),
    ('handler_success_write', 0x5484c0f, '498986', 4, ''),
    ('handler_callback_ptr', 0x5484f56, '4d8bbe', 4, ''),
    ('handler_callback_table', 0x5484f62, '498b9e', 4, ''),
    ('item_output_stride', 0x5867547, '4983c5', 1, ''),
    ('engine_change_byte', 0x5a060d4, '8890', 4, ''),
    ('precheck_success_tag', 0x560dd12, '66817c2410', 2, ''),
    ('handler_input_tag', 0x54848fc, '3d', 4, ''),
    ('handler_success_tag', 0x5484beb, '3d', 4, ''),
    ('handler_fallback_code', 0x5484b5c, '66b8', 2, ''),
    ('handler_penalty_code', 0x5485097, '66b8', 2, ''),
    ('item_flag_failure_code', 0x5867678, '66c78424b0000000', 2, ''),
    ('handler_result_variant', 0x5484deb, '41c64500', 1, ''),
    ('caller_expected_variant', 0x5867747, '80bc24e0010000', 1, ''),
    ('handler_penalty_factor', 0x5484cf4, 'b9', 4, ''),
    ('item_input_stride', 0x5867566, 'ba', 4, ''),
    ('round_failure_length', 0x5a06224, 'be', 4, ''),
    ('frozen_failure_length', 0x5a0623c, 'be', 4, ''),
    ('features_failure_length', 0x5a062bd, 'be', 4, ''),
    ('past_failure_length', 0x5a062e2, 'be', 4, ''),
    ('bridge_past_failure_length', 0x59ed3ec, 'be', 4, ''),
    ('handler_unwrap_length', 0x5485138, 'be', 4, ''),
    ('begin_panic_length', 0x5483eed, 'be', 4, ''),
]

LITERALS = [
    ('round_failure', 0x5a06229, 0x93a61b, 'round_failure_length', 'assertion failed: round > parent_round'),
    ('frozen_failure', 0x5a06241, 0x93a65e, 'frozen_failure_length', 'assertion failed: !self.state.is_frozen()'),
    ('features_failure', 0x5a062c2, 0x93a641, 'features_failure_length', 'assertion failed: features_ok'),
    ('past_failure', 0x5a062d4, 0x929b14, 'past_failure_length', 'assertion failed: freeze_height >= self.locus.context.height()'),
    ('bridge_past_failure', 0x59ed3de, 0x929b14, 'bridge_past_failure_length', 'assertion failed: freeze_height >= self.locus.context.height()'),
    ('handler_unwrap', 0x548511b, 0x92a732, 'handler_unwrap_length', 'called `Result::unwrap()` on an `Err` value'),
    ('begin_panic', 0x5483edf, 0x7db393, 'begin_panic_length', 'explicit panic'),
]


def verify_digest(data, expected=SHA256):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('node-115 size or SHA-256 mismatch')


def file_offset(data, secs, va, size=1, executable=False):
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid address or size')
    candidates = []
    for sec in secs:
        if sec['type'] == 8 or (executable and not sec['flags'] & 4):
            continue
        if sec['address'] <= va and va + size <= sec['address'] + sec['size']:
            offset = sec['offset'] + va - sec['address']
            if offset + size <= len(data):
                candidates.append((offset, sec['name']))
    if len(candidates) != 1:
        raise ValueError('address lacks one file-backed section')
    return candidates[0]


def read_va(data, secs, va, size, executable=False):
    off, _ = file_offset(data, secs, va, size, executable)
    return bytes(data[off:off + size])


def checked_window(data, secs, spec, fde):
    label, owner, start, end, expected = spec
    if owner != fde['start'] or not owner <= start < end <= fde['end']:
        raise ValueError('window outside its selected FDE: ' + label)
    raw = read_va(data, secs, start, end - start, True)
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('selected window mismatch: ' + label)
    return raw


def contained_in_window(owner, site, size):
    return any(window_owner == owner and start <= site and site + size <= end
               for _, window_owner, start, end, _ in WINDOWS)


def decode_transfer(site, raw):
    if len(raw) == 5 and raw[0] in (0xe8, 0xe9):
        return ('call' if raw[0] == 0xe8 else 'jmp', site + 5 + struct.unpack_from('<i', raw, 1)[0])
    if len(raw) == 6 and raw[:2] in (b'\xff\x15', b'\xff\x25'):
        return ('slot_call' if raw[1] == 0x15 else 'slot_jmp', site + 6 + struct.unpack_from('<i', raw, 2)[0])
    if len(raw) == 6 and raw[0] == 0x0f and 0x80 <= raw[1] <= 0x8f:
        return 'jcc', site + 6 + struct.unpack_from('<i', raw, 2)[0]
    if len(raw) == 2 and (0x70 <= raw[0] <= 0x7f or raw[0] == 0xeb):
        return ('jmp' if raw[0] == 0xeb else 'jcc', site + 2 + struct.unpack_from('<b', raw, 1)[0])
    raise ValueError('unsupported transfer pattern')


def checked_transfer(data, secs, spec):
    label, site, expected_hex, expected_dest, expected_kind = spec
    expected = bytes.fromhex(expected_hex)
    raw = read_va(data, secs, site, len(expected), True)
    if raw != expected:
        raise ValueError('transfer bytes differ: ' + label)
    kind, dest = decode_transfer(site, raw)
    if kind != expected_kind or dest != expected_dest:
        raise ValueError('transfer destination differs: ' + label)
    return raw, kind, dest


def checked_operand(data, secs, spec):
    label, site, prefix_hex, width, suffix_hex = spec
    prefix, suffix = bytes.fromhex(prefix_hex), bytes.fromhex(suffix_hex)
    if width not in (1, 2, 4, 8):
        raise ValueError('unsupported operand width')
    raw = read_va(data, secs, site, len(prefix) + width + len(suffix), True)
    if not raw.startswith(prefix) or not raw.endswith(suffix) or (suffix and raw[-len(suffix):] != suffix):
        raise ValueError('operand pattern differs: ' + label)
    value = int.from_bytes(raw[len(prefix):len(prefix) + width], 'little')
    return raw, value


def checked_literal(data, secs, spec, length):
    label, site, va, _, expected = spec
    ref = read_va(data, secs, site, 7, True)
    if ref[:3] != b'\x48\x8d\x3d' or site + 7 + struct.unpack_from('<i', ref, 3)[0] != va:
        raise ValueError('literal reference mismatch: ' + label)
    value = read_va(data, secs, va, length)
    if value != expected.encode('ascii'):
        raise ValueError('literal bytes mismatch: ' + label)
    return ref, value


def section_once(secs, name):
    found = [s for s in secs if s['name'] == name and s['type'] != 8]
    if len(found) != 1:
        raise ValueError('missing or ambiguous section: ' + name)
    return found[0]


def relocated_location(data, secs, location_va):
    location_off, _ = file_offset(data, secs, location_va, 24)
    pointer_word, length, line, column = struct.unpack_from('<QQII', data, location_off)
    rel = section_once(secs, '.rela.dyn')
    if rel['type'] != 4 or rel['size'] % 24:
        raise ValueError('unsupported relocation section')
    matches = []
    for off in range(rel['offset'], rel['offset'] + rel['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, off)
        if slot == location_va:
            matches.append((off, info, addend))
    if len(matches) != 1:
        raise ValueError('Location needs exactly one relocation')
    rel_off, info, addend = matches[0]
    if info != 8 or addend < 0 or pointer_word != 0 or not 1 <= length <= 256:
        raise ValueError('unexpected Location record')
    path = read_va(data, secs, addend, length)
    if not path.endswith(b'l1/src/abci/state.rs'):
        raise ValueError('unexpected Location path')
    return {'record_va': hex(location_va), 'record_file_offset': hex(location_off),
            'record_bytes': data[location_off:location_off + 24].hex(),
            'relocation_file_offset': hex(rel_off), 'relocation_type': info,
            'path_va': hex(addend), 'path': 'l1/src/abci/state.rs', 'path_length': length,
            'line': line, 'column': column}


def read_location(data, secs):
    location_va = 0x64aa208
    location = relocated_location(data, secs, location_va)
    if (location['path_length'], location['line'], location['column']) != (20, 460, 78):
        raise ValueError('unexpected Location record')
    site = 0x5485129
    raw = read_va(data, secs, site, 7, True)
    if raw[:3] != b'\x4c\x8d\x05' or site + 7 + struct.unpack_from('<i', raw, 3)[0] != location_va:
        raise ValueError('Location instruction mismatch')
    location.update(reference_va=hex(site), reference_bytes=raw.hex())
    return location


def historical_crosscheck(data, historical):
    """Compare release-specific Location records; no call site is re-owned."""
    verify_digest(data)
    if len(historical) != HISTORICAL_SIZE or hashlib.sha256(historical).hexdigest() != HISTORICAL_SHA256:
        raise ValueError('historical node size or SHA-256 mismatch')
    old = relocated_location(historical, sections(historical), 0x56dfbf8)
    current = relocated_location(data, sections(data), 0x64767a8)
    if (old['path_length'], old['line'], old['column']) != (49, 107, 37):
        raise ValueError('historical Location differs')
    if (current['path_length'], current['line'], current['column']) != (20, 123, 37):
        raise ValueError('node-115 navigation Location differs')
    return {'node_94': {'sha256': HISTORICAL_SHA256, **old},
            'node_115': {'sha256': SHA256, **current},
            'limit': 'matching path suffixes are navigation evidence, not function or layout equivalence'}


def parse_lsda(blob, start, fde_start, fde_end):
    """Decode the selected zPLR call-site table; action values remain raw."""
    end = len(blob)
    if start < 0 or start + 3 > end or blob[start:start + 2] != b'\xff\x9b':
        raise ValueError('unsupported or truncated LSDA header')
    pos = start + 2
    type_delta, pos = uleb(blob, pos, end)
    type_base = pos + type_delta
    if type_base > end or type_base < pos:
        raise ValueError('LSDA type table outside section')
    if pos >= end or blob[pos] != 1:
        raise ValueError('unsupported LSDA call-site encoding')
    pos += 1
    table_len, pos = uleb(blob, pos, end)
    table_end = pos + table_len
    if table_end > end or table_end > type_base:
        raise ValueError('LSDA call-site table outside bounds')
    rows, previous_end = [], 0
    while pos < table_end:
        row_start = pos
        rel_start, pos = uleb(blob, pos, table_end)
        length, pos = uleb(blob, pos, table_end)
        landing, pos = uleb(blob, pos, table_end)
        action, pos = uleb(blob, pos, table_end)
        if not length or rel_start < previous_end or rel_start + length > fde_end - fde_start:
            raise ValueError('LSDA call-site range outside FDE or overlaps')
        if landing and landing >= fde_end - fde_start:
            raise ValueError('LSDA landing outside FDE')
        previous_end = rel_start + length
        rows.append((fde_start + rel_start, fde_start + rel_start + length,
                     None if landing == 0 else fde_start + landing, action, blob[row_start:pos].hex()))
    if pos != table_end:
        raise ValueError('LSDA table length mismatch')
    return rows


def sat_inc(value):
    if not 0 <= value <= U64_MAX:
        raise ValueError('expected u64')
    return min(value + 1, U64_MAX)


def sequential_mode2_check(counter, height):
    """Model only the no-concurrent-write, stable-pointer case."""
    if not all(0 <= value <= U64_MAX for value in (counter, height)):
        raise ValueError('expected u64 counter and height')
    updated = (counter + 1) & U64_MAX
    return updated, updated == height


def item_state_advance(tag_word, count):
    """Synthetic item completion projection; later helper effects excluded."""
    if not all(0 <= value <= U64_MAX for value in (tag_word, count)):
        raise ValueError('expected u64 state words')
    if tag_word & 0xffffffff == 1:
        return tag_word, sat_inc(count)
    return 1, 1


def same20(left, right):
    if len(left) != 20 or len(right) != 20:
        raise ValueError('expected two 20-byte keys')
    return left[:16] == right[:16] and left[16:] == right[16:]


def later_change(old_tag, new_tag, old_value, new_value):
    if not all(0 <= x <= U64_MAX for x in (old_tag, new_tag, old_value, new_value)):
        raise ValueError('expected u64 fields')
    old_low, new_low = old_tag & 0xffffffff, new_tag & 0xffffffff
    if old_low & new_low:
        return int(old_value != new_value)
    return (old_low | new_low) & 0xff


def signed32(value):
    if not 0 <= value < (1 << 32):
        raise ValueError('expected u32')
    return value if value < (1 << 31) else value - (1 << 32)


def clock_is_later(new, old):
    if len(new) != 3 or len(old) != 3:
        raise ValueError('expected three clock words')
    if any(not 0 <= word < (1 << 32) for word in (*new, *old)):
        raise ValueError('expected u32 clock words')
    return (signed32(new[0]), new[1], new[2]) > (signed32(old[0]), old[1], old[2])


def selected_counter_case(predicate, pre_tag, item_tag, admitted, item_inner_tag, first, second):
    """Synthetic one-item projection, assuming helpers do not alter the counters."""
    first, second = int(first), int(second)
    if not 0 <= first <= U64_MAX or not 0 <= second <= U64_MAX:
        raise ValueError('expected u64 counters')
    if not predicate:
        return first, second, 'precheck_skipped'
    first = sat_inc(first)
    if pre_tag != 0x1a2:
        return first, second, 'precheck_other_tag'
    second = sat_inc(second)
    if item_tag != 0x1a2:
        return first, second, 'item_other_tag'
    if not admitted:
        return first, second, 'item_not_admitted'
    first = sat_inc(first)
    if item_inner_tag == 0x1a2:
        second = sat_inc(second)
        return first, second, 'both_success_tags'
    return first, second, 'item_inner_other_tag'


def tsv(path, header, rows):
    with path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f, delimiter='\t', lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def dump_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def generate(data, out):
    verify_digest(data)  # Fail before creating the output directory.
    secs = sections(data)
    _, fdes, _ = fde_extents(data)
    selected = {start: (label, end) for label, start, end in FUNCTIONS}
    by_start = {}
    for fde in fdes:
        if fde['start'] in selected:
            if fde['start'] in by_start:
                raise ValueError('duplicate selected FDE start')
            by_start[fde['start']] = fde
    if set(by_start) != set(selected):
        raise ValueError('missing selected FDE')
    function_rows = []
    for label, start, end in FUNCTIONS:
        fde = by_start[start]
        if fde['end'] != end or 'index' not in fde:
            raise ValueError('FDE/header extent mismatch: ' + label)
        off, sec_name = file_offset(data, secs, start, end - start, True)
        raw = bytes(data[off:off + end - start])
        function_rows.append([label, hex(start), hex(end), hex(off), sec_name,
                              end - start, hex(fde['fde']), hex(fde['cie']),
                              '' if fde['lsda'] is None else hex(fde['lsda']),
                              fde['index'], hashlib.sha256(raw).hexdigest()])
    window_rows = []
    for spec in WINDOWS:
        label, owner, start, end, _ = spec
        raw = checked_window(data, secs, spec, by_start[owner])
        off, _ = file_offset(data, secs, start, len(raw), True)
        window_rows.append([label, hex(owner), hex(start), hex(end), hex(off), raw.hex(), hashlib.sha256(raw).hexdigest()])
    transfer_rows = []
    for spec in TRANSFERS:
        label, site, _, _, _ = spec
        owners = [f for f in by_start.values() if f['start'] <= site < f['end']]
        if len(owners) != 1:
            raise ValueError('transfer site not in exactly one selected FDE')
        raw, kind, dest = checked_transfer(data, secs, spec)
        if site + len(raw) > owners[0]['end']:
            raise ValueError('transfer crosses FDE')
        if not contained_in_window(owners[0]['start'], site, len(raw)):
            raise ValueError('transfer is outside pinned windows')
        off, _ = file_offset(data, secs, site, len(raw), True)
        transfer_rows.append([label, hex(owners[0]['start']), hex(site), hex(off), raw.hex(), kind, hex(dest)])
    operand_rows = []
    operands = {}
    for spec in OPERANDS:
        label, site, _, width, _ = spec
        owners = [f for f in by_start.values() if f['start'] <= site < f['end']]
        if len(owners) != 1:
            raise ValueError('operand site not in exactly one selected FDE')
        raw, value = checked_operand(data, secs, spec)
        if site + len(raw) > owners[0]['end']:
            raise ValueError('operand crosses FDE')
        if not contained_in_window(owners[0]['start'], site, len(raw)):
            raise ValueError('operand is outside pinned windows')
        off, _ = file_offset(data, secs, site, len(raw), True)
        operand_rows.append([label, hex(owners[0]['start']), hex(site), hex(off), raw.hex(), width, hex(value)])
        if label in operands:
            raise ValueError('duplicate operand label')
        operands[label] = value
    for before, after in [('pre_counter_read', 'pre_counter_write'),
                          ('pre_success_read', 'pre_success_write'),
                          ('pre_counter_read', 'handler_counter_read'),
                          ('pre_counter_read', 'handler_counter_write'),
                          ('pre_success_read', 'handler_success_read'),
                          ('pre_success_read', 'handler_success_write'),
                          ('precheck_success_tag', 'handler_input_tag'),
                          ('precheck_success_tag', 'handler_success_tag'),
                          ('item_rejected_state_tag', 'item_return_state_tag'),
                          ('item_rejected_state_tag', 'item_state_tag_reset'),
                          ('item_rejected_state_tag', 'item_state_count_initial'),
                          ('item_state_count_read', 'item_state_count_write'),
                          ('context_state_slot', 'context_state_slot_second'),
                          ('begin_height_store', 'mode2_state_height'),
                          ('mode2_counter_ptr_first', 'mode2_counter_ptr_second'),
                          ('mode2_counter_inc_offset', 'mode2_counter_read_offset'),
                          ('handler_result_variant', 'caller_expected_variant')]:
        if operands[before] != operands[after]:
            raise ValueError('cross-stage operand mismatch')
    group_slot = operands['group_slot_stack'] - operands['group_argument_stack']
    batch_slot = (operands['batch_copy_stack'] + group_slot - operands['batch_copy_source']
                  - operands['batch_argument_stack'])
    if (operands['owner_context_stack'] - operands['owner_argument_stack'] != operands['bridge_context_input'] or
            operands['bridge_context_stack'] - operands['bridge_argument_stack'] != operands['adapter_context_input'] or
            operands['bridge_change_byte_stack'] - operands['bridge_result_stack'] != operands['engine_change_byte'] or
            operands['upper_change_byte_stack'] - operands['upper_result_stack'] != operands['engine_change_byte'] or
            operands['collector_slot_stack'] - operands['collector_argument_stack'] != operands['group_capture_offset'] or
            batch_slot != operands['item_slot_input'] or
            operands['item_slot_stack'] != operands['handler_slot_stack'] or
            operands['item_descriptor_saved_stack'] != operands['item_unwind_descriptor_stack'] or
            operands['item_external_key_stack'] != operands['item_external_key_reload'] or
            operands['handler_external_key_stack'] != operands['handler_external_key_reload']):
        raise ValueError('cross-stage pointer projection mismatch')
    destinations = {label: expected_dest for label, _, _, expected_dest, _ in TRANSFERS}
    if destinations['precheck_helper_a'] != destinations['handler_helper_a'] or \
            destinations['precheck_helper_b'] != destinations['handler_helper_b']:
        raise ValueError('cross-stage helper slot mismatch')
    location = read_location(data, secs)
    literal_rows = []
    for spec in LITERALS:
        label, site, va, length_label, _ = spec
        ref, value = checked_literal(data, secs, spec, operands[length_label])
        owners = [f for f in by_start.values() if f['start'] <= site < f['end']]
        if len(owners) != 1 or not contained_in_window(owners[0]['start'], site, len(ref)):
            raise ValueError('literal reference is outside pinned windows')
        off, _ = file_offset(data, secs, va, len(value))
        literal_rows.append([label, hex(site), ref.hex(), hex(va), hex(off), len(value), value.decode('ascii')])
    gcc = section_once(secs, '.gcc_except_table')
    gcc_bytes = bytes(data[gcc['offset']:gcc['offset'] + gcc['size']])
    lsda_rows, lsda_by_function = [], {}
    for label, start, _ in FUNCTIONS:
        fde = by_start[start]
        va = fde['lsda']
        if va is None:
            continue
        if not gcc['address'] <= va < gcc['address'] + gcc['size']:
            raise ValueError('LSDA outside exception section')
        decoded_rows = parse_lsda(gcc_bytes, va - gcc['address'], start, fde['end'])
        lsda_by_function[start] = decoded_rows
        for start_va, end_va, landing, action, raw in decoded_rows:
            lsda_rows.append([label, hex(va), hex(start_va), hex(end_va),
                              '' if landing is None else hex(landing), action, raw])
    unwind_links = []
    for spec in TRANSFERS:
        label, site, raw_hex, _, kind = spec
        if kind not in ('call', 'slot_call'):
            continue
        owner = next(f for f in by_start.values() if f['start'] <= site < f['end'])
        rows = [row for row in lsda_by_function.get(owner['start'], [])
                if row[0] <= site and site + len(bytes.fromhex(raw_hex)) <= row[1]]
        if len(rows) > 1:
            raise ValueError('overlapping LSDA call-site ranges')
        if owner['lsda'] is None:
            status, landing, action = 'no_lsda', '', ''
        elif not rows:
            status, landing, action = 'not_in_table', '', ''
        else:
            row = rows[0]
            status = 'landing' if row[2] is not None else 'no_landing'
            landing = '' if row[2] is None else hex(row[2])
            action = row[3]
        unwind_links.append([label, hex(owner['start']), hex(site), status, landing, action])
    cases = [
        ('predicate_zero', 0, 0x1a2, 0x1a2, 1, 0x1a2, 4, 7),
        ('precheck_rejected', 1, 0x123, 0x1a2, 1, 0x1a2, 4, 7),
        ('item_variant', 1, 0x1a2, 0x123, 1, 0x1a2, 4, 7),
        ('item_not_admitted', 1, 0x1a2, 0x1a2, 0, 0x1a2, 4, 7),
        ('inner_rejected', 1, 0x1a2, 0x1a2, 1, 0x123, 4, 7),
        ('two_success', 1, 0x1a2, 0x1a2, 1, 0x1a2, 4, 7),
        ('both_saturated', 1, 0x1a2, 0x1a2, 1, 0x1a2, U64_MAX, U64_MAX),
        ('one_below_saturated', 1, 0x1a2, 0x1a2, 1, 0x1a2, U64_MAX - 1, U64_MAX - 1),
    ]
    case_rows = []
    for label, pred, pre, item, admitted, inner, first, second in cases:
        x, y, outcome = selected_counter_case(pred, pre, item, admitted, inner, first, second)
        case_rows.append([label, pred, hex(pre), hex(item), admitted, hex(inner), hex(first), hex(second),
                          hex(x), hex(y), outcome])
    state_cases = [('initialize', 0, 4), ('advance', 1, 4),
                   ('saturated', 1, U64_MAX), ('low32_tag_only', (1 << 32) | 1, 4)]
    state_rows = []
    for label, tag, count in state_cases:
        new_tag, new_count = item_state_advance(tag, count)
        state_rows.append([label, hex(tag), hex(count), hex(new_tag), hex(new_count)])
    mode2_cases = [('matches', 5, 6), ('mismatch', 5, 7),
                   ('wraps_to_zero', U64_MAX, 0), ('wrap_mismatch', U64_MAX, U64_MAX)]
    mode2_rows = []
    for label, counter, height in mode2_cases:
        updated, matched = sequential_mode2_check(counter, height)
        mode2_rows.append([label, hex(counter), hex(height), hex(updated), int(matched)])
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    tsv(out / 'functions.tsv', ['role', 'start_va', 'end_va_exclusive', 'file_offset', 'section', 'size',
                                'fde_va', 'cie_va', 'lsda_va', 'unwind_index', 'sha256'], function_rows)
    tsv(out / 'windows.tsv', ['label', 'fde_start', 'start_va', 'end_va_exclusive', 'file_offset', 'bytes', 'sha256'], window_rows)
    tsv(out / 'transfers.tsv', ['label', 'fde_start', 'site_va', 'file_offset', 'bytes', 'kind', 'destination_va'], transfer_rows)
    tsv(out / 'operands.tsv', ['label', 'fde_start', 'site_va', 'file_offset', 'bytes', 'encoded_width', 'value'], operand_rows)
    tsv(out / 'literals.tsv', ['label', 'reference_va', 'reference_bytes', 'literal_va', 'file_offset', 'length', 'ascii'], literal_rows)
    tsv(out / 'lsda.tsv', ['role', 'lsda_va', 'range_start_va', 'range_end_va_exclusive', 'landing_va', 'raw_action', 'row_bytes'], lsda_rows)
    tsv(out / 'unwind-links.tsv', ['transfer', 'fde_start', 'site_va', 'status', 'landing_va', 'raw_action'], unwind_links)
    tsv(out / 'synthetic-counters.tsv', ['case', 'predicate_nonzero', 'pre_tag', 'item_tag', 'admitted', 'inner_tag',
                                          'initial_first', 'initial_second', 'final_first', 'final_second', 'outcome'], case_rows)
    tsv(out / 'synthetic-item-state.tsv', ['case', 'initial_tag_word', 'initial_count', 'final_tag_word', 'final_count'], state_rows)
    tsv(out / 'synthetic-mode2.tsv', ['case', 'initial_counter', 'height', 'updated_counter', 'matched'], mode2_rows)
    dump_json(out / 'location.json', location)
    dump_json(out / 'joins.json', {
        'owner_relative_state_slot': hex(operands['owner_context'] + operands['context_state_slot']),
        'owner_context_offset': hex(operands['owner_context']),
        'context_state_slot_offset': hex(operands['context_state_slot']),
        'owner_to_bridge_input_offset': hex(operands['bridge_context_input']),
        'bridge_to_adapter_input_offset': hex(operands['adapter_context_input']),
        'collector_to_group_capture_offset': hex(operands['group_capture_offset']),
        'group_to_batch_capture_offset': hex(group_slot),
        'batch_to_item_capture_offset': hex(batch_slot),
        'engine_to_caller_change_byte_offset': hex(operands['engine_change_byte']),
        'mode2_counter_context_pointer_offset': hex(operands['mode2_counter_ptr_first']),
        'mode2_counter_pointee_offset': hex(operands['mode2_counter_inc_offset']),
        'pre_and_handler_counter_offsets': [hex(operands['pre_counter_read']), hex(operands['pre_success_read'])],
        'pre_and_handler_common_slots': [hex(destinations['precheck_helper_a']), hex(destinations['precheck_helper_b'])],
        'pre_and_handler_equal_tag': hex(operands['precheck_success_tag']),
        'item_output_stride': hex(operands['item_output_stride']),
        'inline_key_item_offset': hex(operands['handler_inline_key_offset']),
        'tree_key_source': 'separate item descriptor pointer, then pointee offset',
        'tree_key_descriptor_pointer_offset': hex(operands['item_external_key_pointer']),
        'tree_key_pointee_offset': hex(operands['item_external_key_offset']),
        'condition': 'static joins require normal helper returns and no intervening alias writes; runtime identity is unproven'
    })
    dump_json(out / 'summary.json', {'target_sha256': SHA256, 'selected_fdes': len(function_rows),
                                    'selected_windows': len(window_rows), 'selected_transfers': len(transfer_rows),
                                    'selected_operands': len(operand_rows), 'lsda_rows': len(lsda_rows),
                                    'selected_literals': len(literal_rows),
                                    'unwind_call_links': len(unwind_links),
                                    'synthetic_counter_cases': len(case_rows),
                                    'synthetic_item_state_cases': len(state_rows),
                                    'synthetic_mode2_cases': len(mode2_rows),
                                    'scope': 'selected static paths only; not a coverage denominator'})
    return {'fdes': len(function_rows), 'windows': len(window_rows), 'transfers': len(transfer_rows),
            'operands': len(operand_rows), 'lsda_rows': len(lsda_rows), 'cases': len(case_rows)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--old-elf', type=Path, help='optional authenticated historical ELF for Location comparison')
    args = parser.parse_args()
    data = BINARY.read_bytes()
    if args.old_elf is not None:
        print(json.dumps(historical_crosscheck(data, args.old_elf.read_bytes()), sort_keys=True))
    generate(data, args.out)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error) as exc:
        print('abci_preflight_result115:', str(exc), file=sys.stderr)
        raise SystemExit(1)
