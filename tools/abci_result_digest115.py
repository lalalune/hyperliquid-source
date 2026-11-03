#!/usr/bin/env python3
"""Extract a digest-bound post-block result fingerprint path (RE-017 / RE-009).

Static analysis only. No captured executable or external program is invoked.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
OLD_DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# FDE starts, exclusive ends and full-range SHA-256 pins. Names are local roles.
FUNCTIONS = [
    ('postblock_dispatch', 0x4f1ec10, 0x4f1f541, 'af3f265101d8fe07f1efeb87855258dab50983a4d7a4a8d5dbd83a6417841ad7'),
    ('postblock_owner', 0x4fc5d70, 0x4fc62d9, '8f27822722cfc351c550d30d291a545ca5629847e01f3d40dae700b30a620e78'),
    ('postblock_collect', 0x4dfe6d0, 0x4dff979, 'a1f1c9176b1b7ce655cb6b60027056894dfa0ffd68114b619273450c19132ec7'),
    ('record_compare_a', 0x53d7b00, 0x53d7be6, '933837de5e2a1c661eb34e4ff60d8f885072da2bbbceb87de5d977f0cb0e0c07'),
    ('record_compare_b', 0x53d7bf0, 0x53d7cf4, 'c9d7c8f9ca7f73f048cacf5190d2d3efec09395f2b378596dee578161da9fb8d'),
    ('result_fingerprint', 0x4e36af0, 0x4e36d11, 'dc785c2a55cef5ee25ba918f5c540dc0aef80377129e1b12bba63aee7cd1d61f'),
    ('array_serializer', 0x531bff0, 0x531c258, 'c5b998d92c079cd1e50ad6ce50126bee41fae7ac1397e74fce535f51856df3dc'),
    ('row_serializer', 0x531e200, 0x531ef79, 'cc5661e03bd4c3d94343726a3decbca6a931eb5d37ae02acc2714206ede5af0f'),
    ('identifier_serializer', 0x53228f0, 0x5322a61, '8ae3e0f61397c4cdeac4f8d064f1d638515e6c69522013f7f0aaa7af39650f46'),
    ('response_serializer', 0x54835f0, 0x5483849, '1420bbaba4347231f1d7a8eeb37ec196b78346cce95ae219f438ffa948c323c1'),
    ('array_header', 0x57ceba0, 0x57cee7f, '7a7c55ebf4eaa015fc8f6541163ba665be721633b0415814fd93793a82ef3f2b'),
    ('array_finish', 0x5306e90, 0x530704e, '2830b58284138fb1d33e97c922b8bf82a774cf9321b00294c8c591223bae18ff'),
    ('sponge_absorb', 0x5cda910, 0x5cdad3a, 'e24dbc47639c217bb45897e746eb069fe9e323e4098cd53fda92d4b95afb390f'),
    ('sponge_squeeze', 0x5cdad40, 0x5cdb03d, '94b1e9200106a1fc11ecd749e7eb693d22687fe87059406140f79c6bfdd53596'),
    ('sponge_permutation', 0x5cda380, 0x5cda902, '15d45b717ea70b1633e3d7972ca6a4dcc1240cc9e0518cfbfcbff4efc11838e8'),
]

# Instruction-aligned, SHA-256-pinned windows. Context windows join previously
# studied FDEs; they are not newly owned functions or a full control-flow graph.
WINDOWS = [
    ('c_worker_callback', 'context', 0x5a6e255, 0x5a6e264, '2a5d11f37ea0ab2b77500d9b4191d1da5a30231ea02206fce824c0bfb92c9752'),
    ('c_postblock_args', 'context', 0x5a6ea9a, 0x5a6eadb, 'c7a582856ed5bd0c0a38d85e8fefc9f6bc9cbd0942918ca755aabc6ab76e1b76'),
    ('post_dispatch', 'selected', 0x4f1ec21, 0x4f1ec2f, '8866fb3addef33333e8ac0d9aa5382eeeef9b4ffb2ee6ccd5849c60d1bda1f26'),
    ('post_tail', 'selected', 0x4f1ec85, 0x4f1ec9e, 'b19ca5927e4fb09465a418abe2629ec4e82049a541dba42d8a072c4f56579abc'),
    ('post_owner_input', 'selected', 0x4fc5d81, 0x4fc5dad, '030e6c2ee365795c7b4a4a9fd42e6e1feb6427600ba34a854a1dcf4a0b19e630'),
    ('post_owner_state', 'selected', 0x4fc5e59, 0x4fc5e78, '08037937f780484a5bb94bc80bdebfa47ac5baaa091f4bb922878626bd2e2f4a'),
    ('post_owner_alt_guard', 'selected', 0x4fc5f4e, 0x4fc5f5e, '6c6792a6f441b3ac4c4156b7390382c2039d43738935258cd56a4e44ac5929be'),
    ('post_owner_alt_state', 'selected', 0x4fc5f9b, 0x4fc5fd4, '04ade05643d4028af2ae2139504f986a83ed5870d3f9ee2d0364715f878e9113'),
    ('collect_input', 'selected', 0x4dfe6d0, 0x4dfe726, '1a3ae3c5fc556b41c1a565fb1aed361853b7598ee64f6b881bbec8ec4f1e994d'),
    ('collect_first_meta', 'selected', 0x4dfe9a0, 0x4dfea75, 'fb2429f1c38b21015f6824877a279a1483b15bcd6d5038877c155202c2557cb2'),
    ('collect_first_filter', 'selected', 0x4dfeb3f, 0x4dfec23, 'a85a889b77a926ae42ea93e606b0b70cb2ebc1cab157daaeab40b5cd4587c2a5'),
    ('collect_second_meta', 'selected', 0x4dfec98, 0x4dfed4b, 'f8e174a9dafeeca0b3b8dde81c66911a01aa170a7fe2db569291347e7c972308'),
    ('collect_second_filter', 'selected', 0x4dfee00, 0x4dfee88, 'c2664af9d40f477a6e95f3b13e58de172ae3aeb69da43592437b909289c28aaf'),
    ('collect_first_update', 'selected', 0x4dff366, 0x4dff3f0, '7551d3b4fa611169c8d780b5b27d1bcebb0abda87e745277ffbe6f5681871a5c'),
    ('collect_second_update', 'selected', 0x4dff3f0, 0x4dff480, '1a347728b4796550e2b21b1e53606f1291deb9af5893ee3a0af303f1724e7d7e'),
    ('compare_first', 'selected', 0x53d7b00, 0x53d7b1d, '62ea8e026b2a812bfddd877a2f0196fc280e43385d29036383e561c7e3f9b0a0'),
    ('compare_second', 'selected', 0x53d7bfa, 0x53d7c13, '46594a0ced4ae2ea222d7b8aacc9a437ff13b7dec6266e350e6c97bb5d0e1a07'),
    ('collect_status_fail', 'selected', 0x4dff84b, 0x4dff858, '3d9fea9c0078a4a9056c6d2d8dd45779639b7e29d23614f9c851207897f210f6'),
    ('collect_failure_guard', 'selected', 0x4dff4b0, 0x4dff4da, '20a68259b835361b025e5b020b91b7c05601d1678e339064ac2f0214e471a320'),
    ('c_worker_output', 'context', 0x5a6e96e, 0x5a6e97b, '3b66a5093373224da69e32c862aeefeb9cb6c1318852bd7630399c91d366d467'),
    ('c_worker_owner', 'context', 0x5a6e98d, 0x5a6ea15, 'b59f90802e72339e19b598676cd9fc46366b50c7d0eadae17061c67c37cffbbe'),
    ('c_height', 'context', 0x4fcb86d, 0x4fcb87f, 'f68a088c1d9128c52908960095ad6803758aac7fcd0242aed6b26181f3602297'),
    ('c_height_pack', 'context', 0x4fcb910, 0x4fcb934, '517faeb3bd71f9cf0ae664ca4a012eaa2bb29671632c692dac90555d25a937c7'),
    ('c_copy_one', 'context', 0x4fcba20, 0x4fcba6b, 'f4d83e8cb2832c86deab00555cd5cedbda6caf363a7c0a4c1f86c8b4066c4ee0'),
    ('c_copy_two', 'context', 0x4fcbaa5, 0x4fcbaf2, 'bd55e242919b61946432bd29c584a63ed4dc215f8a28a3dd0928baeae936cc31'),
    ('c_output', 'context', 0x4fcbb80, 0x4fcbbba, 'dace6c94aa5a45892bc4a624f5ffb8f653fb816689cee0515aef0e318ca3ca6d'),
    ('c_outer_direct', 'context', 0x4f12346, 0x4f12354, '2f46c993ec0e0884fd134bbcf4ffa8ef471ae03ae518082b438785b7fde63aff'),
    ('c_result', 'context', 0x5a6ea10, 0x5a6ea50, 'bf3c5b93109d634c1d99888c3f8dfc7531e2718f368b178e561c86f42d1414ff'),
    ('c_modulo', 'context', 0x5a6ec5c, 0x5a6ec84, 'b66a4fd22cee7e445930ee282134e209d743a71235e1cb17ddd836090da5c018'),
    ('c_hash_call', 'context', 0x5a6eced, 0x5a6ed11, 'da01be122952408a7a6a45126bb2ac09ed3f3f63330bd25f324e16af6b83cf34'),
    ('c_hash_some', 'context', 0x5a6edc4, 0x5a6edeb, 'b754270c7a56cd4a50e3d4ff6fc71292c5dfb59bfbc1cda08077240be83568a1'),
    ('c_record', 'context', 0x5a6ee45, 0x5a6ef0a, 'aa748f4c2e599dfe6902df37ddd21b95b89ba96a2bd5da4cbffb5fbb33d7c303'),
    ('c_output_gate', 'context', 0x5a6f8c3, 0x5a6f8d4, '2d918695ed5a8952731b78912796cdb66bedc116f12ac6c5f3f62edbe2ecb7ce'),
    ('c_hash_select', 'context', 0x5a6f916, 0x5a6f949, '23cd39bdacdaaa3be273bb0b5f5e344a7332fe7b18c474e18e57f5f196cfd788'),
    ('c_sink_call', 'context', 0x5a6f949, 0x5a6f996, '42e7e6fcb412723c2946cac20b2f068357357fa0e9e89959b29344100f579dd3'),
    ('hash_entry', 'selected', 0x4e36af0, 0x4e36b68, '9a34c62757fa64d9f035d6b2daabba2ddc294a874ffa3ece613eb5b2532df3cd'),
    ('hash_setup', 'selected', 0x4e36b68, 0x4e36bfd, '317e2348c310cbc3a21e2c1704bc43c38a4e90acb1e681e43a1fe558360278ac'),
    ('hash_sponge', 'selected', 0x4e36bef, 0x4e36c39, '9006edc388a51fa56e8210c98f26179766eacc3f4371a007f04035c777afbe63'),
    ('hash_error', 'selected', 0x4e36c5e, 0x4e36cc7, '2b57c3f07bdf99acf19b6db49f6df36fc30480303d66d9d042daa11bfa7832b7'),
    ('array_entry', 'selected', 0x531bff0, 0x531c069, '9415140a1d268e068b6aaef3ef0c8a50c9d153a999aae395494ecae314490c0b'),
    ('array_loop', 'selected', 0x531c19c, 0x531c212, 'e9989ed7bb07d73c84c5a325c604fdb11581cb3569688c703d88ca358d138ea4'),
    ('array_error', 'selected', 0x531c0c9, 0x531c13b, '3589de3c138f369d19b20befa2382b69035953e41f602cadfe03340fc76cb0e2'),
    ('header_pick', 'selected', 0x57cebae, 0x57cec27, '677d06a56af162de92572bb53ef175bcb7c7b9c463e2995d846019c680f9897d'),
    ('header_write', 'selected', 0x57ced13, 0x57ced51, 'f642e886e791ed552a027465c7116b00858936943ab75977c87d5094fd07edd1'),
    ('row_first', 'selected', 0x531e21f, 0x531e2d6, 'e94e236c10b7e75978983e2667a72be6267dbbb31399ab229e63a6b1e19822e2'),
    ('row_check', 'selected', 0x531e2d6, 0x531e30d, 'a3da124a17643a375039aae309f48edc0e992a5d64d1c508e11fc4753be3a8b4'),
    ('row_vec', 'selected', 0x531e3ae, 0x531e3ef, 'e1a08cca01500bef832accc984dac31a407dc9969bdfab8405a397ffc93aa5d5'),
    ('row_nested', 'selected', 0x531e6ad, 0x531e718, 'bc6f5867125ba9cfbf5b0950c0edeb7dcef8ef88614dd8e7e995199ecbb1d1c1'),
    ('row_loop', 'selected', 0x531e916, 0x531e97a, '9bad06f4435bec740104685d3b7164eb971f6fb3f276017c23c5ebb7e62aa218'),
    ('id_encode', 'selected', 0x53228f0, 0x5322922, 'c7e244bb3f7519fd3eb7d2dabb99437fe44ac7958fda917c763c47753672d342'),
    ('id_format', 'selected', 0x53229c4, 0x5322a1f, '24bac3382909f024bd6b235c5f25182542ed976b9c6ab21b3a68db3d6db210b4'),
    ('item_head', 'selected', 0x54835fe, 0x5483649, 'c5de6fc0e5bbda9850012475c0a3dabb7640ee7a841f8114ee9f241ef171e683'),
    ('item_fields', 'selected', 0x5483666, 0x5483738, '1ed70f14115126a9176a3cf46a7e6924aed52f6d1d7c82f004fe280a98d0f2ce'),
    ('item_errors', 'selected', 0x5483738, 0x5483790, 'df81629504e2de7329b45c9128ff8c0805768af40f3143ad44c75fcdb234e924'),
    ('array_finish', 'selected', 0x5306e9e, 0x5306ecc, '14e420728cee50ac5cd0a8866d7c1c76cfe148cf293700a74a04a8030a3a2ebd'),
    ('sponge_input', 'selected', 0x5cda910, 0x5cda9f4, '1a3e0cd87677bcc178d72cd723f06db9fab50f2e51d3ffcfbbc7903be38d6484'),
    ('sponge_final', 'selected', 0x5cdadbd, 0x5cdae1a, 'bf3ccbc0e2a9177bdcd188ae767de20c868013bcf65ad8f9426a0d37e27a925a'),
    ('perm_rounds', 'selected', 0x5cda7f0, 0x5cda827, 'f626dcfcd4ddda3980cdf0255ab83aa40aef1567753667b18afdd05a4a3e6c12'),
    ('c_tag_pack', 'context', 0x57d0b20, 0x57d0b6e, '97a69885f4ce8f473e5c0139e173b3c35bbee945b4519ffa9ad5d7e5bdbe1aaa'),
    ('c_hex_string', 'context', 0x57cf860, 0x57cf89c, '26c1dfd471496ae635dbeec91d4bdd1b6d439618ca46abb29244dc2bafce2837'),
    ('c_hex_formatter', 'context', 0x2eabb50, 0x2eabc62, 'd602168583e44b9ff0d8eb071237717971463da37384989806ae213919bf04b4'),
]

# These are selected instruction sites, not a scan of the entire executable.
# Slots and sites in prior packets are tagged context; slot bindings assume the
# static RELATIVE relocations remain effective at runtime.
TRANSFERS = [
    ('prior_worker_postblock', 'context', 0x5a6ead6, 'e8', 0x4f1ec10),
    ('dispatch_direct_tail', 'selected', 0x4f1ec99, 'e9', 0x4fc5d70),
    ('owner_to_collection', 'selected', 0x4fc5e73, 'e8', 0x4dfe6d0),
    ('owner_to_collection_alt', 'selected', 0x4fc5fcf, 'e8', 0x4dfe6d0),
    ('first_maximum_comparator', 'selected', 0x4dff3c6, 'e8', 0x53d7b00),
    ('second_maximum_comparator', 'selected', 0x4dff456, 'e8', 0x53d7bf0),
    ('prior_direct_adapter', 'context', 0x4f1234c, 'e8', 0x4fcb590),
    ('prior_worker_to_block', 'context', 0x5a6ea10, 'e8', 0x4f122c0),
    ('prior_worker_to_hash', 'context', 0x5a6ed0c, 'e8', 0x4e36af0),
    ('hash_to_array', 'selected', 0x4e36b48, 'e8', 0x531bff0),
    ('array_to_header', 'selected', 0x531c055, 'e8', 0x57ceba0),
    ('array_to_row', 'selected', 0x531c1c9, 'e8', 0x531e200),
    ('row_to_id', 'selected', 0x531e2d1, 'e8', 0x53228f0),
    ('id_to_formatter_slot', 'context', 0x53229f4, 'ff15', 0x64e4d08),
    ('id_to_string_writer', 'context', 0x5322a00, 'e8', 0x57cf860),
    ('row_to_nested_header', 'selected', 0x531e6c4, 'e8', 0x57ceba0),
    ('row_to_response', 'selected', 0x531e959, 'e8', 0x54835f0),
    ('response_to_map_header', 'context', 0x5483624, 'e8', 0x57ce100),
    ('response_to_key_writer', 'context', 0x548367c, 'e8', 0x57cf860),
    ('response_to_result', 'context', 0x548372c, 'e8', 0x59229a0),
    ('array_to_finish', 'selected', 0x531c20d, 'e8', 0x5306e90),
    ('hash_to_absorb_slot', 'context', 0x4e36bf7, 'ff15', 0x64e0148),
    ('hash_to_squeeze_slot', 'context', 0x4e36c23, 'ff15', 0x64e0150),
    ('squeeze_to_permutation_slot', 'context', 0x5cdae14, 'ff15', 0x64ecb70),
    ('prior_worker_to_record_sink', 'context', 0x5a6f991, 'e8', 0x595a6b0),
]

BRANCHES = [
    ('postblock_direct', 'selected', 0x4f1ec2d, '74', 0x4f1ec85),
    ('owner_guard_ne', 'selected', 0x4fc5e63, '0f85', 0x4fc5f5e),
    ('owner_guard_eq', 'selected', 0x4fc5f58, '0f84', 0x4fc5e69),
    ('collector_optional_bypass', 'selected', 0x4dfe71c, '75', 0x4dfe726),
    ('first_iterator_null', 'selected', 0x4dfebb0, '0f84', 0x4dfec74),
    ('first_prefix_end', 'selected', 0x4dfebbc, '0f86', 0x4dfec74),
    ('second_iterator_null', 'selected', 0x4dfee4b, '0f84', 0x4dfeeed),
    ('second_prefix_end', 'selected', 0x4dfee5c, '0f86', 0x4dfeeed),
    ('second_row_missing', 'selected', 0x4dfee67, '74', 0x4dfedf5),
    ('collection_helper_status_one', 'selected', 0x4dff4d4, '0f84', 0x4dff84b),
    ('height_modulo_le', 'context', 0x5a6ec82, '76', 0x5a6eced),
    ('hash_serialize_error', 'selected', 0x4e36b62, '0f85', 0x4e36c5e),
    ('array_header_error', 'selected', 0x531c063, '0f85', 0x531c117),
    ('row_encode_error', 'selected', 0x531c1d6, '0f85', 0x531c0c9),
    ('item_array_choice', 'selected', 0x5483615, '74', 0x5483649),
    ('item_missing_user', 'selected', 0x5483690, '75', 0x54836c2),
    ('record_option_select', 'context', 0x5a6f8d2, '75', 0x5a6f916),
]

SLOTS = {
    0x64e0148: 0x5cda910,
    0x64e0150: 0x5cdad40,
    0x64ecb70: 0x5cda380,
    0x64e4d08: 0x2eabb50,
    0x64767a8: None,  # Location path pointer, checked separately.
}


def map_range(secs, va, size, executable=False):
    """Resolve exactly one file-backed section; refuse NOBITS and ambiguity."""
    if not isinstance(va, int) or not isinstance(size, int) or va < 0 or size <= 0:
        raise ValueError('invalid virtual range')
    found = [s for s in secs if s['type'] != 8 and (not executable or s['flags'] & 4)
             and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('unmapped, fileless or ambiguous virtual range')
    s = found[0]
    return s['offset'] + va - s['address']


def get(data, secs, va, size, executable=False):
    off = map_range(secs, va, size, executable)
    if off < 0 or off + size > len(data):
        raise ValueError('mapped range lies outside file')
    return bytes(data[off:off + size])


def require(data, secs, va, expected, executable=True):
    expected = bytes.fromhex(expected)
    if get(data, secs, va, len(expected), executable) != expected:
        raise ValueError('fixed instruction mismatch at ' + hex(va))
    return expected


def validate_windows(data, secs):
    rows = []
    for name, scope, start, end, expected_hash in WINDOWS:
        raw = get(data, secs, start, end - start, True)
        if hashlib.sha256(raw).hexdigest() != expected_hash:
            raise ValueError('window mismatch: ' + name)
        rows.append([name, scope, hex(start), hex(end), hex(map_range(secs, start, len(raw), True)),
                     len(raw), expected_hash, raw.hex()])
    return rows


def read_relative_relocations(data, relasec, required):
    """Read explicitly selected ELF64 RELA records and reject duplicate slots."""
    off, size = relasec['offset'], relasec['size']
    if relasec['type'] != 4 or off < 0 or size % 24 or off + size > len(data):
        raise ValueError('invalid RELA section')
    hits = {}
    for pos in range(off, off + size, 24):
        slot, info, addend = struct.unpack_from('<QQq', data, pos)
        if slot not in required:
            continue
        if slot in hits:
            raise ValueError('duplicate selected relocation')
        if info & 0xffffffff != 8 or info >> 32 != 0:
            raise ValueError('selected relocation is not R_X86_64_RELATIVE')
        wanted = required[slot]
        if wanted is not None and addend != wanted:
            raise ValueError('selected relocation addend mismatch')
        hits[slot] = {'offset': pos, 'info': info, 'addend': addend}
    if set(hits) != set(required):
        raise ValueError('missing selected relocation')
    return hits


def function_records(data, secs, indices, fdes):
    table = {e['start']: e for e in indices}
    if len(table) != len(indices):
        raise ValueError('duplicate unwind start')
    wanted = {start for _, start, _, _ in FUNCTIONS}
    chosen = [f for f in fdes if f['start'] in wanted]
    if len(chosen) != len(wanted) or len({f['start'] for f in chosen}) != len(wanted):
        raise ValueError('missing or duplicate selected FDE')
    fmap = {f['start']: f for f in chosen}
    for selected in chosen:
        for other in fdes:
            if other['fde'] != selected['fde'] and other['start'] < selected['end'] and selected['start'] < other['end']:
                raise ValueError('selected FDE overlaps another FDE')
    ranges = sorted((start, end) for _, start, end, _ in FUNCTIONS)
    if any(a_end > b_start for (_, a_end), (b_start, _) in zip(ranges, ranges[1:])):
        raise ValueError('overlapping selected FDEs')
    rows = []
    for role, start, end, expected in sorted(FUNCTIONS, key=lambda x: x[1]):
        f = fmap[start]
        if f['end'] != end or start not in table or table[start]['fde'] != f['fde']:
            raise ValueError('FDE/header disagreement for ' + role)
        raw = get(data, secs, start, end - start, True)
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('function extent hash mismatch: ' + role)
        rows.append([role, hex(start), hex(end), hex(map_range(secs, start, len(raw), True)),
                     len(raw), hex(f['fde']), hex(f['cie']),
                     hex(f['lsda']) if f['lsda'] is not None else '', table[start]['index'],
                     expected, raw.hex()])
    return rows


def relative_target(data, secs, site, kind):
    if kind == 'e8':
        op, n = b'\xe8', 5
    elif kind == 'e9':
        op, n = b'\xe9', 5
    elif kind == 'ff15':
        op, n = b'\xff\x15', 6
    else:
        raise ValueError('unsupported transfer opcode')
    raw = get(data, secs, site, n, True)
    if not raw.startswith(op):
        raise ValueError('unexpected transfer opcode')
    return site + n + struct.unpack_from('<i', raw, n - 4)[0], raw


def branch_target(data, secs, site, opcode):
    op = bytes.fromhex(opcode)
    width = 1 if len(op) == 1 else 4
    raw = get(data, secs, site, len(op) + width, True)
    if not raw.startswith(op):
        raise ValueError('unexpected branch opcode')
    disp = int.from_bytes(raw[len(op):], 'little', signed=True)
    return site + len(raw) + disp, raw


def transfer_records(data, secs, relocations):
    rows = []
    for label, scope, site, kind, expected in TRANSFERS:
        target, raw = relative_target(data, secs, site, kind)
        if target != expected:
            raise ValueError('transfer target mismatch: ' + label)
        resolved = relocations[target]['addend'] if kind == 'ff15' else None
        rows.append([label, scope, hex(site), hex(map_range(secs, site, len(raw), True)),
                     raw.hex(), kind, hex(target), hex(resolved) if resolved is not None else ''])
    return rows


def branch_records(data, secs):
    rows = []
    for label, scope, site, opcode, expected in BRANCHES:
        target, raw = branch_target(data, secs, site, opcode)
        if target != expected:
            raise ValueError('branch target mismatch: ' + label)
        rows.append([label, scope, hex(site), hex(map_range(secs, site, len(raw), True)),
                     raw.hex(), hex(target)])
    return rows


def location_record(data, secs, relocs):
    va = 0x64767a8
    path_ptr = relocs[va]['addend']
    length, line, column = struct.unpack('<QII', get(data, secs, va + 8, 16))
    if length > 1024:
        raise ValueError('implausible Location length')
    path = get(data, secs, path_ptr, length)
    suffix = b'l1/src/abci/state.rs'
    if not path.endswith(suffix) or (line, column) != (123, 37):
        raise ValueError('unexpected Location')
    ref = get(data, secs, 0x3c1352f, 7, True)
    if ref[:3] != b'\x48\x8d\x15' or 0x3c13536 + struct.unpack_from('<i', ref, 3)[0] != va:
        raise ValueError('Location reference mismatch')
    cmp_bytes = require(data, secs, 0x3c1353b, '4883f801')
    return {'location_va': hex(va), 'file_offset': hex(map_range(secs, va, 24)),
            'path_suffix': suffix.decode('ascii'), 'path_length': length,
            'line': line, 'column': column, 'path_va': hex(path_ptr),
            'reference_va': hex(0x3c1352f), 'reference_bytes': ref.hex(),
            'comparison_va': hex(0x3c1353b), 'comparison_bytes': cmp_bytes.hex(),
            'scope': 'context only; no ownership of the historical loader call or slot'}


def facts(data, secs):
    # Each selected opcode has either a pinned containing window or an explicit
    # exact-byte assertion. Immediates below are decoded from the target bytes.
    mul = require(data, secs, 0x5a6ec67, '48b9a38b2ebae8a28b2e')
    limit = require(data, secs, 0x5a6ec75, '48b9d145175d74d14517')
    m = struct.unpack_from('<Q', mul, 2)[0]
    lim = struct.unpack_from('<Q', limit, 2)[0]
    period = 11
    if (m * period) % (1 << 64) != 1 or lim != ((1 << 64) - 1) // period:
        raise ValueError('modular predicate does not match the proved period')

    owner = require(data, secs, 0x4fcb86d, '498b8e000b0000')
    height = require(data, secs, 0x4fcb874, '4c8b7928')
    packed = require(data, secs, 0x4fcb92a, '4c897c2468')
    output = require(data, secs, 0x4fcbb94, '0f28442450')
    worker_output = require(data, secs, 0x5a6e96e, '488d6c2460')
    worker_height = require(data, secs, 0x5a6ea43, '488b4424784889842420010000')
    hash_input = require(data, secs, 0x5a6ed04, '488db42480010000')
    fields = require(data, secs, 0x4e36b32, '488b4608488b5610')
    serializer = require(data, secs, 0x4e36b25, 'c744240800040001c644240c00')
    sentinel = require(data, secs, 0x4e36b55, '48b80400000000000080')
    rate = require(data, secs, 0x4e36bd9, '48c78424f000000088000000')
    pad = require(data, secs, 0x4e36be5, '66c78424f80000000100')
    out_len = require(data, secs, 0x4e36c1b, 'ba20000000')
    stride = require(data, secs, 0x531c1dc, '4983c438')
    nested = require(data, secs, 0x531e3ae, '498b6c24284d8b642430')
    nested_shift = require(data, secs, 0x531e916, '49c1e406')
    pair = require(data, secs, 0x531e27c, 'c6043092')
    formatter = require(data, secs, 0x53229e2, '488d7c2420be42000000b9200000004531c0')
    prefix = require(data, secs, 0x2eabb62, '66c7073078')[3:]
    string_marker = require(data, secs, 0x57cf88d, 'b3d9')[1]
    alphabet_ref = get(data, secs, 0x2eabb89, 7, True)
    if alphabet_ref[:3] != bytes.fromhex('488d05'):
        raise ValueError('unexpected hex alphabet reference')
    alphabet_va = 0x2eabb90 + struct.unpack_from('<i', alphabet_ref, 3)[0]
    alphabet = get(data, secs, alphabet_va, 16)
    if alphabet != b'0123456789abcdef':
        raise ValueError('unexpected hex alphabet')
    header = require(data, secs, 0x57cebae, '81fa000001000f92c034dd83fa100fb6c0bd90000000')
    user_tag = require(data, secs, 0x548368b, '41807f280175')
    nil = require(data, secs, 0x54836e5, 'c60430c0')
    loop = require(data, secs, 0x5cda816, '4883c2084881fac0000000')
    lea = get(data, secs, 0x5cda7f0, 7, True)
    if lea[:3] != b'\x4c\x8d\x05':
        raise ValueError('unexpected constant-table reference')
    rounds_va = 0x5cda7f7 + struct.unpack_from('<i', lea, 3)[0]
    round_stride = loop[3]
    round_bytes = struct.unpack_from('<I', loop, 7)[0]
    if round_stride != 8 or round_bytes % round_stride:
        raise ValueError('unexpected round table stride')
    rounds = [struct.unpack('<Q', get(data, secs, rounds_va + i, 8))[0]
              for i in range(0, round_bytes, round_stride)]
    threshold32 = struct.unpack_from('<I', header, 2)[0]
    threshold_small = header[13]
    array32 = header[10]
    array16 = array32 ^ 1  # setb followed by XOR of the decoded marker byte.
    array_small = struct.unpack_from('<I', header, 18)[0]
    if (threshold_small, threshold32, array_small, array16, array32) != (16, 65536, 0x90, 0xdc, 0xdd):
        raise ValueError('unexpected array header decision')
    callback = require(data, secs, 0x5a6e255, '488d83a0020000')
    owner_args = require(data, secs, 0x4fc5d81, '488b1f4c8b6708488b4710')
    owner_state = require(data, secs, 0x4fc5e69, '488db3000b0000')
    owner_guard = require(data, secs, 0x4fc5e59, '81bb2801000000ca9a3b')
    alternate_guard = require(data, secs, 0x4fc5f4e, '81bb2801000000ca9a3b')
    if owner_guard != alternate_guard:
        raise ValueError('post-block owner guards differ')
    optional = require(data, secs, 0x4dfe700, '410fb6842460020000')
    thresholds = require(data, secs, 0x4dfe9a0, '498b9c24d0020000498b8424d8020000')
    first_state = require(data, secs, 0x4dfe9dc, '498b81481a0000')
    second_state = require(data, secs, 0x4dfec9d, '498b8040190000')
    first_source_step = require(data, secs, 0x4dfeb83, '4883c1e0')
    second_source_step = require(data, secs, 0x4dfee2e, '4883c1b0')
    first_dest_step = require(data, secs, 0x4dff3d1, '4983c520')
    second_dest_step = require(data, secs, 0x4dff461, '4983c540')
    first_store = require(data, secs, 0x4dff3e3, '49898424d0020000')
    second_store = require(data, secs, 0x4dff473, '49898424d8020000')
    first_threshold = struct.unpack_from('<I', thresholds, 4)[0]
    second_threshold = struct.unpack_from('<I', thresholds, 12)[0]
    if struct.unpack_from('<I', first_store, 4)[0] != first_threshold or struct.unpack_from('<I', second_store, 4)[0] != second_threshold:
        raise ValueError('read/store watermark offsets differ')
    result = {
        'postblock_state_collection': {
            'callback_subobject_offset': struct.unpack_from('<I', callback, 3)[0],
            'callback_arg_offset_in_pair': owner_args[6],
            'owner_state_slot_offset': struct.unpack_from('<I', owner_state, 3)[0],
            'owner_guard_offset': struct.unpack_from('<I', owner_guard, 2)[0],
            'owner_guard_value': struct.unpack_from('<I', owner_guard, 6)[0],
            'optional_branch_byte_offset': struct.unpack_from('<I', optional, 5)[0],
            'first_state_container_offset': struct.unpack_from('<I', first_state, 3)[0],
            'second_state_container_offset': struct.unpack_from('<I', second_state, 3)[0],
            'first_watermark_in_subobject': first_threshold,
            'second_watermark_in_subobject': second_threshold,
            'first_watermark_in_callback': struct.unpack_from('<I', callback, 3)[0] + first_threshold,
            'second_watermark_in_callback': struct.unpack_from('<I', callback, 3)[0] + second_threshold,
            'first_source_stride': -int.from_bytes(first_source_step[3:], 'little', signed=True),
            'second_source_stride': -int.from_bytes(second_source_step[3:], 'little', signed=True),
            'first_collected_stride': first_dest_step[3],
            'second_collected_stride': second_dest_step[3],
            'condition': 'For the selected reverse iterator, stop at the first row key <= old watermark; otherwise collect. The second stream additionally skips a null row field.',
            'limitations': 'Normal helper returns, stable slot and row storage are assumptions; other branches and helper side effects are not closed.',
        },
        'period_predicate': {
            'input': 'outer block result +0x18; conditional prior source is expanded state +0x28',
            'multiplier': hex(m), 'unsigned_limit': hex(lim), 'period': period,
            'branch_target': hex(branch_target(data, secs, 0x5a6ec82, '76')[0]),
        },
        'height_handoff': {
            'owner_state_slot_offset': struct.unpack_from('<I', owner, 3)[0],
            'expanded_state_height_offset': height[3],
            'upper_stack_height_offset': packed[4],
            'upper_stack_record_base': output[4],
            'outer_result_height_offset': packed[4] - output[4],
            'worker_output_stack_base': worker_output[4],
            'worker_height_load_stack_offset': worker_height[4],
            'worker_height_save_stack_offset': struct.unpack_from('<I', worker_height, 9)[0],
            'worker_vector_save_stack_offset': struct.unpack_from('<I', hash_input, 4)[0],
            'assumptions': 'selected branches, normal calls, runtime binding and no conflicting alias writes',
        },
        'serializer': {
            'configuration_bytes': serializer[4:8].hex() + serializer[12:13].hex(),
            'vector_pointer_offset': fields[3], 'vector_count_offset': fields[7],
            'outer_row_stride': stride[3],
            'outer_row_pair_marker': pair[3],
            'identifier_input_bytes': struct.unpack_from('<I', formatter, 11)[0],
            'identifier_rendered_bytes': struct.unpack_from('<I', formatter, 6)[0],
            'identifier_prefix_hex': prefix.hex(), 'identifier_alphabet': alphabet.decode('ascii'),
            'identifier_alphabet_va': hex(alphabet_va), 'string8_marker': string_marker,
            'nested_pointer_offset': nested[4], 'nested_count_offset': nested[9],
            'nested_row_stride': 1 << nested_shift[3],
            'array_small_limit_exclusive': threshold_small,
            'array16_limit_exclusive': threshold32,
            'array_small_base': array_small, 'array16_marker': array16, 'array32_marker': array32,
            'response_optional_user_offset': user_tag[3], 'response_user_present_value': user_tag[4],
            'response_absent_user_marker': nil[3],
            'success_word': hex(struct.unpack_from('<Q', sentinel, 2)[0]),
            'empty_outer_array_preimage_hex': bytes([array_small]).hex(),
            'limitations': 'Selected normal paths and sizes fitting u32; nested result payload is not recovered.',
        },
        'sponge': {
            'rate_bytes': struct.unpack_from('<I', rate, 8)[0],
            'domain_byte': struct.unpack_from('<H', pad, 8)[0] & 0xff,
            'output_bytes': struct.unpack_from('<I', out_len, 1)[0],
            'round_constant_table_va': hex(rounds_va),
            'round_constant_file_offset': hex(map_range(secs, rounds_va, round_bytes)),
            'round_constant_count': len(rounds), 'round_constant_stride': round_stride,
            'permutation_identification': 'Keccak-f[1600] is an inference from selected bytes; full instruction equivalence is not established.',
        },
    }
    return result, rounds, rounds_va


def is_periodic(value, multiplier, limit):
    if not 0 <= value < 1 << 64:
        raise ValueError('height outside unsigned 64-bit range')
    return ((value * multiplier) & ((1 << 64) - 1)) <= limit


def header_bytes(value, schema):
    if not 0 <= value < 1 << 32:
        raise ValueError('selected header domain is unsigned 32-bit')
    if value < schema['array_small_limit_exclusive']:
        return bytes([schema['array_small_base'] | value])
    if value < schema['array16_limit_exclusive']:
        return bytes([schema['array16_marker']]) + value.to_bytes(2, 'big')
    return bytes([schema['array32_marker']]) + value.to_bytes(4, 'big')


def check_historical(data):
    """Optional #94 cross-check; its bytes are never emitted as #115 evidence."""
    if hashlib.sha256(data).hexdigest() != OLD_DIGEST:
        raise ValueError('historical artifact SHA-256 mismatch')
    secs = sections(data)
    relas = [s for s in secs if s['name'] == '.rela.dyn']
    if len(relas) != 1:
        raise ValueError('historical RELA section missing or ambiguous')
    relocs = read_relative_relocations(data, relas[0], {0x56dfbf8: None, 0x57755a8: 0x3273810})
    length, line, column = struct.unpack('<QII', get(data, secs, 0x56dfc00, 16))
    if length > 1024 or not get(data, secs, relocs[0x56dfbf8]['addend'], length).endswith(b'l1/src/abci/state.rs'):
        raise ValueError('historical Location path mismatch')
    if (line, column) != (107, 37):
        raise ValueError('historical Location coordinates mismatch')
    ref = get(data, secs, 0x3273856, 7, True)
    if ref[:3] != b'\x48\x8d\x0d' or 0x327385d + struct.unpack_from('<i', ref, 3)[0] != 0x56dfbf8:
        raise ValueError('historical Location reference mismatch')
    require(data, secs, 0x3273871, '4983fd02')
    slot, _ = relative_target(data, secs, 0x3272785, 'ff15')
    if slot != 0x57755a8:
        raise ValueError('historical caller slot mismatch')


def literal_records(data, secs):
    specs = [
        ('response_user_key', 0x548366d, 0x5483674, b'user'),
        ('response_result_key', 0x5483707, 0x548370e, b'res'),
        ('serialize_failure', 0x4e36c9d, 0x4e36cba, b'called `Result::unwrap()` on an `Err` value'),
    ]
    rows = []
    for label, ref_va, length_va, expected in specs:
        ref = get(data, secs, ref_va, 7, True)
        if ref[:3] not in (b'\x48\x8d\x35', b'\x48\x8d\x3d'):
            raise ValueError('unsupported literal reference')
        va = ref_va + len(ref) + struct.unpack_from('<i', ref, 3)[0]
        length_insn = get(data, secs, length_va, 5, True)
        if length_insn[0] not in (0xba, 0xbe):
            raise ValueError('unsupported literal length')
        length = struct.unpack_from('<I', length_insn, 1)[0]
        actual = get(data, secs, va, length)
        if actual != expected:
            raise ValueError('literal mismatch: ' + label)
        rows.append([label, hex(ref_va), hex(va), hex(map_range(secs, va, length)), length, actual.hex()])
    return rows


def tsv(header, rows):
    out = io.StringIO(newline='')
    writer = csv.writer(out, delimiter='\t', lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return out.getvalue().encode('utf-8')


def encode_json(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode('utf-8')


def analyze(data):
    # Authenticate before parsing or creating any output directory.
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('node 115 SHA-256 mismatch')
    secs = sections(data)
    relasecs = [s for s in secs if s['name'] == '.rela.dyn']
    if len(relasecs) != 1:
        raise ValueError('missing or duplicate RELA section')
    relocations = read_relative_relocations(data, relasecs[0], SLOTS)
    windows = validate_windows(data, secs)
    _, indices = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    functions = function_records(data, secs, indices, fdes)
    flow = transfer_records(data, secs, relocations)
    branches = branch_records(data, secs)
    loc = location_record(data, secs, relocations)
    derived, rounds, rounds_va = facts(data, secs)
    literals = literal_records(data, secs)
    relrows = [[hex(k), hex(v['offset']), 'R_X86_64_RELATIVE', hex(v['addend']), 'context']
               for k, v in sorted(relocations.items())]
    roundrows = [[i, hex(rounds_va + 8 * i), hex(map_range(secs, rounds_va + 8 * i, 8)),
                  f'{value:016x}'] for i, value in enumerate(rounds)]
    report = {
        'target_release': '115', 'binary_sha256': DIGEST,
        'selected_fde_count': len(functions), 'fixed_window_count': len(windows),
        'context_window_count': sum(w[1] == 'context' for w in windows),
        'transfer_count': len(flow), 'context_transfer_count': sum(r[1] == 'context' for r in flow),
        'branch_count': len(branches), 'context_branch_count': sum(r[1] == 'context' for r in branches),
        'relative_relocation_count': len(relrows), 'round_constant_count': len(roundrows),
        'literal_count': len(literals),
        'scope': 'Selected static windows; FDE extents are not a function census or an equivalence claim.',
    }
    return {
        'functions.tsv': tsv(['role', 'start_va', 'end_va_exclusive', 'file_offset', 'size', 'fde_va',
                              'cie_va', 'lsda_va', 'unwind_index', 'sha256', 'raw_hex'], functions),
        'windows.tsv': tsv(['label', 'scope', 'start_va', 'end_va_exclusive', 'file_offset', 'size',
                            'sha256', 'raw_hex'], windows),
        'transfers.tsv': tsv(['label', 'scope', 'site_va', 'file_offset', 'raw_hex', 'form',
                              'target_va_or_slot', 'relative_addend'], flow),
        'branches.tsv': tsv(['label', 'scope', 'site_va', 'file_offset', 'raw_hex', 'target_va'], branches),
        'relocations.tsv': tsv(['slot_va', 'record_file_offset', 'type', 'addend_va', 'scope'], relrows),
        'literals.tsv': tsv(['label', 'reference_va', 'data_va', 'file_offset', 'length', 'bytes_hex'], literals),
        'round-constants.tsv': tsv(['index', 'va', 'file_offset', 'word_hex'], roundrows),
        'location.json': encode_json(loc), 'facts.json': encode_json(derived),
        'summary.json': encode_json(report),
    }


def generate(data, out):
    files = analyze(data)
    out.mkdir(parents=True, exist_ok=True)
    for name in sorted(files):
        (out / name).write_bytes(files[name])
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--historical-node', type=Path,
                        help='optional separately authenticated retired node #94 clue')
    args = parser.parse_args(argv)
    data = TARGET.read_bytes()
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError('node 115 SHA-256 mismatch')
    if args.historical_node is not None:
        check_historical(args.historical_node.read_bytes())
    generate(data, args.out)
    print('node 115 post-block result fingerprint evidence generated')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as error:
        print('abci_result_digest115: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
