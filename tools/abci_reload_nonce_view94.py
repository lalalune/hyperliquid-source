"""Reproduce selected node 94 reload-to-nonce-view evidence from ELF bytes."""
import argparse
import csv
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records, uleb

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'

# Curated FDEs; FDEs are unwind extents, not necessarily source-function boundaries.
FUNCTIONS = (
    ('nonce_hash_lookup', 0x3423840, 0x34239a8, '2a45eeca7a7c2b0546d495dc525ff71eae8ca6e40d4e2e7013389b2c782c35e1'),
    ('lazy_wrapper_b', 0x3431820, 0x343186e, '8f993edf4367163ac38aa53aa72c8e2405d6b265698e3ada2c59ddf65cde6928'),
    ('lazy_wrapper_a', 0x3432790, 0x34327de, 'aacdebd1ddef95818505d03f6c70c5ee0dfad8519941c150af66295b4531e2ff'),
    ('empty_initializer', 0x3438e50, 0x3438e63, 'b9efa784eaae9b9369ffdcaceeb6ea07bcdb2d61975699b12c48e0477cad3ec6'),
    ('record_tree_builder', 0x428c750, 0x428d07a, '921be300567f263a2a8c9c0b8c34301891b8af50c75152fa71a593167f5fbbdf'),
    ('exclusion_set_builder', 0x4451aa0, 0x4451e7a, '23fc9ae6d5d891f71d681d3b12fd0665fcf0f5b2d423600b1ce29bab78cef6ee'),
    ('record_sort_large_wrapper', 0x4488d70, 0x4488e8b, '69a338a3bff84128a72fd8c71ce4a8b634b20ac83fc54298366b118bf024d37e'),
    ('record_collector', 0x4888e80, 0x488984a, 'b73c84f90da9c6dd55e8916bd3783e1a0ece16b32ae8f427cab1a044bd2fcb0e'),
    ('view_map_builder', 0x489ea70, 0x489ec09, 'f0cbf4067ebabb57bee2f42877fff8ac5f75df7bf3bea907ef4163519af59ff0'),
    ('record_sort_small', 0x4913c10, 0x4913d14, '47cbab8542a955954a54e9c8b4d3df346a1676533afef580e40612cde3cd073f'),
    ('adjacent_key_coalescer', 0x4ada600, 0x4ada7ef, '8443eada048b133d234be39f378c57dde86fae8165060525300d0cca2ee7f53a'),
    ('queue_receive_wrapper', 0x4553420, 0x4553654, '5c1e88bd96a5c7e83b24a6df85df40c6ad88b55c5da5c29e4936059edcf1d518'),
    ('queue_receiver', 0x4b45f20, 0x4b460fa, '4b4adee9366829be6e57b92b76699026b4714107f0335b544f05fdab2e25a078'),
    ('queue_producer', 0x4b47900, 0x4b47b05, 'c35018c214ee158a509043a613ca94df1b4f73e45b2ac3fbe7bd39ec6cbc4fb8'),
)

# Short windows in the existing parent are connection context only.
WINDOWS = (
    ('parent_exclusion', 0x4549ac6, 0x4549b54, '4a9e529ce37711f579464b1bb1e2bf95ab706fec812d6acff2f9e9c1d6c71d6c'),
    ('parent_first', 0x4549b65, 0x4549b9c, 'd5b455c96c0b04ca84bf10d512057bdf0ff92d03ca07d11cbe5a9b61e450d98a'),
    ('parent_source_b', 0x4549c90, 0x4549d7d, '5ede26a4438255ad66f9799b3fa8ff171703ced09cca281c859660c1de7d32c6'),
    ('parent_composite', 0x4549d7d, 0x4549e52, 'b757cc950846d237f0735fc2fd25ae5b4c445c75865cf149934e2f464850ac46'),
    ('parent_call', 0x4549e52, 0x4549e97, '63b57f22098629ecec61f8d4b5377b05f2e76319a1d6dfbac1b2f295828a721e'),
    ('parent_result', 0x454a011, 0x454a033, 'f0179862b32788194014dfff909684c3a5d6850f0d80aefca41365d0bb9e2006'),
    ('parent_publish', 0x454a40c, 0x454a4a8, '829857fb5e788af1c469521dca35aad4cb709f436520bcd9674862a2c60bf5d3'),
    ('collector_entry', 0x4888e80, 0x4888ede, '233348a98bd66c0f5a84f347da0e4a919df3bcb4ccc58990f9de555661a3235e'),
    ('exclude_first', 0x4888f3e, 0x4888fbf, '7b53e74d3d5460435422a0b4364a3b1b25da23ff5690085f16e0c3185cdd98e2'),
    ('lookup_first', 0x4889009, 0x4889079, '0217b8f64c35ab26cb373b5ab545da4878cdb2f0349d52667b09566e97b03404'),
    ('exclude_next', 0x488930c, 0x48893a6, 'c472ddd581ac028e39885d9b1fc8c118aa09b2b4f00b401ac5f103365edba0da'),
    ('lookup_next', 0x4889584, 0x4889602, '92111f6d4fa6d88988398c5318b9bd067b281903e183cabb9cfbe6de01e68a36'),
    ('collector_finish', 0x48896c1, 0x4889713, 'f762847db3f740bca9c261b727ab9d6758384adf4fe091bae688ea88109e1f8e'),
    ('collector_fail', 0x4889758, 0x4889785, 'bac31d2ef37b47ceeac93ed3d4ebeb76e7ca589bd278c5a60085acf4c775242f'),
    ('collector_unwind', 0x4889790, 0x488984a, 'c0d23f6faf46c48bda87b08b6c3072b60e42eebd1231c87fd0b8b5d2c7c3b8d8'),
    ('view_entry', 0x489ea70, 0x489ead7, '6d8533606bfbb799fb539f5e4f63bfd9ad246f3e5bc741479aa3143d63fe7fe3'),
    ('view_tree', 0x489ead7, 0x489eb67, '6f63fa2575a046ea633c248ccb8fc8e832ef719f9ceb1683e4d30ba30b2baaab'),
    ('view_empty', 0x489eb67, 0x489eba7, 'aa6973ea19a97f1073740627fc5fb4d78102017d1f60f31e51222a602dda69ff'),
    ('view_branches', 0x489eba7, 0x489ebd9, '31c4588cf4f7a237d69bab4a437f80aac1abea85ba53b15766e58a59a449de60'),
    ('view_unwind', 0x489ebd9, 0x489ec09, '98af117b0fb5a1400b01390215a77de67e41709e631f34cbafaaf7e2618ea276'),
    ('sort', 0x4913c10, 0x4913d14, '47cbab8542a955954a54e9c8b4d3df346a1676533afef580e40612cde3cd073f'),
    ('coalescer', 0x4ada600, 0x4ada7ef, '8443eada048b133d234be39f378c57dde86fae8165060525300d0cca2ee7f53a'),
    ('exclusion_collect', 0x4451aa0, 0x4451b5b, '3ea0ab57a8b411deab3cfa16edf9138b98b6567e8be6ff63ee1a22bfb85901a4'),
    ('exclusion_finish', 0x4451d1b, 0x4451dc0, '23d4c0bc3378ff62cebaa3fd8c6ac947f9cc1737fa027800ee6fc8c0ba6538e8'),
    ('exclusion_sort_fail', 0x4451dd2, 0x4451e7a, '143a3f833ed6c26b8186dc4d643f5f502e0e8ab6c62f4dc3fc8b53c9ee4506f8'),
    ('large_sort_wrapper', 0x4488d70, 0x4488e8b, '69a338a3bff84128a72fd8c71ce4a8b634b20ac83fc54298366b118bf024d37e'),
    ('tree_insert', 0x428c8a0, 0x428c926, '7fa641f8b60d80700802306eca6c515dace231071e4858d8589bc7c1ce38b899'),
    ('tree_grow', 0x428c950, 0x428c9a0, 'aa5a776a707c2c2c69a2fab12da7265c820663ec5395db01ede01917485db164'),
    ('tree_fail', 0x428cf52, 0x428d07a, '85c5d6ee35f7f8a1e41f90f6461279a3b5310cab6cbab2f456ab84fdd17f46aa'),
    ('lookup', 0x3423840, 0x34239a8, '2a45eeca7a7c2b0546d495dc525ff71eae8ca6e40d4e2e7013389b2c782c35e1'),
    ('lazy_a', 0x3432790, 0x34327de, 'aacdebd1ddef95818505d03f6c70c5ee0dfad8519941c150af66295b4531e2ff'),
    ('lazy_b', 0x3431820, 0x343186e, '8f993edf4367163ac38aa53aa72c8e2405d6b265698e3ada2c59ddf65cde6928'),
    ('empty_init', 0x3438e50, 0x3438e63, 'b9efa784eaae9b9369ffdcaceeb6ea07bcdb2d61975699b12c48e0477cad3ec6'),
    ('receiver_block_search', 0x4b45f20, 0x4b45f9e, 'fac156e3065e595f242bd070b939b3a237bc05e7c53c43b698249e65515e4018'),
    ('receiver_copy_or_tag', 0x4b4608b, 0x4b460ed, '325a40d037a76af021b45927bcd8a24648088d1044bfe2ce5cf65283cb171d3f'),
    ('receiver_wrapper_call', 0x45534bc, 0x455352e, '6eca8a12a75b0ddcd2cca1c3265ee5e1757a5330020622a42cc8f3cc3f8ef42c'),
    ('receiver_wrapper_result', 0x4553594, 0x45535fe, 'ea6912f186c3f7d525bb47c473577187044b3e6d265336572c7b96170c7055ee'),
    ('queue_reserve', 0x4b47900, 0x4b47953, '824c57b2ecd50e50c3073edae2dbb3c724efe1bbc80701288d0c4440c896810b'),
    ('queue_allocate', 0x4b47984, 0x4b479d9, 'd483804332d2df298efcf718aecf6ddf5512a6dcde846d4580a9a0fc0adfd463'),
    ('queue_publish', 0x4b47a89, 0x4b47ac9, '67c083c072ca28212e4a965581b76d053103dfac624b8d187d025a1ee5f17a16'),
    ('queue_fail', 0x4b47ac9, 0x4b47b05, '8972437fa48bc7367629b60346299d61e93269483d705616cd49eee2376ea611'),
)

# Explicit instruction starts; slots identify static relocations, not dynamic binding.
SITES = (
    ('first_exhausted', 0x4888e9c, 'j', 0x4888eb6),
    ('first_next', 0x4888ea1, 'c', 0x4895050),
    ('first_available', 0x4888ea9, 'j', 0x4888ffa),
    ('second_tag', 0x4888ebb, 'j', 0x4888ede),
    ('second_next', 0x4888f00, 'c', 0x49478b0),
    ('second_empty', 0x4888f10, 'j', 0x4889713),
    ('exclude_compare', 0x4888f93, 's', 0x576e488),
    ('skip_excluded', 0x4888fb9, 'j', 0x4888ef0),
    ('lookup_first', 0x4889035, 's', 0x5774668),
    ('empty_first', 0x4889040, 'j', 0x4889061),
    ('bad_root_first', 0x4889048, 'j', 0x4889767),
    ('clone_first', 0x488905a, 'c', 0x497b9b0),
    ('second_again', 0x48892c0, 'c', 0x49478b0),
    ('exclude_compare_next', 0x4889356, 's', 0x576e488),
    ('skip_excluded_next', 0x488937c, 'j', 0x48892b0),
    ('lookup_next', 0x48895ba, 's', 0x5774668),
    ('empty_next', 0x48895c5, 'j', 0x48895f0),
    ('bad_root_next', 0x48895cd, 'j', 0x4889758),
    ('clone_next', 0x48895dc, 'c', 0x497b9b0),
    ('exclusion_empty', 0x4451ad8, 'j', 0x4451db1),
    ('exclusion_alloc_fail', 0x4451b06, 'j', 0x4451e22),
    ('exclusion_tree', 0x4451d8f, 'c', 0x428d080),
    ('exclusion_large', 0x4451dd6, 'j', 0x4451e30),
    ('exclusion_small_sort', 0x4451de8, 'c', 0x4913410),
    ('exclusion_large_slot', 0x4451e3b, 's', 0x5774f70),
    ('large_sort_stack', 0x4488db8, 'j', 0x4488ddf),
    ('large_sort_size_ok', 0x4488dd2, 'j', 0x4488deb),
    ('large_sort_alloc', 0x4488df4, 's', 0x576dfd8),
    ('large_sort_alloc_fail', 0x4488dfd, 'j', 0x4488e5e),
    ('large_sort_inner', 0x4488e2e, 'c', 0x4dc76d0),
    ('large_sort_stack_free', 0x4488e37, 'j', 0x4488e4c),
    ('record_collector', 0x489ea9c, 'c', 0x4888e80),
    ('empty_view', 0x489eaa9, 'j', 0x489eb67),
    ('single_record', 0x489eac2, 'j', 0x489eba7),
    ('root_alloc', 0x489eadc, 's', 0x576dfd8),
    ('root_alloc_fail', 0x489eae5, 'j', 0x489ebb7),
    ('bulk_build', 0x489eb4f, 'c', 0x428c750),
    ('large_sort', 0x489ebab, 'j', 0x489ebc9),
    ('sort_small', 0x489ebad, 'c', 0x4913c10),
    ('sort_large_slot', 0x489ebce, 's', 0x5776760),
    ('builder_next', 0x428c904, 'c', 0x4ada600),
    ('builder_finished', 0x428c90e, 'j', 0x428cba5),
    ('builder_room', 0x428c920, 'j', 0x428c8a0),
    ('grow_alloc_fail', 0x428c963, 'j', 0x428cfdf),
    ('coalesce_empty', 0x4ada633, 'j', 0x4ada7ac),
    ('coalesce_different', 0x4ada708, 'j', 0x4ada7bc),
    ('coalesce_drop', 0x4ada723, 'c', 0x49a9fb0),
    ('coalesce_repeat', 0x4ada7a4, 'j', 0x4ada720),
    ('probe_hash', 0x3423865, 'c', 0x399c7a0),
    ('probe_empty', 0x342384f, 'j', 0x342395f),
    ('probe_found', 0x34238fc, 'j', 0x342392e),
    ('probe_stop', 0x342391c, 'j', 0x3423934),
    ('once', 0x34239a0, 's', 0x576e8b8),
    ('default_address', 0x342394c, 'l', 0x5786170),
    ('initial_state_address', 0x342396b, 'l', 0x5786170),
    ('once_state_address', 0x3423981, 'l', 0x5786188),
    ('once_descriptor', 0x3423988, 'l', 0x56eb448),
    ('recv_block_match', 0x4b45f41, 'j', 0x4b45f6e),
    ('recv_missing_next', 0x4b45f5a, 'j', 0x4b460d0),
    ('recv_published', 0x4b4609a, 'j', 0x4b460c9),
    ('recv_copy', 0x4b460b4, 's', 0x576dfe0),
    ('recv_tag_no_advance', 0x4b460be, 'j', 0x4b460e0),
    ('recv_closed', 0x4b460ce, 'j', 0x4b460d9),
    ('recv_wrapper_first', 0x45534d8, 'c', 0x4b45f20),
    ('recv_wrapper_first_closed', 0x45534e6, 'j', 0x45535b9),
    ('recv_wrapper_first_item', 0x45534ef, 'j', 0x4553594),
    ('recv_wrapper_retry', 0x4553515, 'c', 0x4b45f20),
    ('recv_wrapper_retry_closed', 0x4553523, 'j', 0x45535cf),
    ('recv_wrapper_retry_item', 0x455352c, 'j', 0x4553594),
    ('recv_wrapper_ref_fail', 0x455359d, 'j', 0x4553617),
    ('recv_wrapper_copy', 0x45535b1, 's', 0x576dfe0),
    ('queue_alloc', 0x4b4799a, 's', 0x576dfd8),
    ('queue_alloc_fail', 0x4b479a3, 'j', 0x4b47ac9),
    ('queue_linked', 0x4b479d7, 'j', 0x4b47a30),
    ('queue_copy', 0x4b47aa2, 's', 0x576dfe0),
    ('parent_exclusion', 0x4549b4f, 'c', 0x4451aa0),
    ('parent_first_empty', 0x4549b6d, 'j', 0x4549c9e),
    ('parent_first_bad_root', 0x4549b7d, 'j', 0x454a615),
    ('parent_first_clone', 0x4549b92, 'c', 0x497e070),
    ('parent_call', 0x4549e72, 'c', 0x489ea70),
    ('parent_queue_copy_1', 0x454a421, 's', 0x576dfe0),
    ('parent_queue_copy_2', 0x454a48e, 's', 0x576dfe0),
    ('parent_queue_push', 0x454a4a3, 'c', 0x4b47900),
)

RELOCATIONS = (
    ('nonce_lookup_slot', 0x5774668, 8, 0, 0x3423840, ''),
    ('large_sort_slot', 0x5776760, 8, 0, 0x4488d70, ''),
    ('once_method_a', 0x56eb460, 8, 0, 0x3432790, ''),
    ('once_method_b', 0x56eb468, 8, 0, 0x3431820, ''),
    ('default_initializer', 0x5786170, 8, 0, 0x3438e50, ''),
)

LSDA_PINS = {
    0x428c750: (0xb25904, 15, 'e3fa4ce9f5062c7d35583af83e756c3fda07a1cd6660c73899177298d997adf3'),
    0x4451aa0: (0xb3f700, 7, 'ef7757a9a57be88f2316e467a6df12f5ed96cd5cd2ac7f4ae82f53193ca952f3'),
    0x4488d70: (0xb422b0, 5, '59d82f40903ff8988c81768bfae0baf4f639cd42a843efc0cd8ac563d95c0a08'),
    0x4888e80: (0xb8380c, 18, '47f63ca3e832664288db4b0ba8d640b78f045d2a852d5ad8893a2c7d50529e70'),
    0x489ea70: (0xb84704, 6, '6e54b618f9dac3218a9679993d5f49fd847c436a670c660294a7025425da5ed2'),
    0x4553420: (0xb4eb08, 6, 'ead795831360ddf9afd7300ecb518390fc6f474a39571e4b5fdf7bc5c1cf21c9'),
    0x4b47900: (0xb9d624, 4, 'cba903d3190b391d6b52162cef982dfe20cd81d3223933fe96cf4e78daf012cc'),
}

FACTS = (
    ('tracker_offset', 0x4889009, 'bf50410000', 0x1, 0x4, 0x4150),
    ('state_pointer_offset', 0x488900e, '4903be98000000', 0x3, 0x4, 0x98),
    ('exclusion_pointer_offset', 0x4888f3e, '498b8690000000', 0x3, 0x4, 0x90),
    ('address_bytes', 0x4888f89, 'ba14000000', 0x1, 0x4, 0x14),
    ('nonce_length_offset', 0x488903b, '4883781000', 0x3, 0x1, 0x10),
    ('lookup_table_offset', 0x3423871, '498b8e90000000', 0x3, 0x4, 0x90),
    ('lookup_count_offset', 0x3423847, '4883bfa800000000', 0x3, 0x4, 0xa8),
    ('record_sort_threshold', 0x489eba7, '4883fe15', 0x3, 0x1, 0x15),
    ('record_bytes', 0x4ada639, '488d4830', 0x3, 0x1, 0x30),
    ('node_capacity', 0x428c91c, '4883f80b', 0x3, 0x1, 0xb),
    ('large_sort_stack_limit', 0x4488db4, '4983fc56', 0x3, 0x1, 0x56),
    ('large_sort_internal_threshold', 0x4488e20, '4883fe41', 0x3, 0x1, 0x41),
    ('large_sort_buffer_cap', 0x4488d9c, '4881fe0a8b0200', 0x3, 0x4, 0x28b0a),
    ('record_tree_leaf_bytes', 0x489ead7, 'bff0010000', 0x1, 0x4, 0x1f0),
    ('record_tree_internal_bytes', 0x428c958, 'bf50020000', 0x1, 0x4, 0x250),
    ('queue_copy_bytes', 0x4b47a9d, 'ba50010000', 0x1, 0x4, 0x150),
    ('receiver_copy_bytes', 0x4b460ac, 'ba50010000', 0x1, 0x4, 0x150),
    ('receiver_wrapper_copy_bytes', 0x45535a4, 'ba50010000', 0x1, 0x4, 0x150),
    ('parent_payload_bytes', 0x454a41c, 'ba48010000', 0x1, 0x4, 0x148),
    ('default_out_root_value', 0x3438e53, '48c70700000000', 0x3, 0x4, 0x0),
    ('default_out_count_offset', 0x3438e5a, '48c7471000000000', 0x3, 0x1, 0x10),
)



def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_digest(data, expected=SHA256):
    require(hashlib.sha256(data).hexdigest() == expected, 'node 94 SHA-256 mismatch')


class Image:
    def __init__(self, data, secs=None):
        self.data = data
        self.sections = sections(data) if secs is None else secs

    def location(self, va, size=1):
        require(isinstance(va, int) and isinstance(size, int) and va >= 0 and size > 0,
                'invalid file-backed range')
        rows = [s for s in self.sections if s['type'] != 8 and s['size'] and
                s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(rows) == 1, 'range is not uniquely file-backed')
        s = rows[0]
        off = s['offset'] + va - s['address']
        require(0 <= off <= len(self.data) and size <= len(self.data) - off,
                'file-backed range exceeds file')
        return s, off

    def read(self, va, size):
        _, off = self.location(va, size)
        return bytes(self.data[off:off + size])

    def named(self, name):
        rows = [s for s in self.sections if s['name'] == name and s['type'] != 8]
        require(len(rows) == 1, 'missing, duplicate or NOBITS section')
        return rows[0]


def fde_rows(image):
    _, indexed = unwind_index(image.data)
    _, fdes = eh_frame_records(image.data, image.sections)
    by_start = {}
    for row in fdes:
        by_start.setdefault(row['start'], []).append(row)
    by_index = {row['start']: row for row in indexed}
    require(len(by_index) == len(indexed), 'duplicate unwind start')
    output = []
    for name, start, end, expected_hash in FUNCTIONS:
        candidates = by_start.get(start, [])
        require(len(candidates) == 1 and start in by_index, 'missing or duplicate selected FDE')
        fde = candidates[0]
        require(fde['end'] == end and by_index[start]['fde'] == fde['fde'], 'changed selected FDE')
        sec, offset = image.location(start, end - start)
        require(sec['flags'] & 4, 'selected extent is not executable')
        raw = image.read(start, end - start)
        digest = hashlib.sha256(raw).hexdigest()
        require(digest == expected_hash, 'changed selected FDE body')
        _, fde_off = image.location(fde['fde'], 4)
        output.append(dict(role=name, start=start, end=end, size=end-start, section=sec['name'],
                           code_offset=offset, fde=fde['fde'], fde_offset=fde_off,
                           lsda=fde['lsda'], sha256=digest, bytes=raw.hex()))
    return sorted(output, key=lambda r: r['start'])


def window_rows(image):
    result = []
    for name, start, end, digest in WINDOWS:
        sec, offset = image.location(start, end - start)
        require(sec['flags'] & 4, 'window is not executable')
        raw = image.read(start, end - start)
        require(hashlib.sha256(raw).hexdigest() == digest, 'changed selected window')
        context = name.startswith('parent_')
        owners = [f[1] for f in FUNCTIONS if f[1] <= start < end <= f[2]]
        require(context or len(owners) == 1, 'window not inside one selected FDE')
        result.append(dict(role=name, ownership='prior-context' if context else 'new',
                           owner=(0x4548cc0 if context else owners[0]),
                           start=start, end=end, offset=offset, bytes=raw.hex(), sha256=digest))
    return result


def decode_site(image, va, kind):
    if kind == 'c':
        b = image.read(va, 5)
        require(b[0] == 0xe8, 'invalid rel32 call')
        target = va + 5 + struct.unpack_from('<i', b, 1)[0]
    elif kind == 's':
        b = image.read(va, 6)
        require(b[:2] == b'\xff\x15', 'invalid RIP slot call')
        target = va + 6 + struct.unpack_from('<i', b, 2)[0]
    elif kind == 'j':
        prefix = image.read(va, 2)
        if 0x70 <= prefix[0] <= 0x7f:
            b = prefix
            target = va + 2 + struct.unpack_from('<b', b, 1)[0]
        else:
            b = image.read(va, 6)
            require(b[0] == 0x0f and 0x80 <= b[1] <= 0x8f, 'invalid conditional branch')
            target = va + 6 + struct.unpack_from('<i', b, 2)[0]
    elif kind == 'l':
        b = image.read(va, 7)
        require(b[0] in (0x48, 0x4c) and b[1] == 0x8d and b[2] & 0xc7 == 5,
                'invalid RIP-relative LEA')
        target = va + 7 + struct.unpack_from('<i', b, 3)[0]
    else:
        raise ValueError('unsupported transfer kind')
    return b, target


def site_rows(image):
    output = []
    for name, va, kind, expected in SITES:
        b, target = decode_site(image, va, kind)
        require(target == expected, 'changed selected transfer target')
        _, offset = image.location(va, len(b))
        owners = [f[1] for f in FUNCTIONS if f[1] <= va and va + len(b) <= f[2]]
        context = name.startswith('parent_')
        require(context or len(owners) == 1, 'transfer not inside selected FDE')
        owner = 0x4548cc0 if context else owners[0]
        output.append(dict(role=name, owner=owner, ownership='prior-context' if context else 'new',
                           site=va, offset=offset, bytes=b.hex(), kind=kind, target=target))
    return output


def dyn_symbol(image, index):
    syms, strings = image.named('.dynsym'), image.named('.dynstr')
    require(index >= 0 and (index + 1) * 24 <= syms['size'], 'dynamic symbol out of range')
    off = syms['offset'] + index * 24
    name_offset = struct.unpack_from('<I', image.data, off)[0]
    require(name_offset < strings['size'], 'dynamic symbol name outside string table')
    begin, limit = strings['offset'] + name_offset, strings['offset'] + strings['size']
    end = image.data.find(b'\0', begin, limit)
    require(end >= 0, 'unterminated dynamic symbol')
    return bytes(image.data[begin:end]).decode('ascii')


def relocation_rows(image):
    section = image.named('.rela.dyn')
    require(section['size'] % 24 == 0, 'truncated relocation section')
    wanted = {r[1]: r for r in RELOCATIONS}
    found = {}
    for off in range(section['offset'], section['offset'] + section['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', image.data, off)
        if slot not in wanted:
            continue
        require(slot not in found, 'duplicate selected relocation')
        role, _, typ, sym, target, symbol = wanted[slot]
        require((info & 0xffffffff, info >> 32, addend) == (typ, sym, target),
                'changed selected relocation')
        resolved_symbol = dyn_symbol(image, sym) if sym else ''
        require(resolved_symbol == symbol, 'changed dynamic symbol')
        slot_sec, slot_off = image.location(slot, 8)
        found[slot] = dict(role=role, slot=slot, offset=off, bytes=bytes(image.data[off:off+24]).hex(),
                           slot_file_offset=slot_off, slot_section=slot_sec['name'],
                           slot_initial_bytes=image.read(slot, 8).hex(), type=typ,
                           symbol_index=sym, symbol=resolved_symbol, addend=addend)
    require(set(found) == set(wanted), 'missing selected relocation')
    return [found[slot] for slot in sorted(found)]


def fact_rows(image):
    result = []
    for name, va, pattern, start, width, expected in FACTS:
        raw = image.read(va, len(bytes.fromhex(pattern)))
        require(raw == bytes.fromhex(pattern), 'changed operand instruction')
        value = int.from_bytes(raw[start:start+width], 'little')
        require(value == expected, 'changed selected operand')
        _, off = image.location(va, len(raw))
        result.append(dict(role=name, va=va, file_offset=off, bytes=raw.hex(),
                           operand_offset=start, operand_width=width, value=value))
    return result


def data_rows(image):
    # These are on-disk initial bytes, before RELATIVE relocations or lazy init.
    specs = (
        ('once_descriptor_header', 0x56eb448, 24, bytes.fromhex('000000000000000008000000000000000800000000000000')),
        ('initial_default_storage', 0x5786170, 24, bytes(24)),
        ('initial_once_word', 0x5786188, 4, bytes.fromhex('03000000')),
    )
    rows = []
    for role, va, size, expected in specs:
        sec, off = image.location(va, size)
        raw = image.read(va, size)
        require(raw == expected, 'changed selected data bytes')
        rows.append(dict(role=role, va=va, offset=off, section=sec['name'], bytes=raw.hex()))
    return rows


def lsda_rows(image, functions):
    section = image.named('.gcc_except_table')
    limit = section['offset'] + section['size']
    headers, rows, seen = [], [], set()
    for f in functions:
        if f['lsda'] is None:
            require(f['start'] not in LSDA_PINS, 'missing selected LSDA')
            continue
        require(f['start'] in LSDA_PINS, 'unexpected selected LSDA')
        address = f['lsda']
        expected_address, expected_count, expected_digest = LSDA_PINS[f['start']]
        require(address == expected_address, 'changed LSDA pointer')
        sec, origin = image.location(address, 2)
        require(sec['name'] == '.gcc_except_table' and address not in seen, 'invalid LSDA location')
        seen.add(address)
        data, pos = image.data, origin
        require(data[pos] == 0xff and data[pos+1] in (0xff, 0x9b), 'unsupported LSDA header')
        type_encoding = data[pos+1]
        pos += 2
        if type_encoding == 0x9b:
            distance, pos = uleb(data, pos, limit)
            type_base = pos + distance
            require(type_base <= limit, 'LSDA type base outside section')
        else:
            type_base = None
        require(pos < limit and data[pos] == 1, 'unsupported call-site encoding')
        length, pos = uleb(data, pos+1, limit)
        table_start, table_end = pos, pos + length
        require(table_end <= limit and (type_base is None or table_end <= type_base),
                'LSDA table out of bounds')
        count, previous = 0, f['start']
        while pos < table_end:
            begin = pos
            vals = []
            for _ in range(4):
                value, pos = uleb(data, pos, table_end)
                vals.append(value)
            start = f['start'] + vals[0]
            end = start + vals[1]
            landing = f['start'] + vals[2] if vals[2] else None
            require(f['start'] <= start < end <= f['end'] and start >= previous,
                    'overlapping or out-of-range LSDA entry')
            require(landing is None or f['start'] <= landing < f['end'], 'landing outside FDE')
            rows.append(dict(owner=f['start'], lsda=address, index=count, entry_offset=begin,
                             bytes=bytes(data[begin:pos]).hex(), start=start, end=end,
                             landing=landing, action=vals[3]))
            previous, count = end, count + 1
        require(pos == table_end and count == expected_count, 'changed LSDA table end or count')
        raw = bytes(data[origin:table_end])
        digest = hashlib.sha256(raw).hexdigest()
        require(digest == expected_digest, 'changed LSDA bytes')
        headers.append(dict(owner=f['start'], lsda=address, offset=origin,
                            type_encoding=type_encoding, callsite_encoding=1,
                            table_bytes=length, row_count=count, bytes=raw.hex(),
                            sha256=digest))
    require({row['owner'] for row in headers} == set(LSDA_PINS), 'selected LSDA set changed')
    return headers, rows


def witnesses(sites, rows):
    output = []
    for site in sites:
        if site['kind'] not in ('c', 's') or site['ownership'] != 'new':
            continue
        pc = site['site'] + len(bytes.fromhex(site['bytes'])) - 1
        found = [r for r in rows if r['owner'] == site['owner'] and r['start'] <= pc < r['end']]
        require(len(found) <= 1, 'ambiguous LSDA call site')
        hit = found[0] if found else None
        output.append(dict(role=site['role'], owner=site['owner'], site=site['site'], lookup_pc=pc,
                           row=hit['index'] if hit else None,
                           landing=hit['landing'] if hit else None,
                           action=hit['action'] if hit else None))
    return output


def printable(value):
    if value is None:
        return ''
    if isinstance(value, int):
        return hex(value)
    return value


def tsv(path, records, columns):
    with path.open('w', encoding='utf-8', newline='') as out:
        writer = csv.writer(out, delimiter='\t', lineterminator='\n')
        writer.writerow(columns)
        for row in records:
            writer.writerow([printable(row[key]) for key in columns])


def produce(data, out):
    # Authenticate before creating output or parsing any data.
    verify_digest(data)
    image = Image(data)
    funcs = fde_rows(image)
    windows = window_rows(image)
    sites = site_rows(image)
    relocs = relocation_rows(image)
    facts = fact_rows(image)
    data_rows_found = data_rows(image)
    headers, lsda = lsda_rows(image, funcs)
    calls = witnesses(sites, lsda)
    out = Path(out)
    output_names = {'functions.tsv', 'windows.tsv', 'transfers.tsv', 'relocations.tsv',
                    'operands.tsv', 'data.tsv', 'lsda-headers.tsv', 'lsda.tsv', 'lsda-witnesses.tsv',
                    'summary.json', 'README.md', 'MANIFEST.sha256'}
    require(not out.exists() or (out.is_dir() and all(p.is_file() and p.name in output_names
                                                       for p in out.iterdir())),
            'output contains unexpected entries')
    out.mkdir(parents=True, exist_ok=True)
    tsv(out/'functions.tsv', funcs, ('role','start','end','size','section','code_offset','fde','fde_offset','lsda','sha256','bytes'))
    tsv(out/'windows.tsv', windows, ('role','ownership','owner','start','end','offset','bytes','sha256'))
    tsv(out/'transfers.tsv', sites, ('role','ownership','owner','site','offset','bytes','kind','target'))
    tsv(out/'relocations.tsv', relocs, ('role','slot','offset','bytes','slot_file_offset','slot_section','slot_initial_bytes','type','symbol_index','symbol','addend'))
    tsv(out/'operands.tsv', facts, ('role','va','file_offset','bytes','operand_offset','operand_width','value'))
    tsv(out/'data.tsv', data_rows_found, ('role','va','offset','section','bytes'))
    tsv(out/'lsda-headers.tsv', headers, ('owner','lsda','offset','type_encoding','callsite_encoding','table_bytes','row_count','bytes','sha256'))
    tsv(out/'lsda.tsv', lsda, ('owner','lsda','index','entry_offset','bytes','start','end','landing','action'))
    tsv(out/'lsda-witnesses.tsv', calls, ('role','owner','site','lookup_pc','row','landing','action'))
    summary = dict(binary_sha256=SHA256, coordinate_system='unrelocated ELF virtual address; file offsets separate',
                   selected_fdes=len(funcs), selected_fde_bytes=sum(x['size'] for x in funcs),
                   windows=len(windows), prior_context_windows=sum(x['ownership']=='prior-context' for x in windows),
                   selected_transfer_and_lea_sites=len(sites), relocations=len(relocs), operands=len(facts),
                   data_records=len(data_rows_found),
                   lsda_headers=len(headers), lsda_rows=len(lsda), call_witnesses=len(calls),
                   nonzero_landing_witnesses=sum(x['landing'] is not None for x in calls),
                   limitations='Selected static bytes only; FDEs are not complete function boundaries. Dynamic dispatch, state identity, full exception actions, all block paths and binary equivalence remain open.')
    (out/'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True)+'\n', encoding='utf-8')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    with BINARY.open('rb') as stream:
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            summary = produce(data, args.out)
    print(json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, struct.error, UnicodeError) as error:
        print('abci_reload_nonce_view94: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
