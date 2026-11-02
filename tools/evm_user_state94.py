#!/usr/bin/env python3
"""Recover selected node 94 user-to-EVM-state codec decisions from authenticated ELF bytes."""
FUNCTIONS = (
    (0x37609b0, 0x37609c9, '4bf3a9475855b962999ff15b12ecc9c27f66cf5f4a065802a39e1975dcd04f6f'),
    (0x18b68c0, 0x18b7059, 'a92f8f2259aa75b9bcc9ff388b64a01f783a598d13c32402de92b35a72566390'),
    (0x19b1850, 0x19b2825, '5556ee3da365b40af2de5990d02c47d6d0b02984f8a2366a8749acb7828109c0'),
    (0x1a51b00, 0x1a53030, 'e58f00fb9d4b3adefec1167c4f42efa52b96d84e449fb251554764d529f7155b'),
    (0x1dd2920, 0x1dd2ebc, 'ea509608f8f5dd4195b9eb5fa2e84e8ba43de0f392a2e0312bd679c36c084c65'),
    (0x1e4acb0, 0x1e4af3b, '380edde4d9687216ccccd560e75696f8c3d7b94d3a6e9bb78b8184fd2156e965'),
    (0x25df210, 0x25df2d9, 'de432a34250209f87e2e131bab5a219e540d85f6db00001c304dc2b72265ba86'),
    (0x2655570, 0x2655a24, '4f06c9d25e18ed42666f73b7312e688ac48dfda8b51b91b500c4a6956a7f67e9'),
    (0x26a5e90, 0x26a611a, 'af5f2c6e2e378b103de219bfa688d9bccd77585a4f7572214bb0c037a47bf65f'),
    (0x275d830, 0x275db59, '45dbfec35f7763c41917c5a5141d9c79c0b5a1219e38a749db09fb481c6ba6d4'),
    (0x275db60, 0x275df65, 'fb109230c94bb0031f0b8eadc68b5490f90c0b860303ce4f477d8d01fed11b23'),
    (0x2856720, 0x28569af, '78aa29cdf49a6d35e9cf48af26cfaad5cf1e22afeb3fd43a3379c57bc096d34f'),
    (0x3023060, 0x3023113, '0356bd3f7934d4150d801545adfe74b67bdb6dd409e345b6cec6c8d066c0945a'),
    (0x3157280, 0x3157bc1, '8cb030cca00e2482c047d21a0824c396e5f1ef93141356faab7337c59a4e0509'),
    (0x3396d00, 0x3396f8f, 'fbc1abdae121022102c29bab3c0fe0fe9e619ee8456c7b3386f3daf79695aefd'),
    (0x3619930, 0x361a1e2, 'd0c53ca30af893fe0bff293a84fa12dfd6beb126b411da42ec078c21003585a7'),
)

WINDOWS = (
    ('sequence_cases', 0x1a5216f, 0x1a522c2, 'efb8faf8cf60bd24f05336d94628178d1daa99bb34b7ec6bc6f235b11e257023'),
    ('sequence_finish', 0x1a522c2, 0x1a52330, 'a021967cc263fa8b57dee81ba652a05197ffbb4f4367dfeb07916be67250b32b'),
    ('writer_count', 0x275d847, 0x275d8eb, '76b8c438d64559b719646c2208b9b80fcfa1f26d40065defcc816d10181fb182'),
    ('writer_g', 0x275d8eb, 0x275d931, 'c9cd8d917ba57aec444fee049dd59f72b4f085fa444abf2f908e0d153ada55ae'),
    ('writer_t', 0x275d931, 0x275d977, '50f8fc2f8fd360434601d8caa3f7aeedba232521664e1d3292736e9601b8f142'),
    ('writer_b', 0x275d977, 0x275d9d6, '2f4d0cdc19de6ccf622ac33ba48f062e7a910b4d0db2b044fdc6259788019995'),
    ('writer_T', 0x275d9d6, 0x275da59, 'f8118b29f5c4d7df6d14ec34f6b8fe3b8c862d65a979bc720acf18624e9a3c81'),
    ('direct_count', 0x275db77, 0x275dc05, '190df2030ef4fba36e9df35d9c67bc4bbde1168e4e1bab16063d2ae3e02208e2'),
    ('direct_g_t', 0x275dc05, 0x275dcb7, '849e11e2451bf350b78c0a6d764ac264117be3007b15d936cafcbf664b907c12'),
    ('direct_b', 0x275dcb7, 0x275dcfe, '949756d7f6959c4cc5cab7ea099132c48f47fd48a41476bba191a4eb03fe2e72'),
    ('direct_T', 0x275dd52, 0x275ddea, 'be44ae9e1c89eedb9d7b80886f929fdccedc80b599d0272157d0a1a1d8e38a1a'),
    ('compact_map_init', 0x1a51f70, 0x1a51fc7, '3d5f55c1d994e3c8f0b7d1c90718583a77a49ff08978868ee858a7897f28cd11'),
    ('compact_key_dispatch', 0x1a52973, 0x1a5299c, '50fdae52744d0c766be2114a76ec42268bc384c88e40aaa8519264e9d2b5587f'),
    ('compact_key_dispatch_alternate', 0x1a52a94, 0x1a52b0b, 'cb108ccbb8bffb41fa2cc1fbc983f07eb24672152c4e0b577ccf1399d4d7bbf7'),
    ('compact_g', 0x1a52b21, 0x1a52b64, '0dee39a5959ee88476cb6d70a2a8b8f4b03b6584b5ce7852aab968b13b931ae7'),
    ('compact_t', 0x1a52bc2, 0x1a52c05, 'c27e99a0e3ca8f6ff679ca802e7c126a918dbf2e3ba733065a8a0b9234432018'),
    ('compact_unknown', 0x1a52c0a, 0x1a52c40, 'e1213d4b1863f3cdc16bc12b92f6b17ab10032f37bb7d0e183938b105856337a'),
    ('compact_T_b', 0x1a52c40, 0x1a52cad, '05838cf8ad810467a56592f185ed3f4dd2af3c9d70a0c84602c615a1602e62e1'),
    ('compact_defaults', 0x1a525ae, 0x1a5260c, 'e1f3efbf74acd837668a47c6143db18783438a4a9b378abb0d788b3099b3c9f2'),
    ('compact_duplicates', 0x1a52f75, 0x1a52fd1, 'b6ebf73735bb199615449b908897b8dafd4fc4dae509a87c4d0a20561591abca'),
    ('json_select', 0x3157446, 0x315746f, '11e5e852c149fd22d059ec3edbfaf96352c6c4cd7319f1864f0697871b9c511b'),
    ('json_unknown', 0x3157520, 0x315755b, 'b9dcb8067b81ac8675a51de6462ca181e17336ec0efff6f2633481c94bbae5f2'),
    ('json_g_guard', 0x3157560, 0x315756c, 'd4960c39bc4f4e36beda618a3ea5369f9854e4359d72cb0d624eb42f0edd8b74'),
    ('json_t_guard', 0x3157628, 0x3157634, 'f4af261d830335cf8066bd257b3831a33bf153a2fc33cf1c3ebffe8b2103d750'),
    ('json_b_guard', 0x31575d2, 0x31575dc, 'cbd0c504a9d7289d7ce2f6822588186876b01d961c4e94034401eb7a0cf38b4a'),
    ('json_T_guard', 0x315746f, 0x315747a, 'd9306c560c43f81dc3e126de93e749f17bd7b88f4b23e358a5e1667ce1e51241'),
    ('json_g_value', 0x315771a, 0x315774c, 'd325aa31650ff4be207d284ef14853fd6988321e6da9f2d1b1ed49041d4e7d4e'),
    ('json_t_value', 0x3157751, 0x3157783, '9cc170c02179473f34adfe7b2a17d92174e6d016aed4374474eb9862e4e7d3c3'),
    ('json_b_value', 0x31576e0, 0x3157715, 'a07950931239627560adcaf8cf34d01556f3227d12a315222c6b04058e477657'),
    ('json_T_value', 0x315769a, 0x31576db, 'a8ae6c15c44a09293538b68dbbb152a934b414fddcc6715b821afbbc7fc48c92'),
    ('json_defaults', 0x3157827, 0x315786d, 'b1cd1aaa9850c45f279eee89f947f1b1d2acdab53b407ea037dcadd3a03b27be'),
    ('json_output', 0x3157928, 0x315793e, '24c80701b0bf2684e03273f7f240504d48baf55df70e08cd06f6f4260fe5dc03'),
    ('json_duplicates', 0x3157ac4, 0x3157b1b, '8085cb0ee9a713f351c27e6a19348a286e6122420643ec4cb5a45be2f10ce8f9'),
    ('compact_map_call', 0x18b6c63, 0x18b6ce0, '3a0e20f35ecca2bdcb2d070342278bb06ba7a7291f0def140d9077564b911c6a'),
    ('compact_marker_fetch', 0x18b6a87, 0x18b6ab9, '456cd6ec4b1b497861845791eb0975dbdd25819f418c1d8f75e974e2f99c0de7'),
    ('compact_marker_decision', 0x18b6c48, 0x18b6c63, '8ff86e6888891e719bfa88bebab695e93bf1f38c74384016dfc42d74a09d138a'),
    ('compact_array_call', 0x18b6d98, 0x18b6e0c, '98cd6f1cbfb7e728a8c166e064b1864191432e2706f6906500d434e36079d15a'),
    ('compact_keys', 0x26555c0, 0x2655606, '1fdbff45eafa545df68c50be0d40686b5e95647a7784d2028c72b5a7b50b6e89'),
    ('compact_value_call', 0x2655679, 0x265569d, '87965e13d1d07384bbd636c8f04d3b8eb5826478a93e544f2d9b126f8598a207'),
    ('compact_insert_duplicate', 0x2655829, 0x2655882, '514ba0caa6d66cb0ac7a7dab26087e77ba59b0beb1f2c19a4874f020a275d7d8'),
    ('json_value_call', 0x3619b60, 0x3619ba9, '86255bb1bc4e71767ce007f0bee3f453d67e8710ecdb4a6afdd0800752067ac4'),
    ('json_insert_duplicate', 0x3619c51, 0x3619cab, '0f3cb4256fac77765ab51682a05342c330ae2792f11bf51cde2306fc311c479c'),
    ('sort_compare_binary', 0x2856790, 0x2856817, '42dbb5461c51da412471965fd1b16bfa2eaf512470be11e3489d829919b1fc2c'),
    ('sort_compare_json', 0x3396d70, 0x3396df7, '8aadd30d9df98ea96f9f4df93435e067dd1ebf552a8606baa9a872dbd5a5e965'),
    ('writer_adapter', 0x25df21f, 0x25df28d, 'e6867d48f49304b744d4ff610f84bab6ce81d06b72168443de22051fb4423df6'),
    ('rows_loop', 0x1e4ae63, 0x1e4aeba, '7af38991522786e984759d5c4c584fa58058294d592b95989ea16cb48a1c9859'),
    ('pair_direct', 0x1dd2a14, 0x1dd2a74, 'c9ba0acd4cc6ad904c0024b2f276eb5c2f8d2b6c14026fc0f82fc6ac6098b2d1'),
    ('pair_generic', 0x1dd2c9e, 0x1dd2ccf, '6e896eb7416a34a1c9ade5966e81dad8fe307e316ebe871addf00125e1520190'),
    ('array_entry', 0x26a5ee0, 0x26a5f08, 'fa01be04faad28b6d65802ea6488b50cba8f5c610eb268a31586c27e7f8232e5'),
    ('entry_value', 0x19b1f5c, 0x19b1f6e, '97afa43e9e0606f7fe7cc149f4c8128d8c4a8cb04b1d326b63f321f652c9061f'),
)

CALLS = (
    (0x1a521a4, 0x16844a0), (0x1a52224, 0x1684530),
    (0x1a52258, 0x1684650), (0x1a52285, 0x25a8b00),
    (0x18b6c96, 0x2655570),
    (0x18b6dda, 0x26a5e90),
    (0x26555ee, 0x1699080),
    (0x265568d, 0x1a51b00),
    (0x2655843, 0x2856720),
    (0x26a5ef6, 0x19b1850),
    (0x19b1f69, 0x1a51b00),
    (0x3619b6b, 0x301d7f0),
    (0x3619b94, 0x3023060),
    (0x3619c6c, 0x3396d00),
    (0x30230ed, 0x3157280),
    (0x31576b9, 0x3093ec0),
    (0x31576ff, 0x3094420),
    (0x3157730, 0x2fe4650),
    (0x3157767, 0x2fe4ce0),
    (0x315753a, 0x2fe3390),
    (0x1a52b38, 0x16844a0),
    (0x1a52bd9, 0x1684530),
    (0x1a52c17, 0x19682d0),
    (0x1a52c56, 0x25a8b00),
    (0x1a52c95, 0x1684650),
    (0x25df27a, 0x256df50),
    (0x25df288, 0x1e4acb0),
    (0x1e4ae9e, 0x1dd2920),
    (0x1dd2a64, 0x1e0d6c0),
    (0x1dd2bd6, 0x275db60),
    (0x1dd2cb0, 0x275d830),
    (0x275d8a8, 0x25a8f80),
    (0x275d8dc, 0x25a9bd0),
    (0x275d906, 0x25aa7f0),
    (0x275d91e, 0x25ac0d0),
    (0x275d94c, 0x25aa7f0),
    (0x275d964, 0x25ac0d0),
    (0x275d991, 0x25aa7f0),
    (0x275d9ba, 0x25acc20),
    (0x275da19, 0x25aa7f0),
    (0x275da42, 0x1dfca40),
    (0x275dbd8, 0x25a9250),
    (0x275dbf2, 0x25a9aa0),
    (0x275dc4d, 0x25abd40),
    (0x275dca8, 0x25abd40),
    (0x275dd3e, 0x25acc20),
    (0x275ddd3, 0x1dfcba0),
)

BRANCHES = (
    (0x1a5219a, 0x1a521d0, '7434'), (0x1a521bf, 0x1a5221c, '755b'),
    (0x1a5224a, 0x1a52250, '7504'), (0x1a52277, 0x1a521e7, '0f846affffff'),
    (0x1a522bc, 0x1a521ff, '0f853dffffff'), (0x1a521b0, 0x1a52335, '0f857f010000'),
    (0x1a52230, 0x1a52335, '0f85ff000000'), (0x1a52269, 0x1a5233a, '0f85cb000000'),
    (0x1a52291, 0x1a52335, '0f859e000000'), (0x1a521f9, 0x1a522c2, '0f84c3000000'),
    (0x18b6ca2, 0x18b6e20, '0f8578010000'),
    (0x18b6cc2, 0x18b6ce0, '741c'),
    (0x18b6de6, 0x18b6e20, '7538'),
    (0x26555c2, 0x2655710, '0f8448010000'),
    (0x2655697, 0x2655941, '0f84a4020000'),
    (0x2655789, 0x26558cf, '0f8440010000'),
    (0x265584d, 0x26555c0, '0f846dfdffff'),
    (0x3619b78, 0x3619d1f, '0f84a1010000'),
    (0x3619b86, 0x3619d29, '0f849d010000'),
    (0x3619ba3, 0x3619d57, '0f84ae010000'),
    (0x3619c76, 0x3619b60, '0f84e4feffff'),
    (0x1a52b2a, 0x1a52f90, '0f8460040000'),
    (0x1a52b44, 0x1a52d1a, '0f85d0010000'),
    (0x1a52bcb, 0x1a52f75, '0f84a4030000'),
    (0x1a52be5, 0x1a52d1a, '0f852f010000'),
    (0x1a52c21, 0x1a52cad, '0f8486000000'),
    (0x1a52c48, 0x1a52f7e, '0f8530030000'),
    (0x1a52c62, 0x1a52d69, '0f8501010000'),
    (0x1a52c87, 0x1a52f87, '0f85fa020000'),
    (0x1a52ca7, 0x1a52d47, '0f859a000000'),
    (0x3157566, 0x3157adf, '0f8473050000'),
    (0x315762e, 0x3157ac4, '0f8490040000'),
    (0x3157542, 0x3157966, '0f851e040000'),
    (0x31575d6, 0x3157acd, '0f85f1040000'),
    (0x3157474, 0x3157ad6, '0f855c060000'),
    (0x31576c3, 0x3157a52, '0f8489030000'),
    (0x3157709, 0x3157a48, '0f8439030000'),
    (0x3157737, 0x3157a30, '0f85f3020000'),
    (0x315776e, 0x3157a30, '0f85bc020000'),
    (0x3157840, 0x3157857, '7515'),
    (0x315784f, 0x3157b47, '0f84f2020000'),
    (0x275d8a0, 0x275d8d6, '7434'),
    (0x275d8b5, 0x275d8eb, '7434'),
    (0x275d8e9, 0x275d8b7, '75cc'),
    (0x275d8ee, 0x275d931, '7441'),
    (0x275d90f, 0x275da60, '0f854b010000'),
    (0x275d92b, 0x275da5b, '0f852a010000'),
    (0x275d934, 0x275d977, '7441'),
    (0x275d955, 0x275da60, '0f8505010000'),
    (0x275d971, 0x275da5b, '0f85e4000000'),
    (0x275d979, 0x275d9d6, '745b'),
    (0x275d99a, 0x275da60, '0f85c0000000'),
    (0x275da01, 0x275da52, '744f'),
    (0x275da22, 0x275da87, '7563'),
    (0x275da50, 0x275da95, '7543'),
    (0x275dc08, 0x275dc60, '7456'),
    (0x275dc63, 0x275dcb7, '7452'),
    (0x275dcbc, 0x275dd52, '0f8490000000'),
    (0x275dd79, 0x275dde3, '7468'),
    (0x1e4ae6d, 0x1e4aeba, '744b'),
    (0x1e4aeab, 0x1e4ad90, '0f85dffeffff'),
)

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


def digest(data):
    return hashlib.sha256(data).hexdigest()


def admit(data):
    if digest(data) != DIGEST:
        raise ValueError('node 94 digest mismatch')


def file_offset(secs, address, size):
    if address < 0 or size <= 0:
        raise ValueError('invalid VA or size')
    matches = [s for s in secs if s['type'] != 8 and s['size'] and
               s['address'] <= address and address + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('VA is not uniquely file-backed')
    s = matches[0]
    return s['offset'] + address - s['address']


def read_va(data, secs, address, size):
    off = file_offset(secs, address, size)
    result = data[off:off + size]
    if len(result) != size:
        raise ValueError('truncated file-backed span')
    return result


def inspect_functions(data, secs, indexed, fdes):
    by_start = {}
    for f in fdes:
        if f['start'] in by_start:
            raise ValueError('duplicate FDE start')
        by_start[f['start']] = f
    pairs = {(e['start'], e['fde']) for e in indexed}
    rows = []
    for start, end, expected in FUNCTIONS:
        f = by_start.get(start)
        if f is None or f['end'] != end or (start, f['fde']) not in pairs:
            raise ValueError('FDE and unwind index disagree')
        body = read_va(data, secs, start, end - start)
        off = file_offset(secs, start, end - start)
        matches = [s for s in secs if s['type'] != 8 and s['flags'] & 4 and
                   s['address'] <= start < end <= s['address'] + s['size']]
        if len(matches) != 1 or digest(body) != expected:
            raise ValueError('function body or executable mapping changed')
        rows.append({'start': hex(start), 'end_exclusive': hex(end), 'file_offset': hex(off),
                     'fde': hex(f['fde']), 'cie': hex(f['cie']), 'size': len(body),
                     'sha256': digest(body)})
    return rows


def inspect_windows(data, secs):
    rows = []
    for name, start, end, expected in WINDOWS:
        owner = [f for f in FUNCTIONS if f[0] <= start < end <= f[1]]
        if len(owner) != 1:
            raise ValueError('window does not have exactly one selected FDE')
        raw = read_va(data, secs, start, end - start)
        if digest(raw) != expected:
            raise ValueError('window bytes changed: ' + name)
        rows.append({'name': name, 'start': hex(start), 'end_exclusive': hex(end),
                     'owner': hex(owner[0][0]), 'bytes_hex': raw.hex(), 'sha256': digest(raw)})
    return rows


def decode_call(data, secs, site):
    raw = read_va(data, secs, site, 5)
    if raw[0] != 0xe8:
        raise ValueError('expected rel32 call')
    return site + 5 + struct.unpack_from('<i', raw, 1)[0]


def decode_branch(data, secs, site):
    head = read_va(data, secs, site, 2)
    if 0x70 <= head[0] <= 0x7f:
        return site + 2 + struct.unpack('b', head[1:])[0], head
    if head[0] == 0x0f and 0x80 <= head[1] <= 0x8f:
        raw = read_va(data, secs, site, 6)
        return site + 6 + struct.unpack_from('<i', raw, 2)[0], raw
    raise ValueError('expected conditional branch')


def rip_address(data, secs, site, prefix):
    raw = read_va(data, secs, site, 7)
    if raw[:3] != prefix:
        raise ValueError('unexpected RIP-relative instruction')
    return site + 7 + struct.unpack_from('<i', raw, 3)[0]


def inspect_calls(data, secs):
    result = []
    for site, expected in CALLS:
        if sum(start <= site and site + 5 <= end for start, end, _ in FUNCTIONS) != 1:
            raise ValueError('call outside selected extent')
        actual = decode_call(data, secs, site)
        if actual != expected:
            raise ValueError('direct call target changed')
        result.append({'site': hex(site), 'target': hex(actual), 'bytes_hex': read_va(data, secs, site, 5).hex()})
    return result


def inspect_branches(data, secs):
    result = []
    for site, expected, expected_bytes in BRANCHES:
        if sum(start <= site < end for start, end, _ in FUNCTIONS) != 1:
            raise ValueError('branch outside selected extent')
        actual, raw = decode_branch(data, secs, site)
        if actual != expected or raw.hex() != expected_bytes:
            raise ValueError('conditional transfer changed')
        result.append({'site': hex(site), 'target': hex(actual), 'bytes_hex': raw.hex()})
    return result


def field_names(data, secs):
    # The LEA and length-immediate shapes were checked at instruction boundaries.
    sites = (0x275d8f7, 0x275d93d, 0x275d982, 0x275da0a)
    names = ('g', 't', 'b', 'T')
    direct_stores = (0x275dc39, 0x275dc94, 0x275dcf2, 0x275ddae)
    reader_targets = (0x1a52b21, 0x1a52bc2, 0x1a52c83, 0x1a52c40)
    json_targets = (0x3157560, 0x3157628, 0x31575d2, 0x315746f)
    first = read_va(data, secs, 0x275d847, 3)
    second = read_va(data, secs, 0x275d84a, 4)
    flag = read_va(data, secs, 0x275d84e, 4)
    date = read_va(data, secs, 0x275d876, 4)
    if first != b'\x4c\x8b\x2e' or second[:3] != b'\x4c\x8b\x66' or flag[:3] != b'\x0f\xb6\x6e' or date[:3] != b'\x41\x8b\x57':
        raise ValueError('field source instructions changed')
    offsets = (0, second[3], flag[3], date[3])
    if offsets != (0, 8, 28, 16):
        raise ValueError('field source offsets changed')
    rows = []
    for name, site, store, compact, text, offset in zip(names, sites, direct_stores, reader_targets, json_targets, offsets):
        address = rip_address(data, secs, site, b'\x48\x8d\x35')
        ins = read_va(data, secs, site + 7, 5)
        if ins[0] != 0xba:
            raise ValueError('field length instruction changed')
        length = struct.unpack_from('<I', ins, 1)[0]
        literal = read_va(data, secs, address, length)
        direct = read_va(data, secs, store, 5)
        # First three stores use [rcx+rsi], last uses [rcx+r12].
        if length != 1 or literal != name.encode('ascii'):
            raise ValueError('writer field literal changed')
        if direct not in (b'\xc6\x04\x31'+literal+b'\x48', b'\x42\xc6\x04\x20'+literal):
            raise ValueError('direct writer field store changed')
        rows.append({'name': literal.decode('ascii'), 'literal_va': hex(address),
                     'literal_length': length, 'name_lea': hex(site), 'direct_name_store': hex(store),
                     'input_offset': hex(offset), 'compact_case': hex(compact), 'json_case': hex(text)})
    return rows


def read_table(data, secs, address, owner, expected):
    raw = read_va(data, secs, address, 33 * 4)
    targets = [address + x[0] for x in struct.iter_unpack('<i', raw)]
    if any(not owner[0] <= x < owner[1] for x in targets):
        raise ValueError('dispatch target outside selected FDE')
    for char, target in expected.items():
        if targets[ord(char) - ord('T')] != target:
            raise ValueError('dispatch target changed')
    fallback = targets[1]
    if any(v != fallback for i, v in enumerate(targets) if chr(ord('T') + i) not in expected):
        raise ValueError('unexpected dispatch arm')
    return [{'input': chr(ord('T') + i), 'target': hex(t), 'recognized': chr(ord('T') + i) in expected}
            for i, t in enumerate(targets)]


def relocations(data, secs, slots):
    relsec = [s for s in secs if s['name'] == '.rela.dyn' and s['type'] == 4]
    syms = [s for s in secs if s['name'] == '.dynsym' and s['type'] == 11]
    strs = [s for s in secs if s['name'] == '.dynstr' and s['type'] == 3]
    if len(relsec) != 1 or len(syms) != 1 or len(strs) != 1 or relsec[0]['size'] % 24:
        raise ValueError('unsupported relocation or symbol table')
    r, sym, strings = relsec[0], syms[0], strs[0]
    hits = {slot: [] for slot in slots}
    for pos in range(r['offset'], r['offset'] + r['size'], 24):
        slot, info, addend = struct.unpack_from('<QQq', data, pos)
        if slot not in hits:
            continue
        typ, index = info & 0xffffffff, info >> 32
        name = None
        if index:
            if index * 24 + 24 > sym['size']:
                raise ValueError('symbol index outside table')
            no = struct.unpack_from('<I', data, sym['offset'] + index * 24)[0]
            if no >= strings['size']:
                raise ValueError('symbol name outside table')
            begin, end = strings['offset'] + no, strings['offset'] + strings['size']
            nul = data.find(b'\0', begin, end)
            if nul < 0:
                raise ValueError('unterminated symbol name')
            name = data[begin:nul].decode('ascii')
        hits[slot].append({'slot': hex(slot), 'type': typ, 'symbol_index': index,
                           'symbol': name, 'addend': hex(addend)})
    if any(len(v) != 1 for v in hits.values()):
        raise ValueError('missing or duplicate relocation')
    rows = [hits[s][0] for s in slots]
    if [(r['type'], r['symbol'], r['addend']) for r in rows] != [(8, None, '0x37609b0'), (6, 'memcmp', '0x0'), (8, None, '0x151f6f0'), (8, None, '0x3c0c870')]:
        raise ValueError('selected relocations changed')
    return rows


def duplicate_fields(data, secs):
    # Both readers pass a one-byte field name to the same error format data.
    entries = (('g', 0x1a52f90, 0x3157adf), ('t', 0x1a52f75, 0x3157ac4),
               ('b', 0x1a52f87, 0x3157acd), ('T', 0x1a52f7e, 0x3157ad6))
    rows = []
    for name, compact, text in entries:
        item = {'name': name}
        for kind, site in (('compact', compact), ('json', text)):
            literal_va = rip_address(data, secs, site, b'\x48\x8d\x05')
            if read_va(data, secs, literal_va, 1) != name.encode('ascii'):
                raise ValueError('duplicate field name changed')
            item[kind + '_site'] = hex(site)
            item[kind + '_literal_va'] = hex(literal_va)
        rows.append(item)
    format_a = rip_address(data, secs, 0x1a52fc0, b'\x48\x8d\x35')
    format_b = rip_address(data, secs, 0x3157b0a, b'\x48\x8d\x3d')
    if format_a != format_b or read_va(data, secs, format_a, 18) != b'\x11duplicate field `':
        raise ValueError('duplicate field format data changed')
    return {'format_va': hex(format_a), 'format_bytes_hex': read_va(data, secs, format_a, 18).hex(),
            'fields': rows}


def key_evidence(data, secs):
    length_ins = read_va(data, secs, 0x26555d5, 5)
    if length_ins[0] != 0xb9:
        raise ValueError('key type length instruction changed')
    length = struct.unpack_from('<I', length_ins, 1)[0]
    literal_va = rip_address(data, secs, 0x26555e7, b'\x48\x8d\x15')
    literal = read_va(data, secs, literal_va, length)
    if literal != b'User':
        raise ValueError('key type literal changed')
    comparisons = []
    for count_site, call_site in ((0x28567a0, 0x28567a8), (0x3396d80, 0x3396d88)):
        imm = read_va(data, secs, count_site, 5)
        call = read_va(data, secs, call_site, 6)
        if imm[0] != 0xba or call[:2] != b'\xff\x15':
            raise ValueError('key comparison instruction changed')
        count = struct.unpack_from('<I', imm, 1)[0]
        slot = call_site + 6 + struct.unpack_from('<i', call, 2)[0]
        if count != 20 or slot != 0x576e488:
            raise ValueError('key comparison length or slot changed')
        comparisons.append({'length_site': hex(count_site), 'call_site': hex(call_site),
                            'length': count, 'slot': hex(slot), 'call_bytes_hex': call.hex()})
    return {'key_type': literal.decode('ascii'), 'literal_va': hex(literal_va),
            'literal_length': length, 'comparisons': comparisons}


def fixed_headers(data, secs):
    # This is the selected fresh-byte route: signed negative markers below
    # 0x90 call the map child and those below 0xa0 call the row-array child.
    raw = read_va(data, secs, 0x18b6c48, 0x1b)
    expected = bytes.fromhex('41b1e080f9df0f879afcffff80f9900f833b01000080e10f0fb6d9')
    if raw != expected:
        raise ValueError('fixed header predicate changed')
    array = read_va(data, secs, 0x18b6d98, 12)
    if array[:3] != b'\x80\xf9\xa0' or array[9:12] != b'\x80\xe1\x0f':
        raise ValueError('fixed array predicate changed')
    if decode_branch(data, secs, 0x18b6c57)[0] != 0x18b6d98:
        raise ValueError('fixed header dispatch changed')
    lower, split, upper, mask = 0x80, raw[14], array[2], raw[23]
    if (split, upper, mask) != (0x90, 0xa0, 0x0f):
        raise ValueError('fixed header bounds changed')
    map_child = decode_call(data, secs, 0x18b6c96)
    array_child = decode_call(data, secs, 0x18b6dda)
    if (map_child, array_child) != (0x2655570, 0x26a5e90):
        raise ValueError('fixed header child changed')
    return [{'byte': hex(x), 'route': 'map' if x < split else 'row-array',
             'count': x & mask, 'child': hex(map_child if x < split else array_child)}
            for x in range(lower, upper)]


def analyze(data):
    admit(data)
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    functions = inspect_functions(data, secs, index, fdes)
    windows = inspect_windows(data, secs)
    calls = inspect_calls(data, secs)
    branches = inspect_branches(data, secs)
    fields = field_names(data, secs)
    if rip_address(data, secs, 0x1a5298c, b'\x48\x8d\x0d') != 0x3aaddc:
        raise ValueError('compact key table reference changed')
    if rip_address(data, secs, 0x315745f, b'\x48\x8d\x0d') != 0x57c60c:
        raise ValueError('JSON key table reference changed')
    compact = read_table(data, secs, 0x3aaddc, (0x1a51b00, 0x1a53030),
                         {'g': 0x1a52b21, 't': 0x1a52bc2, 'b': 0x1a52c83, 'T': 0x1a52c40})
    text = read_table(data, secs, 0x57c60c, (0x3157280, 0x3157bc1),
                      {'g': 0x3157560, 't': 0x3157628, 'b': 0x31575d2, 'T': 0x315746f})
    rels = relocations(data, secs, (0x56de3c8, 0x576e488, 0x576e890, 0x5770e28))
    type_vtable = rip_address(data, secs, 0x3157a8f, b'\x48\x8d\x15')
    if type_vtable + 0x18 != int(rels[0]['slot'], 16):
        raise ValueError('reader type descriptor slot changed')
    type_name_va = rip_address(data, secs, 0x37609bb, b'\x48\x8d\x35')
    type_length_ins = read_va(data, secs, 0x37609c2, 5)
    if type_length_ins[0] != 0xba:
        raise ValueError('type formatter length shape changed')
    type_length = struct.unpack_from('<I', type_length_ins, 1)[0]
    type_name = read_va(data, secs, type_name_va, type_length)
    if type_name != b'struct EvmUserState':
        raise ValueError('type formatter literal changed')
    type_record = {'name': type_name.decode('ascii'), 'name_va': hex(type_name_va),
                   'length': type_length, 'reader_vtable': hex(type_vtable),
                   'formatter': rels[0]['addend']}

    # Fixed immediate construction writes the literal "duplicate key" in two pieces.
    for site in (0x2655867, 0x3619c90):
        a, b = read_va(data, secs, site, 10), read_va(data, secs, site + 14, 10)
        if a[:2] != b'\x48\xb9' or b[:2] != b'\x48\xb9':
            raise ValueError('duplicate diagnostic construction changed')
        if b[2:] + a[2:][3:] != b'duplicate key':
            raise ValueError('duplicate diagnostic bytes changed')
    return {'binary_sha256': digest(data), 'coordinate_system': 'unrelocated ELF virtual addresses',
            'functions': functions, 'windows': windows, 'calls': calls, 'branches': branches,
            'fields': fields, 'type_record': type_record, 'compact_key_table': compact, 'json_key_table': text,
            'compact_key_table_va': hex(0x3aaddc),
            'compact_key_table_bytes_hex': read_va(data, secs, 0x3aaddc, 33 * 4).hex(),
            'json_key_table_va': hex(0x57c60c),
            'json_key_table_bytes_hex': read_va(data, secs, 0x57c60c, 33 * 4).hex(),
            'relocations': rels, 'duplicate_field_diagnostics': duplicate_fields(data, secs),
            'key_evidence': key_evidence(data, secs),
            'fresh_byte_fixed_headers': fixed_headers(data, secs),
            'limitations': 'Selected static ranges only; FDE extents do not establish all function boundaries.'}


def tsv(headers, rows):
    out = io.StringIO(newline='')
    w = csv.writer(out, delimiter='\t', lineterminator='\n')
    w.writerow(headers)
    w.writerows(rows)
    return out.getvalue().encode('utf-8')


def render(data):
    r = analyze(data)
    json_data = (json.dumps(r, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode('ascii')
    fields = tsv(('name', 'literal_va', 'literal_length', 'name_lea', 'direct_name_store', 'input_offset', 'compact_case', 'json_case'),
                 ([x[k] for k in ('name', 'literal_va', 'literal_length', 'name_lea', 'direct_name_store', 'input_offset', 'compact_case', 'json_case')] for x in r['fields']))
    headers = tsv(('byte', 'route', 'count', 'child'),
                  ((x['byte'], x['route'], x['count'], x['child']) for x in r['fresh_byte_fixed_headers']))
    return {'evidence.json': json_data, 'fields.tsv': fields, 'fixed-headers.tsv': headers}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    data = BINARY.read_bytes()
    products = render(data)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, content in products.items():
        (args.out / name).write_bytes(content)


if __name__ == '__main__':
    main()
