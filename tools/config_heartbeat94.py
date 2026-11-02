#!/usr/bin/env python3
"""Collect static node 94 heartbeat configuration initialization evidence.

Inputs are authenticated before any interpretation. No executable is run.
The selected machine-code partitions use a restricted byte-pattern decoder;
they do not assert source-level boundaries or complete runtime behavior.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))
from elf_index import sections
from fde_extents import eh_frame_records, uleb

ROOT = TOOLS.parent
TARGET = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280

# Body digests are additional controls; the full-artifact digest remains primary.
FUNCTIONS = (
    ('json_document', 0x43a33b0, 0x43a34c5, '7d830414ec0592fb4b5f0737737ef90fb72e40c0dd6f9d77f39f8010894e600e'),
    ('json_error_builder', 0x43a3de0, 0x43a3e98, 'de6384918d9726382293d3461d609a226e530862850ef9d105dc63f0f105b09d'),
    ('json_sequence_bool', 0x43a6aa0, 0x43a6c02, 'ab2539f21a62eae49379cf9f5e700ad34395267a0a355618c96205d0c33eff0a'),
    ('json_number_dispatch', 0x43a9250, 0x43a93b7, 'd399e763ddfb16a7f86656a0561905c9c578cad1c8ff771af37e4e39c7e7fb18'),
    ('json_bool_parser', 0x43aa8d0, 0x43aaaa9, '3b02bd58628d17923f9a145877df29e3da6e199180b34a476baa424e85b5102d'),
    ('json_config_parser', 0x43ae9c0, 0x43af1ff, '957e747551d01675f77948f15e27e7b7bb32357f4c6e67a18ec227384ec28138'),
    ('failure_cleanup', 0x4732600, 0x47326a3, '932dbde70dbe9f9674b8bb5158904451a0ab04dac886d0b3f090805880a466b2'),
    ('seed_rows', 0x474e220, 0x474e50e, 'd6e0e75149021d0f03290d6b2c2c0b5448769feab634fdfedccf2a850b5c8ccd'),
    ('tracker_constructor', 0x474ece0, 0x474f8a0, '780d242d212c11e0d8726acc465d1091c30c6675fe32cd9c782a6186678b19fd'),
    ('binary_config_encoder', 0x474ff60, 0x475014e, 'e830d0d7474a4cce711b8913c8565f1a87c05f5418bf65016ed2396ff9e98989'),
    ('seed_map_insert', 0x4938330, 0x493864c, 'ce709a780ba9a2796b56f51fa7a9de139b2612c5a75d00b8ef26094d37e5152e'),
    ('json_float_field', 0x4a806e0, 0x4a8085a, '9f0a6d61a19e9f9f0195b33a3e20cd529f6cdb530706a2b80f8e8f8f3f77d6ac'),
    ('json_bool_field', 0x4a99530, 0x4a99653, 'be38ca576aa91f41aeb242c7c1d4c7ec11c46294f18f9d0b95784b8effb1b976'),
    ('json_key_writer', 0x4ab04c0, 0x4ab06ad, '9291616ba9c56cfa5a4954c6e8f92da4ec3e91e0dd0b109b5ed23690e1c288d3'),
    ('binary_float_writer', 0x4aeafc0, 0x4aeb161, '060858df75c758f8eed6f3d21151eb9ba9601b6ece11ab78d0a35fb26293a4e6'),
)

# Exact digest-bound byte contracts for the interpretation in the README.
CONTRACTS = (
    ('old_json_call_boundary', 0x4721f97, 'e81414c8ff0fb64424203c020f85b6000000'),
    ('document_parse_and_trailing', 0x43a33f7, 'e8c4b50000807b08027454488b442428488b4c24304839c17345488b54242048f7d848ffc148be0026000001000000662e0f1f8400000000000fb67c0aff4883ff20773b480fa3fe7335'),
    ('document_trailing_error', 0x43a3476, '48c744245816000000488d7c2408488d742458e852090000488903c6430802'),
    ('container_start', 0x43ae9f2, '49bc00260000010000000fb67c02ff4883ff207735490fa3fc732f49894628488d3c0648ffc748ffc04883ff0175db48c744240805000000488d7424084c89f7e8a953ffffe9b006000083ff5b0f845103000083ff7b0f857c060000'),
    ('bool_key_comparison', 0x43aeb76, '488b4424184883f81a747a4883f8070f85a50000008b4500330582bf34fc8b4d03330d7cbf34fc09c10f858b0000004180fd020f856d050000'),
    ('float_key_comparison', 0x43aebfb, 'f30f6f051abf34fcf30f6f4d00660f74c8f30f6f450af30f6f150ebf34fc660f74d0660fdbd1660fd7c23dffff00000f8490000000'),
    ('unknown_key_skip', 0x43aec80, '4883fe3a0f85320400004885c00f84d8040000498946284c89f7e80152ffff4885c00f85dc020000'),
    ('float_duplicate_test', 0x43aecc0, '48837c2438010f8439040000'),
    ('object_field_parsers', 0x43aed14, '4883fe3a0f859e0300004885c00f844404000049894628488d7c24204c89f6e898bbffff807c2420010f8432030000440fb66c2421e95affffff4883fe3a0f85640300004885c00f840a04000049894628488d7c24084c89f6e8dea4ffff837c2408010f8402030000488b4424104889442440b8010000004889442438e912ffffff'),
    ('object_defaults', 0x43aee6f, '4489e824014180fd020fb6c041bf01000000440f45f8f64424380148bd333333333333c33f480f456c2440'),
    ('object_duplicate_errors', 0x43af105, '488d055e2a34fc488944242048c74424281a000000eb15488d05402a34fc488944242048c744242807000000488d4424204889442408488d052eaa8b004889442410488d3d871ee3fb488d742408e8489d1c00e927feffff'),
    ('sequence_bool_and_closing', 0x43a6b82, '4183fa5d750b66c70300024883c4205bc3807808007440c6400800eb064183f85d7442488d7c2408e8213d0000807c2408007412488b44241048894308c603014883c4205bc30fb6442409884301c603004883c4205bc3'),
    ('bool_lexical_comparisons', 0x43aa947, '4183f966747a4183f9740f851e0100004883f8010f843b010000488d78ff48897e284839d70f83cc0000000fb67c01ff488946284080ff720f85e50000004839d00f83b0000000488d7801440fb6040148897e284180f8750f85c50000004839d70f83900000000fb64c01014883c00248894628b00180f9657475e9a30000004883f8010f84cb000000488d78ff48897e284839d773600fb67c01ff488946284080ff61757d4839d0734c488d7801440fb6040148897e284180f86c75654839d77334488d7802440fb644010148897e284180f873754c4839d7731b0fb64c01024883c0034889462880f965753531c088430131c0eb1f'),
    ('number_initial_dispatch', 0x43a92be, '4983f82d75324885c00f84dd000000488946284889e731d2e805b5ffff488b0c244883f9037432488b4424084885c9746c83f9017444eb6c4180c0d04180f80a737c4889e7ba01000000e8d3b4ffff488b0c244883f9037512488b442408'),
    ('number_convert_result', 0x43a9338, '66480f6ec8660f620d3babe5fb660f5c0d539be5fb660f28c1660f15c1f20f58c1eb0c66480f6ec0eb05f2480f2ac0f20f11430831c0488903'),
    ('time_conversion_guard', 0x474ecff, 'ff159bfb0101488db4247c020000488dbc2400010000bab400000031c9ff1586fb0101488b84240801000048b9000000004057ffff4801c148ba81aefeff7faefeff4839d10f82f5080000f20f108424000100000f298424600200008bbc247802000048b9572951cea0c8451848f7e94889d648c1ee3f48c1ea0d01d6ff152efb010185c00f84b508000089c5'),
    ('config_template_args', 0x474edee, '488b1d33fb01018b435085c00f85c70600004883c31848899c2400010000488d053d5902004889842408010000488d052e76abfb4889842410010000488d053fad51004889842418010000488d0df8fefd0048898c24200100004889842428010000488d35e7f1a9fb488d5c24284c8da424000100004889df4c89e2ff15d0f10101'),
    ('regular_file_route', 0x474ee9b, '4c89ef4c89feff1541fb010184c07426'),
    ('initial_default', 0x474eed1, '48b8333333333333c33f4889842488000000c684249000000001'),
    ('device_and_format_gate', 0x474ef0e, '4983ff09752048b82f6465762f6e756c49334500410fb64d084883f16c4809c10f847e0300004c89ef4c89feff15e006020184c0747a'),
    ('msgpack_call_and_result', 0x474ef71, '488dbc2400010000488db42488000000488d542440e8d50f0000488b9c240001000048b800000000000000804883c8044839c30f85f2060000'),
    ('json_fields_and_errors', 0x474efbe, 'bf80000000ff150ff001014885c00f84b5060000488d8c249000000048c7442440800000004889442448488d5424404889942400010000488d1595b5fafb488994240801000048c78424100100000200000048c784241801000001000000c684242001000000c6007b48c74424500100000066c744247000014c89642478488d35d3bafafb488d7c2470ba07000000e8dea434004989c64885c00f85af060000807c2470010f8489060000488d35adbafafb488d7c2470488d8c2488000000ba1a000000e8591633004989c64885c00f857a060000'),
    ('metadata_and_parse', 0x474f172, '488dbc24000100004c89ee4c897c24104c89faff1565f8010183bc24000100000175144c8bb42408010000488b7424184885f67547eb788bac24040100004c8bbc2408010000488dbc24000100004c89ee488b542410e8e329fdff440fb6a424080100004180fc02488b742418751a4c8bb424000100004885f674334c89ef31d2ff1517ee0101eb26'),
    ('initial_error_fallback', 0x474f221, '4c8974244048c784240001000000000000c784241001000000000000c684241401000000488d4424404889442428488b059af201014889442430488d35fbd8a9fb488d0d27f6fd00488dbc2400010000488d542428ff15fcf60101488b4424404889442460f20f10057ab0abfbf20f1144245841b401c74424241a40f6004531f64889dd4c8b7c2410'),
    ('end_json_object', 0x474f2cc, '488b430842c604207d49ffc44c8963104c8b6424404c8b7424484c89e048f7d80f8032040000488b6c2450'),
    ('write_steps_and_result', 0x474f2f7, '4c89ef4c89fb4c89feff1562f701014989c74885c00f85460300004c8d05bffbfd004c89f74889ee4c89ea4889d9ff15450302014989c74d85e4740e4c89f74c89e631d2ff15cfec01014d85ff0f85ed030000'),
    ('default_route_assignments', 0x474f34a, 'f20f1005b6afabfbf20f1144245841b401c74424241a40f6004531f648c7442460000000004c8b6c2418488b6c24684989df'),
    ('final_tracker_publication', 0x474f3fa, '488d9c2400010000488db42478020000bab00000004889dfff15c8eb01014c89ac24b00100004889ac24b80100004c89bc24c0010000f20f10442458f20f118424c80100004488a424d001000048b8000000000000144048898424d8010000c78424e001000000000000488b44246048898424f00100008b442424898424f80100004c89b424fc0100004889df488bb424a0000000e88cedffff488db42400010000ba60010000488b9c24980000004889dfff152eeb0101'),
    ('initial_error_exits', 0x474f69c, '4c8bb424080100004c8bbc2410010000488b7424284885f6740d488b7c243031d2ff154de9010148899c24000100004c89b424080100004c89bc2410010000488dbc24a8000000488db42400010000e8202ffdffeb4248c74424280a000000488d7c242831f631d2ff1576f801014989c6488b7424404885f6740d488b7c244831d2ff15ece80101488dbc24a80000004c89f6e80c2efdff4989c74c89bc2400010000488d3dbcb9fafb488d0d7bf3fd004c8d0584f7fd00488d942400010000be2b000000ff15e1e80101eb0d488d3df002fe00ff15dae90101'),
    ('input_map_gates', 0x474e242, '498b0e4d8b6e104885c90f95c04d85ed0f95c220c280fa010f858b020000'),
    ('seed_row_and_insert', 0x474e290, '4c8d60014989d749ffcd488d04808b4c8218894c24200f104482080f294424100f57c00f1145b88b44240c41894608488b4424044989068b44240c894508488b4424044889450048c74424780000000048c74424280000000048b800000000008066404889442448c744245000000000c7442460000000008b8424a00000008945f40f108424900000000f1145e4488dbc24900000004889de488d542410488d4c2428e8f89f1e00'),
    ('compare_keys', 0x4938358, '0f8434010000488b46084889442410410fb7855e050000498d6da048894424308d0485000000004c8d3c8049f7df49c7c6ffffffffbb8004000066666666662e0f1f840000000000498d041f483d8004000074444a8d342bba140000004c89e7ff15ca60e30048984885c00f98c10f9fc028c84883c56849ffc64883c3143c0174c60fb6c085c07435eb12'),
    ('replace_found_value', 0x4938416, '488b4d60488b442408488948600f1045500f1140500f1045400f1140400f1045000f104d100f1055200f105d300f1158300f1150200f1148100f1100488b0c240f10010f1049100f1051200f1059300f1145000f114d100f1155200f115d300f1041400f1145400f1041500f114550488b496048894d60e97f010000'),
    ('create_root_insert', 0x4938552, '4989cebf60050000ff15785ae3004885c00f84ba00000048c7000000000066c7805e050000000049890649c74608000000000fb7885e0500004883f90b0f839e0000004c89f78d51016689905e050000488d14898b731089b490900400000f10030f11849080040000486bc968488b3424488b566048895408680f1046500f114408580f1046400f114408480f10060f104e100f1056200f105e300f115c08380f115408280f114c08180f1144080848ff4710'),
    ('messagepack_two_fields', 0x474ff81, '807a0b007432488d7c24084c89f6ba02000000e867993900488b4424084883f8027432488b4c24104c89234889430848894b10e946010000488d7c24084c89f6ba02000000e855a43900488b4424084883f80275ce450fb67d0841807e0b01751e488d352dabfafbba070000004c89f7e87ab139004883f8020f85f40000004c896c24204d8b264d8b2c24498b6c24104939ed0f84860000004180cfc2410fb6ffe879d539004189c74939ed0f84f6000000498b44240844883c2849ff44241041807e0b01751a488d35ceaafafbba1a0000004c89f7e814b139004883f802752f488b442420f20f10004c89f7e84daf39004883f80248b9000000000000008075094883c10448890beb7348890beb6648b9000000000000008048890beb57'),
    ('messagepack_float_marker', 0x4aeafdc, '4939f60f842d010000488b4308c60430cb488b03488b4b10488d710148897310'),
    ('messagepack_float_bytes', 0x4aeb082, '66480f7ec0480fc8488b4b0848890431488343100841be02000000'),
    ('json_bool_values', 0x4a9953a, 'e8816f010041803e010f848e0000004d8b76080fb62b498b1e488b03488b73104829f04883f8010f8689000000488b430866c704303a204883c60248897310498b1e40f6c5017421488b03488b73104829f04883f803767f488b4308c70430747275654883c604eb24488b03488b73104829f04883f804767f488b4308c644300465c7043066616c734883c6054889731041c646200131c05b415e5dc3'),
    ('json_float_values', 0x4a806f1, 'e8cafd020041803e010f84d10000004d8b6608f30f7e03498b1c24488b03488b73104829f04883f8010f86ca000000488b430866c704303a204883c60248897310498b1c2466480f7ec048b9ffffffffffffff7f4821c148b8000000000000f07f4839c17c29488b03488b73104829f04883f8030f86ac000000488b4308c704306e756c6c4883c60448897310eb3d488d7c2410ff15edecce004989c6488b034c8b7b104c29f84939c60f8797000000488b7b084c01ff488d7424104c89f2ff152ad8ce004d01fe4c89731041c64424200131c0'),
    ('json_key_writer', 0x4ab04ce, '803f010f8437010000488b5f08807f01014c8b234889542420488974241848897c2410751e4d8b6c24104d392c240f8461010000498b44240842c604280a49ffc5eb26498b04244d8b6c24104c29e84883f8010f8661010000498b4424086642c704282c0a4983c5024d896c241048895c24084c8b7b184d85ff7462488b442408488b6808488b58104c8b3582dacb006690498b04244c29e84839c37720498b7c24084c01ef4889ee4889da41ffd64901dd4d896c241049ffcf75d6eb20b90100000041b8010000004c89e74c89ee4889dae82bf0a9ff4d8b6c2410ebc0488b442410c6400102488b4424084c8b38498b77104939377461498b4708c604302248ffc6498977104c89ff488b742418488b542420e85963f1ff498b77104939377455498b4708c604302248ffc649897710'),
    ('unwind_cleanup', 0x4732600, '41574156534889fb31c0483b47487009488d7b48e857d5ffff488b334885f6740c488b7b0831d2ff15e3b903014c8d7b184c89ffff15cec90301498b374885f67411488b7b2031d25b415e415fff25bdb903015b415e415fc3'),
)


def verify_identity(data, expected=DIGEST):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('node 94 size or SHA-256 mismatch')


class View:
    def __init__(self, data, secs=None):
        self.data = data
        self.sections = sections(data) if secs is None else secs

    def offset(self, va, size):
        if type(va) is not int or type(size) is not int or va < 0 or size <= 0 or va + size > 1 << 64:
            raise ValueError('invalid virtual range')
        hits = [s for s in self.sections if s['type'] != 8 and s['flags'] & 2 and s['size']
                and s['address'] <= va and va + size <= s['address'] + s['size']]
        if len(hits) != 1:
            raise ValueError('virtual range lacks a unique allocated, file-backed section')
        offset = hits[0]['offset'] + va - hits[0]['address']
        if offset < 0 or offset + size > len(self.data):
            raise ValueError('file-backed range is truncated')
        return offset

    def read(self, va, size):
        p = self.offset(va, size)
        return self.data[p:p + size]


def require_bytes(actual, expected, label):
    if actual != expected:
        raise ValueError('byte contract changed: ' + label)


def contract(view, label, va, expected_hex):
    expected = bytes.fromhex(expected_hex)
    actual = bytes(view.read(va, len(expected)))
    require_bytes(actual, expected, label)
    return {'label': label, 'va': hex(va), 'file_offset': hex(view.offset(va, len(actual))),
            'size': len(actual), 'bytes': actual.hex()}

# Restricted x86 byte-pattern reader adapted from the MIT replica-route collector.
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
        elif 0xc8 <= op2 <= 0xcf:
            pass
        elif (op2 in (0x10, 0x11, 0x13, 0x14, 0x15, 0x1f, 0x28, 0x29, 0x2a, 0x2e, 0x2f, 0x57, 0x58, 0x5c, 0x5e,
                      0x60, 0x62, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x72, 0x73, 0x74, 0x7e, 0x7f, 0xa3, 0xaf, 0xb6, 0xb7,
                      0xb0, 0xb1, 0xbc, 0xc1, 0xbe, 0xbf, 0xd6, 0xd7, 0xdb, 0xdf, 0xe6, 0xeb, 0xef)
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
        if op == 0x0f and op2 in (0x70, 0x72, 0x73):
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



# Site, branch role, taken meaning, fallthrough meaning. Each row must decode as
# a conditional instruction inside a selected body; targets come from rel bytes.
BRANCHES = (
    (0x43a3400, 'json_document_result', 'parser error, return', 'check trailing input'),
    (0x43a3439, 'json_trailing_above_space', 'trailing input error', 'check whitespace mask'),
    (0x43a343f, 'json_trailing_mask', 'trailing input error', 'consume whitespace'),
    (0x43aea3f, 'json_sequence_open', 'sequence representation', 'test object opener'),
    (0x43aea48, 'json_object_open', 'invalid container', 'object representation'),
    (0x43aeb7f, 'json_key_length_26', 'compare float key', 'test bool key length'),
    (0x43aeb85, 'json_key_length_7', 'unknown key', 'compare bool key'),
    (0x43aeb9f, 'json_bool_key_match', 'unknown key', 'matched bool key'),
    (0x43aeba9, 'json_bool_key_duplicate', 'duplicate error', 'parse bool value'),
    (0x43aec2a, 'json_float_key_match', 'matched float key', 'unknown key'),
    (0x43aecc6, 'json_float_key_duplicate', 'duplicate error', 'parse float value'),
    (0x43aeca2, 'json_unknown_value', 'skip error', 'continue object'),
    (0x43aed3d, 'json_bool_value', 'boolean parse error', 'store boolean'),
    (0x43aed77, 'json_float_value', 'number parse error', 'store float'),
    (0x43aeb23, 'json_object_close', 'apply absent-field defaults', 'expect next key'),
    (0x43a6b86, 'json_sequence_end', 'check element or separator', 'absent first element'),
    (0x43aa94b, 'json_bool_first_f', 'check false suffix', 'test true initial'),
    (0x43aa951, 'json_bool_first_t', 'invalid boolean type', 'check true suffix'),
    (0x43aa96c, 'json_bool_truncated_true', 'unexpected end', 'compare next byte'),
    (0x43a92c2, 'json_number_minus', 'check digit', 'negative numeric scanner'),
    (0x43a92fe, 'json_number_digit', 'invalid number type', 'nonnegative numeric scanner'),
    (0x43a9315, 'json_number_scanner', 'number success conversion', 'number error'),
    (0x474ed44, 'clock_range', 'invalid range', 'time conversion'),
    (0x474ed84, 'clock_conversion', 'zero result to failure', 'continue'),
    (0x474edfa, 'config_once', 'initialize cell', 'cell ready'),
    (0x474eea9, 'regular_file', 'predicate zero to default route', 'existing-file route'),
    (0x474eeb1, 'path_copy', 'zero length', 'allocate and copy'),
    (0x474eec3, 'path_allocation', 'allocation failure', 'copy path'),
    (0x474eef8, 'default_once', 'initialize diagnostic cell', 'continue'),
    (0x474ef12, 'special_length', 'length differs', 'compare nine bytes'),
    (0x474ef2e, 'special_match', 'special path bypass', 'test extension'),
    (0x474ef42, 'format_predicate', 'JSON route', 'binary route'),
    (0x474efa4, 'binary_result', 'encoder failure', 'buffer ready'),
    (0x474efcc, 'json_allocation', 'allocation failure', 'open JSON object'),
    (0x474f058, 'json_bool_error', 'field failure', 'check writer state'),
    (0x474f063, 'json_bool_state', 'invalid state', 'write float field'),
    (0x474f08d, 'json_float_error', 'field failure', 'close object'),
    (0x474f0b5, 'json_indent_state', 'invalid nesting', 'close object'),
    (0x474f193, 'metadata_tag', 'metadata accepted', 'metadata error'),
    (0x474f1df, 'parse_tag', 'parsed value', 'parse error'),
    (0x474f2ec, 'json_result', 'serialization error', 'buffer ready'),
    (0x474f30c, 'parent_result', 'first file step failed', 'second file step'),
    (0x474f344, 'write_result', 'second file step failed', 'use defaults'),
    (0x474e25a, 'source_set', 'empty or null source', 'iterate source'),
    (0x49383df, 'map_comparison', 'equal key, replace', 'seek insertion'),
    (0x49384f0, 'map_root', 'empty root', 'nonempty insertion'),
    (0x4938563, 'map_allocation', 'allocation failure', 'initialize root'),
    (0x493858f, 'map_capacity', 'capacity failure', 'store first row'),
    (0x474ff85, 'binary_representation', 'positional header', 'named header'),
    (0x474ffa2, 'binary_header', 'success sentinel', 'error return'),
    (0x4750060, 'binary_field_name', 'error return', 'success sentinel'),
    (0x4750081, 'binary_float', 'error return', 'success sentinel'),
    (0x4a99580, 'json_boolean', 'low bit zero', 'low bit one'),
    (0x4a80755, 'json_float_class', 'finite magnitude', 'nonfinite magnitude'),
    (0x4ab04f1, 'json_field_separator', 'later field', 'first field'),
)

# These sites and expected encoded operands establish the selected local call
# chain. RIP-relative slot targets are resolved independently in .rela.dyn.
EDGES = (
    ('json_document_to_config', 0x43a33f7, 0x43ae9c0),
    ('json_trailing_error', 0x43a3489, 0x43a3de0),
    ('json_container_error', 0x43aea32, 0x43a3de0),
    ('json_unknown_value_skip_boundary', 0x43aec9a, 0x43a3ea0),
    ('json_object_bool', 0x43aed33, 0x43aa8d0),
    ('json_object_number', 0x43aed6d, 0x43a9250),
    ('json_sequence_first_element', 0x43aedd0, 0x43a6aa0),
    ('json_sequence_bool', 0x43a6baa, 0x43aa8d0),
    ('json_negative_number_scanner_boundary', 0x43a92d6, 0x43a47e0),
    ('json_nonnegative_number_scanner_boundary', 0x43a9308, 0x43a47e0),
    ('bool_key_first_bytes', 0x43aeb8e, 0x6fab16),
    ('bool_key_last_bytes', 0x43aeb97, 0x6fab19),
    ('float_key_first_bytes', 0x43aebfb, 0x6fab1d),
    ('float_key_last_bytes', 0x43aec11, 0x6fab27),
    ('config_cell', 0x474edee, 0x576e928),
    ('config_adapter', 0x474ee0c, 0x4774750),
    ('empty_descriptor', 0x474ee1b, 0x206450),
    ('name_descriptor', 0x474ee39, 0x572ed38),
    ('path_template', 0x474ee50, 0x1ee03e),
    ('format_path', 0x474ee6a, 0x576e040),
    ('regular_file_predicate', 0x474eea1, 0x576e9e8),
    ('extension_predicate', 0x474ef3a, 0x576f620),
    ('binary_encoder', 0x474ef86, 0x474ff60),
    ('json_bool', 0x474f04d, 0x4a99530),
    ('json_float', 0x474f082, 0x4a806e0),
    ('metadata', 0x474f185, 0x576e9f0),
    ('existing_parser_boundary', 0x474f1c8, 0x4721bb0),
    ('parent_step', 0x474f300, 0x576ea68),
    ('write_step', 0x474f325, 0x576f670),
    ('seed_rows', 0x474f48f, 0x474e220),
    ('insert_seed_row', 0x474e333, 0x4938330),
    ('failure_cleanup', 0x474f866, 0x4732600),
    ('named_header', 0x474ff94, 0x4ae9900),
    ('positional_header', 0x474ffc6, 0x4aea420),
    ('first_binary_key', 0x474fff1, 0x4aeb170),
    ('binary_bool_marker', 0x4750022, 0x4aed5a0),
    ('second_binary_key', 0x4750057, 0x4aeb170),
    ('binary_float', 0x475006e, 0x4aeafc0),
    ('json_bool_key', 0x4a9953a, 0x4ab04c0),
    ('json_float_key', 0x4a806f1, 0x4ab04c0),
)

# role, store instruction, displacement location, stack base of the final
# temporary. The checked memcpy later copies that temporary into the result.
OUTPUT_STORES = (
    ('path_capacity', 0x474f418, 4, 0x100),
    ('path_pointer', 0x474f420, 4, 0x100),
    ('path_length', 0x474f428, 4, 0x100),
    ('threshold_bits', 0x474f436, 5, 0x100),
    ('dry_run_byte', 0x474f43f, 4, 0x100),
    ('check_interval_bits', 0x474f451, 4, 0x100),
    ('error_word', 0x474f469, 4, 0x100),
    ('metadata_first_word', 0x474f475, 3, 0x100),
    ('metadata_other_words', 0x474f47c, 4, 0x100),
)

REQUIRED_RELOCS = {
    0x572ed38: (8, 0x6fb695), 0x576e040: (8, 0x1344760),
    0x576e928: (8, 0x577b288), 0x577b288: (8, 0x164ff00),
    0x576e9e8: (8, 0x144a710), 0x576e9f0: (8, 0x144c930),
    0x576ea68: (8, 0x144c180), 0x576f620: (8, 0x144a3e0),
    0x576f670: (8, 0x144c560),
}


def parse_relocations(view, wanted):
    names = ('.rela.dyn', '.dynsym', '.dynstr')
    if any(sum(s['name'] == name for s in view.sections) != 1 for name in names):
        raise ValueError('missing or duplicate relocation or symbol section')
    by_name = {s['name']: s for s in view.sections}
    rel, sym, strings = (by_name[n] for n in ('.rela.dyn', '.dynsym', '.dynstr'))
    if (rel['type'] != 4 or sym['type'] != 11 or strings['type'] == 8
            or rel['size'] % 24 or sym['size'] % 24):
        raise ValueError('invalid relocation or symbol section')
    out = {}
    for off in range(rel['offset'], rel['offset'] + rel['size'], 24):
        where, info, addend = struct.unpack_from('<QQq', view.data, off)
        if where not in wanted:
            continue
        if where in out:
            raise ValueError('duplicate selected relocation')
        typ, idx = info & 0xffffffff, info >> 32
        symbol = ''
        if idx:
            if idx * 24 + 24 > sym['size']:
                raise ValueError('symbol index out of bounds')
            noff = struct.unpack_from('<I', view.data, sym['offset'] + idx * 24)[0]
            if noff >= strings['size']:
                raise ValueError('symbol name out of bounds')
            pos = strings['offset'] + noff
            end = view.data.find(b'\0', pos, strings['offset'] + strings['size'])
            if end < 0:
                raise ValueError('unterminated symbol')
            symbol = view.data[pos:end].decode('ascii')
        out[where] = {'slot_va': hex(where), 'record_file_offset': hex(off),
                      'type': typ, 'symbol_index': idx, 'symbol': symbol,
                      'addend': hex(addend), 'record_bytes': view.data[off:off + 24].hex()}
    for address, (typ, addend) in REQUIRED_RELOCS.items():
        r = out.get(address)
        if r is None or r['type'] != typ or int(r['addend'], 16) != addend or r['symbol_index'] != 0:
            raise ValueError('required relocation changed: ' + hex(address))
    return out


def parse_template(raw):
    """Parse only literal-length and default-argument tokens in this template."""
    pos, result, arg = 0, [], 0
    while pos < len(raw):
        tag = raw[pos]
        pos += 1
        if tag == 0:
            if pos != len(raw):
                raise ValueError('trailing template bytes')
            return result
        if tag == 0xc0:
            result.append({'kind': 'argument', 'index': arg})
            arg += 1
        elif 1 <= tag <= 0x7f:
            if pos + tag > len(raw):
                raise ValueError('truncated template literal')
            result.append({'kind': 'literal', 'size': tag, 'hex': raw[pos:pos + tag].hex()})
            pos += tag
        else:
            raise ValueError('unsupported template token')
    raise ValueError('unterminated template')


def immediate(view, address, prefix, size):
    raw = bytes(view.read(address, len(prefix) + size))
    require_bytes(raw[:len(prefix)], prefix, 'immediate opcode')
    return int.from_bytes(raw[len(prefix):], 'little')

def table(path, rows, names):
    with path.open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=names, delimiter='\t', lineterminator='\n', extrasaction='raise')
        writer.writeheader()
        writer.writerows(rows)


def collect(data):
    verify_identity(data)
    view = View(data)
    _, raw_fdes = eh_frame_records(data, view.sections)
    by_start = {}
    for fde in raw_fdes:
        by_start.setdefault(fde['start'], []).append(fde)
    funcs, decoded, lsda_headers, lsda_sites = [], {}, [], []
    for role, start, expected_end, expected_sha in FUNCTIONS:
        candidates = by_start.get(start, [])
        if len(candidates) != 1:
            raise ValueError('missing or duplicate selected FDE')
        fde = candidates[0]
        if fde['end'] != expected_end:
            raise ValueError('FDE end changed: ' + role)
        body = bytes(view.read(start, fde['end'] - start))
        digest = hashlib.sha256(body).hexdigest()
        if digest != expected_sha:
            raise ValueError('selected body digest changed: ' + role)
        rows = decode_body(body, start)
        decoded[role] = rows
        funcs.append({'role': role, 'start_va': hex(start), 'end_va': hex(fde['end']),
                      'file_offset': hex(view.offset(start, len(body))), 'size': len(body),
                      'fde_va': hex(fde['fde']), 'cie_va': hex(fde['cie']),
                      'lsda_va': hex(fde['lsda']) if fde['lsda'] is not None else '',
                      'instructions': len(rows), 'sha256': digest})
        if fde['lsda'] is not None:
            head, sites = parse_lsda(view, start, fde['end'], fde['lsda'])
            lsda_headers.append(head)
            lsda_sites.extend(sites)

    contracts = [contract(view, label, va, expected) for label, va, expected in CONTRACTS]
    instructions = []
    transfers = []
    site_lookup = {}
    for role, _, _, _ in FUNCTIONS:
        for row in decoded[role]:
            if row['va'] in site_lookup:
                raise ValueError('selected instruction overlap')
            site_lookup[row['va']] = row
            entry = {'function': role, 'va': hex(row['va']),
                     'file_offset': hex(view.offset(row['va'], row['end'] - row['va'])),
                     'end_va': hex(row['end']), 'bytes': row['bytes'].hex(),
                     'kind': row['kind'],
                     'target_or_slot': hex(row['target']) if row['target'] is not None else '',
                     'rip_relative': int(row['rip_relative'])}
            instructions.append(entry)
            if row['kind'] != 'instruction':
                transfers.append(entry)

    wanted = set(REQUIRED_RELOCS)
    for row in site_lookup.values():
        if row['kind'] in ('indirect_call', 'indirect_jump') and row['rip_relative']:
            wanted.add(row['target'])
    relocs = parse_relocations(view, wanted)
    edges = []
    for label, va, expected_target in EDGES:
        row = site_lookup.get(va)
        if row is None or row['target'] != expected_target:
            raise ValueError('selected edge changed: ' + label)
        r = relocs.get(expected_target)
        edges.append({'role': label, 'site_va': hex(va),
                      'site_file_offset': hex(view.offset(va, row['end'] - va)),
                      'bytes': row['bytes'].hex(), 'kind': row['kind'],
                      'encoded_target_or_slot': hex(expected_target),
                      'relocation_type': r['type'] if r else '',
                      'relative_addend': r['addend'] if r and r['type'] == 8 else '',
                      'symbol': r['symbol'] if r else ''})

    # One call instruction in the previously documented parser is boundary
    # context only: its caller is not added to the selected FDEs.
    boundary_va = 0x4721f97
    boundary = decode_one(view.read(boundary_va, 5), 0, boundary_va)
    if boundary['kind'] != 'call' or boundary['target'] != 0x43a33b0:
        raise ValueError('existing-parser boundary call changed')
    edges.append({'role': 'prior_parser_json_boundary', 'site_va': hex(boundary_va),
                  'site_file_offset': hex(view.offset(boundary_va, 5)), 'bytes': boundary['bytes'].hex(),
                  'kind': boundary['kind'], 'encoded_target_or_slot': hex(boundary['target']),
                  'relocation_type': '', 'relative_addend': '', 'symbol': ''})

    decisions = []
    for va, role, taken, fallthrough in BRANCHES:
        row = site_lookup.get(va)
        if row is None or row['kind'] != 'conditional' or row['target'] is None:
            raise ValueError('selected conditional changed: ' + role)
        decisions.append({'role': role, 'site_va': hex(va), 'bytes': row['bytes'].hex(),
                          'taken_va': hex(row['target']), 'taken': taken,
                          'fallthrough_va': hex(row['end']), 'fallthrough': fallthrough})

    stores = []
    for label, va, index, temporary_base in OUTPUT_STORES:
        row = site_lookup.get(va)
        if row is None or index + 4 > len(row['bytes']):
            raise ValueError('invalid output-store instruction')
        displacement = struct.unpack_from('<I', row['bytes'], index)[0]
        if displacement < temporary_base:
            raise ValueError('output-store displacement below temporary')
        stores.append({'role': label, 'site_va': hex(va), 'bytes': row['bytes'].hex(),
                       'stack_displacement': hex(displacement),
                       'result_offset': hex(displacement - temporary_base)})

    # Stack offsets are read from the locked instructions, relative to the
    # selected 104-byte row passed to the insert helper at stack +0x28.
    seed_stores = []
    for label, va, index, basis in (
        ('zero_header', 0x474e2e0, 4, 0),
        ('duration_word', 0x474e2f3, 4, 0),
        ('zero_dword_after_duration', 0x474e2f8, 3, 0),
        ('zero_dword_38', 0x474e300, 3, 0),
        ('zero_word_50', 0x474e2d7, 4, 0),
        ('zero_sixteen', 0x474e2b3, 3, 0x80),
    ):
        row = site_lookup.get(va)
        if row is None or index >= len(row['bytes']):
            raise ValueError('invalid seed-row store')
        raw_disp = row['bytes'][index]
        displacement = raw_disp - 256 if basis and raw_disp >= 128 else raw_disp
        relative = basis + displacement - 0x28
        if relative < 0 or relative >= 0x68:
            raise ValueError('seed-row store outside input record')
        seed_stores.append({'role': label, 'site_va': hex(va), 'bytes': row['bytes'].hex(),
                            'row_offset': hex(relative)})
    map_layout = {
        'key_bytes': immediate(view, 0x49383b0, b'\xba', 4),
        'value_stride': immediate(view, 0x49385bb, bytes.fromhex('486bc9'), 1),
        'new_root_allocation': immediate(view, 0x4938555, b'\xbf', 4),
        'new_root_capacity_limit': immediate(view, 0x493858b, bytes.fromhex('4883f9'), 1),
        'tracker_map_offset': immediate(view, 0x474e268, bytes.fromhex('4881c3'), 4),
        'final_copy_bytes': immediate(view, 0x474f49c, b'\xba', 4),
    }
    if map_layout != {'key_bytes': 20, 'value_stride': 104, 'new_root_allocation': 1376,
                      'new_root_capacity_limit': 11, 'tracker_map_offset': 288, 'final_copy_bytes': 352}:
        raise ValueError('seed-map layout changed')

    raw_template = bytes.fromhex('c0c0172f66696c655f6d6f645f74696d655f747261636b65722fc0052e6a736f6e00')
    require_bytes(view.read(0x1ee03e, len(raw_template)), raw_template, 'path template')
    tokens = parse_template(raw_template)
    if [t['kind'] for t in tokens] != ['argument', 'argument', 'literal', 'argument', 'literal']:
        raise ValueError('unexpected template structure')
    empty = struct.unpack('<QQ', view.read(0x206450, 16))
    descriptor = struct.unpack('<QQ', view.read(0x572ed38, 16))
    if empty != (1, 0) or descriptor != (0, 24):
        raise ValueError('path descriptor changed')
    strings = []
    for label, address, expected in (
        ('config_name', 0x6fb695, b'heartbeat_jailing_config'),
        ('bool_key', 0x6fab16, b'dry_run'),
        ('float_key', 0x6fab1d, b'latency_ema_jail_threshold'),
        ('duplicate_bool_key', 0x6f1b63, b'dry_run'),
        ('duplicate_float_key', 0x6f1b6a, b'latency_ema_jail_threshold'),
        ('metric_name', 0x6fb86e, b'validator_latency_ema'),
        ('indent', 0x6fa591, b'  '),
        ('initial_error', 0x1ecb5e, b'could not load file, using default value. Error: '),
        ('time_error', 0x21a01f, b'`NaiveDateTime + TimeDelta` overflowed'),
        ('map_capacity_error', 0x20ca60, b'assertion failed: idx < CAPACITY'),
        ('unwrap_error', 0x6fb102, b'called `Result::unwrap()` on an `Err` value'),
    ):
        actual = bytes(view.read(address, len(expected)))
        require_bytes(actual, expected, label)
        strings.append({'role': label, 'va': hex(address),
                        'file_offset': hex(view.offset(address, len(actual))),
                        'length': len(actual), 'bytes': actual.hex(), 'ascii': actual.decode('ascii')})
    path = {'template_va': hex(0x1ee03e), 'template_file_offset': hex(view.offset(0x1ee03e, len(raw_template))),
            'template_bytes': raw_template.hex(), 'tokens': tokens,
            'arguments': [
                {'position': 0, 'origin': 'configuration_cell_plus_0x18', 'adapter_va': hex(0x4774750)},
                {'position': 1, 'descriptor_va': hex(0x206450), 'raw_pointer': hex(empty[0]), 'length': empty[1]},
                {'position': 2, 'descriptor_va': hex(0x572ed38), 'raw_pointer': hex(descriptor[0]),
                 'length': descriptor[1], 'relative_addend': relocs[0x572ed38]['addend']},
            ],
            'rendering_is_inference': True}
    fixed_suffix = (bytes.fromhex(tokens[2]['hex']) + bytes(view.read(0x6fb695, descriptor[1]))
                    + bytes.fromhex(tokens[4]['hex']))
    path['fixed_suffix_hex'] = fixed_suffix.hex()
    path['fixed_suffix_length'] = len(fixed_suffix)

    # Compare the complete key coverage through the exact scalar/SIMD memory
    # operand forms, rather than deriving offsets from disassembler text.
    key_specs = (
        ('bool', 0x6fab16, 0x43aeb81, '4883f8',
         ((0x43aeb8b, '8b45', 4, 0x43aeb8e), (0x43aeb94, '8b4d', 4, 0x43aeb97))),
        ('float', 0x6fab1d, 0x43aeb7b, '4883f8',
         ((0x43aec03, 'f30f6f4d', 16, 0x43aebfb), (0x43aec0c, 'f30f6f45', 16, 0x43aec11))),
    )
    key_windows, key_layout = [], {}
    for role, base, length_site, length_prefix, windows in key_specs:
        length = immediate(view, length_site, bytes.fromhex(length_prefix), 1)
        full = bytes(view.read(base, length))
        covered = set()
        for index, (site, prefix, width, target_site) in enumerate(windows):
            offset = immediate(view, site, bytes.fromhex(prefix), 1)
            if offset >= 0x80 or offset + width > length:
                raise ValueError('key-comparison operand outside key')
            target = site_lookup[target_site]['target']
            if target != base + offset:
                raise ValueError('key-comparison constant differs from input offset')
            window = bytes(view.read(target, width))
            require_bytes(window, full[offset:offset + width], 'key-comparison bytes')
            covered.update(range(offset, offset + width))
            key_windows.append({'key': role, 'index': index, 'input_site_va': hex(site),
                                'input_offset': offset, 'length': width,
                                'constant_site_va': hex(target_site), 'constant_va': hex(target),
                                'constant_file_offset': hex(view.offset(target, width)), 'bytes': window.hex()})
        if covered != set(range(length)):
            raise ValueError('key-comparison windows do not cover the complete key')
        key_layout[role] = {'key_length': length, 'covered_bytes': len(covered),
                            'overlap_bytes': sum(x[2] for x in windows) - len(covered)}

    initial = view.read(0x474eed1, 10)
    interval = view.read(0x474f447, 10)
    row_default = view.read(0x474e2e9, 10)
    magnitude = view.read(0x4a8073b, 10)
    infinity = view.read(0x4a80748, 10)
    for label, raw in (('initial', initial), ('interval', interval), ('row_default', row_default),
                       ('magnitude_mask', magnitude), ('infinity', infinity)):
        require_bytes(raw[:2], b'\x48\xb8' if label in ('initial', 'interval', 'row_default', 'infinity') else b'\x48\xb9', label)
    initial_bits = int.from_bytes(initial[2:], 'little')
    if int.from_bytes(view.read(0x20a308, 8), 'little') != initial_bits:
        raise ValueError('fallback threshold differs from initial threshold')
    flag = view.read(0x474eee3, 8)
    require_bytes(flag[:7], bytes.fromhex('c6842490000000'), 'initial flag store')
    marker = view.read(0x4aeafe9, 4)
    require_bytes(marker[:3], bytes.fromhex('c60430'), 'binary float marker')
    bool_mask = view.read(0x4a9957c, 4)
    require_bytes(bool_mask[:3], bytes.fromhex('40f6c5'), 'boolean bit test')
    binary_bool = view.read(0x475001a, 4)
    require_bytes(binary_bool[:3], bytes.fromhex('4180cf'), 'binary boolean marker')
    true_write = view.read(0x4a99596, 7)
    false_write = view.read(0x4a995bc, 7)
    false_tail = view.read(0x4a995b7, 5)
    require_bytes(true_write[:3], bytes.fromhex('c70430'), 'true write')
    require_bytes(false_write[:3], bytes.fromhex('c70430'), 'false write')
    require_bytes(false_tail[:4], bytes.fromhex('c6443004'), 'false tail')
    constants = {'threshold_bits': hex(initial_bits), 'threshold_bytes_le': initial[2:].hex(),
                 'threshold_site': hex(0x474eed1), 'fallback_float_va': hex(0x20a308),
                 'dry_run_default': flag[7], 'interval_bits': hex(int.from_bytes(interval[2:], 'little')),
                 'seed_row_float_bits': hex(int.from_bytes(row_default[2:], 'little')),
                 'binary_float_marker': hex(marker[3]), 'binary_bool_base': hex(binary_bool[3]),
                 'json_true_hex': true_write[3:].hex(), 'json_false_hex': (false_write[3:] + false_tail[4:]).hex(),
                 'json_bool_mask': hex(bool_mask[3]),
                 'json_magnitude_mask': hex(int.from_bytes(magnitude[2:], 'little')),
                 'json_infinity_bits': hex(int.from_bytes(infinity[2:], 'little'))}

    whitespace_mask = immediate(view, 0x43ae9f2, bytes.fromhex('49bc'), 8)
    for at, prefix in ((0x43a341c, '48be'), (0x43aa8f5, '49b8'), (0x43a9271, '48bf')):
        if immediate(view, at, bytes.fromhex(prefix), 8) != whitespace_mask:
            raise ValueError('JSON whitespace masks disagree')
    true_word = bytes(immediate(view, at, bytes.fromhex(prefix), 1) for at, prefix in (
        (0x43aa94d, '4183f9'), (0x43aa97b, '4080ff'),
        (0x43aa99b, '4180f8'), (0x43aa9bd, '80f9')))
    false_word = bytes(immediate(view, at, bytes.fromhex(prefix), 1) for at, prefix in (
        (0x43aa947, '4183f9'), (0x43aa9e7, '4080ff'), (0x43aa9ff, '4180f8'),
        (0x43aaa18, '4180f8'), (0x43aaa30, '80f9')))
    json_default_bits = immediate(view, 0x43aee8a, bytes.fromhex('48bd'), 8)
    json_default_bool = immediate(view, 0x43aee7b, bytes.fromhex('41bf'), 4)
    if (true_word, false_word, json_default_bits, json_default_bool) != (b'true', b'false', initial_bits, 1):
        raise ValueError('JSON literal or missing-field default changed')
    constants.update({'json_whitespace_mask': hex(whitespace_mask),
                      'json_bool_true_word': true_word.hex(), 'json_bool_false_word': false_word.hex(),
                      'json_missing_bool': json_default_bool, 'json_missing_float_bits': hex(json_default_bits),
                      'json_trailing_error_code': immediate(view, 0x43a3476, bytes.fromhex('48c7442458'), 4)})
    whitespace_upper = immediate(view, 0x43a3435, bytes.fromhex('4883ff'), 1)
    constants['json_whitespace_upper_byte'] = whitespace_upper
    whitespace = [{'byte': byte, 'hex': f'{byte:02x}'} for byte in range(whitespace_upper + 1)
                  if whitespace_mask >> byte & 1]

    checks = (
        ('json_document_to_object', 'json_document', 0x43a33b0, 0x43a33f7, True),
        ('json_object_to_bool', 'json_config_parser', 0x43ae9c0, 0x43aed33, True),
        ('json_object_to_number', 'json_config_parser', 0x43ae9c0, 0x43aed6d, True),
        ('json_duplicate_to_bool_parser', 'json_config_parser', 0x43af11c, 0x43aed33, False),
        ('json_trailing_error_to_return', 'json_document', 0x43a3476, 0x43a3475, True),
        ('entry_to_file_test', 'tracker_constructor', 0x474ece0, 0x474eea1, True),
        ('existing_to_metadata', 'tracker_constructor', 0x474eeab, 0x474f185, True),
        ('existing_to_parse', 'tracker_constructor', 0x474f1a9, 0x474f1c8, True),
        ('default_to_binary', 'tracker_constructor', 0x474eed1, 0x474ef86, True),
        ('default_to_json', 'tracker_constructor', 0x474eed1, 0x474f04d, True),
        ('binary_to_file_step', 'tracker_constructor', 0x474ef86, 0x474f300, True),
        ('json_to_file_step', 'tracker_constructor', 0x474f082, 0x474f300, True),
        ('fallback_to_seed_rows', 'tracker_constructor', 0x474f221, 0x474f48f, True),
        ('binary_error_to_write', 'tracker_constructor', 0x474f69c, 0x474f325, False),
        ('special_to_defaults', 'tracker_constructor', 0x474f2b2, 0x474f34a, True),
        ('first_failure_to_diagnostic', 'tracker_constructor', 0x474f658, 0x474f737, True),
        ('second_failure_to_diagnostic', 'tracker_constructor', 0x474f737, 0x474f761, True),
        ('write_success_to_seed_rows', 'tracker_constructor', 0x474f34a, 0x474f48f, True),
        ('metadata_error_to_fallback', 'tracker_constructor', 0x474f195, 0x474f221, True),
        ('parse_error_to_fallback', 'tracker_constructor', 0x474f1e1, 0x474f221, True),
        ('input_to_map_insert', 'seed_rows', 0x474e220, 0x474e333, True),
        ('binary_to_float', 'binary_config_encoder', 0x474ff60, 0x475006e, True),
        ('float_to_marker', 'binary_float_writer', 0x4aeafc0, 0x4aeafe9, True),
    )
    cfg = []
    for label, role, a, z, expected in checks:
        actual = reachable(decoded[role], a, z)
        if actual != expected:
            raise ValueError('selected CFG check changed: ' + label)
        cfg.append({'role': label, 'function': role, 'start_va': hex(a), 'end_va': hex(z),
                    'reachable_overapprox': int(actual)})

    summary = {'target': 'node94', 'sha256': DIGEST, 'target_size': len(data),
               'functions': len(funcs), 'selected_bytes': sum(f['size'] for f in funcs),
               'instructions': len(instructions), 'transfers': len(transfers),
               'conditional_transfers': sum(1 for row in transfers if row['kind'] == 'conditional'),
               'local_branch_decisions': len(decisions), 'selected_edges': len(edges),
               'contracts': len(contracts), 'lsda_tables': len(lsda_headers), 'lsda_sites': len(lsda_sites),
               'json_whitespace_bytes': len(whitespace),
               'cfg_queries': len(cfg),
               'limitations': 'Static fixed-byte analysis; calls may not return, unwind action meanings are not decoded, and no runtime or component gate is claimed.'}
    return {'functions': funcs, 'instructions': instructions, 'transfers': transfers, 'contracts': contracts,
            'branches': decisions, 'edges': edges, 'stores': stores, 'relocations': [relocs[k] for k in sorted(relocs)],
            'lsda_headers': lsda_headers, 'lsda_sites': lsda_sites, 'strings': strings, 'path': path,
            'constants': constants, 'map_layout': map_layout, 'seed_stores': seed_stores,
            'key_windows': key_windows, 'key_layout': key_layout,
            'whitespace': whitespace,
            'cfg': cfg, 'summary': summary}


def generate(data, out):
    r = collect(data)
    out.mkdir(parents=True, exist_ok=True)
    def write_tsv(name, rows, cols):
        table(out / name, rows, cols.split())
    write_tsv('functions.tsv', r['functions'], 'role start_va end_va file_offset size fde_va cie_va lsda_va instructions sha256')
    cols = 'function va file_offset end_va bytes kind target_or_slot rip_relative'
    write_tsv('instructions.tsv', r['instructions'], cols)
    write_tsv('transfers.tsv', r['transfers'], cols)
    write_tsv('contracts.tsv', r['contracts'], 'label va file_offset size bytes')
    write_tsv('branches.tsv', r['branches'], 'role site_va bytes taken_va taken fallthrough_va fallthrough')
    write_tsv('edges.tsv', r['edges'], 'role site_va site_file_offset bytes kind encoded_target_or_slot relocation_type relative_addend symbol')
    write_tsv('output-stores.tsv', r['stores'], 'role site_va bytes stack_displacement result_offset')
    write_tsv('seed-stores.tsv', r['seed_stores'], 'role site_va bytes row_offset')
    write_tsv('relocations.tsv', r['relocations'], 'slot_va record_file_offset type symbol_index symbol addend record_bytes')
    write_tsv('lsda-headers.tsv', r['lsda_headers'], 'function lsda_va header_file_offset lpstart_encoding type_encoding callsite_encoding callsite_file_offset callsite_size entries')
    write_tsv('lsda-sites.tsv', r['lsda_sites'], 'function lsda_va entry_file_offset start_va end_va landing_va action_index')
    write_tsv('strings.tsv', r['strings'], 'role va file_offset length bytes ascii')
    write_tsv('json-whitespace.tsv', r['whitespace'], 'byte hex')
    write_tsv('key-windows.tsv', r['key_windows'], 'key index input_site_va input_offset length constant_site_va constant_va constant_file_offset bytes')
    write_tsv('cfg.tsv', r['cfg'], 'role function start_va end_va reachable_overapprox')
    for key in ('path', 'constants', 'map_layout', 'key_layout', 'summary'):
        (out / (key + '.json')).write_text(json.dumps(r[key], indent=2, sort_keys=True, ensure_ascii=True) + '\n', encoding='utf-8')
    return r['summary']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(generate(TARGET.read_bytes(), args.out), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, struct.error) as exc:
        print('config_heartbeat94: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
