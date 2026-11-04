#!/usr/bin/env python3
"""RE-005: digest-bound node115 reader-state limit writers trace.

Answers the next question of the open state-construction packet
(PR #2501): who writes the limit qwords in the top dispatchers'
context objects ([rbx+0x220], [rbx+0x180], [rbx+0xa60] and the
bulk-b dispatcher's rcx source), and what values they set.

The four top dispatchers of #2501 are the functions
0x2b67e50 (bulk a), 0x2b69d20 (twin a), 0x5a64aa0 (bulk b) and
0x5a6a640 (twin b). Each receives its object as the entry rsi
(saved to rbx, or to r13 in bulk b) and loads the reader limit
from one field of that object into the rcx argument of the
state constructor (bulk a / twin a) or of the view builder that
feeds the constructor (bulk b / twin b):

- bulk a: limit field +0x220, load at 0x2b68885, constructor
  0x26fe940 called at 0x2b688b4.
- twin a: limit field +0x180, load at 0x2b6aa24, constructor
  0x26ff210 called at 0x2b6aa53.
- bulk b: limit field +0xc40 of the r13 object, load at
  0x5a66d03, view builder 0x5860cd0 called at 0x5a66d32 (this
  resolves #2501's bulk-b boundary: the top caller's rcx is
  that field).
- twin b: limit field +0xa60, load at 0x5a6b881, view builder
  0x58606f0 called at 0x5a6b8b5.

Every direct access to each limit field inside its dispatcher
is pinned below (cross-checked with two independent
disassemblies). Each dispatcher writes its limit field in
exactly two (bulk) or three (twin) arms, in stage order:

- bulk arms: (1) an immediate 0 store while building a fresh
  five-qword record at the field and calling the record helper
  on it with its tag byte set to 0; (2) the final store, of a
  value selected by one object byte (selector at +0x1e8 /
  +0xc08): 1000 when the byte is 0, 4000000000 (0xee6b2800)
  when it is nonzero; the selected value is also stored to
  two sibling slots.
- twin arms: (1) a store of the record base pointer
  (lea obj+0x140 / obj+0xa20); the field is read later in the
  same stage and propagated to a sibling slot (+0x268 /
  +0xb48); (2) a 16-byte copy of the sibling pair at
  +0x158/+0x160 (twin a) or +0xa38/+0xa40 (twin b) into the
  field and the following qword, while building a fresh
  record beside it and calling the record helper; (3) the
  final store, of r13/r15, which is either copied from the
  sibling slot (+0x178 / +0xa58) on one entry or computed on
  the other entry from a source object pointed to by the
  dispatcher object (+0x78 / +0x958): tag 2 gives 120, tag 1
  gives 10000, otherwise the saturating value
  min((end-start+1)*10000000, 1000000000) over the source's
  +0x8/+0x10 pair (borrow or multiplication overflow also
  saturate to 1000000000); a flag byte records
  value >= 100000000 and is passed to the constructor. The
  value is also stored to two sibling slots.

Last-writer analysis: in each dispatcher's direct control
flow, the only instructions that can reach the limit load
without passing a limit store are the tail instructions
beginning immediately after the final store (the parse helper
call 0x2b788e0 / 0x5ab4390 and the result tag checks); the
dispatcher entry is not among them. The only jump-table
targets inside (final store, load] land inside the final
stage's own block, downstream of the store (pinned table
slots in records.json); bulk b has none. So when the final
stage is entered at or before its store, the loaded limit is
that store's value; when it is entered downstream of the
store, the field keeps its incoming value, whose writer is
an earlier arm above or the object's incoming state (a
stated boundary).

The copy-b record helper 0x5ab6ce0 (267 bytes, exported in
full) stores only at +0x28..+0x48 and +0x308..+0x310 of its
record argument -- never at +0x0 -- so the bulk-b first arm's
immediate 0 at the limit field survives that helper call.
The copy-a record helper 0x2b7a290 is recorded by pins only;
its effect on its record's first qword is a stated boundary.

Caller census: the dispatchers have no rip-relative lea
references; their direct callers are two (bulk a), two
(twin a), one (bulk b) and two (twin b) sites, recorded in
records.json.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
from artifacts import ROOT
from elf_index import sections
from fde_extents import fde_extents
from foundation_millis import decode_export

TARGET = ROOT / 'artifacts/node/115/hl-node'
PACKET = ROOT / 'research/work-items/RE-005-node115-limit-writers'
SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
OWNERS = {
 'top_bulk_a': (0x2b67e50, 0x2b69279,
            '3584f0ac010d68cbcb1583dc2d6761695f0f22a45d44fe659a2b3403ef1ac9b8'),
 'top_twin_a': (0x2b69d20, 0x2b6ae9f,
            '5b854640e07f22fdce4262d719e531d12d68014e9518b7f848b2dcb4c13069ba'),
 'top_bulk_b': (0x5a64aa0, 0x5a69c05,
            '7ef4223a0df3ad1e2489d38b717dfc79df37e94c6f92b32d5c651445fb257d6c'),
 'top_twin_b': (0x5a6a640, 0x5a6bfaa,
            '24b644822cfac0aad7bea4dfb9f819f70101780c0e9bd563122908f6e13d894a'),
 'record_helper_b': (0x5ab6ce0, 0x5ab6deb,
            '08357015a1b05bbfc9165468f78eef893001cc4d76ee61463c1e474cc69d779b')}
FRAMES = {
 'top_bulk_a': {'fde': {'va': '0x11856e4', 'bytes_hex': '50000000e480140064279e0129140000043f390eff410e10420e18420e20420e28420e30410e38470ec00883078c068d058e048f03860203b30d0e38410e30420e28420e20420e18420e10410e08410ec0080000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
 'top_twin_a': {'fde': {'va': '0x1185820', 'bytes_hex': '5000000020821400f8449e017f11000004373a0eff410e10420e18420e20420e28420e30410e38470e900783078c068d058e048f038602038e0e0e38410e30420e28420e20420e18420e10410e08410e90070000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
 'top_bulk_b': {'fde': {'va': '0x13a9d84', 'bytes_hex': '5400000084c7360014ad6b0465510000048fed03ff410e10420e18420e20420e28420e30410e38470eb8204f0e803f83078c068d058e048f038602035f4a0e38410e30420e28420e20420e18420e10410e08410e803f0000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
 'top_twin_b': {'fde': {'va': '0x13a9e84', 'bytes_hex': '5400000084c83600b4076c046a19000004cbf103ff410e10420e18420e20420e28420e30410e38470eb8204f0ea02a83078c068d058e048f038602032a160e38410e30420e28420e20420e18420e10410e08410ea02a0000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}},
 'record_helper_b': {'fde': {'va': '0x13ae5f8', 'bytes_hex': '3c000000f80f3700e08670040b01000004170704ff420e10420e18420e20410e28410e3083058c048e038f0202af0e28410e20420e18420e10420e08410e3000'}, 'cie': {'va': '0x103d604', 'bytes_hex': '1c00000000000000017a504c5200017810079b11244b051b1b0c070890010000'}}}
EXPORTED = ('record_helper_b',)
PIN_STARTS = {'record_helper_b': [0x5ab6ce0, 0x5ab6d02,
                                  0x5ab6d8d, 0x5ab6d9f]}
# Jump-table slots whose targets land inside (final store,
# load] of a dispatcher, downstream of the store.
TAIL_SLOTS = [(0x604ac4, 10, 0x2b68776), (0x604ae0, 3, 0x2b68792),
              (0x604b48, 9, 0x2b6a90d), (0x604b60, 3, 0x2b6a925),
              (0x939690, 17, 0x5a6b73f), (0x9396b0, 9, 0x5a6b75f),
              (0x9396a0, 13, 0x5a6b74f), (0x9396c8, 3, 0x5a6b777)]
CALL_TARGETS = {
 'top_bulk_a': {0x2b6846e: 0x27013e0, 0x2b684b5: 0x2b7a290,
                0x2b687a7: 0x2b788e0, 0x2b688b4: 0x26fe940,
                0x2b68b9d: 0x2abc7e0, 0x2b69009: 0x2abc7e0},
 'top_twin_a': {0x2b6a65f: 0x2701770, 0x2b6a6a6: 0x2b7a290,
                0x2b6a93a: 0x2b788e0, 0x2b6aa53: 0x26ff210},
 'top_bulk_b': {0x5a668d8: 0x5860f30, 0x5a66926: 0x5ab6ce0,
                0x5a66c2e: 0x5ab4390, 0x5a66d32: 0x5860cd0,
                0x5a6703b: 0x5a52490, 0x5a68983: 0x5a52490},
 'top_twin_b': {0x5a6b4b8: 0x5861830, 0x5a6b4ff: 0x5ab6ce0,
                0x5a6b78c: 0x5ab4390, 0x5a6b8b5: 0x58606f0},
 'record_helper_b': {0x5ab6d5e: 0x5ab5be0, 0x5ab6d81: 0x5a59590}}
PINS = {
 'top_bulk_a': [
     (20, '4889f3', 'object register rbx is the entry rsi'),
     (1566, 'e86d8fb9ff', 'sibling-record call at the first bulk_a arm'),
     (1571, '0f108310020000', 'movups load of the sibling pair at +0x210'),
     (1578, '48c7832002000000000000', 'first bulk_a limit store: immediate 0 at +0x220'),
     (1589, '48b80000000000004e40', 'movabs of the 60.0 bit pattern'),
     (1599, '48898328020000', 'store of the 60.0 bit pattern at +0x228'),
     (1606, '4c89ab30020000', 'saved-register store at +0x230'),
     (1613, '0f118338020000', 'movups store of the sibling pair at +0x238'),
     (1620, 'c6833005000000', 'record tag byte at +0x530 is set to 0'),
     (1627, '488dbb20020000', 'lea of the limit field +0x220 for the record helper'),
     (1637, 'e8d61d0100', 'record helper call in the first bulk_a arm'),
     (2193, '0fb6b3e8010000', 'selector byte load from +0x1e8'),
     (2200, '0fb68beb010000', 'second byte load from +0x1eb'),
     (2207, '4084f6', 'selector byte test'),
     (2210, 'bf00286bee', 'large candidate constant 0xee6b2800'),
     (2215, 'bae8030000', 'small candidate constant 0x3e8'),
     (2220, '480f45d7', 'conditional move selecting the bulk limit'),
     (2231, '4889bb08020000', 'string pointer store at +0x1f8'),
     (2238, '48c7831002000019000000', 'string length store at +0x200'),
     (2249, '48899318020000', 'selected value also stored at +0x218'),
     (2301, '48899320020000', 'final bulk_a limit store at +0x220'),
     (2356, '48899348020000', 'selected value also stored at +0x248'),
     (2391, 'e834010100', 'parse helper call after the final bulk_a store'),
     (2613, '488b8b20020000', 'bulk_a limit load for the constructor'),
     (2660, 'e88760b9ff', 'bulk_a constructor call'),
     (3398, '488dbb20020000', 'exit-path lea of the limit field +0x220'),
     (3405, 'e83e3cf5ff', 'exit-path call taking the limit field address'),
     (4530, '488dbb20020000', 'second exit-path lea of the limit field +0x220'),
     (4537, 'e8d237f5ff', 'second exit-path call taking the limit field address')],
 'top_twin_a': [
     (20, '4889f3', 'object register rbx is the entry rsi'),
     (273, '488d8b40010000', 'lea of the record base +0x140 into rcx'),
     (301, '48c783580100000b000000', 'sibling slot +0x158 is set to 0xb'),
     (312, '48b80000000000000040', 'movabs of the 2.0 bit pattern'),
     (322, '48898360010000', 'store of the 2.0 bit pattern at +0x160'),
     (329, '48898b80010000', 'first twin_a limit store at +0x180: the record base pointer'),
     (485, '4c8bab78010000', 'copy-entry load of the sibling slot +0x178 into r13'),
     (513, 'e9ba090000', 'copy-entry jump to the final twin_a limit store'),
     (557, '488b8b80010000', 'twin_a limit read at +0x180 in the first stage'),
     (575, '48898b68020000', 'read value propagated to +0x268'),
     (2367, 'e80c71b9ff', 'sibling-record call at the second twin_a arm'),
     (2372, '0f108358010000', 'movups load of the sibling pair at +0x158'),
     (2379, '48c7836801000000000000', 'record slot +0x168 is set to 0'),
     (2400, '48898370010000', 'store of the 60.0 bit pattern at +0x170'),
     (2407, '4889ab78010000', 'saved-register store at +0x178'),
     (2414, '0f118380010000', 'second twin_a limit store: movups of the sibling pair at +0x180'),
     (2421, 'c6837804000000', 'record tag byte at +0x478 is set to 0'),
     (2428, '488dbb68010000', 'lea of the record at +0x168 for the record helper'),
     (2438, 'e8e5fb0000', 'record helper call in the second twin_a arm'),
     (2738, '488b4378', 'computation source pointer load from +0x78'),
     (2742, '488b08', 'computation tag load from the source object'),
     (2745, '4883f902', 'computation tag compare with 2'),
     (2751, '41bd10270000', 'case constant 10000'),
     (2757, '83f901', 'computation tag compare with 1'),
     (2762, '488b4810', 'computation end load from source +0x10'),
     (2766, '41bd00ca9a3b', 'saturation constant 1000000000'),
     (2772, '482b4808', 'computation difference (end - start)'),
     (2778, '48ffc1', 'computation difference increment'),
     (2788, '480f45c1', 'zero guard conditional move'),
     (2792, 'b980969800', 'scale constant 10000000'),
     (2797, '48f7e1', 'scale multiplication'),
     (2806, '4981fd00ca9a3b', 'saturation compare with 1000000000'),
     (2818, '4c0f43e9', 'saturation clamp on above-or-equal'),
     (2824, '4c0f45e9', 'saturation clamp on multiplication overflow'),
     (2830, '41bd78000000', 'case constant 120'),
     (2906, '4981fd00e1f505', 'flag threshold compare with 100000000'),
     (2970, '4c89ab78010000', 'computed value also stored at +0x178'),
     (3008, '4c89ab80010000', 'final twin_a limit store at +0x180'),
     (3063, '4c89aba8010000', 'computed value also stored at +0x1a8'),
     (3098, 'e8a1df0000', 'parse helper call after the final twin_a store'),
     (3332, '488b8b80010000', 'twin_a limit load for the constructor'),
     (3379, 'e8b847b9ff', 'twin_a constructor call')],
 'top_bulk_b': [
     (37, '4989f5', 'object register r13 is the entry rsi'),
     (7736, 'e853a6dfff', 'sibling-record call at the first bulk_b arm'),
     (7741, 'f3410f6f85300c0000', 'movdqu load of the sibling pair at +0xc30'),
     (7750, '49c785400c000000000000', 'first bulk_b limit store: immediate 0 at +0xc40'),
     (7761, '48b80000000000004e40', 'movabs of the 60.0 bit pattern'),
     (7771, '498985480c0000', 'store of the 60.0 bit pattern at +0xc48'),
     (7778, '4989ad500c0000', 'saved-register store at +0xc50'),
     (7785, 'f3410f7f85580c0000', 'movdqu store of the sibling pair at +0xc58'),
     (7794, '41c685500f000000', 'record tag byte at +0xf50 is set to 0'),
     (7802, '498dbd400c0000', 'lea of the limit field +0xc40 for the record helper'),
     (7814, 'e8b5030500', 'record helper call in the first bulk_b arm'),
     (8371, '410fb6b5080c0000', 'selector byte load from +0xc08'),
     (8379, '410fb68d0b0c0000', 'second byte load from +0xc0b'),
     (8387, '4084f6', 'selector byte test'),
     (8390, 'bf00286bee', 'large candidate constant 0xee6b2800'),
     (8395, 'bae8030000', 'small candidate constant 0x3e8'),
     (8400, '480f45d7', 'conditional move selecting the bulk limit'),
     (8429, '498995380c0000', 'selected value also stored at +0xc38'),
     (8493, '498995400c0000', 'final bulk_b limit store at +0xc40'),
     (8590, 'e85dd70400', 'parse helper call after the final bulk_b store'),
     (8803, '498b8d400c0000', 'bulk_b limit load for the view builder'),
     (8850, 'e8999fdfff', 'bulk_b view builder call'),
     (9620, '498dbd400c0000', 'exit-path lea of the limit field +0xc40'),
     (9627, 'e850b4feff', 'exit-path call taking the limit field address'),
     (16092, '498dbd400c0000', 'second exit-path lea of the limit field +0xc40'),
     (16099, 'e8089bfeff', 'second exit-path call taking the limit field address')],
 'top_twin_b': [
     (32, '4889f3', 'object register rbx is the entry rsi'),
     (1118, '488d8b200a0000', 'lea of the record base +0xa20 into rcx'),
     (1146, '48c783380a00000b000000', 'sibling slot +0xa38 is set to 0xb'),
     (1157, '48b80000000000000040', 'movabs of the 2.0 bit pattern'),
     (1167, '488983400a0000', 'store of the 2.0 bit pattern at +0xa40'),
     (1174, '48898b600a0000', 'first twin_b limit store at +0xa60: the record base pointer'),
     (1419, '4c8bbb580a0000', 'copy-entry load of the sibling slot +0xa58 into r15'),
     (1447, 'e9460b0000', 'copy-entry jump to the final twin_b limit store'),
     (1487, '488b8b600a0000', 'twin_b limit read at +0xa60 in the first stage'),
     (1505, '48898b480b0000', 'read value propagated to +0xb48'),
     (3704, 'e87363dfff', 'sibling-record call at the second twin_b arm'),
     (3709, '0f1083380a0000', 'movups load of the sibling pair at +0xa38'),
     (3716, '48c783480a000000000000', 'record slot +0xa48 is set to 0'),
     (3737, '488983500a0000', 'store of the 60.0 bit pattern at +0xa50'),
     (3744, '4c89a3580a0000', 'saved-register store at +0xa58'),
     (3751, '0f1183600a0000', 'second twin_b limit store: movups of the sibling pair at +0xa60'),
     (3758, 'c683580d000000', 'record tag byte at +0xd58 is set to 0'),
     (3765, '488dbb480a0000', 'lea of the record at +0xa48 for the record helper'),
     (3775, 'e8dcb70400', 'record helper call in the second twin_b arm'),
     (4064, '488b8358090000', 'computation source pointer load from +0x958'),
     (4071, '488b08', 'computation tag load from the source object'),
     (4074, '4883f902', 'computation tag compare with 2'),
     (4080, '41bf10270000', 'case constant 10000'),
     (4086, '83f901', 'computation tag compare with 1'),
     (4091, '488b4810', 'computation end load from source +0x10'),
     (4095, '41bf00ca9a3b', 'saturation constant 1000000000'),
     (4101, '482b4808', 'computation difference (end - start)'),
     (4107, '48ffc1', 'computation difference increment'),
     (4117, '480f45c1', 'zero guard conditional move'),
     (4121, 'b980969800', 'scale constant 10000000'),
     (4126, '48f7e1', 'scale multiplication'),
     (4135, '4981ff00ca9a3b', 'saturation compare with 1000000000'),
     (4147, '4c0f43f9', 'saturation clamp on above-or-equal'),
     (4153, '4c0f45f9', 'saturation clamp on multiplication overflow'),
     (4159, '41bf78000000', 'case constant 120'),
     (4238, '4981ff00e1f505', 'flag threshold compare with 100000000'),
     (4300, '4c89bb580a0000', 'computed value also stored at +0xa58'),
     (4338, '4c89bb600a0000', 'final twin_b limit store at +0xa60'),
     (4393, '4c89bb880a0000', 'computed value also stored at +0xa88'),
     (4428, 'e8ff8b0400', 'parse helper call after the final twin_b store'),
     (4673, '488b8b600a0000', 'twin_b limit load for the view builder'),
     (4725, 'e8364edfff', 'twin_b view builder call')],
 'record_helper_b': [
     (8, '4889fb', 'record helper object register rbx is the entry rdi'),
     (11, '0fb68710030000', 'record helper tag byte load from +0x310'),
     (88, '48894b28', 'record helper store at +0x28'),
     (92, 'f20f114330', 'record helper store at +0x30'),
     (97, '0f114b38', 'record helper store at +0x38'),
     (101, '48894348', 'record helper store at +0x48'),
     (105, '4088bb08030000', 'record helper store at +0x308'),
     (112, 'c6830903000000', 'record helper store at +0x309'),
     (126, 'e87deeffff', 'record helper inner call'),
     (161, 'e80a28faff', 'record helper cleanup call')]}
LIMITS = (
 'Static trace only: no pinned bytes were executed and no live '
 'node, network, signer, or exchange state was used. The '
 'access census for each limit field covers direct accesses '
 'through the dispatcher object register inside the dispatcher '
 'FDE, cross-checked with two independent disassemblies; '
 'stores through a differently-based alias of the same object '
 'inside the dispatcher, and writes by callees other than the '
 'recorded record-helper behaviour, are not excluded. The '
 'last-writer analysis covers direct branches and the pinned '
 'jump-table slots; other jump-table targets were enumerated '
 'in the analysis and none lands in (final store, load] '
 'except the pinned ones. Who first set the object fields the '
 'final values are derived from (the bulk selector bytes, the '
 'twin sibling slots and source-object fields, and the '
 'incoming limit value on a downstream stage entry) sits '
 'above the traced window and is a stated boundary, as is '
 'the copy-a record helper effect on its record first qword '
 'and the writer of the twin-a stage result +0x28 field left '
 'open by #2501. Raw values are recorded mechanically; which '
 'Rust types or enum variants they belong to is not '
 'established. No Rust reconstruction is included or claimed.')


def read(data, va, n):
    matches = [s for s in sections(data) if s['type'] != 8
               and s['address'] <= va and va + n <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError('expected one file-backed mapping')
    s = matches[0]
    o = s['offset'] + va - s['address']
    return o, bytes(data[o:o + n])


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pin(body, rel, expected, message):
    require(body[rel:rel + len(expected)] == expected,
            f'{message} changed')


def call_target(body, rel, base):
    return base + rel + 5 + struct.unpack_from('<i', body, rel + 1)[0]


def body_of(data, role):
    a, b, _ = OWNERS[role]
    return a, read(data, a, b - a)[1]


def run_pins(data, role):
    base, body = body_of(data, role)
    for rel, hexs, message in PINS[role]:
        pin(body, rel, bytes.fromhex(hexs), f'{role} {message}')
    for va, target in CALL_TARGETS[role].items():
        rel = va - base
        require(body[rel] == 0xe8, f'{role} call opcode changed '
                                   f'at {va:#x}')
        require(call_target(body, rel, base) == target,
                f'{role} call target changed at {va:#x}')
    return base, body


def bulk_semantics(data, role):
    run_pins(data, role)
    if role == 'top_bulk_a':
        return {
         'object': 'entry rsi saved to rbx',
         'limit_field': '+0x220',
         'limit_load': '0x2b68885',
         'downstream_call': '0x2b688b4',
         'downstream_target': '0x26fe940 (state constructor, #2501)',
         'selector_byte': '+0x1e8',
         'first_store': '0x2b6847a',
         'final_store': '0x2b6874d',
         'record_helper_call': '0x2b684b5 -> 0x2b7a290',
         'sibling_record_call': '0x2b6846e -> 0x27013e0 on +0x208',
         'parse_helper_call': '0x2b687a7 -> 0x2b788e0',
         'exit_path_calls': ['0x2b68b9d -> 0x2abc7e0',
                             '0x2b69009 -> 0x2abc7e0']}
    return {
     'object': 'entry rsi saved to r13',
     'limit_field': '+0xc40',
     'limit_load': '0x5a66d03',
     'downstream_call': '0x5a66d32',
     'downstream_target': '0x5860cd0 (view builder, #2501)',
     'selector_byte': '+0xc08',
     'first_store': '0x5a668e6',
     'final_store': '0x5a66bcd',
     'record_helper_call': '0x5a66926 -> 0x5ab6ce0',
     'sibling_record_call': '0x5a668d8 -> 0x5860f30 on +0xc28',
     'parse_helper_call': '0x5a66c2e -> 0x5ab4390',
     'exit_path_calls': ['0x5a6703b -> 0x5a52490',
                         '0x5a68983 -> 0x5a52490']}


def twin_semantics(data, role):
    run_pins(data, role)
    common = {
     'case_values': {'tag_2': 120, 'tag_1': 10000},
     'formula': 'min((end-start+1)*10000000, 1000000000), '
                'saturating on borrow or multiplication '
                'overflow',
     'flag': 'a byte records value >= 100000000 and is '
             'passed to the downstream call'}
    if role == 'top_twin_a':
        return {**common,
         'object': 'entry rsi saved to rbx',
         'limit_field': '+0x180',
         'limit_load': '0x2b6aa24',
         'downstream_call': '0x2b6aa53',
         'downstream_target': '0x26ff210 (state constructor, #2501)',
         'first_store': '0x2b69e69 (record base pointer, '
                        'lea obj+0x140)',
         'first_stage_read': '0x2b69f4d, propagated to +0x268 '
                             'at 0x2b69f5f',
         'second_store': '0x2b6a68e (movups of the pair at '
                         '+0x158)',
         'record_helper_call': '0x2b6a6a6 -> 0x2b7a290 on +0x168',
         'sibling_record_call': '0x2b6a65f -> 0x2701770 on +0x150',
         'final_store': '0x2b6a8e0',
         'copy_entry': 'r13 = [obj+0x178] at 0x2b69f05, jump '
                       'at 0x2b69f21',
         'compute_source': 'pointer at [obj+0x78]; tag at '
                           '[ptr], start at [ptr+0x8], end at '
                           '[ptr+0x10]',
         'also_stored_to': ['+0x178', '+0x1a8'],
         'parse_helper_call': '0x2b6a93a -> 0x2b788e0'}
    return {**common,
     'object': 'entry rsi saved to rbx',
     'limit_field': '+0xa60',
     'limit_load': '0x5a6b881',
     'downstream_call': '0x5a6b8b5',
     'downstream_target': '0x58606f0 (view builder, #2501)',
     'first_store': '0x5a6aad6 (record base pointer, '
                    'lea obj+0xa20)',
     'first_stage_read': '0x5a6ac0f, propagated to +0xb48 '
                         'at 0x5a6ac21',
     'second_store': '0x5a6b4e7 (movups of the pair at '
                     '+0xa38)',
     'record_helper_call': '0x5a6b4ff -> 0x5ab6ce0 on +0xa48',
     'sibling_record_call': '0x5a6b4b8 -> 0x5861830 on +0xa30',
     'final_store': '0x5a6b732',
     'copy_entry': 'r15 = [obj+0xa58] at 0x5a6abcb, jump '
                   'at 0x5a6abe7',
     'compute_source': 'pointer at [obj+0x958]; tag at '
                       '[ptr], start at [ptr+0x8], end at '
                       '[ptr+0x10]',
     'also_stored_to': ['+0xa58', '+0xa88'],
     'parse_helper_call': '0x5a6b78c -> 0x5ab4390'}


def record_helper_b_semantics(data):
    run_pins(data, 'record_helper_b')
    return {
     'entry': 'rdi saved to rbx; dispatch on the tag byte at '
              '+0x310',
     'stores': ['+0x28', '+0x30', '+0x38', '+0x48', '+0x308',
                '+0x309', '+0x310 (tag byte outcomes)'],
     'first_qword': 'read at +0x0 and copied to +0x28; no '
                    'store to +0x0 anywhere in the 267-byte '
                    'body (retained export)'}


def census(data):
    sec = next(s for s in sections(data) if s['name'] == '.text')
    base, off, size = sec['address'], sec['offset'], sec['size']
    body = data[off:off + size]
    _, fs, _ = fde_extents(data)
    fdes = sorted((f['start'], f['end']) for f in fs)
    import bisect
    starts = [s for s, _ in fdes]

    def containing(va):
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0 and fdes[i][0] <= va < fdes[i][1]:
            return fdes[i]
        return None

    targets = {a: role for role, (a, _, _) in OWNERS.items()
               if role != 'record_helper_b'}
    calls = {name: [] for name in targets.values()}
    i = body.find(b'\xe8')
    while i != -1:
        va = base + i
        t = va + 5 + struct.unpack_from('<i', body, i + 1)[0]
        if t in targets:
            c = containing(va)
            calls[targets[t]].append(
             {'site': hex(va),
              'containing_fde': (f'{c[0]:#x}..{c[1]:#x}'
                                 if c else None)})
        i = body.find(b'\xe8', i + 1)
    lea_refs = {name: [] for name in targets.values()}
    for pat in (b'\x48\x8d', b'\x4c\x8d'):
        j = body.find(pat)
        while j != -1:
            if j + 7 <= size:
                tgt = base + j + 7 + struct.unpack_from(
                    '<i', body, j + 3)[0]
                if tgt in targets:
                    lea_refs[targets[tgt]].append(hex(base + j))
            j = body.find(pat, j + 1)
    lea_refs = {k: sorted(set(v)) for k, v in lea_refs.items()}
    return calls, lea_refs


EXPECTED_CALLERS = {
 'top_bulk_a': [{'site': '0x2ad7ff7',
                 'containing_fde': '0x2ad7140..0x2adce3a'},
                {'site': '0x2cc52bf',
                 'containing_fde': '0x2cc1120..0x2cc971b'}],
 'top_twin_a': [{'site': '0x2ae0454',
                 'containing_fde': '0x2ae0100..0x2ae0917'},
                {'site': '0x2cb2101',
                 'containing_fde': '0x2cb1eb0..0x2cb2563'}],
 'top_bulk_b': [{'site': '0x5a856d1',
                 'containing_fde': '0x5a82670..0x5a89535'}],
 'top_twin_b': [{'site': '0x5a83698',
                 'containing_fde': '0x5a82670..0x5a89535'},
                {'site': '0x5a85a2c',
                 'containing_fde': '0x5a82670..0x5a89535'}]}


def exports(data):
    out = {}
    with tempfile.TemporaryDirectory() as td:
        snapshot = Path(td) / 'hl-node'
        snapshot.write_bytes(data)
        for role in EXPORTED:
            a, b, _ = OWNERS[role]
            asm = subprocess.check_output(
             ['objdump', '-d', '-M', 'intel', '--insn-width=16',
              f'--start-address={a:#x}', f'--stop-address={b:#x}',
              str(snapshot)], text=True)
            ins = decode_export(asm, a, b, read(data, a, b - a)[1])
            for va in PIN_STARTS[role]:
                require(va in ins,
                        f'{role} instruction start missing')
            out[role] = asm.replace(str(snapshot),
                                    '<authenticated-node115>')
    return out


def analyze(data):
    calls, lea_refs = census(data)
    for name, expected in EXPECTED_CALLERS.items():
        require(calls[name] == expected,
                f'{name} direct caller census changed')
        require(lea_refs[name] == [],
                f'{name} lea reference census changed')
    bulk_a = bulk_semantics(data, 'top_bulk_a')
    bulk_b = bulk_semantics(data, 'top_bulk_b')
    twin_a = twin_semantics(data, 'top_twin_a')
    twin_b = twin_semantics(data, 'top_twin_b')
    helper_b = record_helper_b_semantics(data)
    exps = exports(data)
    require(len(exps) == len(EXPORTED), 'export count changed')
    _, fs, _ = fde_extents(data)
    fdes = {(f['start'], f['end']): f for f in fs}
    owners = []
    for role, (a, b, sha) in OWNERS.items():
        require((a, b) in fdes, f'{role} FDE changed')
        offset, raw = read(data, a, b - a)
        require(hashlib.sha256(raw).hexdigest() == sha,
                f'{role} body changed')
        records = {}
        for kind in ('fde', 'cie'):
            va = fdes[(a, b)][kind]
            n = struct.unpack('<I', read(data, va, 4)[1])[0] + 4
            records[kind] = {'va': hex(va),
                             'bytes_hex': read(data, va, n)[1].hex()}
        require(records == FRAMES[role],
                f'{role} frame records changed')
        owners.append({'role': role, 'start': hex(a),
                       'end': hex(b), 'file_offset': hex(offset),
                       'bytes': b - a, 'sha256': sha,
                       'frames': records})
    tail = []
    for table, index, target in TAIL_SLOTS:
        raw = read(data, table + 4 * index, 4)[1]
        got = table + struct.unpack('<i', raw)[0]
        require(got == target,
                f'tail slot {table:#x}[{index}] changed')
        tail.append({'table': hex(table), 'index': index,
                     'target': hex(target)})
    census_records = {}
    for name in EXPECTED_CALLERS:
        census_records[name] = {
         'direct_calls': calls[name],
         'lea_references': lea_refs[name]}
    return {
     'target_sha256': SHA,
     'owners': owners,
     'dispatchers': {'bulk_a': bulk_a, 'twin_a': twin_a,
                     'bulk_b': bulk_b, 'twin_b': twin_b},
     'bulk_limit_value': 'selected by one object byte '
      '(bulk_a +0x1e8, bulk_b +0xc08): 1000 when the byte is '
      '0, 4000000000 (0xee6b2800) when it is nonzero; the '
      'selected value is stored to the limit field and to '
      'two sibling slots (bulk_a +0x218/+0x248, bulk_b '
      '+0xc38/+0xc68)',
     'twin_limit_value': 'on the compute entry, a saturating '
      'formula over a source object: tag 2 -> 120, tag 1 -> '
      '10000, otherwise min((end-start+1)*10000000, '
      '1000000000) with saturation on borrow or overflow; '
      'on the copy entry, the current sibling slot value '
      '(twin_a +0x178, twin_b +0xa58); the value is stored '
      'to the limit field and to two sibling slots',
     'first_arm_values': 'bulk: an immediate 0 at the limit '
      'field while a fresh record (0, 60.0 bit pattern, saved '
      'register, copied pair) is built at the field; twin: '
      'the record base pointer (first arm) and a 16-byte '
      'copy of the sibling pair (second arm)',
     'last_writer': 'in direct control flow the only '
      'instructions reaching each limit load without passing '
      'a limit store are the tail instructions after the '
      'final store; the pinned jump-table slots are the only '
      'targets inside (final store, load] and land inside '
      'the final stage block downstream of the store (bulk '
      'b: none)',
     'tail_slots': tail,
     'record_helper_b': helper_b,
     'call_census': census_records,
     'boundaries': {
      'incoming_values': 'who first set the bulk selector '
       'bytes, the twin sibling slots and source-object '
       'fields, and the incoming limit value when the final '
       'stage is entered downstream of its store, is above '
       'the traced window',
      'record_helper_a': 'the copy-a record helper 0x2b7a290 '
       'is pinned at its call sites only; whether its tag-0 '
       'arm writes its record first qword is not traced '
       '(the copy-b helper is exported in full and does not)',
      'sibling_record_calls': 'the calls on the sibling '
       'records (bulk 0x27013e0 / 0x5860f30, twin 0x2701770 / '
       '0x5861830) do not take the limit field address; '
       'their internal writes are not traced',
      'twin_a_result_0x28': 'the writer of the twin-a stage '
       'result +0x28 field left open by #2501 is a different '
       'field and remains open'},
     'captured_code_executed': False,
     'limits': LIMITS}


def generate(binary, output):
    data = binary.read_bytes()
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('pinned node115 distribution changed')
    payload = analyze(data)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        snapshot = Path(td) / 'hl-node'
        snapshot.write_bytes(data)
        native = subprocess.check_output(
         ['readelf', '-wf', str(snapshot)], text=True)
        wanted = []
        for a, b, _ in OWNERS.values():
            needle = f'pc={a:016x}..{b:016x}'
            wanted += [ln for ln in native.splitlines()
                       if needle in ln]
        require(len(wanted) == len(OWNERS),
                'owner frame lines missing')
        (output / 'frames.txt').write_text('\n'.join(wanted) + '\n')
        exps = exports(data)
        for role, asm in exps.items():
            (output / f'{role}.objdump.txt').write_bytes(
             asm.encode('utf-8'))
    (output / 'records.json').write_text(
     json.dumps(payload, indent=1, sort_keys=True) + '\n')
    return payload


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('output', nargs='?', default=str(PACKET))
    args = parser.parse_args()
    payload = generate(TARGET, Path(args.output))
    for owner in payload['owners']:
        print(owner['role'], owner['start'], owner['end'],
              owner['bytes'], owner['sha256'])


if __name__ == '__main__':
    main()
