"""Static evidence for the RE-005 gate-checkers packet.

Answers, for the authenticated hl-node 115 artifact only
(open edge 5 of RE-005-node115-gate-postcheck, PR #2606):

1.  What do the two gate checker bodies actually test?
    checker_a (gate_c 0x2c7f360, gate_a clone 0x2a90a50) is
    called with rdi = &[record+0x150] (and, from gate_c's r14
    phase, with rdi = &[record+0xd8]); checker_b (gate_c
    0x2c7fa40, gate_a clone 0x2a91280) is called with
    rdi = &[record+0x128].  This packet pins each checker's
    argument layout, callees, stores and exact return rule.
2.  Are the gate_a clones byte-identical in logic, or
    divergent?
3.  Who writes the fields the checkers read - the gates
    themselves, the shapers, or earlier record life?
4.  What pointer does gate_c's r14 phase pass to checker_a
    at 0x2cb9923, and is it the same sub-object kind?

Method: both checkers and their gate_a clones are exported
in full; their decision callees (the shared builder
0x5cf2150 and predicate 0x5cf2d30 for checker_a; the shared
key builder 0x2b3c9d0, lookup 0x2e4adb0, vtable method
0x2b15630 and payload helper 0x2c7f720 / clone 0x2a90e10
for checker_b) are exported in full as well.  The five
relative jump tables of each family are read through the
section table (.rodata is identity-mapped; .text resolves
at VA-0x1000; .data.rel.ro at VA-0x2000); GOT slots are
resolved from .rela.dyn addends; gate_c is censused for
every rbx-relative access in the checker field ranges;
clone equivalence is decided by normalised instruction
streams plus table-offset equality.  The two gates are
hash- and pin-pinned only.
"""

import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifacts import ROOT  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402

TARGET = ROOT / 'artifacts' / 'node' / '115' / 'hl-node'
TARGET_SIZE = 105896032
TARGET_SHA256 = ('a6e2897cd051213d004802deca416e8eca62b7a8278'
                 'fa39f249e98c3867b5301')
WORK_ITEM = 'RE-005-node115-gate-checkers'
OUT = ROOT / 'research' / 'work-items' / WORK_ITEM
SNAPSHOT = '<authenticated-node115>'

OWNERS = {
    'gate_c': ('0x2cb6500', '0x2cbbbdf',
               '62835f8a447ea034c30a4fa0663abad74226444817882'
               'c469f883d7d92e4a8d0'),
    'gate_a': ('0x2aeaef0', '0x2af0654',
               'd1b4e3ecb40fb4027b69240f48eacf2de2cf5f7e8c3ae'
               '5c0e6910a784fdcce29'),
    'checker_a': ('0x2c7f360', '0x2c7f71b',
                  'ff59e02e9d3e078985ba6e3b58d8f64f3a6ed5171f2'
                  '120d314cbb5a3c744daed'),
    'checker_b': ('0x2c7fa40', '0x2c7fd80',
                  'c2dd071311e360249b28d2cacda998b6727b2e1d57a'
                  '74ebde965c96325b6c6fa'),
    'checker_a_clone': ('0x2a90a50', '0x2a90e0b',
                        '90fee1bcb70f92349f72110532387ae5bb776b8f'
                        '9008a8571a183ed9cf57a408'),
    'checker_b_clone': ('0x2a91280', '0x2a915c0',
                        '670fc5536cbea0417be82ae30b48b921c666ed77'
                        'bd0e9957d6e75bb2bf2a7955'),
    'builder_a': ('0x5cf2150', '0x5cf22e9',
                  '63364fa5c7e4158629d264ba1afefeb9e1353840a2b'
                  'fae7d34266cc38d7dcade'),
    'predicate_a': ('0x5cf2d30', '0x5cf2fef',
                    'fb3fb193f0b14f251e01da509c670d299323482419'
                    'd1edef4170d948604cbbb2'),
    'keyhash_b': ('0x2b3c9d0', '0x2b3ccb6',
                  '7cd872d3ced0fadd2a0a51bf5016c058dee1ca7e53'
                  '3463f87c66ba3d43384a04'),
    'lookup_b': ('0x2e4adb0', '0x2e4aef7',
                 '2abbeabba442b83ccaa7aab6e706c0f13f5940983338'
                 '29fa22647ef74c3fdfec'),
    'method_b': ('0x2b15630', '0x2b157a9',
                 'f9020e7b0771945423359b0851bb8f78085898184bbe'
                 '8b1c9bbfb22bdc2373b0'),
    'helper_b720': ('0x2c7f720', '0x2c7f803',
                    '2659efb0e8163a0a0082bb1feed80250f5ef08f56'
                    '97edd044c151a5063e302bd'),
    'helper_b720_clone': ('0x2a90e10', '0x2a90ef3',
                          '35fb5fd082da56d0f98fe9ff41b79e8e2b50b8'
                          'efd0e295df5c418bb1de3f7556'),
    'drop_pair': ('0x2ca0790', '0x2ca0818',
                  '822e344d7f1a38846b7da399bcf1728c8358ece0d2'
                  'a2f8865ab7ad5b4b395dff'),
    'drop_pair_a': ('0x2abc7e0', '0x2abc868',
                    '705c05cbdbaed614864a7ca96cd0a9a69be32f3179'
                    'f0191b58e09a4494e07f02'),
}
EXPORTED = ('checker_a', 'checker_b', 'checker_a_clone',
            'checker_b_clone', 'builder_a', 'predicate_a',
            'keyhash_b', 'lookup_b', 'method_b', 'helper_b720',
            'helper_b720_clone')

_CIE = {'bytes_hex': '1c00000000000000017a504c5200017810079b'
                     '11244b051b1b0c070890010000',
        'va': '0x103d604'}
FRAMES = {
 'builder_a': {'cie': _CIE,
   'fde': {'bytes_hex': '4c000000746d3900d4dd91049901000004ebfd02ff410e10420e18420e20420e28420e30410e38440e5083078c068d058e048f0386020320010e38410e30420e28420e20420e18420e10410e08410e50',
           'va': '0x13d4374'}},
 'checker_a': {'cie': _CIE,
   'fde': {'bytes_hex': '50000000700e1500e80eaf01bb0300000433240eff410e10420e18420e20420e28420e30410e38470ec00283078c068d058e048f03860203db020e38410e30420e28420e20420e18420e10410e08410ec0020000',
           'va': '0x118e470'}},
 'checker_a_clone': {'cie': _CIE,
   'fde': {'bytes_hex': '50000000e4261300640d9201bb030000040f600eff410e10420e18420e20420e28420e30410e38470ec00283078c068d058e048f03860203db020e38410e30420e28420e20420e18420e10410e08410ec0020000',
           'va': '0x116fce4'}},
 'checker_b': {'cie': _CIE,
   'fde': {'bytes_hex': '50000000fc0e15003c15af01400300000417240eff410e10420e18420e20420e28420e30410e38440ea00183078c068d058e048f03860203e5010e38410e30420e28420e20420e18420e10410e08410ea0010000',
           'va': '0x118e4fc'}},
 'checker_b_clone': {'cie': _CIE,
   'fde': {'bytes_hex': '5000000070281300081492014003000004bf5f0eff410e10420e18420e20420e28420e30410e38440ea00183078c068d058e048f03860203e5010e38410e30420e28420e20420e18420e10410e08410ea0010000',
           'va': '0x116fe70'}},
 'drop_pair': {'cie': _CIE,
   'fde': {'bytes_hex': '380000003871150050c0b0018800000004aff30dff420e10410e18410e2083038e0202480e18410e10420e08430e20440e18410e10420e08410e2000',
           'va': '0x1194738'}},
 'drop_pair_a': {'cie': _CIE,
   'fde': {'bytes_hex': '380000006cba13006c3794018800000004df240eff420e10410e18410e2083038e0202480e18410e10420e08430e20440e18410e10420e08410e2000',
           'va': '0x117906c'}},
 'gate_a': {'cie': _CIE,
   'fde': {'bytes_hex': '6400000098ef130050e996016457000004d72b0eff410e10420e18420e20420e28420e30410e38470eb8204f0eb8404f0eb8604f0eb880014f0ee08d0183078c068d058e048f0386020307530e38410e30420e28420e20420e18420e10410e08410ee08d01000000',
           'va': '0x117c598'}},
 'gate_c': {'cie': _CIE,
   'fde': {'bytes_hex': '64000000dc9215001cfcb101df56000004a3ed0dff410e10420e18420e20420e28420e30410e38470eb8204f0eb8404f0eb8604f0eb880014f0ee08d0183078c068d058e048f0386020391520e38410e30420e28420e20420e18420e10410e08410ee08d01000000',
           'va': '0x11968dc'}},
 'helper_b720': {'cie': _CIE,
   'fde': {'bytes_hex': '34000000c40e15005412af01e3000000042b240eff420e10420e18410e20440e4083048e038f0202810e20410e18420e10420e08410e4000',
           'va': '0x118e4c4'}},
 'helper_b720_clone': {'cie': _CIE,
   'fde': {'bytes_hex': '3400000038271300d0109201e30000000407600eff420e10420e18410e20440e4083048e038f0202810e20410e18420e10420e08410e4000',
           'va': '0x116fd38'}},
 'keyhash_b': {'cie': _CIE,
   'fde': {'bytes_hex': '3000000080541400489f9b01e6020000043b350eff410e108602430d065483078c068d058e048f0303d7010c0708410c06100000',
           'va': '0x1182a80'}},
 'lookup_b': {'cie': _CIE,
   'fde': {'bytes_hex': '4c000000985e17001079c90147010000040b680dff410e10420e18420e20420e28420e30410e38440e6083078c068d058e048f0386020303010e38410e30420e28420e20420e18420e10410e08410e60',
           'va': '0x11b3498'}},
 'method_b': {'cie': _CIE,
   'fde': {'bytes_hex': '3c00000038061400f07999017901000004cf410eff420e10420e18420e20410e28440e7083058c048e038f0202770e28410e20420e18420e10420e08410e7000',
           'va': '0x117dc38'}},
 'predicate_a': {'cie': _CIE,
   'fde': {'bytes_hex': '4c000000346f3900f4e79104bf020000046ffd02ff410e10420e18420e20420e28420e30410e38440e6083078c068d058e048f03860203cc010e38410e30420e28420e20420e18420e10410e08410e60',
           'va': '0x13d4534'}},
}

# Relative jump tables: (role, table base, dispatch byte).
# All five tables per family hold exactly four arms; the next
# table starts 0x10 later, so reads stop at four entries.
TABLES = {
 'checker_a': [
   ('state_90', 0x60AF90,
    ['0x2c7f38e', '0x2c7f664', '0x2c7f657', '0x2c7f3ad']),
   ('substate_88', 0x60AFA0,
    ['0x2c7f3cf', '0x2c7f680', '0x2c7f671', '0x2c7f5e7'])],
 'checker_b': [
   ('state_a0', 0x60AFB0,
    ['0x2c7fa6b', '0x2c7fc84', '0x2c7fc77', '0x2c7fa96']),
   ('substate_98', 0x60AFC0,
    ['0x2c7fab8', '0x2c7fcb5', '0x2c7fca1', '0x2c7fc3e']),
   ('substate_90', 0x60AFD0,
    ['0x2c7fc6a', '0x2c7fcd8', '0x2c7fcc9', '0x2c7fb72'])],
 'checker_a_clone': [
   ('state_90', 0x603368, None), ('substate_88', 0x603378, None)],
 'checker_b_clone': [
   ('state_a0', 0x603388, None), ('substate_98', 0x603398, None),
   ('substate_90', 0x6033A8, None)],
}
CLONE_OF = {'checker_a_clone': 'checker_a',
            'checker_b_clone': 'checker_b'}

# GOT slots resolved from R_X86_64_RELATIVE addends.
SLOTS = {
 '0x64e13a0': '0x5cf2150',   # checker_a builder call
 '0x64e0858': '0x5cf2d30',   # checker_a predicate call
 '0x64e0848': '0x5cf2b50',   # descriptor accessor (builder/keyhash)
 '0x64e0510': '0x5ca0d20',   # TLS guard init (predicate/lookup)
 '0x64e0518': '0x5ce91b0',   # predicate post-check on &[S+0x40]
 '0x64e0520': '0x5cf3b90',   # TLS fast path (predicate/lookup)
 '0x64e7718': '0x5cf5100',   # registry insert (keyhash)
 '0x64dfe80': '0x5cdb250',   # method_b readiness callee
 '0x64e1880': '0x5ce1860',   # helper_b720 callback context value
 '0x64df6b8': '0x1680e80',   # panic shim
 '0x64df770': '0x1680bd0',   # assert-fail callee
 '0x64e1360': '0x1681e80',   # trap shim (checker state 1)
 '0x64e1368': '0x1681e60',   # trap shim (checker state 2)
 '0x64e13a8': '0x1689370',   # fn qword in checker_a panic descriptor
 '0x64e16c0': '0x64fee40',   # keyhash spinlock word pointer
 '0x64dfdc8': '0x5ce8da0',   # drop fn variant (801 B)
 '0x64dfdb8': '0x5ce86d0',   # drop fn variant (389 B)
 '0x64df590': '0x63577f0',   # allocator size/align (keyhash)
 '0x64df490': '0x141e251',   # alloc error (keyhash)
 '0x64df4c0': '0x1680cab',   # EH pad glue
 '0x64e0990': '0x1629690',   # gate funnel time-pair call 1
 '0x64e0fc0': '0x162a290',   # gate funnel time-pair call 2
 '0x64e7460': '0x63f0080',   # gate funnel f64 callee
 '0x64e1200': '0x1562300',   # gate funnel counter bound call
 '0x64df6e8': '0x141e3a0',   # gate funnel descriptor call
}
SYMBOL_SLOTS = {'0x64df508': 'memcpy'}

# Location statics in .data.rel.ro: {file ptr (RELATIVE addend),
# len qword, packed line/col qword}; all name base/src/lu.rs.
LU_STATICS = {
 '0x644db98': '0x2e0000003f',   # checker_a trap, state 1
 '0x644dc40': '0x390000004a',   # checker_a trap, state 2
 '0x644dc28': '0x50000004b',    # builder_a descriptor
 '0x644dbe0': '0x500000074',    # keyhash_b location descriptor
}
LU_FILE_VA = 0x4326C1

VTABLE_B = 0x6449B00
VTABLE_B_ENTRIES = ['0x2b1d460', '0x2b2d620', '0x2b2d580',
                    '0x2b15630', '0x2b19230', '0x2b17ab0']

# Direct E8 call sites -> callee, decoded from the artifact.
CALL_PINS = {
 '0x2cbb490': '0x2c7fa40',   # gate_c state-3 arm -> checker_b
 '0x2cbb717': '0x2c7f360',   # gate_c state-4 arm -> checker_a (+0x150)
 '0x2cb9923': '0x2c7f360',   # gate_c r14 phase -> checker_a (+0xd8)
 '0x2cbb4a3': '0x2ca3cd0',   # gate_c post-checker_b cleanup
 '0x2cb9991': '0x2ca3ab0',   # r14 phase post-checker_a cleanup
 '0x2cb9985': '0x2ca0790',   # r14 phase drop_pair on &[rbx+0x100]
 '0x2c7fb66': '0x2b3c9d0',   # checker_b -> keyhash_b
 '0x2c7fb84': '0x2e4adb0',   # checker_b -> lookup_b
 '0x2c7fbf3': '0x2c7f720',   # checker_b -> helper_b720
 '0x2c7f633': '0x2ca0790',   # checker_a -> drop_pair
}
# Raw byte pins at decision-relevant sites.
BYTE_PINS = {
 '0x2cbb6f1': 'f20f108330010000',  # movsd xmm0,[rbx+0x130]
 '0x2cbb6f9': 'f20f118350010000',  # movsd [rbx+0x150],xmm0
 '0x2cbb701': 'c683e001000000',    # movb $0,[rbx+0x1e0]
 '0x2cbb552': 'f20f118b28010000',  # movsd [rbx+0x128],xmm1
 '0x2cbb610': 'f20f118b30010000',  # movsd [rbx+0x130],xmm1
 '0x2cbb724': '80bbe001000003',    # cmpb $3,[rbx+0x1e0]
 '0x2cbb72d': '80bbd801000003',    # cmpb $3,[rbx+0x1d8]
 '0x2cbb495': 'a801',              # test $1,%al after checker_b
 '0x2cbb71c': '84c0',              # test %al,%al after checker_a
 '0x2cb98fc': '4c8db3d8000000',    # lea r14,[rbx+0xd8]
 '0x2cb9903': '48b800000060d71d3442',  # movabs rax,0x42341dd760000000
 '0x2cb990d': '488983d8000000c6',  # mov [rbx+0xd8],rax ...
 '0x2cb9914': 'c6836801000000',    # movb $0,[rbx+0x168]
 '0x2cb98f5': 'c6837001000000',    # movb $0,[rbx+0x170]
}
R14_F64_BITS = 0x42341DD760000000  # 86400000000.0

# .rodata f64 constants used by gate_c's funnel computations.
DOUBLES = {'0x458d50': 1e9, '0x459010': 'inf', '0x459568': 600.0,
           '0x458eb0': 2.0, '0x458dc8': -1.0}

# gate_c rbx census over the checker field ranges, derived by
# classifying every objdump line whose operand names (%rbx).
EXPECTED_CENSUS = {
 '0x120': {'leas': ['0x2cb67b1', '0x2cb67dd'],
           'loads': ['0x2cb67e9', '0x2cbb053'],
           'stores': ['0x2cb67bd']},
 '0x121': {'loads': ['0x2cb6809'], 'stores': ['0x2cb67c4']},
 '0x122': {'loads': ['0x2cb6810']},
 '0x123': {'loads': ['0x2cb6818']},
 '0x124': {'loads': ['0x2cb681f']},
 '0x128': {'leas': ['0x2cbb481'], 'loads': ['0x2cb74bf'],
           'stores': ['0x2cb7245', '0x2cbb552']},
 '0x130': {'leas': ['0x2cbb5f9'], 'loads': ['0x2cbb6f1'],
           'stores': ['0x2cbb610']},
 '0x138': {'loads': ['0x2cb74c7', '0x2cbb6cb', '0x2cbb77b'],
           'stores': ['0x2cb724d', '0x2cbb69e']},
 '0x140': {'loads': ['0x2cbb6d7', '0x2cbb787']},
 '0x148': {'loads': ['0x2cb74cf'],
           'stores': ['0x2cb7255', '0x2cbb68e']},
 '0x150': {'leas': ['0x2cbb708'], 'stores': ['0x2cbb6f9']},
 '0x158': {'loads': ['0x2cb748b']},
 '0x160': {'loads': ['0x2cb7492', '0x2cb9945'],
           'stores': ['0x2cb73e0']},
 '0x168': {'leas': ['0x2cbb01e'],
           'loads': ['0x2cb74fb', '0x2cb8903', '0x2cb993c',
                     '0x2cbb73d'],
           'stores': ['0x2cb73ed', '0x2cb9914']},
 '0x170': {'leas': ['0x2cb7019', '0x2cb98ee', '0x2cbafeb',
                    '0x2cbb736'],
           'loads': ['0x2cb7020', '0x2cb86b1'],
           'stores': ['0x2cb7449', '0x2cb98f5']},
 '0x178': {'leas': ['0x2cbb766', '0x2cbb9fa']},
 '0x180': {'loads': ['0x2cb86b9'], 'stores': ['0x2cb7451']},
 '0x190': {'loads': ['0x2cb86a2'], 'stores': ['0x2cb7461']},
 '0x198': {'leas': ['0x2cb8973', '0x2cb97aa', '0x2cbad82'],
           'stores': ['0x2cb8068']},
 '0x1a0': {'leas': ['0x2cb806f']},
 '0x1d8': {'loads': ['0x2cbb72d']},
 '0x1e0': {'loads': ['0x2cbb724'], 'stores': ['0x2cbb701']},
}


def read(va, data, size=None):
    for section in sections(data):
        start = section['address']
        if start <= va < start + section['size']:
            offset = section['offset'] + (va - start)
            end = (len(data) if size is None else
                   min(len(data), offset + size))
            return offset, bytes(data[offset:end])
    raise ValueError(hex(va))


def read_string(va, data, size):
    _, raw = read(va, data, size)
    return raw.decode('ascii')


def section_name(va, data):
    for section in sections(data):
        if (section['address'] <= va and
                va < section['address'] + section['size']):
            return section['name']
    raise ValueError(hex(va))


def check(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def owners(data):
    check(len(data) == TARGET_SIZE and sha(data) == TARGET_SHA256,
          'unexpected node artifact')
    _, fdes, _ = fde_extents(data)
    extents = {(f['start'], f['end']): f for f in fdes}
    records = {}
    for role, (start, end, digest) in OWNERS.items():
        start, end = int(start, 16), int(end, 16)
        check((start, end) in extents, f'missing FDE {role}')
        offset, body = read(start, data, end - start)
        check(sha(body) == digest, f'body hash mismatch {role}')
        for kind in ('fde', 'cie'):
            fva = extents[(start, end)][kind]
            size = struct.unpack('<I', read(fva, data, 4)[1])[0] + 4
            want = FRAMES[role][kind]
            check(int(want['va'], 16) == fva and
                  read(fva, data, size)[1].hex() == want['bytes_hex'],
                  f'frame mismatch {role} {kind}')
        records[role] = {
            'start': hex(start), 'end': hex(end),
            'file_offset': hex(offset), 'bytes': end - start,
            'sha256': digest}
    return records


def frame_lines(data):
    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.bin',
                                     delete=False) as tmp:
        tmp.write(data)
        name = tmp.name
    try:
        text = subprocess.run(['readelf', '-wf', name],
                              check=True, capture_output=True,
                              text=True).stdout
    finally:
        Path(name).unlink()
    wanted = []
    for start, end, _ in OWNERS.values():
        needle = (f'pc={int(start, 16):016x}..{int(end, 16):016x}')
        wanted += [ln for ln in text.splitlines() if needle in ln]
    check(len(wanted) == len(OWNERS), 'owner frame lines missing')
    return [line + '\n' for line in wanted]


def exports(data, role):
    start, end = OWNERS[role][0], OWNERS[role][1]
    text = subprocess.run(
        ['objdump', '-d', '-M', 'intel', '--no-show-raw-insn',
         '--start-address', start, '--stop-address', end,
         str(TARGET)],
        check=True, capture_output=True, text=True).stdout
    return text.replace(str(TARGET), SNAPSHOT, 1)


def rela_entries(data):
    entries = {}
    for section in sections(data):
        if section['name'] != '.rela.dyn':
            continue
        blob = data[section['offset']:
                    section['offset'] + section['size']]
        for i in range(0, len(blob) - 23, 24):
            off, info, addend = struct.unpack_from('<QQq', blob, i)
            entries[off] = (info & 0xFFFFFFFF, info >> 32, addend)
    return entries


def dynsym_name(data, index):
    dynsym = next(s for s in sections(data)
                  if s['name'] == '.dynsym')
    dynstr = next(s for s in sections(data)
                  if s['name'] == '.dynstr')
    name_off = struct.unpack_from(
        '<I', data, dynsym['offset'] + index * 24)[0]
    start = dynstr['offset'] + name_off
    end = data.index(b'\0', start)
    return data[start:end].decode()


def slots_census(data):
    entries = rela_entries(data)
    records = {}
    for slot, want in SLOTS.items():
        off = int(slot, 16)
        check(off in entries, f'slot {slot} has no relocation')
        typ, _, addend = entries[off]
        check(typ == 8, f'slot {slot} is not R_X86_64_RELATIVE')
        check(addend == int(want, 16),
              f'slot {slot} resolves to {hex(addend)}, want {want}')
        records[slot] = {'relocation_type': typ, 'addend': want}
    for slot, want in SYMBOL_SLOTS.items():
        off = int(slot, 16)
        check(off in entries, f'slot {slot} has no relocation')
        typ, sym_index, _ = entries[off]
        name = dynsym_name(data, sym_index)
        check(name == want, f'slot {slot} symbol {name} != {want}')
        records[slot] = {'relocation_type': typ, 'symbol': name}
    vt = {}
    for i, want in enumerate(VTABLE_B_ENTRIES):
        off = VTABLE_B + 8 * i
        check(off in entries, f'vtable entry {i} has no relocation')
        typ, _, addend = entries[off]
        check(typ == 8 and addend == int(want, 16),
              f'vtable entry {i} resolves to {hex(addend)}')
        vt[hex(8 * i)] = want
    records['vtable_b'] = {'base': hex(VTABLE_B), 'entries': vt}
    statics = {}
    for va, packed in LU_STATICS.items():
        off = int(va, 16)
        check(off in entries, f'lustatic {va} has no relocation')
        typ, _, addend = entries[off]
        check(typ == 8 and addend == LU_FILE_VA,
              f'lustatic {va} file pointer is {hex(addend)}')
        len_q = struct.unpack('<Q', read(off + 8, data, 8)[1])[0]
        packed_q = struct.unpack(
            '<Q', read(off + 16, data, 8)[1])[0]
        check(len_q == 0xE, f'lustatic {va} len {len_q}')
        check(packed_q == int(packed, 16),
              f'lustatic {va} packed {hex(packed_q)}')
        statics[va] = {'file': hex(LU_FILE_VA), 'len': '0xe',
                       'packed': packed}
    records['lu_statics'] = statics
    return records


def table_entries(data, base, lo, hi, count=4):
    offset, _ = read(base, data, 4 * count)
    raw = data[offset:offset + 4 * count]
    out = []
    for i in range(count):
        delta = struct.unpack_from('<i', raw, 4 * i)[0]
        target = base + delta
        check(lo <= target < hi,
              f'table {hex(base)} entry {i} escapes its body')
        out.append(target)
    return out


def tables_census(data):
    records = {}
    for role, specs in TABLES.items():
        lo = int(OWNERS[role][0], 16)
        hi = int(OWNERS[role][1], 16)
        per = {}
        for name, base, want in specs:
            got = table_entries(data, base, lo, hi)
            if want is not None:
                check([hex(t) for t in got] == want,
                      f'{role} table {name} mismatch')
            per[name] = {'base': hex(base), 'section':
                         section_name(base, data),
                         'entries': {hex(i): hex(t)
                                     for i, t in enumerate(got)},
                         'offsets': [hex(t - lo) for t in got]}
        records[role] = per
    # Clone tables must reproduce the originals arm-for-arm,
    # offset for offset.
    for clone, orig in CLONE_OF.items():
        for name in records[orig]:
            check(records[clone][name]['offsets'] ==
                  records[orig][name]['offsets'],
                  f'{clone} table {name} offsets diverge')
    return records


_LINE = re.compile(r'^\s*([0-9a-f]+):\t[0-9a-f ]+\t(.*)$')


def gate_census(data):
    start, end = OWNERS['gate_c'][0], OWNERS['gate_c'][1]
    text = subprocess.run(
        ['objdump', '-d', '--start-address', start,
         '--stop-address', end, str(TARGET)],
        check=True, capture_output=True, text=True).stdout
    stores, loads, leas = {}, {}, {}

    def put(table, off, va):
        table.setdefault(off, []).append(va)

    for ln in text.splitlines():
        m = _LINE.match(ln)
        if not m:
            continue
        va, ins = int(m.group(1), 16), m.group(2).strip()
        mm = re.search(r'0x([0-9a-f]+)\(%rbx\)', ins)
        if not mm:
            continue
        off = int(mm.group(1), 16)
        if not (0x120 <= off < 0x1F0):
            continue
        key = hex(off)
        if ins.startswith('lea'):
            put(leas, key, hex(va))
        elif ins.startswith(('cmp', 'test')):
            put(loads, key, hex(va))
        elif '(%rbx)' in (ins.split(',', 1)[-1] if ',' in ins
                          else ''):
            put(stores, key, hex(va))
        else:
            put(loads, key, hex(va))
    records = {}
    for off in sorted(set(stores) | set(loads) | set(leas)):
        entry = {}
        if off in stores:
            entry['stores'] = stores[off]
        if off in loads:
            entry['loads'] = loads[off]
        if off in leas:
            entry['leas'] = leas[off]
        records[off] = entry
    check(records == EXPECTED_CENSUS, 'gate_c census mismatch')
    return records


def norm_stream(data, role):
    start, end = OWNERS[role][0], OWNERS[role][1]
    text = subprocess.run(
        ['objdump', '-d', '-M', 'intel', '--no-show-raw-insn',
         '--start-address', start, '--stop-address', end,
         str(TARGET)],
        check=True, capture_output=True, text=True).stdout
    lines = []
    for ln in text.splitlines():
        m = re.match(r'^\s*[0-9a-f]+:\t(.*)$', ln)
        if not m:
            continue
        ins = m.group(1).split('#')[0].strip()
        ins = re.sub(r'0x[0-9a-f]+', 'X', ins)
        ins = re.sub(r'\b[0-9a-f]{5,}\b', 'X', ins)
        ins = re.sub(r'\s+', ' ', ins)
        lines.append(ins)
    return lines


def clone_equivalence(data):
    pairs = [('checker_a', 'checker_a_clone'),
             ('checker_b', 'checker_b_clone'),
             ('helper_b720', 'helper_b720_clone')]
    records = {}
    for orig, clone in pairs:
        a, b = norm_stream(data, orig), norm_stream(data, clone)
        check(a == b, f'{clone} instruction stream diverges')
        records[f'{orig}__{clone}'] = {
            'normalised_lines': len(a), 'equal': True}
    return records


def pins_census(data):
    records = {'calls': {}, 'bytes': {}}
    for site, want in CALL_PINS.items():
        va = int(site, 16)
        _, raw = read(va, data, 5)
        check(raw[0] == 0xE8, f'pin {site} is not a direct call')
        rel = struct.unpack('<i', raw[1:])[0]
        got = va + 5 + rel
        check(got == int(want, 16),
              f'call pin {site} -> {hex(got)}, want {want}')
        records['calls'][site] = want
    for site, want in BYTE_PINS.items():
        va = int(site, 16)
        _, raw = read(va, data, len(bytes.fromhex(want)))
        check(raw.hex() == want, f'byte pin {site} mismatch')
        records['bytes'][site] = want
    bits = struct.unpack('<Q', read(0x2CB9903 + 2, data, 8)[1])[0]
    check(bits == R14_F64_BITS, 'r14 f64 immediate mismatch')
    records['r14_f64'] = {'bits': hex(bits),
                          'value': struct.unpack(
                              '<d', struct.pack('<Q', bits))[0]}
    return records


def strings_census(data):
    records = {}
    lu = read_string(LU_FILE_VA, data, 14)
    check(lu == 'base/src/lu.rs', 'lu.rs string mismatch')
    records['lu_rs'] = {'va': hex(LU_FILE_VA),
                        'section': section_name(LU_FILE_VA, data),
                        'value': lu}
    aw = read_string(0x451330, data, 16)
    check(aw == 'async_wait_inner', 'async string mismatch')
    records['async_wait_inner'] = {
        'va': '0x451330', 'section': section_name(0x451330, data),
        'value': aw}
    jh = read_string(0x6068D2, data, 34)
    check(jh == 'JoinHandle polled after completion',
          'joinhandle string mismatch')
    records['joinhandle_panic'] = {
        'va': '0x6068d2', 'section': section_name(0x6068D2, data),
        'value': jh}
    _, bg = read(0x43B857, data, 128)
    for piece in (b'$min > max, or either was NaN. min = ',
                  b', max = ', b'base/src/bucket_guard.rs'):
        check(piece in bg, f'bucket_guard piece missing {piece}')
    records['bucket_guard_fmt'] = {
        'va': '0x43b857', 'section': section_name(0x43B857, data),
        'bytes_hex': bg.hex()}
    _, te = read(0x433ED3, data, 15)
    check(te == b'\rtimer error: \xc0', 'timer fmt mismatch')
    records['timer_error_fmt'] = {'va': '0x433ed3',
                                  'bytes_hex': te.hex()}
    _, sp = read(0x431A60, data, 40)
    check(b"OS can't spawn worker thread: " in sp,
          'spawn fmt piece missing')
    records['spawn_fmt'] = {'va': '0x431a60', 'bytes_hex': sp.hex()}
    doubles = {}
    for va, want in DOUBLES.items():
        _, raw = read(int(va, 16), data, 8)
        val = struct.unpack('<d', raw)[0]
        if want == 'inf':
            check(val == float('inf'), f'double {va} not +inf')
            doubles[va] = 'inf'
        else:
            check(val == want, f'double {va} is {val}')
            doubles[va] = val
    records['gate_doubles'] = doubles
    return records


FINDINGS = {
 'checker_a_question':
   'checker_a is a resumable state machine over a 0x98-byte '
   'sub-object (arg = rdi). In gate_c it runs on two instances '
   'of the same kind: arg = record+0x150 (state-4 arm call at '
   'gate_c 0x2cbb717) and arg = record+0xd8 (r14-phase call at '
   '0x2cb9923).',
 'checker_a_layout':
   'arg+0x00 f64 value v (read); arg+0x08 f64 copy of v '
   '(written by the state-0 arm); arg+0x10 f64 copy of v / '
   're-entry value source; arg+0x18..0x88 the 0x70-byte '
   'built struct S (builder output, then predicate input); '
   'arg+0x88 sub-state byte; arg+0x90 state byte.',
 'checker_a_return_rule':
   'State byte [arg+0x90]: 0 = fresh, 3 = resume, 1 and 2 are '
   'trap arms (location-static shims 0x1681e80 / 0x1681e60 '
   'from base/src/lu.rs statics, then ud2). Fresh arm: v := '
   '[arg+0x00]; [arg+0x08] := v. If v == +-0.0: [arg+0x90] := '
   '1 and return 0 (the [arg+0x88] byte is NOT written on '
   'this path). If v < 0: panic through slot 0x64df6b8 with '
   'the base/src/bucket_guard.rs format pieces at 0x43b857 '
   'and dl = 0; NaN reaches the same panic with dl = 1. If v '
   '> 0 finite: v is decomposed (biased exponent, 1e9-unit '
   'scaling) into the (rsi, rdx) inputs of builder 0x5cf2150 '
   '(slot 0x64e13a0, descriptor static 0x644dc28); the '
   '0x70-byte result is copied into S = [arg+0x18..0x88) and '
   'predicate 0x5cf2d30 (slot 0x64e0858) runs on S with the '
   'caller context. Predicate nonzero: [arg+0x88] := 3, '
   '[arg+0x90] := 3, return the predicate eax (nonzero). '
   'Predicate zero: the handle pair is dropped (refcount dec '
   'on [arg+0x20]; drop fn chosen by byte [arg+0x18] between '
   'slots 0x64dfdc8 / 0x64dfdb8; drop_pair 0x2ca0790 on '
   '&[arg+0x28]), [arg+0x88] := 1, [arg+0x90] := 1, return 0. '
   'Resume arm ([arg+0x90] == 3) dispatches on [arg+0x88]: '
   '0 re-runs builder+predicate from v = [arg+0x10] (no copy, '
   'no state zeroing), 3 calls the predicate directly on the '
   'existing S, 1 and 2 trap. EH pads drop &[arg+0x28] and '
   'the bodies at &[arg+0x18] / &[arg+0x10], write state 2 '
   'to [arg+0x88] and [arg+0x90], and _Unwind_Resume.',
 'builder_a_rule':
   'builder 0x5cf2150 (409 B, shared by both gates) calls '
   'the descriptor accessor 0x5cf2b50 (slot 0x64e0848) and '
   'base-value callee 0x5c842e0(1), performs checked 1e9 / '
   '946684800 arithmetic, asserts through slot 0x64df770 '
   'when a handle dword equals 1000000000, and writes only '
   'S+0x00 (accessor rax), S+0x08 (accessor rdx), S+0x10 := '
   '2, S+0x60 (computed value) and S+0x68 (dword). The rest '
   'of S is initialised by the predicate normalisation.',
 'predicate_a_rule':
   'predicate 0x5cf2d30 (703 B, shared) first consults a TLS '
   'cache (TLS-0x1130; guard slot 0x64e0510): if the TLS u16 '
   'low bit is set and its high byte is 0 it calls slot '
   '0x64e0520 -> 0x5cf3b90 (context, static 0x64c6648) and '
   'returns 1. Otherwise, when [S+0x10] == 2, it normalises '
   'S: refcount-inc on [S+0x08], conversion 0x5cf1d70 on '
   '&[S+0x10], [S+0x18] := handle, [S+0x20..0x38) := 0, '
   '[S+0x38] := -1, [S+0x40] := 0, [S+0x50] := 0, byte '
   '[S+0x58] := 0, then conversion 0x5cead40(&[S+0x10], '
   '[S+0x60], dword [S+0x68]). Decision: if dword '
   '[handle + (tag&1 ? 0x160 : 0x240) + 0x90] == 1000000000 '
   '-> assert-fail (slot 0x64df770) and ud2; else if byte '
   '[handle + base + 0x80] != 0 -> panic with the '
   'bucket_guard "$min > max" pieces and ud2; else call '
   'slot 0x64e0518 -> 0x5ce91b0 on &[S+0x40] (result '
   'unused), then return 1 iff [S+0x38] != -1; return 0 iff '
   '[S+0x38] == -1 and byte [S+0x58] == 0; [S+0x38] == -1 '
   'with [S+0x58] != 0 unwinds through the "timer error: " '
   'format piece at 0x433ed3 (not a normal return). So '
   'checker_a returns nonzero exactly when the predicate '
   'fast path fires or the normalised struct carries a '
   'converted value at S+0x38 after the post-check call.',
 'checker_b_question':
   'checker_b is a resumable state machine over a 0xa8-byte '
   'sub-object (arg = record+0x128 in gate_c). It turns the '
   'source byte string at arg+0x00 into a registry-backed '
   'handle and polls it once per call.',
 'checker_b_layout':
   'arg+0x00..0x20 source descriptor D {cap +0x00, ptr '
   '+0x08, len +0x10, tag byte +0x18}; arg+0x20..0x40 the '
   'working copy of D; arg+0x40 pointer slot holding '
   '&[arg+0x20]; arg+0x48..0x68 built key struct B {len '
   '+0x48, buffer +0x50, len +0x58, tag +0x60}; arg+0x68 / '
   '+0x78 the constant &str pair (0x451330, 16) written '
   'twice ("async_wait_inner"); arg+0x88 the handle object '
   'pointer written by keyhash_b; arg+0x90 / +0x98 / +0xa0 '
   'state bytes.',
 'checker_b_return_rule':
   'Entry dispatch on [arg+0xa0]; states 1 and 2 trap. The '
   'fresh arm copies D to [arg+0x20..0x40), stores '
   '[arg+0x40] := &[arg+0x20] and [arg+0x98] := 0; the '
   'resume arm dispatches on [arg+0x98], whose state-0 arm '
   'reloads the descriptor through [arg+0x40]. The string '
   'bytes are copied to a fresh allocation (allocator slot '
   '0x64df480, memcpy slot 0x64df508; len 0 uses sentinel '
   'buffer 1), B is built, the constant name pair is '
   'written, [arg+0x90] := 0, and keyhash_b 0x2b3c9d0 '
   '(direct call at 0x2c7fb66) stores a heap handle at '
   '[arg+0x88]. lookup_b 0x2e4adb0 (0x2c7fb84) then polls: '
   'it presets the result tag qword to 1 and calls the '
   'vtable method [handle+0x10]+0x18 = 0x2b15630. The '
   'method returns without writing when its readiness '
   'callee (slot 0x64dfe80 -> 0x5cdb250, on &[obj+0x60]) '
   'returns 0, leaving tag 1; when ready it requires '
   '[obj+0x38] == 1 (else the "JoinHandle polled after '
   'completion" panic at 0x6068d2), sets [obj+0x38] := 2 '
   'and writes result {tag 0, payload triple from '
   'obj+0x40..0x58}. lookup_b also forces tag 1 on its TLS '
   'fast path. checker_b returns 1 (bit 0 set, all three '
   'state bytes := 3, second return value = the caller '
   'context) when the result tag byte != 0, and returns 0 '
   'when the tag is 0: it then CAS-transitions the handle '
   'state word 0xcc -> 0x84 (contention calls the vtable '
   'drop 0x2b19230), consumes the payload triple through '
   'helper 0x2c7f720 (callback fn 0x24a7c50; its rax becomes '
   'checker_b second return value in rdx), sets all state '
   'bytes := 1 and frees the source descriptor buffer when '
   '[arg+0x20] != 0. EH pads drop B (0x2c93260) and the '
   '[arg+0x40] descriptor (0x2ca6960), free the source '
   'buffer, write state 2 to all three state bytes and '
   '_Unwind_Resume. Re-entry through sub-state [arg+0x98] '
   '== 3 dispatches on [arg+0x90]: state 0 reloads the '
   'constant pair from [arg+0x68] / [arg+0x70] and rejoins '
   'the keyhash phase with the previously built B.',
 'keyhash_b_rule':
   'keyhash_b 0x2b3c9d0 (742 B, shared) resolves the '
   'location descriptor (static 0x644dbe0) through accessor '
   '0x5cf2b50, takes the spinlock on global word 0x64fee40 '
   '(pointer from slot 0x64e16c0), builds a 0x100-byte '
   'object on the stack {state 0xcc at +0x00, vtable '
   '0x6449b00 at +0x10, registry refcount/value at '
   '+0x20/+0x28, B copied in}, allocates it via slot '
   '0x64df590 -> 0x63577f0, inserts it into one of two '
   'registry slots through slot 0x64e7718 -> 0x5cf5100 '
   '(a duplicate insert panics with the "OS can\'t spawn '
   'worker thread: " pieces at 0x431a60) and returns the '
   'heap object pointer.',
 'clone_verdict':
   'The gate_a clones are logic-identical to the gate_c '
   'originals. All five relative jump tables reproduce the '
   'original arm offsets exactly (checker_a +0x2e/+0x304/'
   '+0x2f7/+0x4d and +0x6f/+0x320/+0x311/+0x287; checker_b '
   '+0x2b/+0x244/+0x237/+0x56, +0x78/+0x275/+0x261/+0x1fe, '
   '+0x22a/+0x298/+0x289/+0x132), the normalised instruction '
   'streams are equal, and the decision callees are shared '
   'bodies (builder 0x5cf2150 and predicate 0x5cf2d30 via '
   'the same slots; keyhash_b 0x2b3c9d0 and lookup_b '
   '0x2e4adb0 by the same direct calls). The only per-family '
   'differences are family-local drop glue: checker_b '
   'payload helper 0x2c7f720 vs clone 0x2a90e10 (both 227 B, '
   'normalised-equal), drop_pair 0x2ca0790 vs 0x2abc7e0, and '
   'the EH drop bodies (gate_c 0x2c8b730 96 B / 0x2ca4700 '
   '114 B / 0x2c93260 62 B / 0x2ca6960 69 B; gate_a '
   'analogues 0x2a9e950 96 B / 0x2ac0e00 114 B / 0x2aaab40 '
   '62 B / 0x2ac30e0 69 B), plus each clone its own jump '
   'tables and location statics.',
 'producer_census':
   'gate_c writes the tested fields itself, in the phases '
   'that immediately precede the calls; the shapers write '
   'none of them (the #2604 bracket census records no '
   'shaper access at the phase offsets of record+0x128 / '
   '+0x150 / +0x1d8 / +0x1e0). Per field: (a) checker_b '
   'source triple [rec+0x130 ptr / +0x138 len / +0x140 tag '
   'byte] - on entry rounds it arrives through the verbatim '
   '0x40-byte copy at gate_c 0x2cb7225..0x2cb7255 that '
   'fills rec+0x118..0x158 from a caller-supplied struct '
   '(*rax): gate-copied, not gate-computed; its producer '
   'outside the gate is the boundary. In the funnel round '
   'the gate overwrites +0x128 (f64 store 0x2cbb552), '
   '+0x130 (f64 store 0x2cbb610), +0x138..+0x148 and '
   '+0x148 (0x2cbb69e / 0x2cbb68e, from the slot-0x64df6e8 '
   'descriptor call) - but those stores land AFTER the '
   '0x2cbb490 checker_b call of the same arm. (b) '
   'checker_a f64 [rec+0x150]: exactly one gate store, '
   '0x2cbb6f9, copying the gate-computed double at '
   '[rec+0x130] (clamped computation from [rec+0xa8] via '
   'slot 0x64e7460, constants 2.0 / -1.0 / 600.0) - '
   'gate-built. (c) checker_a state bytes: [rec+0x1e0] '
   'zeroed by the gate at 0x2cbb701 immediately before the '
   'call; [rec+0x1d8] has NO gate store - it is written '
   'only by checker_a itself, so its pre-first-call value '
   'is incoming record residue. (d) the +0xd8 instance: '
   'the gate stores the f64 constant 86400000000.0 (bits '
   '0x42341dd760000000) at [rec+0xd8] at 0x2cb990d and '
   'zeroes its state byte [rec+0x168] at 0x2cb9914 - '
   'gate-built; its [arg+0x88] byte at rec+0x160 is '
   'written by checker_a itself and, in one other phase, '
   'by the gate store at 0x2cb73e0 (paired with '
   '[rec+0x168] at 0x2cb73ed). The two checker_a instances '
   'are staggered by 0x78 bytes, so instance fields alias: '
   'rec+0x160 / +0x168 are both the +0xd8 instance state '
   'bytes and the +0x150 instance [arg+0x10] / S+0x00.',
 'r14_phase_call':
   'At gate_c 0x2cb98fc, r14 := lea [rbx+0xd8]; the gate '
   'stores the f64 constant 86400000000.0 at [rbx+0xd8] '
   '(0x2cb9903 / 0x2cb990d), zeroes [rbx+0x170] (r15 target) '
   'and [rbx+0x168], then calls checker_a at 0x2cb9923 with '
   'rdi = r14 and rsi = the context spill [rsp+0x8]. It is '
   'the same sub-object kind as the +0x150 instance: the '
   'zero path tests [rbx+0x168] == 3 and [rbx+0x160] == 3 '
   '(its [arg+0x90] / [arg+0x88]), drops the handle pair '
   'at [rbx+0xf8] with the tag byte at [rbx+0xf0] (its '
   'S+0x00 / S+0x08) and calls drop_pair 0x2ca0790 on '
   '&[rbx+0x100] (its &[arg+0x28]) at 0x2cb9985, exactly '
   'mirroring checker_a internal layout; a nonzero return '
   'sets [rbx+0x170] := 3 and joins the funnel mid-tail at '
   '0x2cb802d with outcome 4; a zero return sets '
   '[rbx+0x170] := 1, calls cleanup 0x2ca3ab0 on &[rbx+0xd8] '
   'and reaches the return-0 arm at 0x2cb99a7.',
 'precise_negatives':
   'Not statically decidable from these bodies: (1) which '
   'callee inside the predicate post-check chain overwrites '
   'the -1 sentinel at S+0x38 (the conversion 0x5cead40 and '
   'the slot-0x64e0518 callee 0x5ce91b0 both run between '
   'the sentinel store and the decision read; their '
   'internals are not pinned here). (2) The semantic '
   'identity of method_b readiness callee 0x5cdb250 beyond '
   'its (obj, &[obj+0x60]) -> al contract. (3) The producer '
   'of the caller-supplied struct that gate_c copies into '
   'rec+0x118..0x158 at 0x2cb7225 (outside the gate body). '
   '(4) The pre-first-call value of [rec+0x1d8] (no writer '
   'inside the gates or the shapers).',
}


def derive(data):
    return {
        'artifact': {'size': len(data), 'sha256': sha(data)},
        'work_item': WORK_ITEM,
        'owners': owners(data),
        'exported_bodies': list(EXPORTED),
        'tables': tables_census(data),
        'slots': slots_census(data),
        'strings': strings_census(data),
        'pins': pins_census(data),
        'gate_census': {'gate_c': gate_census(data)},
        'clone_equivalence': clone_equivalence(data),
        'findings': FINDINGS,
    }


def analyze(data):
    return derive(data)


def generate(data):
    OUT.mkdir(parents=True, exist_ok=True)
    records = analyze(data)
    (OUT / 'records.json').write_text(
        json.dumps(records, indent=1, sort_keys=True) + '\n')
    (OUT / 'frames.txt').write_text(''.join(frame_lines(data)))
    for role in EXPORTED:
        (OUT / f'{role}.objdump.txt').write_text(
            exports(data, role))


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--generate', action='store_true')
    args = parser.parse_args()
    data = TARGET.read_bytes()
    if args.generate:
        generate(data)
        return
    records = analyze(data)
    expected = json.loads((OUT / 'records.json').read_text())
    check(records == expected, 'records.json is stale')
    for role in EXPORTED:
        check((OUT / f'{role}.objdump.txt').read_text() ==
              exports(data, role), f'{role}.objdump.txt is stale')
    check((OUT / 'frames.txt').read_text() ==
          ''.join(frame_lines(data)), 'frames.txt is stale')
    print(json.dumps({'packet': WORK_ITEM, 'matches': True},
                     sort_keys=True))


if __name__ == '__main__':
    main()
