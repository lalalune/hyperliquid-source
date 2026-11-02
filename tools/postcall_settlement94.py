#!/usr/bin/env python3
"""Recover node94 post-call settlement and output state transitions.

Static byte inspection only. Semantic labels are hypotheses; the original
operands, FDE records, RELA entries and exception call-site rows are retained.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
from elf_index import sections
from fde_extents import eh_frame_records, uleb, sleb

ROOT = Path(__file__).resolve().parents[1]
SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = {41343088: 'normalize final frame gas by instruction status', 38073344: 'add signed refund and cap by spent gas', 38073488: 'caller reimbursement callback adapter', 38175760: 'effective price and caller balance credit', 38073552: 'beneficiary credit callback adapter', 38178032: 'effective tip and beneficiary balance credit', 38144720: 'load or install journal account through private database', 38074048: 'move frame result into output callback', 38179408: 'take context error or finalize state and classify output', 37928512: 'instruction status to result category and reason', 38146320: 'drain account state and logs and reset journal', 38124976: 'release account value on failed installation', 38132816: 'release output logs on unwind', 33705776: 'release drained account map on unwind', 38827984: 'release one output log'}
BODY_HASHES = {41343088: '679371297cea5eddc918d23ead7ea7e923b2e4177ddbe33cdf9e291e9ac58201', 38073344: '5c0763c715bf38e9e71f851cb998021c8cebb2366f0c5006946d723c9684a8c2', 38073488: 'c98f16894ad778aa8b5f6c013a378933e979dbd600ed0d26967840aebac12bdc', 38175760: '20b14b982f14d428387adab78e12b05c6cb0dd93198eb82ba9e539c2c9239bfe', 38073552: '9d14324598a7d8bf5494f50a3be3c6acc7b402bb45e09e1ff18cdf4b14884be5', 38178032: '5e0fa5628e4929e0f2b5164e6b77f068c85ebefeab79c356efda20d5fb3a88f5', 38144720: 'd2f327dff484bd0b695dced4784bc05194a574bf885d6a0760367a85b2d58381', 38074048: '5c33c0d636625c4f65ece51ca991be217ced55ecfd0533e035be6ecc172caef2', 38179408: '3e5e180340bd824c69a2e8245c6a1144de10146b27dd79aab21ea89b6747f56f', 37928512: '6c498001e64142c6bd4521591e2142364f60ba56256a3970a06320d8cf7065c1', 38146320: '9177aa3aec3c15e0a62fca5759f5158d11c77a1aab103bb3a089169957fff2e1', 38124976: 'd65b31bdb0df78e68a6c924b1b6388db8b7459887639f5f7f191cadd09c4a893', 38132816: 'cc073a2c9341c9c0ed5d97732f7941e04eaaa1fe3d3e4f23a8ddf35a1d621ad1', 33705776: 'f031241581f5afae329fc40d9d6d59f33a052f752733088e4e446412227fce2f', 38827984: '035dd1a2ad002d8862becc9061a0d1b2c589a2fef8850ec7ba61658c7f3b332a'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


class Image:
    def __init__(self, data):
        require(digest(data) == SHA, 'target digest mismatch')
        self.data = data
        self.secs = sections(data)
        self.cies, fdes = eh_frame_records(data, self.secs)
        self.fdes = {}
        for f in fdes:
            self.fdes.setdefault(f['start'], []).append(f)
        s = self.section('.rela.dyn')
        require(s['size'] % 24 == 0, 'partial RELA record')
        self.relas = {}
        for off in range(s['offset'], s['offset'] + s['size'], 24):
            va, info, addend = struct.unpack_from('<QQq', data, off)
            require(va not in self.relas, 'duplicate RELA slot')
            self.relas[va] = (info, addend, off)

    def section(self, name):
        rows = [s for s in self.secs if s['name'] == name and s['type'] != 8]
        require(len(rows) == 1, 'missing or ambiguous section')
        return rows[0]

    def offset(self, va, size):
        require(type(va) is int and type(size) is int and va >= 0 and size > 0,
                'invalid requested range')
        matches = [s for s in self.secs if s['type'] != 8 and s['flags'] & 2
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'range not uniquely file backed')
        s = matches[0]
        off = s['offset'] + va - s['address']
        require(off + size <= len(self.data), 'truncated file range')
        return off

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def fde(self, va):
        rows = self.fdes.get(va, [])
        require(len(rows) == 1, 'missing or duplicate FDE')
        f = rows[0]
        text = self.section('.text')
        require(text['address'] <= va < f['end'] <= text['address'] + text['size'],
                'invalid executable FDE interval')
        return f

    def relative(self, slot):
        require(slot in self.relas, 'missing relocation')
        info, addend, _ = self.relas[slot]
        require(info == 8, 'not a symbol-free RELATIVE relocation')
        return addend

    def expect(self, va, hexbytes):
        raw = bytes.fromhex(hexbytes)
        require(self.read(va, len(raw)) == raw, 'byte predicate mismatch')
        return raw


# Restricted x86-64 length/operand decoder. No text disassembler output enters
# the evidence. It rejects unsupported encodings instead of guessing lengths.
# This decodes operands, not effects; it never executes or emulates a function.
def instruction(code, pos):
    start = pos
    prefixes = []
    def take(n):
        nonlocal pos
        require(n > 0 and pos + n <= len(code), 'truncated instruction')
        v = code[pos:pos+n]
        pos += n
        require(pos - start <= 15, 'oversized instruction')
        return v
    while pos < len(code) and (code[pos] in (0x66, 0x2e, 0x64, 0x65, 0xf0, 0xf2, 0xf3)
                              or 0x40 <= code[pos] <= 0x4f):
        prefixes.append(take(1)[0])
    rex = next((p for p in reversed(prefixes) if 0x40 <= p <= 0x4f), 0)
    word = 2 if 0x66 in prefixes else 4
    op = take(1)[0]
    opcode = [op]
    kind = 'ordinary'
    immediate = 0
    relative = False
    modrm_needed = False
    if op in (0xe8, 0xe9, 0xeb) or 0x70 <= op <= 0x7f:
        immediate = 4 if op in (0xe8, 0xe9) else 1
        relative = True
        kind = 'call' if op == 0xe8 else 'jump' if op in (0xe9,0xeb) else 'conditional'
    elif op in (0xc3,0xcc):
        kind = 'return' if op == 0xc3 else 'trap'
    elif 0x50 <= op <= 0x5f or op in (0x90,0x98,0x99):
        pass
    elif 0xb0 <= op <= 0xb7 or op in (0x04,0x0c,0x24,0x2c,0x34,0x3c,0xa8,0x6a):
        immediate = 1
    elif 0xb8 <= op <= 0xbf:
        immediate = 8 if rex & 8 else word
    elif op in (0x05,0x0d,0x25,0x2d,0x35,0x3d,0xa9,0x68):
        immediate = word
    elif op == 0x0f:
        op2 = take(1)[0]
        opcode.append(op2)
        if 0x80 <= op2 <= 0x8f:
            relative, immediate, kind = True, 4, 'conditional'
        elif op2 == 0x0b:
            kind = 'trap'
        elif 0xc8 <= op2 <= 0xcf:
            pass
        elif (0x40 <= op2 <= 0x4f or 0x90 <= op2 <= 0x9f or op2 in
              (0x10,0x11,0x1f,0x28,0x29,0x54,0x55,0x56,0x57,0x60,0x61,0x62,
               0x6c,0x6d,0x6e,0x6f,0x74,0x75,0x76,0x7e,0x7f,0xaf,0xb0,0xb1,
               0xb6,0xb7,0xbc,0xbd,0xbe,0xbf,0xc1,0xd4,0xd6,0xd7,0xdb,0xdf,0xeb,0xef,0xfb)):
            modrm_needed = True
        elif op2 in (0x70,0x71,0x72,0x73,0xba,0xc2,0xc4,0xc5,0xc6):
            modrm_needed, immediate = True, 1
        else:
            raise ValueError('unsupported two-byte opcode')
    elif op in (0x80,0x83,0xc0,0xc1,0xc6,0x6b):
        modrm_needed, immediate = True, 1
    elif op in (0x81,0xc7,0x69):
        modrm_needed, immediate = True, word
    elif op in (0xf6,0xf7,0xfe,0xff,0x63,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8d,
                0xd0,0xd1,0xd2,0xd3) or (op < 0x40 and op % 8 < 4):
        modrm_needed = True
    else:
        raise ValueError('unsupported opcode')
    row = {'kind': kind, 'opcode': bytes(opcode).hex(), 'rex': rex}
    rip_disp = None
    if modrm_needed:
        mr = take(1)[0]
        mod, reg, rm = mr >> 6, (mr >> 3) & 7, mr & 7
        row['modrm'] = mr
        if op == 0xff and reg in (2,4):
            row['kind'] = 'indirect-call' if reg == 2 else 'indirect-jump'
        if op in (0xf6,0xf7) and reg == 0:
            immediate = 1 if op == 0xf6 else word
        displacement = 0
        if mod != 3 and rm == 4:
            sib = take(1)[0]
            row['sib'] = sib
            if mod == 0 and sib & 7 == 5:
                displacement = 4
        elif mod == 0 and rm == 5:
            displacement = 4
            rip_disp = pos
        if mod in (1,2):
            displacement = 1 if mod == 1 else 4
        if displacement:
            row['displacement'] = int.from_bytes(take(displacement), 'little', signed=True)
    if immediate:
        raw = take(immediate)
        row['immediate'] = int.from_bytes(raw, 'little')
        if relative:
            row['target_offset'] = pos + int.from_bytes(raw, 'little', signed=True)
    if rip_disp is not None:
        row['rip_offset'] = pos + struct.unpack_from('<i', code, rip_disp)[0]
    if row['kind'] == 'conditional':
        row['condition'] = opcode[-1] & 15
    row['size'] = pos - start
    row['bytes'] = code[start:pos].hex()
    return row


def decode(code, base):
    rows = []
    pos = 0
    while pos < len(code):
        try:
            row = instruction(code, pos)
        except ValueError as e:
            raise ValueError(f'instruction at {base+pos:#x}: {e}') from e
        row['va'] = base + pos
        for source, dest in [('target_offset','target'),('rip_offset','rip')]:
            if source in row:
                row[dest] = base + row.pop(source)
        rows.append(row)
        pos += row['size']
    boundaries = {r['va'] for r in rows}
    for r in rows:
        if 'target' in r and base <= r['target'] < base + len(code):
            require(r['target'] in boundaries, 'branch into instruction')
    return rows


def tsv(rows, keys):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, keys, delimiter='\t', lineterminator='\n', extrasaction='ignore')
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def js(obj):
    return json.dumps(obj, sort_keys=True, indent=2) + '\n'




WINDOWS = [
    (0x276d870, '4889f84c8b82d80000004531c948833900410f94c141c1e104420fb67409404a8d14094883c230420f104409304a8b7c09304d8b80380200004e894409280f57c9420f114c09308d4ef083f906730748893ac60005c383fe0477f70f1102c60005c3', 'frame variant selects gas offsets; status controls restoration'),
    (0x244f400, '5048034a10702e4889d648894a10488b02482b4208722b48bacdcccccccccccccc48f7e248c1ea024839ca480f43d14889561058c3', 'checked signed refund addition and unsigned one-fifth cap'),
    (0x244f435, '488d3dac3c2503ff15d6ec3103488d3db71b2503ff1501ed3103', 'refund overflow and spent-gas underflow panic edges'),
    (0x2468429, '488bbed80000008b8790020000894424400f1087800200000f2944243083bf78010000010f85ae000000488baf400200004c8baf480200004c8bbf500200004c8ba758020000488b8f90000000488b87a000000048038790010000488b9798000000410f92c048038f800100004c8b8fa8000000481397880100004883d000410f92c24508c24c038f98010000410fb6fa83e7014c01cf4989f84d89e14c39e775214989c04d89f94c39f875164989d04d89e94c39ea750b4989c84989e94839e974314d39c8480f42e94c0f42ea4c0f42f84c0f42e7eb1c488baf400200004c8baf480200004c8bbf500200004c8ba758020000', 'caller address and wrapped four-limb effective price selection'),
    (0x246851d, '488b8ee0000000488d7c2408488d542430e89d85ffff0fb64424083c050f85a60000004c037424280f82dd000000', 'load account then success-tag and gas-add overflow checks'),
    (0x246854b, '4889e849f7e64889d74889c14c89e849f7e64889c64989d04c8b4c24104c89f849f7e64d0fafe64801fe4c11c04911d4490341500f92c249034940491371484883d000400f92c74008d74d8b41584f8d1404400fb6d783e2014c01d2400f92c74d01c472054084ff741c48c7c1ffffffff48c7c6ffffffff48c7c0ffffffff48c7c2ffffffff49894940498971484989415049895158c60305eb33', 'truncated four-limb product and saturating balance addition'),
    (0x24685e6, '8b4c24098b54240c895304894b01488b4c24100fb6542418488b74242048897318488b74241948897311880348894b08885310', 'forward non-success helper result without credit'),
    (0x2468d04, '488baed80000008b85e0000000894424400f1085d00000000f2944243083bd78010000010f85cc0000004c893c244c897424084c8bad400200004c8ba548020000488b9d50020000488b85580200004c8b8590000000488bbd98000000488b95a0000000488b8da80000004c8b8d900100004901d1410f92c34c8b95800100004d01c24c8bb5880100004911fe4983d100410f92c74508df4c8b9d980100004901cb410fb6ef83e5014c01dd4989eb4989c74839c575214d89cb4989df4939d975164d89f34d89e74d39e6750b4d89d34d89ef4d39ea74134d39fb4d0f42ea4d0f42e6490f42d9480f42c54c8b7424084c8b3c24eb384c8bad400200004c8ba548020000488b9d50020000488b85580200004c8b8590000000488bbd98000000488b95a0000000488b8da8000000', 'beneficiary address and effective price selection'),
    (0x2468e32, '4889c54829cd4d29c54919fc4819d34883dd000f92c24839c8720484d2740a31ed31db4531e44531ed', 'effective tip subtracts base fee with zero saturation'),
    (0x2468e5b, '488b8ee0000000488d7c2410488d542430e85f7cffff0fb64424103c050f85bb0000004c8b54241841808ab000000004498b3f492b7f080f82e7000000492b7f100f82ea000000', 'load account, touch bit before two checked gas subtractions'),
    (0x2468ea2, '4889f849f7e54989d04889c14889f849f7e44989d14889c64889f848f7e3480fafef4c01c64c11c84811d5490342500f92c249034a40491372484d8b42584883d000400f92c74008d74d8d0c28400fb6d783e2014c01ca400f92c74c01c572054084ff741c48c7c1ffffffff48c7c6ffffffff48c7c0ffffffff48c7c2ffffffff49894a4049897248498942504989525841c60605eb37', 'tip product and saturating credit stores'),
    (0x2468f39, '8b4c24118b5424144189560441894e01488b4c24180fb6542420488b74242849897618488b7424214989761141880649894e08418856104883c4485b415c415d415e415f5dc3488d3d1ae02403ff15c4513003488d3d25e02403ff15b7513003', 'non-success forwarding, normal return, gas panic tails'),
    (0x2460aed, '4883c6308b421089842470010000f30f6f02660f7f842460010000488dbc24a0000000488d942460010000e853383600488b9c24a00000004885db0f8492010000', 'twenty-byte account key to external entry helper'),
    (0x2460b7d, '488d9424600100004889eee86346b0ff', 'private database boundary'),
    (0x2460c03, '4883fd050f85d6000000488dbc24a0000000ff154d263103', 'backend tag five selects external default account builder'),
    (0x2460cc0, '488b8424a8000000488d9848ffffff0fb648f8f6c1100f855703000031c0e931030000', 'occupied account and cold-bit decision'),
    (0x2460ece, '498dbf800000004c89f6e813453600', 'new account address inserted into context address set'),
    (0x2460f34, '49c1ed39488d72f04821c645882c1445886c341080e1010fb6c14829431048f7da4c69ead00000004b89bc2c30ffffff488b4424104b89842c38ffffff8b4424184389842c40ffffff4b8d3c2c4881c744ffffff488db424a0000000babc000000ff1545d0300348ff43184b8d1c2c4881c348ffffff4084ed740931c04c8b6c2408eb5c', 'publish bucket controls key account payload and count'),
    (0x2460fb8, '4c8b6c2408498b4f284885c9747c498b4720488d0c494c8d3cc84c8b64c8f84c3b64c8e8750e488d3cc84883c7e8ff1584223103498b47f0496bcc58c6040800f3410f6f06f30f7f440801418b56108954081149ffc44d8967f8b00149895d084188451041c64500054881c4a80200005b415c415d415e415f5dc380e1ef8848f8498b4f284885c97584', 'append tag-zero journal record and return tag five'),
    (0x2461110, '554157415641554154534883ec184889f348b9447370032e8a191364488b042588faffff4831c8488d4c240848f7e14889c14989fe4831d148bad0319f29223809a44889c848f7e24989d46448890c2588faffff4931c44c89642408488b056dd230030fb640203c020f85c90100004c8d6b58488b73604885f6742e', 'reset helper seed derivation and transient allocation check'),
    (0x24611ba, '0f1005b75b2403410f1145100f10059b5b2403410f1145004c896378bf18000000ff15f7cd30034885c00f84790100004989c44c8974241048c7000000000048c740080800000048c7401000000000', 'reset transient header and allocate single journal frame'),
    (0x2461230, '4983c71848ffcd7417498b47f84885c074ee498b3f486bf05831d241ffd6ebe0488b43184885c0741348c1e003488d34404c89ef31d2ff15a4cd300348c74318010000004c89632048c743280100000048c783a800000000000000', 'release frame allocations and reset depth'),
    (0x24612df, '488b4350498947200f1043300f104b40410f114f10410f11070f1005795a24030f1143400f10055e5a24030f11433048895350488b4310498947380f1003410f11472848c7030000000048c743080800000048c74310000000004883c4185b415c415d415e415f5dc3', 'move account map and logs into output; reset context headers'),
    (0x2469267, '0fb686b8000000c686b8000000053c057573498b042431c94885c00f94c1c1e1044d8b6c0c284d2b6c0c300f826e0400004d8b740c384d29f50f8269040000', 'take pending context error before checked net gas computation'),
    (0x24692ec, '0f1086b90000000f108ec8000000410f114f18410f1147094188470848b800000000000000804883c80249890731c049833c24000f94c0c1e0044a8b4c20084a8b742010488b49204a8d3c204883c7204a8b5420184881c4480100005b415c415d415e415f5dffe1', 'pending context error result and frame payload tail destruction'),
    (0x24693dc, '488dbc2408010000e8277dffff49bc0000000000000080488b84242801000048898424b00000000f108424080100000f108c24180100000f298c24a00000000f29842490000000488b84244001000048894424700f108424300100000f294424608bbc24f8000000e8f729fcff0fb6c8488d350595f7fd48630c8e4801f1ffe1', 'drain context then classify raw instruction status'),
    (0x246945c, '0fb6442470488b4c24100fb6742418488b7c24200f28442460410f1107418847108b442471448b442474418947114589471449894f18418877208b4424198b4c241c4189472141894f2449897f280f10030f104b10410f114730410f114f404d896f504d897758418857600f288424900000000f288c24a0000000410f114768410f114f78488b8424b0000000498987880000004531f6e941010000', 'success layout retains logs output gas and reason'),
    (0x24694f8, '49ffc441b6014c89eeeb62', 'halt sentinel and output-drop flag'),
    (0x2469503, '488d7c2421488d4424314c8d442441f644241001480f45f84c0f44c08b5424308b4424400f44c2488b742428488b4c2438480f44ce0f44542420480f44742418448b0f8b7f0344894c2450897c2453418b38458b4003897c2448448944244b4531f64d892749897708418857108b5424508b742453418957114189771449894f18418847208b4424488b4c244b4189472141894f244d896f28488b8424b0000000498987880000000f288424900000000f288c24a0000000410f114f78410f1147684c8b6424684c8b7c2470', 'revert layout and shared account-state transfer'),
    (0x24695e0, '498b4518498b7520498d7d30498b55284983c55049ffcfff50204983ff017417498b75004885f674d7498b7d0848c1e60531d2ffd5ebc9488b4424604885c0741348c1e004488d34804c89e731d2ff15dc493003', 'non-success log destruction and allocation release'),
    (0x2469639, '488b8424c0000000488bb424c8000000488dbc24d8000000488b9424d0000000ff50204584f67432807c24100074124889d84889e9488d5c2438488d7c2440eb0d488d4424184889ef488d4c2420488b00488b31488b13ff50204881c4480100005b415c415d415e415f5dc3', 'frame destruction and halt-only output destruction'),
    (0x24696a5, '8844240e8854240f488d44240e4889842408010000488d054faa04004889842410010000488d8424c00000004889842418010000488d05e08d04004889842420010000488d3d1a14d8fd488d15f2d82403488db42408010000ff1594493003eb16488d3d93d82403eb07488d3dbad82403ff15344a30030f0b', 'unexpected classification diagnostic and underflow traps'),
]
VTABLE_EXPECTED = {0x56bfa40: 0x276d870, 0x56a7b98: 0x244f400, 0x56a7bc8: 0x244f490, 0x56a7bf8: 0x244f4d0, 0x56a6e18: 0x244f6c0}
VTABLES = {90962496: 'final-frame gas', 90864536: 'refund', 90864584: 'caller reimbursement', 90864632: 'beneficiary reward', 90861080: 'final output'}
LOCATIONS = [90845416, 90836992, 90926984, 90927008, 90927032, 90927056, 90927080, 90860880]
TABLE_HASHES = {(4070624, 108): 'fc309e5fa3df5dee8ca28513025c9b744edd32df98e4935e61f516212aa980bd', (4073816, 5): '7698f02ad6eb09363342c720157bdaacf73df8cf6be262c8c56830741b81afcb'}

U64 = (1 << 64) - 1
U256 = (1 << 256) - 1


def unsigned(value, bits):
    require(type(value) is int and 0 <= value < 1 << bits, 'unsigned model input out of range')
    return value


def normalize_gas(status, limit, remaining, refund):
    """Arithmetic model of the fixed final-frame window, not machine execution."""
    unsigned(status, 8)
    for value in (limit, remaining, refund): unsigned(value, 64)
    if status <= 4:
        return {'limit': limit, 'remaining': remaining, 'refund': refund}
    if 16 <= status < 22:
        return {'limit': limit, 'remaining': remaining, 'refund': 0}
    return {'limit': limit, 'remaining': 0, 'refund': 0}


def cap_refund(limit, remaining, refund, extra):
    for value in (limit, remaining, refund): unsigned(value, 64)
    require(type(extra) is int and -(1 << 63) <= extra < 1 << 63, 'signed extra refund out of range')
    signed = refund if refund < 1 << 63 else refund - (1 << 64)
    total = signed + extra
    if not -(1 << 63) <= total < 1 << 63:
        return {'failure': 'signed-refund-overflow', 'refund': refund}
    raw = total & U64
    if remaining > limit:
        return {'failure': 'spent-underflow', 'refund': raw}
    return {'failure': None, 'refund': min(raw, (limit - remaining) // 5)}


def effective_price(cap, base, priority, priority_tag):
    for value in (cap, base, priority): unsigned(value, 256)
    unsigned(priority_tag, 32)
    return min(cap, (base + priority) & U256) if priority_tag == 1 else cap


def credit_balance(balance, price, gas):
    unsigned(balance, 256); unsigned(price, 256); unsigned(gas, 64)
    product = (price * gas) & U256
    return min(U256, balance + product)


def settlement(status, limit, remaining, refund, extra, cap, base, priority,
               priority_tag, sender_balance, beneficiary_balance):
    gas = normalize_gas(status, limit, remaining, refund)
    capped = cap_refund(**gas, extra=extra)
    result = {'normalized': gas, 'cap_result': capped}
    if capped['failure']: return result
    final_refund = capped['refund']
    if gas['remaining'] + final_refund > U64:
        result['failure'] = 'caller-credit-gas-overflow'
        return result
    price = effective_price(cap, base, priority, priority_tag)
    tip = max(0, price - base)
    used = limit - gas['remaining'] - final_refund
    require(used >= 0, 'model cap invariant violated')
    result.update(price=price, tip=tip, gas_used=used, gas_refund=final_refund,
                  caller_balance=credit_balance(sender_balance, price, gas['remaining'] + final_refund),
                  beneficiary_balance=credit_balance(beneficiary_balance, tip, used),
                  beneficiary_flag_or=4, failure=None)
    return result


def branch_table(im, base, count, owner, decoded):
    dispatch = {0x242be40: (0x242be46, 0x242be54), 0x2469250: (0x246944c, 0x246945a)}
    lea, jump = dispatch[owner]
    by_va = {r['va']: r for r in decoded[owner]}
    require(by_va[lea].get('rip') == base and by_va[jump]['kind'] == 'indirect-jump',
            'table is not bound to the selected RIP operand and dispatch')
    raw = im.read(base, count * 4)
    require(digest(raw) == TABLE_HASHES[(base, count)], 'branch table bytes changed')
    boundaries = {r['va'] for r in decoded[owner]}
    result = []
    for i in range(count):
        delta = struct.unpack_from('<i', raw, i * 4)[0]
        target = base + delta
        require(target in boundaries, 'table target outside admitted instruction boundaries')
        result.append({'index': i, 'slot_va': hex(base + i * 4), 'raw': raw[i*4:i*4+4].hex(),
                       'delta': delta, 'target_va': hex(target)})
    return result


def classifier_terminal(im, target, status):
    """Read constant-return byte shapes; no x86 interpreter or emulator."""
    end = im.fde(0x242be40)['end']
    require(0x242be40 <= target < end, 'classifier target outside function')
    raw = im.read(target, min(10, end-target))
    if raw.startswith(b'\x0f\x0b'):
        return {'category': None, 'reason': None, 'terminal': 'ud2', 'bytes': '0f0b'}
    # Each terminal consists solely of constant writes, then mov edx,edi;ret.
    category, reason, pos = 4, status, 0
    while not raw[pos:].startswith(bytes.fromhex('89fac3')):
        if raw[pos:pos+1] == b'\xb0' and pos+2 <= len(raw):
            category=raw[pos+1];pos+=2
        elif raw[pos:pos+2] == bytes.fromhex('40b7') and pos+3 <= len(raw):
            reason=raw[pos+2];pos+=3
        elif raw[pos:pos+2] == bytes.fromhex('31c0'):
            category=0;pos+=2
        elif raw[pos:pos+2] == bytes.fromhex('31ff'):
            reason=0;pos+=2
        else: raise ValueError('unsupported classifier terminal shape')
    require(category <= 4, 'unexpected result category')
    return {'category': category, 'reason': reason, 'terminal': 'return', 'bytes': raw[:pos+3].hex()}


def classify(im, status, decoded):
    unsigned(status,8)
    require(status < 108, 'outside selected classifier table window')
    rows=branch_table(im,0x3e1ce0,108,0x242be40,decoded)
    return classifier_terminal(im,int(rows[status]['target_va'],16),status)


def exception_sites(im, start, rows):
    f=im.fde(start)
    if not f['lsda']: return [], None
    va=f['lsda'];off=im.offset(va,1);sec=im.section('.gcc_except_table')
    end=sec['offset']+sec['size'];d=im.data;pos=off
    require(sec['offset']<=off<end,'LSDA outside exception section')
    require(d[pos]==255,'unsupported LSDA landing-pad base');pos+=1
    require(pos<end,'truncated LSDA type encoding');enc=d[pos];pos+=1;type_base=None
    if enc!=255:
        require(enc==155,'unsupported LSDA type encoding')
        delta,pos=uleb(d,pos,end);type_base=pos+delta
        require(type_base<=end,'type base outside section')
    require(pos<end and d[pos]==1,'unsupported call-site encoding');pos+=1
    size,pos=uleb(d,pos,end);limit=pos+size
    require(limit<=end and (type_base is None or limit<=type_base),'call-site table outside bounds')
    boundaries={r['va'] for r in rows}|{f['end']};out=[];previous=0
    while pos<limit:
        record=pos;lo,pos=uleb(d,pos,limit);size,pos=uleb(d,pos,limit)
        landing,pos=uleb(d,pos,limit);action,pos=uleb(d,pos,limit)
        require(lo>=previous and start+lo+size<=f['end'],'invalid exception interval')
        previous=lo+size
        require(start+lo in boundaries and start+lo+size in boundaries,'exception endpoint not an instruction boundary')
        require(not landing or start+landing in boundaries-{f['end']},'invalid landing pad')
        out.append(dict(function_va=hex(start),lsda_va=hex(va),record_file_offset=hex(record),
                        range_start=hex(start+lo),range_end=hex(start+lo+size),
                        landing_pad=hex(start+landing) if landing else '',action=action,raw=d[record:pos].hex()))
    return out,dict(function_va=hex(start),lsda_va=hex(va),raw_prefix=d[off:type_base or limit].hex(),
                   scope='Call-site intervals only; action chains and personality behavior unresolved.')


def validate_windows(im, decoded):
    boundaries={r['va'] for rows in decoded.values() for r in rows}
    ends={im.fde(a)['end'] for a in FUNCTIONS}
    result=[]
    for va,raw,label in WINDOWS:
        b=im.expect(va,raw)
        require(va in boundaries and va+len(b) in boundaries|ends,'semantic window splits instruction')
        result.append(dict(start_va=hex(va),end_va=hex(va+len(b)),bytes=raw,observation=label))
    return result


def arithmetic_cases():
    cases=[]
    for status in (2,16,21,22,83,96):
        for extra in (0,19,20001):
            args=dict(status=status,limit=100000,remaining=98000,refund=7,extra=extra,
                      cap=100,base=30,priority=5,priority_tag=1,sender_balance=1000,beneficiary_balance=2000)
            cases.append(dict(input=args,output=settlement(**args)))
    for refund,extra,limit,remaining in [(0,-1,10,0),(U64,1,10,0),((1<<63)-1,1,10,0),
                                      (1<<63,-1,10,0),(0,1,10,11),(0,0,U64,0),(5,0,24,0),(5,0,25,0)]:
        args=dict(limit=limit,remaining=remaining,refund=refund,extra=extra)
        cases.append(dict(input=args,output=cap_refund(**args)))
    return cases


FIELD_SITES = {
    0x276d873: 'context environment pointer',
    0x276d889: 'frame instruction-status byte; index offset selected by frame tag',
    0x276d8a2: 'environment transaction gas limit',
    0x276d8a9: 'replace frame gas limit; index offset selected by frame tag',
    0x276d8b1: 'zero frame remaining and refund; indexed sixteen-byte store',
    0x244f401: 'signed refund input',
    0x244f40a: 'store signed refund sum before spent-gas subtraction',
    0x244f411: 'subtract remaining from gas limit',
    0x244f42f: 'store capped refund',
    0x2468429: 'context environment pointer',
    0x2468430: 'caller address final four bytes',
    0x246843a: 'caller address first sixteen bytes',
    0x2468446: 'priority-fee presence discriminant equals immediate one',
    0x2468453: 'fee cap low limb',
    0x246846f: 'base fee low limb',
    0x246848f: 'priority fee low limb',
    0x246851d: 'private database pointer',
    0x24685d1: 'caller balance limb zero',
    0x24685d5: 'caller balance limb one',
    0x24685d9: 'caller balance limb two',
    0x24685dd: 'caller balance limb three',
    0x2468d0b: 'beneficiary address final four bytes',
    0x2468d15: 'beneficiary address first sixteen bytes',
    0x2468e83: 'beneficiary account flags OR immediate four',
    0x2460c03: 'backend absent discriminator comparison',
    0x2460cb3: 'default installed account flags',
    0x2460ec6: 'present installed account flags',
    0x2460f55: 'account bucket stride multiplier',
    0x2460f9b: 'increment account table occupied count',
    0x2460ff0: 'journal entry stride multiplier',
    0x2460ff4: 'journal entry tag zero',
    0x2461014: 'success output account pointer',
    0x2461018: 'success output cold-access boolean',
    0x246101c: 'success output discriminator five',
    0x246126c: 'reset journal outer capacity to one',
    0x2461278: 'reset journal outer length to one',
    0x2461280: 'reset call depth to zero',
    0x24612e3: 'drained account map seed destination',
    0x246130e: 'replacement context account map seed',
    0x2461316: 'drained log length destination',
    0x2461322: 'reset context log capacity',
    0x2461329: 'reset context log pointer to alignment sentinel',
    0x2461331: 'reset context log length',
    0x2469267: 'take pending context error discriminator',
    0x246926e: 'reset pending context error discriminator to five',
    0x24694bb: 'success output net gas used',
    0x24694bf: 'success output refund',
    0x24694c3: 'success output reason',
    0x2469565: 'revert or halt output sentinel',
    0x2469568: 'revert output capacity or halt net gas used',
    0x246956c: 'revert output ownership byte or halt reason',
}


def field_operands(decoded):
    by_va={r['va']:r for rows in decoded.values() for r in rows}
    result=[]
    for va,label in sorted(FIELD_SITES.items()):
        r=by_va[va]
        require('displacement' in r or 'immediate' in r or r.get('modrm',255) < 192,'missing selected encoded operand')
        result.append(dict(va=hex(va),bytes=r['bytes'],displacement=r.get('displacement',0 if r.get('modrm',255)<192 else ''),
                           immediate=r.get('immediate',''),inferred_role=label))
    return result


FAILURE_SITES = {
    0x244f405: ('signed refund overflow', []),
    0x244f415: ('spent gas underflow after refund sum is stored', [0x244f40a]),
    0x246853a: ('non-five account result forwarding guard', []),
    0x2468545: ('remaining plus refund unsigned overflow', []),
    0x24685ae: ('balance saturation on high-limb carry', []),
    0x2468e4b: ('tip subtraction saturation from high limb', []),
    0x2468e78: ('non-five beneficiary account result forwarding guard', []),
    0x2468e92: ('limit minus remaining underflow after touch', [0x2468e83]),
    0x2468e9c: ('spent minus refund underflow after touch', [0x2468e83]),
    0x2468f00: ('beneficiary balance saturation on high-limb carry', [0x2468e83]),
    0x2460fc4: ('missing journal frame panic after new account publication', [0x2460f9b]),
    0x24611e4: ('empty journal allocation null after transient-header reset', [0x24611d2]),
    0x2469277: ('forward taken context error before state drain', [0x246926e]),
    0x2469292: ('output limit minus remaining underflow after error reset', [0x246926e]),
    0x24692a0: ('output spent minus refund underflow after error reset', [0x246926e]),
}


def failure_ledger(decoded):
    by_va={r['va']:r for rows in decoded.values() for r in rows}
    names=('overflow','not-overflow','below','above-or-equal','equal','not-equal','below-or-equal','above',
           'sign','not-sign','parity','not-parity','less','greater-or-equal','less-or-equal','greater')
    result=[]
    for va,(label,writes) in sorted(FAILURE_SITES.items()):
        r=by_va[va]
        require(r['kind']=='conditional','failure gate is not a conditional branch')
        result.append(dict(va=hex(va),bytes=r['bytes'],condition=names[r['condition']],
            taken=hex(r['target']),fallthrough=hex(va+r['size']),inferred_trigger=label,
            same_path_prior_writes=[dict(va=hex(w),bytes=by_va[w]['bytes']) for w in writes]))
    return result


def collect(im):
    decoded={};functions=[];bodies={};instructions=[];controls=[];riprefs=[];relocslots=set();unwind=[]
    for start,role in sorted(FUNCTIONS.items()):
        f=im.fde(start);b=im.read(start,f['end']-start)
        require(digest(b)==BODY_HASHES[start],'admitted function body changed')
        rows=decode(b,start);decoded[start]=rows;bodies[hex(start)]=b.hex()
        functions.append(dict(start_va=hex(start),end_va=hex(f['end']),bytes=len(b),file_offset=hex(im.offset(start,len(b))),
                              fde_va=hex(f['fde']),cie_va=hex(f['cie']),lsda_va=hex(f['lsda']) if f['lsda'] else '',
                              sha256=digest(b),instruction_rows=len(rows),inferred_role=role))
        for record in (f['fde'],f['cie']):
            n=struct.unpack('<I',im.read(record,4))[0]
            unwind.append(dict(function_va=hex(start),record_va=hex(record),bytes=im.read(record,n+4).hex()))
        for r in rows:
            instructions.append(dict(function_va=hex(start),va=hex(r['va']),bytes=r['bytes'],kind=r['kind'],
                                     target=hex(r['target']) if 'target'in r else '',rip=hex(r['rip']) if 'rip'in r else ''))
            if 'rip' in r:
                slot=r['rip'];relocslots.add(slot)
                riprefs.append(dict(function_va=hex(start),va=hex(r['va']),operand_va=hex(slot),bytes=r['bytes']))
            if r['kind']!='ordinary':
                dest=r.get('target');slot=None
                if r['kind'].startswith('indirect') and 'rip'in r:
                    slot=r['rip']
                    if slot in im.relas and im.relas[slot][0]==8: dest=im.relative(slot)
                controls.append(dict(function_va=hex(start),va=hex(r['va']),bytes=r['bytes'],kind=r['kind'],
                                     target=hex(dest) if dest is not None else '',slot=hex(slot) if slot else '',
                                     fallthrough=hex(r['va']+r['size']) if r['kind'] in ('conditional','call','indirect-call') else ''))
    windows=validate_windows(im,decoded)
    status_table=branch_table(im,0x3e1ce0,108,0x242be40,decoded)
    output_table=branch_table(im,0x3e2958,5,0x2469250,decoded)
    for row in status_table:
        row.update(classifier_terminal(im,int(row['target_va'],16),row['index']))
        row['output_branch_va']=output_table[row['category']]['target_va'] if row['category'] is not None else ''
    vtables=[]
    for va,role in sorted(VTABLES.items()):
        raw=im.read(va,48);words=struct.unpack('<6Q',raw)
        require(words[:3]==(0,0,1),'unexpected zero-sized callback vtable layout')
        methods=[]
        for offset in (24,32,40):
            relocslots.add(va+offset);methods.append(hex(im.relative(va+offset)))
        require(int(methods[-1],16)==VTABLE_EXPECTED[va],'borrowed callback binding changed')
        vtables.append(dict(va=hex(va),bytes=raw.hex(),role=role,drop=words[0],size=words[1],alignment=words[2],
                            consuming=methods[0],mutable=methods[1],borrowed=methods[2]))
    locations=[]
    for va in LOCATIONS:
        raw=im.read(va,24);length,line,column=struct.unpack('<QII',raw[8:]);ptr=im.relative(va);relocslots.add(va)
        path=im.read(ptr,length);parts=path.decode('ascii').split('/')
        index=next(i for i,p in enumerate(parts) if p.startswith('revm-'))
        locations.append(dict(va=hex(va),bytes=raw.hex(),path_va=hex(ptr),path_bytes=path.hex(),
                              source_suffix='/'.join(parts[index:]),line=line,column=column))
    # Constants used in the context reset and account default-map header.
    constants=[]
    for va,size in ((0x56a6d68,32),(0x574fbc0,32)):
        constants.append(dict(va=hex(va),bytes=im.read(va,size).hex()))
        for slot in range(va,va+size,8): relocslots.add(slot)
    relocs=[]
    for slot in sorted(relocslots & im.relas.keys()):
        info,addend,off=im.relas[slot]
        relocs.append(dict(slot_va=hex(slot),info=hex(info),addend=hex(addend),file_offset=hex(off),raw=im.data[off:off+24].hex()))
    sites=[];lsdas=[]
    for a,rows in sorted(decoded.items()):
        ss,header=exception_sites(im,a,rows);sites+=ss
        if header: lsdas.append(header)
    external=[]
    table_sites={0x242be54,0x246945a}
    for row in controls:
        if row['kind'] not in ('call','jump','indirect-call','indirect-jump'): continue
        dest=int(row['target'],16) if row['target'] else None
        if dest is not None and any(a<=dest<im.fde(a)['end'] for a in FUNCTIONS): continue
        state='table-bound' if int(row['va'],16) in table_sites else 'dynamic' if dest is None else 'external'
        external.append(dict(row,closure=state))
    outputs={
        'field-operands.tsv':tsv(field_operands(decoded),['va','bytes','displacement','immediate','inferred_role']),
        'functions.tsv':tsv(functions,list(functions[0])),
        'instructions.tsv':tsv(instructions,list(instructions[0])),
        'control-flow.tsv':tsv(controls,list(controls[0])),
        'external-edges.tsv':tsv(external,list(external[0])),
        'rip-references.tsv':tsv(riprefs,list(riprefs[0])),
        'function-bytes.json':js(bodies), 'unwind-records.json':js(unwind),
        'failure-paths.json':js(failure_ledger(decoded)),'semantic-windows.json':js(windows),'status-table.json':js(status_table),
        'output-table.json':js(output_table),'callback-vtables.json':js(vtables),
        'source-locations.json':js(locations),'data-constants.json':js(constants),
        'relocations.json':js(relocs),'exception-sites.json':js(sites),'exception-prefixes.json':js(lsdas),
        'arithmetic-cases.json':js(arithmetic_cases()),
        'gas-status-cases.tsv':tsv([dict(status=i,**normalize_gas(i,100000,98000,7)) for i in range(256)],['status','limit','remaining','refund']),
    }
    outputs['summary.json']=js(dict(target_sha256=SHA,functions=len(functions),code_bytes=sum(r['bytes'] for r in functions),
        instruction_rows=len(instructions),control_rows=len(controls),external_sites=sum(r['closure']=='external' for r in external),
        dynamic_sites=sum(r['closure']=='dynamic' for r in external),table_bound_sites=len(table_sites),
        exception_sites=len(sites),failure_gates=len(FAILURE_SITES),semantic_windows=len(windows),status_table_window=len(status_table),
        table_trap_entries=sum(r['terminal']=='ud2' for r in status_table),callback_vtables=len(vtables),
        scope='Selected post-call callback bodies only; prior constructor, lookup and compression bodies excluded.'))
    return outputs


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    image=Image((ROOT/'artifacts'/'node'/'94'/'hl-node').read_bytes())
    outputs=collect(image)
    args.out.mkdir(parents=True,exist_ok=True)
    for name,content in sorted(outputs.items()):
        (args.out/name).write_bytes(content.encode('ascii'))


if __name__=='__main__': main()
