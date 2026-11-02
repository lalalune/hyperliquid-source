#!/usr/bin/env python3
"""Static node94 private-precompile installation evidence. MIT license.

The byte-shape reader is deliberately restricted to the selected, digest-bound
bodies. It is not a general x86 disassembler or an instruction interpreter.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / 'tools') not in sys.path:
    sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records, uleb

DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TARGET = ROOT / 'artifacts/node/94/hl-node'
# These are selection seeds, validated against actual FDEs and complete bytes.
FUNCTIONS = {
    0x2464bd0: 'revision byte to handler table and canonical revision',
    0x247fd20: 'adapter setup and revision-change hook replay; downstream transaction semantics unresolved',
    0x24b6590: 'borrowed hook reinstalls captured-revision factory',
    0x25154a0: 'factory consumption and context-map publication; later transaction semantics unresolved',
    0x25b6ca0: 'derive address set from owned or borrowed registry',
    0x2048200: 'copy full keys from forty-eight-byte map buckets',
    0x26b8980: 'consume address set into context address set',
    0x27c7e10: 'insert or recognize full twenty-byte address',
    0x202cf90: 'release consuming set iterator storage',
    0x20249e0: 'release temporary address set storage',
    0x244FE00: 'install captured-revision registry factory',
    0x244FD00: 'consuming factory adapter',
    0x24448A0: 'materialize registry and private records',
    0x247D7F0: 'retain twenty callback references',
    0x2456680: 'release twenty callback references',
    0x25B6E20: 'borrowed registry to owned map',
    0x26BA880: 'initialize owned-map seed and copy entries',
    0x20482C0: 'clone borrowed entries by value tag',
    0x26BA640: 'extend owned map with twenty records',
    0x27C9190: 'insert or replace one full address key',
    0x277C590: 'release replaced value',
    0x258D300: 'release unconsumed array elements',
    0x25B3780: 'release one private key-value record',
    0x4890F10: 'reserve or rehash owned map',
    0x488EF00: 'allocate raw bucket storage',
    0x2025340: 'release partially constructed map',
    0x1FA3F30: 'release replaced value during borrowed copy',
}
# Filled from authenticated bytes during research; not generated from binutils.
BODY_PINS = {
    0x1fa3f30: (248, '62af837111550c87e46aa0e1919fbc1c8a8917628c2aa77477452ab3bf256114'),
    0x2025340: (224, 'c639a657eac867ec51bd8faeea3427b9e43c3bf3a373037a224ece8005e773b1'),
    0x20482c0: (361, '32cc0807b0c19456d29c9142805835bd1af86a6df34746528541cc3d00175d03'),
    0x24448a0: (2482, 'd9cf7a5b19d7c6f4c8294b9d69d8ee30dcf68a4f556ba5b747a32c72a42b590a'),
    0x244fd00: (59, '04f7685faea058294f20f10f006f68bd46d2360797fbc23b09874dacbcbf42d6'),
    0x244fe00: (223, '63f689637cbc6d2e33b28eae5077680e82e7380cabbb04f0dcee95a4624e1640'),
    0x2456680: (1000, 'bbf707a04efe1bcc160e65d0b94f9469ceea870b520d61024c5a7df819b50f54'),
    0x2464bd0: (14387, '5c9b0664396faf51bd59ef508242a0a3a48a5a3609bcd83ca69b64f0e1cce323'),
    0x247d7f0: (483, '44b57644e6602b8057579e4c397a718d612e1a9cc0436492b0b8dd64b8b24ad1'),
    0x258d300: (116, '950254db3a2db5184f6b4833c170bb26abd68d07a1a1088ab488f66132c7ed50'),
    0x25b3780: (249, '309437e31777e3f0e2843c2cc8303d8b5f6312223241958b2a3645139410b961'),
    0x25b6e20: (121, '69f5f24ae8d21e846300c8a25704118d62cec37c65a503293166cdde8c0b6537'),
    0x26ba640: (337, 'c4d80a1bd19ad29ef1f8b61c62becc44844692e3f1ace1fe3b8554879948516f'),
    0x26ba880: (279, 'ffb915a0b136e4e87d57412a2fc61d8a6afa49be39d18bc36c380a88216a0adb'),
    0x277c590: (248, '385a073bb549943d35ba69e219d83632ec7d9ce21c72d20b455f23327182744f'),
    0x27c9190: (625, '18d2d93decdf9887846b7fa3de0fb12d2467f4398234e5063775ba9078c1a2c9'),
    0x488ef00: (425, 'f3b432f7149dd62f3c4e3732c92c90ad3e9b68317881c7f4ea2c8f00b893da1d'),
    0x4890f10: (1484, '9613ef242595fc059ec4f3237897796213eb574ba64284d482753cba2b86ffca'),
    0x247fd20: (4564, 'd22c71b38ebfeac9beaa120c30e940261f54f5efb763d160e6fd523fb7466e7f'),
    0x24b6590: (223, '2c386f01f3fd76efe085e29999e3b907cf553d8fc8a8258942aacd40aed41c73'),
    0x25154a0: (8374, '7ea244e306bc64cc01515324073b104ea082615c86bd5d8d6c3e5316378e620c'),
    0x25b6ca0: (374, 'a562539cb4ec3b4c7d6cd7ad7cb8c1486b628a01cef5b42bdead80882a6b0583'),
    0x2048200: (189, '4e1f3002294d366e65d72c4442100c7daada304ac10c291fbeae65e47d41b5fb'),
    0x26b8980: (545, '5608827fdf58787198e2a4472fb18cb981913126b79df6affdb50581f8e8e0a7'),
    0x27c7e10: (487, '264a82824314bcddfcbd3d09e4f53e8832302483a1fbfa0ca0747a9e0e754671'),
    0x202cf90: (48, '04d991b6dea3bfd0947bce0d3d4c446d7609fb80b834ce95294ec8125bd9cda0'),
    0x20249e0: (59, '8860bb4e747e20e0689ef3f509de64d59bae65fcc8ef97384dca7ca70210b3d5'),
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


class Image:
    def __init__(self, data):
        require(hashlib.sha256(data).hexdigest() == DIGEST, 'target digest mismatch')
        self.data = data
        self.secs = sections(data)
        names = [s['name'] for s in self.secs]
        require(len(names) == len(set(names)), 'duplicate section names')
        self.cies, self.fdes = eh_frame_records(data, self.secs)
        starts = [f['start'] for f in self.fdes]
        require(len(starts) == len(set(starts)), 'duplicate FDE starts')
        self.by_start = {f['start']: f for f in self.fdes}
        rela = next(s for s in self.secs if s['name'] == '.rela.dyn')
        require(rela['type'] == 4 and rela['size'] % 24 == 0, 'invalid RELA section')
        self.relocs = {}
        for i in range(0, rela['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, rela['offset'] + i)
            require(slot not in self.relocs, 'duplicate relocation slot')
            self.relocs[slot] = (info, addend, rela['offset'] + i)

    def offset(self, va, size):
        require(type(va) is int and type(size) is int and va >= 0 and size > 0, 'invalid range')
        matches = [s for s in self.secs if s['type'] != 8 and s['flags'] & 2
                   and s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'range is not uniquely file-backed')
        s = matches[0]
        return s['offset'] + va - s['address']

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def relocation(self, slot):
        require(slot in self.relocs, 'missing relocation')
        info, addend, offset = self.relocs[slot]
        require(info == 8, 'expected symbol-free R_X86_64_RELATIVE')
        return addend

    def body(self, start):
        require(start in self.by_start, 'missing selected FDE')
        f = self.by_start[start]
        blob = self.read(start, f['end'] - start)
        require(any(s['flags'] & 4 and s['type'] != 8 and s['address'] <= start
                    and f['end'] <= s['address'] + s['size'] for s in self.secs), 'non-code FDE')
        if BODY_PINS:
            require((len(blob), hashlib.sha256(blob).hexdigest()) == BODY_PINS[start], 'body pin mismatch')
        return f, blob


# Full linear traversal including padding and landing pads. Each returned shape
# records its original bytes; relative fields are calculated only after bounds.
def decode(blob, base):
    rows = []
    p = 0
    while p < len(blob):
        start = p
        prefixes = []
        rex = 0
        while p < len(blob) and (blob[p] in (0x66, 0xF2, 0xF3, 0xF0, 0x2E, 0x64, 0x65)
                                or 0x40 <= blob[p] <= 0x4F):
            b = blob[p]; prefixes.append(b); p += 1
            if 0x40 <= b <= 0x4F: rex = b
        require(p < len(blob), 'truncated opcode')
        op = blob[p]; p += 1
        op2 = None
        modrm = False
        imm_size = 0
        relative = False
        kind = 'ordinary'
        if op == 0x0F:
            require(p < len(blob), 'truncated two-byte opcode')
            op2 = blob[p]; p += 1
            if 0x80 <= op2 <= 0x8F:
                imm_size = 4; relative = True; kind = 'conditional'
            elif op2 == 0x0B: kind = 'trap'
            elif op2 in (0x10,0x11,0x1F,0x28,0x29,0x2E,0x2F,0x57,0x60,0x62,0x64,0x6C,
                         0x6E,0x6F,0x70,0x73,0x74,0x76,0x7E,0x7F,0xAF,0xB6,0xB7,
                         0xBC,0xBD,0xBE,0xBF,0xC6,0xD7,0xDB,0xEB,0xEF,0xFB) or 0x40 <= op2 <= 0x4F or 0x90 <= op2 <= 0x9F:
                modrm = True
                if op2 in (0x70,0x73,0xC6): imm_size = 1
            else: raise ValueError(f'unsupported opcode at {base+start:#x}: 0f{op2:02x}')
        elif 0x50 <= op <= 0x5F or op in (0x90,0x98,0x99,0xC3,0xCC):
            if op == 0xC3: kind = 'return'
            elif op == 0xCC: kind = 'padding-trap'
        elif op in (0xE8,0xE9,0xEB) or 0x70 <= op <= 0x7F:
            imm_size = 4 if op in (0xE8,0xE9) else 1
            relative = True
            kind = 'call' if op == 0xE8 else 'jump' if op in (0xE9,0xEB) else 'conditional'
        elif 0xB8 <= op <= 0xBF: imm_size = 8 if rex & 8 else 2 if 0x66 in prefixes else 4
        elif 0xB0 <= op <= 0xB7 or op in (0x04,0x0C,0x24,0x2C,0x34,0x3C,0xA8,0x6A): imm_size = 1
        elif op in (0x05,0x0D,0x25,0x2D,0x35,0x3D,0xA9,0x68): imm_size = 2 if 0x66 in prefixes else 4
        elif op in (0x00,0x01,0x02,0x03,0x08,0x09,0x0A,0x0B,0x10,0x11,0x18,0x19,
                    0x20,0x21,0x22,0x23,0x28,0x29,0x2A,0x2B,0x30,0x31,0x32,0x33,
                    0x38,0x39,0x3A,0x3B,0x63,0x69,0x6B,0x80,0x81,0x83,0x84,0x85,
                    0x86,0x87,0x88,0x89,0x8A,0x8B,0x8D,0xC0,0xC1,0xC6,0xC7,0xD0,
                    0xD1,0xD2,0xD3,0xF6,0xF7,0xFE,0xFF):
            modrm = True
            if op in (0x6B,0x80,0x83,0xC0,0xC1,0xC6): imm_size = 1
            if op in (0x69,0x81,0xC7): imm_size = 2 if 0x66 in prefixes else 4
        else: raise ValueError(f'unsupported opcode at {base+start:#x}: {op:02x}')
        mem = None; reg = None; rmreg = None; group = None; disp_offset = None
        if modrm:
            require(p < len(blob), 'truncated ModRM')
            m = blob[p]; p += 1
            mode, group, rm = m >> 6, (m >> 3) & 7, m & 7
            reg = group + (8 if rex & 4 else 0)
            if mode == 3: rmreg = rm + (8 if rex & 1 else 0)
            else:
                mem = {'base': rm + (8 if rex & 1 else 0), 'index': None, 'scale': 1, 'disp': 0}
                disp_size = 1 if mode == 1 else 4 if mode == 2 else 0
                if rm == 4:
                    require(p < len(blob), 'truncated SIB')
                    sib = blob[p]; p += 1
                    idx = (sib >> 3) & 7; sb = sib & 7
                    mem['scale'] = 1 << (sib >> 6)
                    mem['index'] = None if idx == 4 and not rex & 2 else idx + (8 if rex & 2 else 0)
                    mem['base'] = sb + (8 if rex & 1 else 0)
                    if mode == 0 and sb == 5: mem['base'] = None; disp_size = 4
                elif mode == 0 and rm == 5: mem['base'] = 'rip'; disp_size = 4
                if disp_size:
                    require(p + disp_size <= len(blob), 'truncated displacement')
                    disp_offset = p - start
                    mem['disp'] = int.from_bytes(blob[p:p+disp_size], 'little', signed=True); p += disp_size
                if 0x64 in prefixes: mem['segment'] = 'fs'
                if 0x65 in prefixes: mem['segment'] = 'gs'
            if op in (0xF6,0xF7) and group == 0: imm_size = 1 if op == 0xF6 else 2 if 0x66 in prefixes else 4
            if op == 0xFF and group in (2,4): kind = 'indirect-call' if group == 2 else 'indirect-jump'
        require(p + imm_size <= len(blob), 'truncated immediate')
        imm_offset = p - start if imm_size else None
        imm = int.from_bytes(blob[p:p+imm_size], 'little') if imm_size else None
        target = base+p+imm_size+int.from_bytes(blob[p:p+imm_size], 'little', signed=True) if relative else None
        p += imm_size
        require(p-start <= 15, 'oversized instruction')
        rip = base+p+mem['disp'] if mem and mem['base'] == 'rip' else None
        rows.append(dict(va=base+start, size=p-start, hex=blob[start:p].hex(), op=op, op2=op2,
                         prefixes=prefixes, rex=rex, reg=reg, rmreg=rmreg, group=group,
                         mem=mem, imm=imm, imm_size=imm_size, imm_offset=imm_offset,
                         disp_offset=disp_offset, kind=kind, target=target, rip=rip))
    starts = {r['va'] for r in rows}
    for r in rows:
        if r['target'] is not None and base <= r['target'] < base+len(blob):
            require(r['target'] in starts, 'branch into instruction')
    return rows


def tsv(columns, rows):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, delimiter='\t', lineterminator='\n')
    writer.writerow(columns); writer.writerows(rows)
    return stream.getvalue().encode()


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def collect(im):
    functions=[]; insns=[]; bodies={}; control=[]; riprefs=[]; decoded={}
    for start, role in sorted(FUNCTIONS.items()):
        f,b=im.body(start); rows=decode(b,start); decoded[start]=rows
        bodies[hex(start)]=b.hex()
        functions.append([hex(start),hex(f['end']),len(b),hex(im.offset(start,len(b))),hex(f['fde']),hex(f['cie']),hex(f['lsda']) if f['lsda'] else '',hashlib.sha256(b).hexdigest(),len(rows),role])
        for r in rows:
            insns.append([hex(start),hex(r['va']),r['hex'],r['kind'],hex(r['target']) if r['target'] is not None else '',hex(r['rip']) if r['rip'] is not None else ''])
            if r['kind']!='ordinary':
                dest=r['target']; slot=None
                if r['kind'].startswith('indirect') and r['rip'] is not None:
                    slot=r['rip']; dest=im.relocation(slot) if im.relocs.get(slot, (None,))[0] == 8 else None
                control.append([hex(start),hex(r['va']),r['hex'],r['kind'],hex(dest) if dest is not None else '',hex(slot) if slot else '',hex(r['va']+r['size']) if r['kind'] in ('conditional','call','indirect-call') else ''])
            if r['rip'] is not None:
                riprefs.append([hex(start),hex(r['va']),r['hex'],hex(r['rip']),hex(im.relocs[r['rip']][1]) if r['rip'] in im.relocs else ''])
    outputs = {'functions.tsv':tsv(['start_va','end_va','bytes','file_offset','fde_va','cie_va','lsda_va','sha256','instruction_count','inferred_role'],functions),
            'instructions.tsv':tsv(['function_va','va','bytes','kind','relative_target','rip_operand'],insns),
            'control-flow.tsv':tsv(['function_va','va','bytes','kind','target','relocation_slot','fallthrough'],control),
            'rip-references.tsv':tsv(['function_va','va','bytes','operand_va','relocation_addend'],riprefs),
            'function-bytes.json':json_bytes(bodies)}
    outputs.update(semantic_outputs(im,decoded))
    ehrows=[]; ehd=[]
    for start, rows in sorted(decoded.items()):
        sites, header=exception_sites(im,start,rows);ehrows.extend(sites)
        if header: ehd.append(header)
    outputs['exception-sites.tsv']=tsv(['function_va','lsda_va','record_file_offset','range_start','length','range_end','landing_pad','action_index','raw_record'],ehrows)
    outputs['exception-prefixes.json']=json_bytes(ehd)
    outputs['allocation-cases.json']=json_bytes(arithmetic_cases())
    external=[]
    for row in control:
        if row[3] not in ('call','jump','indirect-call','indirect-jump'): continue
        dest=int(row[4],16) if row[4] else None
        if dest is not None and any(a<=dest<im.by_start[a]['end'] for a in FUNCTIONS): continue
        external.append(row+['dynamic' if dest is None else 'external'])
    outputs['external-edges.tsv']=tsv(['function_va','va','bytes','kind','target','relocation_slot','fallthrough','closure_status'],external)
    outputs['summary.json']=json_bytes({'target_sha256':DIGEST, 'functions':len(functions), 'code_bytes':sum(r[2] for r in functions), 'instruction_rows':len(insns), 'control_rows':len(control), 'external_control_sites':len(external), 'dynamic_control_sites':sum(r[-1]=='dynamic' for r in external), 'exception_sites':len(ehrows), 'semantic_windows':len(WINDOWS), 'private_records':20, 'revision_inputs':256, 'scope':'Static installation and materialization; external callbacks and runtime execution are not reconstructed.'})
    return outputs


# Exact semantic windows qualified independently of full-body admission.
WINDOWS = [
    (0x2464bf3, '4080fe130f873a0f0000400fb6c6488d0d00ddf7fd486304814801c8ffe0', 'revision range check and signed relative dispatch'),
    (0x2466c82, '488dbb98010000488db424d80100004c8b3548733003ba0010000041ffd6488b442410488943100f1004240f1103', 'common handler publication begins'),
    (0x2466cd4, '0f108424e80000000f108c24f80000000f109424080100000f109c24180100000f114b580f1153680f115b780f114348', 'default factory pair copied into handler'),
    (0x244fe0e, '4889f3488b374883c6084c8d7c24104c89ffe8cbd902000fb6839811000048c704240100000048c744240801000000888424b0000000', 'clone captures and snapshot canonical handler revision'),
    (0x244fe44, 'bfb8000000ff1589e131034885c074464989c64889e6bab80000004889c7ff1578e13103', 'allocate and copy new factory object before old release'),
    (0x244fe68, '488b4348f048ff08750a488d7b48ff150c4232034c897348488d05c969250348894350', 'release old factory and publish replacement pair'),
    (0x244fe9a, 'bf08000000beb8000000ff1576e131030f0b', 'factory allocation failure'),
    (0x244feac, '4989c44c897348488d0596692503488943504c89e7e84a022103', 'publish replacement even on old-factory drop unwind'),
    (0x244fec6, '4989c44c89ffe8af6700004c89e7e837022103ff1549e23103', 'drop cloned captures on allocation unwind'),
    (0x244fd04, '4889f34989fee8914bffff4889dfe8696900004c89f04883c4085b415ec34989c64889dfe8536900004c89f7e8db032103', 'consuming adapter drops captures on return and unwind'),
    (0x2444a04, '410fb686a0000000fec00fb6c0488d0d14fbf9fd0fb63c08', 'load captured revision and wrapping increment table index'),
    (0x2444a3c, 'ff150ef5320348c78424f8000000000000004889842400010000', 'registry selector call and borrowed representation'),
    (0x2444f7b, '488dbc24f8000000e8981e17004883bc24f800000000751b488d3dc072fafd488d1547662703be87000000ff15ec9032030f0b', 'force owned representation and reject impossible borrowed result'),
    (0x2444fae, '488dbc24f8040000488db42420010000bac0030000ff151790320348c78424e80400000000000048c78424f004000014000000488dbc24f8000000488db424e8040000e84a562700', 'form private record iterator and extend'),
    (0x2444ff6, '488b8c2418010000488b8424a8000000488948200f108424f80000000f108c24080100000f1148100f11004881c4b80800005b415c415d415e415f5dc3', 'publish five-word owned map result'),
    (0x25b6e20, '48833f007401c3534883ec50488b4708488b08488b5008488d541101', 'borrowed tag zero guard and iterator setup'),
    (0x25b6e3c, '660f6f01660fd7f0f7d6668974241848890c244883c11048894c24084889542410488b40184889442420488d4424284889e64889fb4889c7e8073a1000', 'occupied-control mask and clone call'),
    (0x25b6e79, '488b442448488943200f104424280f104c24380f114b100f11034883c4505bc3', 'commit owned map only after clone returns'),
    (0x26ba88e, '48b8447370032e8a1913644833042588faffff4989e449f7e44889c14889fb4831d148bad0319f29223809a44889c848f7e26448890c2588faffff4831c248891424488b05093b0b030fb640203c027574', 'thread-local seed update and process seed readiness'),
    (0x26ba8df, '0f10054a2900030f294424100f10052e2900030f2904244889542420498b76204885f6755f4c89642428410f1006410f104e100f294424300f294c2440488d7c2430488d542428e895d998ff', 'empty map words and borrowed iterator transfer'),
    (0x26ba953, '4989d7e8f5dff8fe4c89fae97cffffff488d5424204889e74989f7b901000000ff15878d0b034c89feeb86', 'seed initialization and capacity reservation boundaries'),
    (0x26ba97e, '4889c34889e7e8b7a996ff4889dfe87f57fa02ff1591370b03', 'partial owned map cleanup on unwind'),
    (0x20482f8, '664585e4753a4885db0f8411010000660f1f840000000000660f6f450066440fd7e04981c500fdffff4883c5104181fcffff000074e241f7d44c892f48896f08', 'occupied groups and counted iterator termination'),
    (0x2048338, '418d4424fff3410fbccc4421e04189c46689471848f7d94c8d344949c1e6044b8d042e4f8b7c35e8488d1539b937fe4a630cba4801d1ffe1', 'backward bucket addressing and value-tag dispatch'),
    (0x2048370, 'f30f6f40f0eb4c', 'plain callback clone arm'),
    (0x2048380, '488b48f0f048ff010f8e99000000f30f7e48f866480f6ec1eb25', 'reference-counted clone arm'),
    (0x20483a0, '488b78f048895c2408488b58f8ff531866480f6ecb488b5c240866480f6ec0660f6cc1', 'dynamic clone arm'),
    (0x20483c3, '4b8d042e4883c0d08b4810894c24300f10080f294c24204c897c2438f30f7f442440488d7c2450488b742410488d542420488d4c2438e8920d7800837c2450060f84e7feffff488d7c2450e81dbbf5ffe9d8feffff', 'preserve full key and tag, insert cloned value, release replacement'),
    (0x26ba67a, '4c89e04c29f8488d700148d1ee48837b1800480f44f0483b73100f8799000000', 'reserve all remaining entries for empty map or half rounded up otherwise'),
    (0x26ba6b0, '4c8b7c24384c8b7424404d39f775124881c4d80700005b415c415d415e415f5dc34b8d047f48c1e0044e8d24284983c4284c8d6c24204889e5', 'empty iterator exit and record stride'),
    (0x26ba6f0, '49ffc74983c4304d39fe74c3498d5424e8498b4424104889442410410f1004240f2904244c89ef4889de4889e9e86eea1000837c24200674c74c89efe85f1e0c00ebbd', 'private record insertion and replacement cleanup loop'),
    (0x26ba733, '488d53204889dfb901000000ff15bb8f0b03e950ffffff', 'reserve boundary and resume insertion'),
    (0x26ba74a, '4889c3488dbc24180400004c89fe4c89e2e8a02bedffeb21ff15c0390b034889c349ffc74c897c2438488d7c24484c89fe4c89f2e87d2bedff4889dfe88559fa02ff1597390b03', 'unconsumed record cleanup on either unwind path'),
    (0x27c91a7, '488b153252fa024c8b0a498b7f0c4c31cf498b0f498b47084833420848f7e74889c74989d0498b57044c31ca48334e204889c848f7e24931d04931f84c31c04883f01449f7e14989c54989d448837e10000f84b2010000', 'twenty-byte hash and reserve-on-zero-growth check'),
    (0x27c91fe, '4d31ec488b06488b56084c89e148c1e939660f6ec1660f60c0f20f70c000660f70c0444531c9660f76c94531c04921d4f3420f6f1420660f6fda660f74d866440fd7d34585d2745a', 'fingerprint and control-group lookup'),
    (0x27c9246, 'f3450fbcda4d01e34921d349f7db4f8d1c5b49c1e304f3410f6f1ff3420f6f6418d0660f74e366410f6e5f1066420f6e6c18e0660f74eb660fdbec660fd7ed81fdffff00007454458d5aff664521d34589da75ac660f1f440000', 'full twenty-byte equality before replacement'),
    (0x27c92a0, '4983f9017412660fd7fa85ff7420f30fbcff4c01e74821d7660f74d166440fd7ca4585c9754241b901000000eb034531c94d01c44983c4104983c010e94affffff', 'remember vacancy and triangular group probing'),
    (0x27c92e1, '4c01d8488b48f848894b100f1040e80f1103410f10060f1140e8498b4e10488948f8e996000000', 'replacement returns old value without changing key or count'),
    (0x27c9308, '440fb604384584c00f89bc0000004d8b4e104c894c2428410f10060f11442418410f10070f290424458b4f1044894c2410', 'empty-slot selection and key/value staging'),
    (0x27c9339, '4180e0014c8d4ff04921d1880c3842884c0810f30f6f4610410fb6c8660f6ec9660fc60d1ea1a3fd02660ffbc1f30f7f461048f7df488d0c7f48c1e1040f280424660f6f4c2410660f6f542420f30f7f5408f0f30f7f4c08e00f114408d048c70306000000', 'control mirror, growth and item counters, bucket stores, absent sentinel'),
    (0x27c93b0, '488d56204889f5be010000004889efb901000000ff1536a3fa024889eee92cfeffff660f6f00660fd7f8f30fbcff440fb60438e92effffff4889c34c89f7e89d31fbff4889dfe8156de902ff15274dfa02', 'growth, small-table fallback and incoming-value cleanup'),
    (0x488ef11, '4883fa0f731989d083e0084883c0084883fa0441bd040000004c0f43e8eb474889d048c1e83d0f853801000048c1e20348b993244992244992244889d04889d748f7e14829d748d1ef4801d748c1ef0248ffcf480fbdcff7d149c7c5ffffffff49d3ed49ffc5', 'bucket sizing thresholds and overflow guard'),
    (0x488ef77, '4889f049f7e5702f4883f8f077294883c00f4883e0f04d8d75104989c74d01f70f92c148baf0ffffffffffff7f4939d70f97c208ca741f4584c00f85cb00000031c0488943084c897b1048c70300000000e988000000', 'allocation-size multiplication alignment and signed-limit checks'),
    (0x488f014, '4901c44d8d7dff4c89e848c1e8034983e5f84929c54983ff084d0f42ef4c89e7beff0000004c89f2ff15b6f1ed004c89234c897b084c896b1048c7431800000000', 'initialize controls and publish raw table words'),
    (0x488f064, '807c2404007530b810000000e944ffffff4584c075080f57c00f1103ebd3488d3ddd179ffb488d15186adf00be39000000ff15fdefed00bf100000004c89feff1577efed00', 'fallible versus infallible allocation failures'),
    (0x4890f1e, '4c8b7f184c01fe0f82860500004989d44989fd488b6f08488d55014889d748c1ef034889d04883e0f84829f84883fd08480f42c54889c748d1ef4839fe0f86ba01000048ffc04839f0480f46c60fb6c9488d7c2428be300000004889c2e880dfffff', 'capacity sum overflow and rehash versus grow choice'),
    (0x489144f, '498b7d0048b801000000000000804c29fa4d8955004d894d08498955104885ed74cf488d0c6d000000004801e948c1e1044883c13f4883e1f04801cd4883c51174af4829cf31d24883fd100f92c2c1e2024889ee4889c3ff1564cbed004889d8eb8f84c9750431c0eb87488d3da6f39efb488d15e145df00be39000000ff15c6cbed00bf10000000e919fdffff', 'publish new table and dispose old storage or reject overflow'),
    (0x258d308, '4889d34829f3750c4883c4085b415c415e415fc3488d047648c1e0044801c748ffc3660f1f4400004883fb0174da4c8d773048ffcbe83e6402004c89f7ebe94989c7660f1f44000048ffcb74114d8d66304c89f7e81f6402004d89e6ebea4c89ffe8a22d0d03ff15b40d1e03', 'array cleanup walks unconsumed tail including unwind cleanup'),
    (0x247ff1e, '8bb42420280000488dbc2438280000e89e4cfeff', 'initial handler constructor'),
    (0x247ff8a, '4c89384983c7084c8db424901500004c89f74c89fee84cd8ffff0fb684247815000048c78424801500000100000048c78424881500000100000088842430160000bfb8000000ff1502e02e034885c00f84060c0000', 'clone captures and snapshot initial revision before factory allocation'),
    (0x247fff8, '488b842428040000f048ff08750e488dbc2428040000ff1574402f0348899c2428040000488d052d6822034889842430040000', 'initial factory release and publication'),
    (0x2480046, '488b8424e80300004889d948c1e1044c892c08488d15d87f2303488954080848ffc348899c24f0030000', 'append installation hook with captured pointer and vtable'),
    (0x248015d, '8b5c24204138df0f84a7010000', 'skip hook replay only when requested byte equals initial canonical byte'),
    (0x24801aa, '0fb6f3488dbc2438280000e8164afeff', 'construct replacement handler from requested revision'),
    (0x2480255, '4d8b7c24f0498b5c24f84d85ff740c4c89ff4889eeff5328eb06904889efffd3', 'borrowed trait hook or plain function hook dispatch'),
    (0x24802d1, '889c24d0390000488dbc24d0020000488db42438280000baa0110000ff15eddc2e034c89e7e8f587fdff488db424d0020000baa01100004c89e7ff15cfdc2e03', 'write raw requested byte after replay then replace old handler'),
    (0x24b659e, '4889f3488b374883c6084c8d7c24104c89ffe83b72fcff0fb6839811000048c704240100000048c744240801000000888424b0000000', 'borrowed hook clones captures and snapshots revision'),
    (0x24b65d4, 'bfb8000000ff15f9792b034885c074464989c64889e6bab80000004889c7ff15e8792b03488b4348f048ff08750a488d7b48ff157cda2b034c897348488d0539021f0348894350', 'borrowed hook allocates releases and publishes'),
    (0x24b662a, 'bf08000000beb8000000ff15e6792b030f0b4989c44c897348488d0506021f03488943504c89e7e8ba9a1a034989c44c89ffe81f00faff4c89e7e8a79a1a03ff15b97a2b03', 'borrowed hook allocation and unwind branches'),
    (0x25154bd, '0fb6aea8120000488b8668010000488b8e70010000488b511048ffca4883e2f0488d34104883c610488dbc24f00100004c89e2ff512880bc24f0010000050f8505030000', 'pre-factory callback must return tag five or bypass materialization'),
    (0x251550e, '498b842458010000498b8c2460010000488b511048ffca4883e2f0488d34104883c6104c8dac24a80400004c89efff5128', 'handler factory data and vtable load and borrowed invocation'),
    (0x251553f, '488dbc24f00100004c89eee851170a00498dbc2480000000488db424f0010000e81c341a00', 'derive auxiliary address collection before context publication'),
    (0x2515596, '4d8dbc24e8000000498b9c24e80000004885db4c896424280f84df0000004d8bac24f00000004d85ed0f84ce000000', 'old context map nonempty cleanup guards'),
    (0x251569d, '488b842410020000498947200f288424f00100000f288c2400020000410f114f10410f1107', 'publish five-word factory result into context map'),
    (0x2515806, '0f108424f00100000f108c2400020000410f114e18410f11460848b80200000000000080498906eb52', 'forward pre-factory failure without calling factory'),
    (0x489108b, '48c1ea39488d4ef04c21c9418814324188540a1048f7d3488d0c5b48c1e10448f7d6488d147648c1e204f30f6f040ff30f6f4c0f100f10540f20410f11541220f3410f7f4c1210f3410f7f0412', 'grow path copies complete forty-eight-byte records and rebuilds control mirrors'),
    (0x48912c4, '410fb61c3748c1ea394c8d76f04921c6418814374d8b7d00438854371080fbff0f84f1000000498b03488b11498913488901498b4308488b51084989530848894108498b4310488b51104989531048894110498b4318488b51184989531848894118498b4320488b51204989532048894120498b4328488b51284989532848894128', 'in-place rehash swaps all six words when destination is a tombstone'),
    (0x48913db, '498d42f04923450843c60417ff41c6440710fff3410f6f03f3410f6f4b10410f1053200f115120f30f7f4910f30f7f01', 'in-place rehash marks source empty and moves complete record'),
    (0x489140d, '498b45084d8b7d18488d48014889ca48c1ea034883e1f84829d14883f808480f42c84c29f948b8010000000000008049894d10', 'recompute growth budget after in-place rehash'),
    (0x25173bb, '4889c34883bc24a8040000000f847b010000488dbc24a8040000e866dfb0ffe969010000', 'release new owned map if auxiliary address processing unwinds'),
    (0x25173e5, '4889c3488b842410020000498947200f288424f00100000f288c2400020000410f114f10410f11074889dfe8fb8c1403', 'publish new context map even when old value release unwinds'),
    (0x25b6cb1, '4c8b3e4d85ff0f84e80000004c8b6608410f28070f29442460', 'owned representation selects forty-eight-byte bucket iterator'),
    (0x25b6d41, '660f6f442460660fd7c0f7d04b8d0c2748ffc14c896c2430488d54243048895424384c897c24404983c7104c897c244848894c24506689442458488d7c2440488d542438e87614a9ff488b442420488943200f2804240f284c24100f114b100f1103eb18', 'clone all occupied keys and publish temporary key set'),
    (0x25b6da5, '488b76084c8b76484883c6284889dfe857c9a6ff4c897320', 'borrowed representation delegates existing key set clone'),
    (0x25b6de5, '488d5424204889e74989f6b901000000ff1595c91b034c89f6e93effffff4889c34889e7e8d2dba6ff4889dfe8fa920a03', 'reserve temporary set and release it on unwind'),
    (0x2048239, '448d78fff30fbcc84121c76645897e1848f7d9488d044948c1e004488b7d00418b4c04e0894c2410f3410f6f4404d0660f7f04244889e6e89bfb770048ffcb4489f8', 'extract sixteen plus four key bytes from map and insert into set'),
    (0x26b8a25, '488d750148d1ee49837e1800480f44f5493b761048897c241048895424080f87f1000000', 'reserve destination set according to remaining cardinality'),
    (0x26b8aae, '8d43fff30fbccb21d889c348f7d9488d048948ffcd418b4c85fc894c2470f3410f6f4485ec660f7f4424604c89f74c89e6e82cf310004885ed7597', 'copy twenty-byte set keys and insert into context set'),
    (0x26b8ae9, '48837c241800488b74241074324885f6742d488b0c24f3480fbcd131c04839f10f46d0488b7c24084881c4b80000005b415c415d415e415f5dff25e8540b034881c4b80000005b415c415d415e415f5dc3', 'release consumed key set on normal completion'),
    (0x26b8b63, '4989c6488d7c2478e8204497ff4c89f7e89875fa024989c64c897c24404c896c243866895c245048896c2458488d7c2420e8f74397ff4c89f7e86f75fa02', 'release consumed key set on reserve or insertion unwind'),
    (0x27c7e17, '488b0dc265fa024c8b09488b560c488b4608483341084c31ca48f7e24889c14989d0488b06488b5604483347204c31ca48f7e24931d04931c84c31c04883f01449f7e14831c248837f10000f844a010000', 'set hashing uses all twenty key bytes and reserves if growth is zero'),
    (0x27c7eb0, 'f3410fbcc74801d04c21c848f7d8488d0480f30f6f1ef3410f6f2483660f74e3660f6e5e1066410f6e6c8310660f74eb660fdbec660fd7edb00181fdffff00000f84b1000000', 'existing set key requires full twenty-byte equality and returns one'),
    (0x27c7f5d, '2401498d52f04c21ca468804114488441110f30f6f47100fb6c0660f6ec8660fc60dfcb4a3fd02660ffbc1f30f7f471049f7da4b8d04928b5610895481fcf30f6f06f30f7f4481ec31c0', 'new set key stores sixteen plus four bytes updates counts and returns zero'),
    (0x202cf90, '488b074885c07427488b77084885f6741ef3480fbcc831d24839f00f47d14883f8110f43d1488b7f10ff2551107403c3', 'iterator cleanup requests storage release only for nonzero layout and size'),
    (0x20249e0, '488b77084885f67431488d04b6488d0485230000004883e0f04801c64883c6117418488b3f4829c731d24883fe100f92c2c1e202ff25f6957403c3', 'temporary set cleanup derives twenty-byte bucket storage layout'),
]

def validate_windows(im):
    records=[]
    for va,expected,note in WINDOWS:
        raw=bytes.fromhex(expected)
        require(im.read(va,len(raw))==raw, f'semantic window mismatch: {va:#x}')
        records.append([hex(va),len(raw),raw.hex(),note])
    return records


def memory_at(row, base, disp):
    return row['mem'] is not None and row['mem']['base']==base and row['mem']['index'] is None and row['mem']['disp']==disp


def private_records(im, rows):
    """Recover each key from its literal load plus immediate suffix stores."""
    records=[]
    for i,r in enumerate(rows):
        if not (0x2444a56 <= r['va'] < 0x2444c5e): continue
        if r['op']==0x0f and r['op2']==0x10 and r['rip'] is not None:
            store,suffix=rows[i+1:i+3]
            require(store['op']==0x0f and store['op2']==0x29 and store['reg']==r['reg'], 'key prefix store shape')
            require(store['mem']['base']==4 and store['mem']['index'] is None, 'key stack base')
            dst=store['mem']['disp']
            require(suffix['op']==0xc7 and suffix['rex']==0 and memory_at(suffix,4,dst+16), 'key suffix store shape')
            key=im.read(r['rip'],16)+suffix['imm'].to_bytes(4,'little')
            tags=[x for x in rows if x['op']==0xc7 and x['rex']&8 and memory_at(x,4,dst+24)]
            require(len(tags)==1 and tags[0]['imm']==2, 'private value tag')
            vstores=[(j,x) for j,x in enumerate(rows) if x['op']==0x89 and memory_at(x,4,dst+40)]
            require(len(vstores)==1, 'private vtable store')
            j,vs=vstores[0]; lea=rows[j-1]
            require(lea['op']==0x8d and lea['reg']==vs['reg'] and lea['rip'] is not None,'private vtable source')
            vt=lea['rip']; callback=im.relocation(vt+24)
            records.append({'index':len(records),'key_hex':key.hex(),'key_integer':int.from_bytes(key,'big'),
                            'stack_offset':dst,'prefix_va':r['rip'],'prefix_load_va':r['va'],
                            'suffix_store_va':suffix['va'],'tag_store_va':tags[0]['va'],
                            'tag':tags[0]['imm'],'vtable_va':vt,'vtable_store_va':vs['va'],
                            'callback_slot':vt+24,'callback_va':callback,
                            'vtable_size':struct.unpack('<Q',im.read(vt+8,8))[0],
                            'vtable_alignment':struct.unpack('<Q',im.read(vt+16,8))[0],
                            'vtable_raw_bytes':im.read(vt,32).hex(),
                            'drop_slot_is_null':im.read(vt,8)==bytes(8) and vt not in im.relocs})
    require(len(records)==20, 'private record cardinality')
    require([r['stack_offset'] for r in records]==list(range(0x120,0x4e0,48)), 'private record stride')
    require(len({r['key_hex'] for r in records})==len(records),'duplicate private key')
    require({r['key_integer'] for r in records}==set(range(0x800,0x814)), 'unexpected private address range')
    require(all(r['vtable_size']==0x50 and r['vtable_alignment']==8 and r['drop_slot_is_null'] for r in records),'private vtable layout')
    return records


def revision_routes(im, rows):
    """Normal allocation-return paths; null branches remain separate evidence."""
    byva={r['va']:r for r in rows}
    dispatch=byva[0x2464c01]
    require(dispatch['op']==0x8d and dispatch['rip'] is not None,'revision dispatch base')
    table=dispatch['rip']
    bound=byva[0x2464bf3]['imm']
    require(bound==19,'revision dispatch bound')
    default=byva[0x2464bf7]['target']
    entries=[table+x for x in struct.unpack('<'+str(bound+1)+'i',im.read(table,4*(bound+1)))]
    case_records={}
    for entry in sorted(set(entries+[default])):
        require(entry in byva,'revision branch target is not an instruction')
        pc=entry; path=[]
        while pc!=0x2466c82:
            require(pc in byva and pc not in {r['va'] for r in path},'invalid revision case path')
            r=byva[pc];path.append(r)
            require(len(path)<180,'revision path is unbounded')
            if r['kind']=='jump':pc=r['target']
            else:
                require(r['kind'] not in ('return','trap','indirect-jump'),'revision path escaped')
                pc+=r['size']
        stores=[r for r in path if r['op']==0xc6 and memory_at(r,3,0x1198)]
        require(len(stores)==1,'canonical revision store count')
        sources=[r for r in path if r['op']==0x8d and r['reg']==6 and r['rip'] is not None]
        require(len(sources)==1,'opcode table source count')
        src=sources[0]['rip']
        calls=[r for r in path if r['kind']=='call']
        fails=[r for r in path if r['kind']=='conditional']
        require(len(fails)==6 and all(r['op2']==0x84 for r in fails),'expected six allocation-null branches')
        case_records[entry]={'entry_va':entry,'canonical_revision':stores[0]['imm'],
                            'revision_store_va':stores[0]['va'],'opcode_table_va':src,
                            'opcode_table_bytes':0x800,'opcode_table_sha256':hashlib.sha256(im.read(src,0x800)).hexdigest(),
                            'direct_helper_targets':[r['target'] for r in calls],
                            'allocation_failures':[[r['va'],r['target']] for r in fails]}
    mode_base=0x3e452c
    mode_bytes=im.read(mode_base,bound+2)
    require(mode_bytes==bytes.fromhex('060000000000000101010202030303030303040505'),'revision-to-mode table mismatch')
    routes=[]
    for raw in range(256):
        entry=entries[raw] if raw<=bound else default
        case=case_records[entry]; canonical=case['canonical_revision']; index=(canonical+1)&255
        require(index<len(mode_bytes),'canonical revision exceeds admitted mode table')
        routes.append({'input_byte':raw,'case_entry_va':entry,'canonical_revision':canonical,
                       'mode_table_index':index,'mode_table_entry_va':mode_base+index,'registry_mode':mode_bytes[index]})
    return routes,list(case_records.values())


def jump_table(im, base, count, instruction_va, rows):
    starts={r['va'] for r in rows}
    result=[]
    for tag,delta in enumerate(struct.unpack('<'+str(count)+'i',im.read(base,count*4))):
        target=base+delta
        require(target in starts,'jump-table target is not an instruction in selected body')
        result.append([hex(instruction_va),tag,hex(base+4*tag),delta,hex(target)])
    return result


def capture_edges(decoded, records):
    """Static MOV def-use slices, not an instruction evaluator.

    No captured instructions are run. The two admitted straight-line slices
    have fixed stack positions; the selector call uses SysV preserved registers.
    Values are opaque origin labels, never pointer values or simulated memory.
    """
    def moves(rows, stack, input_base=None):
        regs={}; stores={}
        for r in rows:
            op=r['op']; mem=r['mem']; value=None
            if r['kind'] in ('call','indirect-call'):
                for reg in (0,1,2,6,7,8,9,10,11): regs.pop(reg,None)
            if op==0x8b and r['rex']&8:
                if mem and mem['index'] is None:
                    if mem['base']==4: value=stack.get(mem['disp'])
                    elif input_base is not None and mem['base']==input_base: value=(mem['disp'],[])
                elif mem is None: value=regs.get(r['rmreg'])
                regs[r['reg']]=(value[0],value[1]+[r['va']]) if value else None
            elif op==0x89 and r['rex']&8:
                value=regs.get(r['reg'])
                value=(value[0],value[1]+[r['va']]) if value else None
                if mem and mem['index'] is None:
                    stores[(mem['base'],mem['disp'])]=(value,r['va'])
                    if mem['base']==4:stack[mem['disp']]=value
                elif mem is None:regs[r['rmreg']]=value
            elif op==0x8d or (op==0x0f and r['op2'] in (0xb6,0xb7)):
                regs[r['reg']]=None
        return stores
    clone_rows=[r for r in decoded[0x247d7f0] if 0x247d7fa<=r['va']<0x247d9c6]
    clone=moves(clone_rows,{},6)
    copied={offset:value for (base,offset),(value,_) in clone.items() if base==7}
    require(set(copied)==set(range(0,160,8)),'capture copy destinations')
    require(all(v and v[0]==offset for offset,v in copied.items()),'capture copy order')
    stack={0x4e8+offset:value for offset,value in copied.items()}
    material_rows=[r for r in decoded[0x24448a0] if 0x24448c9<=r['va']<0x2444f7b]
    stored=moves(material_rows,stack)
    output=[]
    for record in records:
        value,site=stored[(4,record['stack_offset']+32)]
        require(value and value[0]==record['index']*8,'private record capture order')
        output.append({'key_hex':record['key_hex'],'factory_payload_offset':value[0],
                       'record_data_store_va':site,'mov_def_use_sites':value[1],
                       'callback_va':record['callback_va'],
                       'assumption':'SysV preserved registers and stable nonaliasing capture storage.'})
    return output


def entry_binding(im, decoded):
    """Bind the installation hook and factory call using concrete slot layouts.

    Only the registry lifecycle inside the two larger callers is interpreted.
    Other transaction callbacks remain explicit external edges.
    """
    root={r['va']:r for r in decoded[0x247fd20]}
    consumer={r['va']:r for r in decoded[0x25154a0]}
    hook={r['va']:r for r in decoded[0x24b6590]}
    vt=root[0x2480059]['rip']
    require(vt==0x56b8038,'hook vtable address')
    slots=[vt+24,vt+32,vt+40]
    targets=[im.relocation(s) for s in slots]
    require(targets==[0x244fe00,0x24b6590,0x24b6590],'hook relocation lineage')
    require(root[0x247ff2d]['target']==root[0x24801b5]['target']==0x2464bd0,'constructor lineage')
    require(root[0x24804db]['target']==0x25154a0,'consumer lineage')
    require(root[0x248026a]['mem']['disp']==40,'hook invocation slot')
    require(consumer[0x251553c]['mem']['disp']==40,'factory invocation slot')
    require(root[0x248001c]['rip']==hook[0x24b6610]['rip']==0x56a6850,'factory publication lineage')
    factory_target=im.relocation(root[0x248001c]['rip']+consumer[0x251553c]['mem']['disp'])
    require(factory_target==0x24448a0,'materialization lineage')
    context_header=root[0x2480080]['imm']
    data_offset=consumer[0x251550e]['mem']['disp']
    vtable_offset=consumer[0x2515516]['mem']['disp']
    require(data_offset-context_header==0x48 and vtable_offset-context_header==0x50,'context handler offset composition')
    require(consumer[0x25154fb]['target']==0x2515806,'pre-factory failure target')
    return {'entry_va':0x247fd20,'constructor_va':root[0x247ff2d]['target'],
            'initial_constructor_call_va':0x247ff2d,'rebuild_constructor_call_va':0x24801b5,
            'requested_revision_save_va':0x247fd5e,'requested_revision_stack_offset':root[0x247fd5e]['mem']['disp'],
            'equality_branch_va':0x2480164,'equal_skip_target_va':root[0x2480164]['target'],
            'hook_vtable_va':vt,'hook_payload_size':struct.unpack('<Q',im.read(vt+8,8))[0],
            'hook_alignment':struct.unpack('<Q',im.read(vt+16,8))[0],
            'hook_slots':[{'slot_va':s,'target_va':t} for s,t in zip(slots,targets)],
            'hook_call_va':0x248026a,'hook_slot_offset':root[0x248026a]['mem']['disp'],
            'plain_hook_call_va':0x2480273,'raw_revision_store_after_replay_va':0x24802d1,
            'consumer_call_va':0x24804db,'consumer_va':root[0x24804db]['target'],
            'context_header_bytes':context_header,'context_factory_data_offset':data_offset,
            'context_factory_vtable_offset':vtable_offset,'factory_call_va':0x251553c,
            'factory_slot_offset':consumer[0x251553c]['mem']['disp'],'factory_target_va':factory_target,
            'pre_factory_gate_va':0x25154f3,'required_gate_tag':consumer[0x25154f3]['imm'],
            'pre_factory_failure_va':consumer[0x25154fb]['target'],
            'auxiliary_collection_calls':[{'call_va':a,'target_va':consumer[a]['target']} for a in (0x251554a,0x251555f)],
            'old_map_cleanup_base_offset':consumer[0x2515596]['mem']['disp'],
            'map_publication_start_va':0x251569d,'map_publication_end_va':0x25156c2,
            'context_address_set_offset':consumer[0x251554f]['mem']['disp'],
            'scope':'Registry keys flow into the context address set before map publication; later transaction callbacks remain external.'}


def revision_transition(routes, initial, requested):
    """Static normal-return model, not execution of either caller."""
    require(type(initial) is int and 0<=initial<256 and type(requested) is int and 0<=requested<256,'revision byte domain')
    initial_canonical=routes[initial]['canonical_revision']
    replay=initial_canonical!=requested
    captured=routes[requested]['canonical_revision'] if replay else initial_canonical
    return {'initial_input':initial,'requested_input':requested,'replay':replay,
            'captured_revision':captured,'handler_revision':requested,
            'registry_mode':routes[requested]['registry_mode']}


def literal_records(im, decoded):
    require(im.read(0x203480,16)==bytes(8)+bytes([255])*8,'counter vector constant')
    require(im.read(0x207980,16)==bytes([128])*16,'rehash control vector constant')
    refs={}
    for rows in decoded.values():
        for r in rows:
            if r['op']==0x0f and r['op2'] in (0x10,0x6f,0xc6,0xeb) and r['rip'] is not None:
                refs.setdefault(r['rip'],[]).append(r['va'])
    result=[]
    for va,sites in sorted(refs.items()):
        nested=[]
        for slot in (va,va+8):
            if slot in im.relocs:
                info,value,off=im.relocs[slot]
                nested.append({'slot_va':slot,'info':info,'addend':value,'record_file_offset':off})
        result.append({'va':va,'file_offset':im.offset(va,16),'bytes':im.read(va,16).hex(),
                       'reference_sites':sorted(sites),'relocations':nested})
    return result


def semantic_outputs(im, decoded):
    windows=validate_windows(im)
    binding=entry_binding(im,decoded)
    private=private_records(im,decoded[0x24448a0])
    routes,cases=revision_routes(im,decoded[0x2464bd0])
    # Valid plain/shared/dynamic precompile tags are 0..3 here. This table is
    # indexed without a range check; no semantics are assigned to other tags.
    tags=jump_table(im,0x3c3ca0,4,0x204836e,decoded[0x20482c0])
    factory=[]
    for slot in (0x56a6850,0x56a6868,0x56a6870,0x56a6878):
        factory.append([hex(slot),hex(im.relocation(slot))])
    require([int(r[1],16) for r in factory]==[0x2456680,0x244fd00,0x24448a0,0x24448a0],'factory relocation lineage')
    relevant_slots=set(int(x[0],16) for x in factory)
    relevant_slots.update(r['slot_va'] for r in binding['hook_slots'])
    relevant_slots.update(r['callback_slot'] for r in private)
    for rows in decoded.values():
        relevant_slots.update(r['rip'] for r in rows if r['rip'] in im.relocs)
    relocs=[]
    for slot in sorted(relevant_slots):
        info,addend,off=im.relocs[slot]
        relocs.append([hex(slot),hex(off),info&0xffffffff,info>>32,hex(addend),im.read(slot,8).hex()])
    unwind=[]
    for start in sorted(decoded):
        f=im.by_start[start]
        for role,va in [('fde',f['fde']),('cie',f['cie'])]:
            n=struct.unpack('<I',im.read(va,4))[0]+4
            unwind.append({'function_va':hex(start),'role':role,'va':hex(va),'bytes':im.read(va,n).hex()})
    retain=decoded[0x247d7f0]
    retain_branches=[r for r in retain if r['kind']=='conditional']
    require(len(retain_branches)==20 and all(r['op2']==0x8e and r['target']==0x247d9d1 for r in retain_branches),'capture retain failure pattern')
    install={r['va']:r for r in decoded[0x244fe00]}
    materialize={r['va']:r for r in decoded[0x24448a0]}
    layout={'factory_vtable_va':0x56a6850,
            'payload_size':struct.unpack('<Q',im.read(0x56a6858,8))[0],
            'alignment':struct.unpack('<Q',im.read(0x56a6860,8))[0],
            'allocation_bytes':install[0x244fe44]['imm'],
            'handler_revision_offset':install[0x244fe25]['mem']['disp'],
            'factory_revision_offset':materialize[0x2444a04]['mem']['disp'],
            'handler_factory_data_offset':install[0x244fe7c]['mem']['disp'],
            'handler_factory_vtable_offset':install[0x244fe87]['mem']['disp'],
            'captured_reference_count':len(retain_branches),
            'retain_failure_edges':[[r['va'],r['target']] for r in retain_branches],
            'note':'Source-level names are inferred; padding bytes are not claimed initialized.'}
    require(layout['payload_size']==0xa8 and layout['allocation_bytes']==0xb8,'factory allocation layout')
    return {'literal-records.json':json_bytes(literal_records(im,decoded)),
            'capture-edges.json':json_bytes(capture_edges(decoded,private)),
            'entry-binding.json':json_bytes(binding),
            'revision-transition-examples.json':json_bytes([revision_transition(routes,a,b) for a,b in [(9,9),(9,10),(10,9),(19,20),(0,255),(255,255)]]),
            'factory-layout.json':json_bytes(layout),'semantic-windows.tsv':tsv(['va','length','bytes','observation'],windows),
            'private-records.json':json_bytes(private),'revision-cases.json':json_bytes(cases),
            'revision-routes.json':json_bytes(routes),'clone-tag-table.tsv':tsv(['jump_va','tag','entry_va','signed_delta','target_va'],tags),
            'factory-relocations.tsv':tsv(['slot_va','target_va'],factory),
            'relocations.tsv':tsv(['slot_va','record_file_offset','type','symbol_index','addend','raw_slot_bytes'],relocs),
            'unwind-records.json':json_bytes(unwind)}

def exception_sites(im, start, rows):
    """Decode only the observed LSDA call-site table, using shared ULEB reader.

    Action indexes are retained, not interpreted as catch or cleanup types.
    """
    f=im.by_start[start]
    if not f['lsda']: return [],None
    va=f['lsda']; off=im.offset(va,1)
    section=next(s for s in im.secs if s['type']!=8 and s['name']=='.gcc_except_table')
    end=section['offset']+section['size']
    require(section['offset']<=off<end,'LSDA outside exception section')
    d=im.data; pos=off
    require(d[pos]==0xff,'unsupported LSDA landing-pad base');pos+=1
    require(pos<end,'truncated LSDA type encoding')
    enc=d[pos];pos+=1; type_base=None
    if enc!=0xff:
        require(enc==0x9b,'unsupported LSDA type encoding')
        delta,pos=uleb(d,pos,end);type_base=pos+delta
        require(type_base<=end,'LSDA type base outside section')
    require(pos<end and d[pos]==1,'unsupported LSDA call-site encoding');pos+=1
    n,pos=uleb(d,pos,end);limit=pos+n
    require(limit<=end and (type_base is None or limit<=type_base),'LSDA call-site table outside bounds')
    boundaries={r['va'] for r in rows}|{f['end']}; result=[]; previous=0
    while pos<limit:
        record=pos
        lo,pos=uleb(d,pos,limit);size,pos=uleb(d,pos,limit)
        landing,pos=uleb(d,pos,limit);action,pos=uleb(d,pos,limit)
        require(lo>=previous and start+lo+size<=f['end'],'overlapping or out-of-range exception site')
        previous=lo+size
        require(start+lo in boundaries and start+lo+size in boundaries,'exception range not on instruction boundary')
        require(not landing or start+landing in boundaries-{f['end']},'landing pad is not an instruction')
        result.append([hex(start),hex(va),hex(record),hex(start+lo),size,hex(start+lo+size),
                       hex(start+landing) if landing else '',action,d[record:pos].hex()])
    raw_end=type_base if type_base is not None else limit
    return result,{'function_va':hex(start),'lsda_va':hex(va),'type_encoding':enc,
                   'type_table_file_offset':type_base,'call_site_end_file_offset':limit,
                   'raw_prefix':d[off:raw_end].hex(),
                   'scope':'Call-site landing-pad edges only; action chains and personality semantics unresolved.'}

def allocation_plan(requested):
    """Instruction-derived arithmetic for the selected 48-byte bucket caller.

    This computes integers only. It does not run captured instructions, allocate
    a target table, or claim that an external allocator succeeds.
    """
    require(type(requested) is int and 0<=requested<1<<64,'capacity must be u64')
    if requested<15:
        buckets=4 if requested<4 else 8 if requested<8 else 16
    else:
        if requested>>61: return {'outcome':'capacity-overflow'}
        scaled=requested*8//7
        buckets=1<<(scaled-1).bit_length()
    body=buckets*48
    if body>=(1<<64) or body>(1<<64)-16: return {'outcome':'layout-overflow'}
    aligned=(body+15)&~15
    allocation=aligned+buckets+16
    if allocation>(1<<63)-16: return {'outcome':'layout-overflow'}
    growth=buckets-1 if buckets<8 else buckets-buckets//8
    return {'outcome':'allocation-request','buckets':buckets,'mask':buckets-1,
            'growth_left':growth,'bucket_bytes':aligned,'control_bytes':buckets+16,
            'allocation_bytes':allocation,'items':0}


def arithmetic_cases():
    requests=[0,1,3,4,7,8,14,15,27,28,29,55,56,57,255,256,
              (1<<56)-1,1<<56,(1<<57)-1,1<<57,(1<<60)-1,1<<60,(1<<61)-1,1<<61,(1<<64)-1]
    return [{'requested':n,**allocation_plan(n)} for n in requests]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    im=Image(TARGET.read_bytes())
    outputs=collect(im)
    args.out.mkdir(parents=True,exist_ok=True)
    for name,content in sorted(outputs.items()): (args.out/name).write_bytes(content)
    print(f'wrote {len(outputs)} deterministic evidence files')


if __name__=='__main__':
    main()
