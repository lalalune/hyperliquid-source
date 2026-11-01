#!/usr/bin/env python3
"""Static ELF admission, full native exports and selected structural obligations. No evaluation."""
from __future__ import annotations
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
GNU = '/opt/homebrew/opt/binutils/bin/objdump'
LLVM = '/Library/Developer/CommandLineTools/usr/bin/llvm-objdump'
SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
SIZE = 91774280


class EvidenceError(ValueError):
    pass


def need(condition, message):
    if not condition:
        raise EvidenceError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def dependencies():
    deps = json.loads((HERE / 'dependencies.json').read_text())
    for name, sha in deps.items():
        need(digest((ROOT / name).read_bytes()) == sha, f'dependency changed: {name}')
    return deps


# Import only the two reviewed static ELF/DWARF parsers, after binding their hashes.
dependencies()
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records


class Elf:
    def __init__(self, data, *, identity=True):
        need(len(data) == SIZE, 'target size')
        if identity:
            need(digest(data) == SHA, 'target SHA-256')
        need(data[:6] == b'\x7fELF\x02\x01', 'ELF64 little endian')
        need(struct.unpack_from('<H', data, 18)[0] == 62, 'x86-64 machine')
        self.data = data
        self.secs = sections(data)
        need(len({s['name'] for s in self.secs}) == len(self.secs), 'duplicate section names')
        self.byname = {s['name']: s for s in self.secs}
        off = struct.unpack_from('<Q', data, 32)[0]
        stride, count = struct.unpack_from('<HH', data, 54)
        need(stride == 56 and count > 0 and off + stride * count <= len(data), 'program headers')
        self.loads = [struct.unpack_from('<IIQQQQQQ', data, off + i * stride) for i in range(count)]
        self.loads = [x for x in self.loads if x[0] == 1]
        for x in self.loads:
            need(x[5] <= x[6] and x[2] + x[5] <= len(data), 'PT_LOAD bounds')
        self.cies, self.fdes = eh_frame_records(data, self.secs)
        self.relas = {}
        s = self.byname['.rela.dyn']
        need(s['size'] % 24 == 0, 'RELA width')
        for at in range(s['offset'], s['offset'] + s['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, at)
            need(slot not in self.relas, 'duplicate RELA slot')
            self.relas[slot] = dict(offset=at, info=info, addend=addend)

    def offset(self, va, count, execute=False):
        need(va >= 0 and count >= 0, 'negative span')
        matches = [x[2] + va - x[3] for x in self.loads
                   if x[3] <= va and va + count <= x[3] + x[5] and (not execute or x[1] & 1)]
        need(len(matches) == 1, f'file-backed PT_LOAD span {va:#x}+{count}')
        return matches[0]

    def read(self, va, count, execute=False):
        off = self.offset(va, count, execute)
        return self.data[off:off + count]

    def record(self, va):
        length = struct.unpack('<I', self.read(va, 4))[0]
        need(4 <= length < 1024 and length != 0xffffffff, 'DWARF record length')
        return self.read(va, length + 4)

    def symbol(self, index):
        s = self.byname['.dynsym']; strings = self.byname['.dynstr']
        need((index + 1) * 24 <= s['size'], 'dynsym index')
        at = s['offset'] + index * 24
        name = struct.unpack_from('<I', self.data, at)[0]
        need(name < strings['size'], 'dynstr offset')
        start = strings['offset'] + name
        end = self.data.find(b'\0', start, strings['offset'] + strings['size'])
        need(end >= start, 'dynstr terminator')
        return self.data[start:end].decode('ascii')


def native_rows(text):
    rows = []
    for line in text.splitlines():
        m = re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)\s*(.*)', line)
        if not m:
            continue
        row = dict(va=int(m[1], 16), raw=bytes.fromhex(m[2]), asm=m[3].strip())
        if rows and rows[-1]['asm'] == 'lock' and rows[-1]['va'] + len(rows[-1]['raw']) == row['va']:
            rows[-1]['raw'] += row['raw']; rows[-1]['asm'] += ' ' + row['asm']
        else:
            rows.append(row)
    return rows


def partition(elf, rows, start, end):
    pos = start
    for r in rows:
        need(r['va'] == pos and len(r['raw']) > 0, f'contiguous native partition at {pos:#x}')
        need(r['raw'] == elf.read(pos, len(r['raw']), True), f'row raw bytes at {pos:#x}')
        pos += len(r['raw'])
    need(pos == end, f'full FDE partition ending {end:#x}')


def scope_rows(scope=None):
    scope = scope or json.loads((HERE / 'scope.json').read_text())
    need(scope['sha256'] == SHA and scope['size'] == SIZE, 'scope target')
    need(scope['base'] == '56c0ec672bd8fdcfaa80f2db700a61e6240b3663', 'scope baseline')
    rows = scope['ranges']
    # Exact census is independent of caller-supplied ranges.
    starts = [int(x['start'], 16) for x in rows]
    need(starts == EXPECTED_STARTS, 'scope start census/order')
    need(sum(x['size'] for x in rows) == 19172 and sum(x['rows'] for x in rows) == 4655, 'scope denominator')
    return rows


EXPECTED_STARTS = [
    0x44c5850,0x44c5a60,0x44c5e30,0x44c6340,0x454aa10,0x454aec0,0x454b170,0x454b300,
    0x454b430,0x454bd70,0x454c050,0x45873d0,0x466cec0,0x466d630,0x471ce30,0x4778820,
    0x4778a70,0x4779b00,0x4779c40,0x48454d0,0x485b780,0x496d910,0x496df30,0x4aa9ae0,
    0x4aa9c90,0x4aa9e20,0x4aa9e50,0x4aa9ed0,0x4aa9f50,0x4aa9f80,0x4aaa230,0x4b747d0,
    0x4c7e7a0,0x4df20d0,0x4df2250,0x4f59480,0x4f59a10,0x4f59e40]


def call_record(elf, row):
    va, raw, asm = row['va'], row['raw'], row['asm']
    result = dict(at=hex(va), asm=asm)
    if raw[0] == 0xe8 and len(raw) == 5:
        result['target'] = hex(va + 5 + struct.unpack_from('<i', raw, 1)[0])
    elif raw[:2] == b'\xff\x15' and len(raw) == 6:
        slot = va + 6 + struct.unpack_from('<i', raw, 2)[0]
        need(slot in elf.relas, 'indirect call lacks RELA')
        r = elf.relas[slot]; typ, sym = r['info'] & 0xffffffff, r['info'] >> 32
        result.update(slot=hex(slot), relocation_type=typ, symbol_index=sym, addend=hex(r['addend']))
        if typ == 8:
            need(sym == 0, 'RELATIVE requires symbol index zero')
            result['target'] = hex(r['addend'])
        else:
            need(typ == 6 and elf.symbol(sym) == 'memcpy' and r['addend'] == 0, 'import is memcpy')
            result['symbol'] = 'memcpy'
    return result


def validate(elf, decoded, *, body_identity=True, scope=None):
    wanted = scope_rows(scope)
    need(sorted(decoded) == EXPECTED_STARTS, 'decoded function census')
    result = []
    pins = json.loads((HERE / 'obligations.json').read_text())
    need(pins['target'] == SHA, 'obligation target')
    need(len(pins['instructions']) == 619 and len({x['va'] for x in pins['instructions']}) == 619,
         'instruction obligation census')
    need([(int(x['va'],16),len(bytes.fromhex(x['raw']))) for x in pins['data']] ==
         [(0x6f605b,29),(0x6f6078,13),(0x6f5e18,20),(0x6f5e2c,20),
          (0x209edc,4),(0x209ee4,4),(0x209d60,4),(0x7d04c8,192)], 'data obligation census')
    all_rows = {}
    for r in wanted:
        start, end = int(r['start'], 16), int(r['end'], 16)
        need(end - start == r['size'] and end > start, 'range size')
        overlaps = [f for f in elf.fdes if f['start'] < end and f['end'] > start]
        need(len(overlaps) == 1, f'unique overlapping FDE at {start:#x}')
        f = overlaps[0]
        need(f['start'] == start and f['end'] == end and f['fde'] == int(r['fde'],16)
             and f['cie'] == int(r['cie'],16), 'FDE extent/CIE match')
        raw = elf.read(start, end - start, True)
        if body_identity:
            need(digest(raw) == r['sha256'], f'body identity {start:#x}')
        gr, lr = decoded[start]
        partition(elf, gr, start, end); partition(elf, lr, start, end)
        need([(x['va'],x['raw']) for x in gr] == [(x['va'],x['raw']) for x in lr], 'native byte/boundary agreement')
        need(len(gr) == r['rows'], 'native instruction denominator')
        for row in gr:
            # Prefixes cannot disguise a data write or transfer in structural checks.
            if row['asm'].split()[0] in ('data16','cs','ds','es','ss','fs','gs','rep','repz','repnz','addr32'):
                need(re.fullmatch(r'(?:(?:data16|cs) )*nop(?: .*)?', row['asm']) is not None,
                     f'unreviewed non-NOP prefix {row["va"]:#x}')
            need(row['va'] not in all_rows, 'overlapping native row')
            all_rows[row['va']] = row
        calls = [call_record(elf,x) for x in gr if x['asm'].startswith('call')]
        # Preserve the complete call census, including opaque and exceptional tails.
        need([x['at'] for x in calls] == [x['at'] for x in r['calls']], 'full call-site census')
        for actual, original in zip(calls, r['calls']):
            if 'slot' in original:
                rel = original['rela']
                if isinstance(rel, list):
                    rel = dict(type=int(rel[0],16) & 0xffffffff,
                               symbol=int(rel[0],16) >> 32, addend=rel[1])
                need(actual.get('slot') == original['slot'], 'call slot')
                need(actual.get('addend') == rel['addend'], 'call RELA addend')
                need(actual['relocation_type'] == rel['type'], 'call RELA type')
                need(actual['symbol_index'] == rel['symbol'], 'call RELA symbol')
            elif 'target' in original:
                need(actual.get('target') == original['target'], 'direct call target')
            else:
                need(actual['asm'] == original['asm'], 'register/dynamic call shape')
        result.append(dict(start=hex(start),end=hex(end),size=end-start,rows=len(gr),sha256=digest(raw),
                           fde=hex(f['fde']),cie=hex(f['cie']),lsda=hex(f['lsda']) if f['lsda'] else None,
                           fde_raw=elf.record(f['fde']).hex(),cie_raw=elf.record(f['cie']).hex(),calls=calls))
    for pin in pins['instructions']:
        va = int(pin['va'],16); need(va in all_rows, 'obligation address')
        actual = all_rows[va]
        need(actual['raw'].hex() == pin['raw'], f'obligation bytes: {pin["reason"]} at {va:#x}')
        need(actual['asm'] == pin['asm'], f'obligation decode: {pin["reason"]} at {va:#x}')
    for pin in pins['data']:
        actual = elf.read(int(pin['va'],16),len(bytes.fromhex(pin['raw'])))
        need(actual.hex() == pin['raw'], f'data obligation: {pin["reason"]}')
    return dict(target_sha256=SHA,functions=len(result),bytes=19172,instructions=4655,
                obligations=len(pins['instructions']),data_obligations=len(pins['data']),ranges=result)


def decode_snapshot(elf, *, gnu=GNU, llvm=LLVM, subset=None):
    wanted = scope_rows(); outputs = {}; decoded = {}
    with tempfile.TemporaryDirectory(prefix='consensus-static-') as directory:
        path = Path(directory)/'hl-node'; path.write_bytes(elf.data); path.chmod(0o400)
        for r in wanted:
            start, end = int(r['start'],16),int(r['end'],16)
            if subset is not None and start not in subset: continue
            texts=[]
            commands=[[gnu,'-d','-w','-Mintel','--insn-width=16'],[llvm,'-d','--x86-asm-syntax=intel']]
            for cmd in commands:
                cmd += [f'--start-address={start}',f'--stop-address={end}',str(path)]
                run=subprocess.run(cmd,check=True,capture_output=True,text=True,env={**os.environ,'LC_ALL':'C'})
                need(not run.stderr, 'native stderr')
                texts.append(run.stdout.replace(str(path),'hl-node'))
            outputs[f'gnu/{start:x}.gnu.txt']=texts[0].encode()
            outputs[f'llvm/{start:x}.llvm.txt.gz']=gzip.compress(texts[1].encode(),mtime=0)
            decoded[start]=(native_rows(texts[0]),native_rows(texts[1]))
        need(path.read_bytes()==elf.data,'snapshot changed during native export')
    return outputs,decoded


def collect(binary=None, *, gnu=GNU, llvm=LLVM):
    dependencies(); elf=Elf((binary or ROOT/'artifacts/node/94/hl-node').read_bytes())
    outputs,decoded=decode_snapshot(elf,gnu=gnu,llvm=llvm)
    outputs['records.json']=(json.dumps(validate(elf,decoded),separators=(',',':'))+'\n').encode()
    return outputs


def write_new(out,outputs):
    need(not out.exists(),'output must be new')
    for name,data in outputs.items():
        path=out/name; path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--binary',type=Path);ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--gnu',default=GNU);ap.add_argument('--llvm',default=LLVM);a=ap.parse_args()
    outputs=collect(a.binary,gnu=a.gnu,llvm=a.llvm);write_new(a.out,outputs)
    print(json.dumps({'functions':38,'bytes':19172,'instructions':4655,'files':len(outputs)}))


if __name__=='__main__':main()
