"""Node94 bounded local-port instruction oracle; authorized offline evaluation.

No capture process, libc, socket, or chain executes. Inputs remain pinned.
"""
import sys, json, struct, hashlib
from pathlib import Path
repo = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo / 'tools'))
import decimal_scaled_u64 as cpu
import node_port_static as prior
data = (repo / prior.TARGET).read_bytes()
if not hashlib.sha256(data).hexdigest() == cpu.SHA256:
    raise ValueError('target-grounded port check failed')
image = cpu.Image(data)
pimage = prior.Image(data)
records = json.loads((repo / 'research/work-items/transport-node-port-94/records.json').read_text())

class Machine(cpu.Machine):

    def unary(self, insn, key, bits, here):
        kind = self.image.data[insn.modrm] >> 3 & 7
        if key == 247 and bits == 16 and (kind == 4):
            v = self.read(self.operand(insn), 16)
            a = self.get(cpu.RAX, 16)
            if not (v is not None and a is not None):
                raise ValueError('target-grounded port check failed')
            full = a * v
            self.put(cpu.RAX, 16, full & 65535)
            self.put(cpu.RDX, 16, full >> 16)
            over = bool(full >> 16)
            self.flags = [over, None, None, over]
            return
        return super().unary(insn, key, bits, here)

    def call(self, target, where):
        raise ValueError('Unexpected call')

def equation(index, base):
    product = index * 1000
    return ['M'] if product > 65535 else ['A'] if product + base > 65535 else ['K', product + base]

def native(site, index, base, img=image):
    start = int(site['mul'], 16)
    if site['shape'] == 'const_cmp':
        stop = start + 13 + 3 + 6 + 6 + 5
        reg = cpu.RAX
    else:
        stop = int(site['add'], 16) + 9
        raw = img.data[img.file_offset(int(site['add'], 16)) + 2]
        reg = raw & 7
    m = Machine(img)
    m.pc = start
    m.set_reg(cpu.RAX, index)
    m.set_reg(cpu.RSI, base)
    m.set_reg(cpu.RCX, base)
    panics = {int(site['mul_overflow']['stub'], 16): ['M'], int(site['add_overflow']['stub'], 16): ['A']}
    lo, hi = image.fde_of(start)
    for _ in range(64):
        if m.pc in panics:
            return (panics[m.pc], sorted(m.seen))
        if m.pc == stop:
            value = m.get(reg, 16)
            if not value is not None:
                raise ValueError('target-grounded port check failed')
            return (['K', value], sorted(m.seen))
        if not lo <= m.pc < hi:
            raise ValueError('escaped owning FDE')
        m.step()
    raise ValueError('step bound')

def produce(output):
    rows = []
    seen = set()
    sites = []
    for site in records['sites']:
        start = int(site['mul'], 16)
        lo, hi = image.fde_of(start)
        if not hex(lo) == site['fde']:
            raise ValueError('target-grounded port check failed')
        checked = prior.check_site(pimage, start, prior.find_tables(pimage))
        if not checked == site:
            raise ValueError('target-grounded port check failed')
        bases = prior.PORTS if site['base_port'] is None else [site['base_port']]
        for base in bases:
            for index in range(256):
                actual, trace = native(site, index, base)
                if not actual == equation(index, base):
                    raise ValueError((site, index, base, actual))
                rows.append({'fde': site['fde'], 'base': base, 'index': index, 'outcome': actual})
                seen.update(trace)
        sites.append({'fde': site['fde'], 'start': hex(start), 'end': hex(hi), 'full_fde_sha256': hashlib.sha256(data[image.file_offset(lo):image.file_offset(lo) + hi - lo]).hexdigest()})
    widths = [(36459749, 36459821, 415, 416, 413), (70840813, 70840907, 552, 553, None), (75188901, 75188995, 584, 585, None)]
    width_rows = []
    for start, stop, tagoff, indexoff, selector in widths:
        for tag in (0, 1):
            for index in range(256):
                m = Machine(image)
                m.pc = start
                m.set_reg(cpu.RBX, cpu.INPUT)
                m.set_reg(cpu.RSP, cpu.STACK)
                m.mem[cpu.INPUT + tagoff] = tag
                m.mem[cpu.INPUT + indexoff] = index
                if selector is not None:
                    m.mem[cpu.INPUT + selector] = 0
                for _ in range(60):
                    if m.pc == stop or (tag == 0 and m.pc in (36459892, 70840932, 75189020)):
                        break
                    m.step()
                else:
                    raise ValueError('width step bound')
                if tag:
                    if not (m.pc == stop and m.get(cpu.RAX, 32) == index):
                        raise ValueError('target-grounded port check failed')
                elif not m.get(cpu.RAX, 32) == (0 if start == 36459749 else 0):
                    raise ValueError('target-grounded port check failed')
                width_rows.append([hex(start), tag, index, m.get(cpu.RAX, 32), hex(m.pc)])
    payload = b''.join(((json.dumps(r, sort_keys=True, separators=(',', ':')) + '\n').encode() for r in rows))
    control_records = []
    site = records['sites'][0]
    start = int(site['mul'], 16)
    for name, va, newbyte in [('stride', start + 2, 231), ('multiply-branch', start + 8, 129), ('add-branch', start + 23, 134)]:
        private = bytearray(data)
        off = image.file_offset(va)
        oldbyte = private[off]
        private[off] = newbyte
        changed = cpu.Image(private)
        mismatches = 0
        for index in range(256):
            actual, _ = native(site, index, 4001, changed)
            if actual != equation(index, 4001):
                mismatches += 1
        if not mismatches > 0:
            raise ValueError('target-grounded port check failed')
        control_records.append({'name': name, 'va': hex(va), 'old_byte': oldbyte, 'new_byte': newbyte, 'mismatches': mismatches, 'cases': 256})
    root = Path(output)
    root.mkdir(parents=True, exist_ok=False)
    (root / 'native-rows.jsonl').write_bytes(payload)
    (root / 'width-rows.json').write_text(json.dumps(width_rows) + '\n')
    gold = {}
    for row in rows:
        key = (row['base'], row['index'])
        if not (key not in gold or gold[key] == row['outcome']):
            raise ValueError('target-grounded port check failed')
        gold[key] = row['outcome']
    (root / 'target-vectors.tsv').write_text(''.join((f'{prior.PORTS.index(base)}\t{index}\t' + '\t'.join(map(str, out)) + '\n' for (base, index), out in sorted(gold.items(), key=lambda r: (prior.PORTS.index(r[0][0]), r[0][1])))))
    (root / 'freeze.json').write_text(json.dumps({'target': cpu.SHA256, 'site_cases': len(rows), 'distinct_port_index_cases': len(gold), 'width_cases': len(width_rows), 'native_rows_sha256': hashlib.sha256(payload).hexdigest(), 'sites': sites, 'scope': 'Arithmetic corridor beginning at multiply, stopping at success or resolved panic stub, not whole functions or unwinder. Width corridors separately checked.'}, indent=2) + '\n')
    (root / 'native-controls.json').write_text(json.dumps(control_records, indent=2) + '\n')

    native_rows=[]
    for va in sorted(seen):
        insn=cpu.decode(data,image.file_offset(va),va)
        native_rows.append({'va':hex(va),'size':insn.size,
            'bytes':data[insn.off:insn.off+insn.size].hex()})
    (root/'visited-instructions.json').write_text(json.dumps(native_rows,indent=2)+'\n')

    return {'site_cases': len(rows), 'distinct_cases': len(gold), 'width_cases': len(width_rows)}

if __name__ == '__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(produce(args.output)))
