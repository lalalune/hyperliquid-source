"""Independent cursor image/ELF review; no packet imports or executable replay."""
import argparse, gzip, hashlib, json, struct
from pathlib import Path
N = 1 << 64
TARGET = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
STARTS = [0x52c6e50, 0x52c6e70, 0x52c6e80, 0x52c6ea0]
BODIES = [
 'f30f1efa488b5710488b4208482b024883c028c3',
 'f30f1efa488b4720488b00c3',
 'f30f1efa488b5710488b4720483b420874084883c00848894720c3',
 'f30f1efa488b5710488b4720483b02740f4883e80848894720c3660f1f440000488b420848894720c3',
]
def need(ok, message):
    if not ok: raise ValueError(message)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def inspect(repo):
    packet = repo / 'research/work-items/RE-004-cursor-family-rust-94'
    rawin = gzip.decompress((packet / 'inputs.bin.gz').read_bytes())
    rawout = gzip.decompress((packet / 'expected.bin.gz').read_bytes())
    frozen = json.loads((packet / 'frozen.json').read_text())
    need(len(rawin) % 168 == 0 and len(rawout) == len(rawin)//168*152, 'framing')
    counts = {'cases': 0, 'refusals': 0, 'changed_images': 0, 'preserved_rdx': 0, 'admitted_per_member': [0]*4}
    witnesses = dict.fromkeys(['read_skips_absent_bounds', 'span_skips_absent_cursor', 'advance_skips_absent_first', 'unequal_retreat_skips_absent_last', 'wrapped_field', 'arithmetic_wrap', 'high_result', 'write_overlaps_read', 'advance_equal_no_write'], 0)
    for idx in range(len(rawin)//168):
        data = rawin[idx*168:(idx+1)*168]
        member, base, obj, incoming, length = struct.unpack_from('<5Q', data)
        image = data[40:]
        need(member < 4 and length <= 128, 'descriptor')
        reads = []
        def offset(address):
            delta = address-base
            return delta if 0 <= delta <= length-8 else None
        def get(address):
            at = offset(address)
            if at is None: raise LookupError
            reads.append(address)
            return struct.unpack_from('<Q', image, at)[0]
        at16 = (obj+16) & (N-1)
        at32 = (obj+32) & (N-1)
        output = image
        store = None
        arithmetic = False
        try:
            if base+length > N: raise LookupError
            if member == 1:
                c = get(at32)
                a, d = get(c), incoming
            elif member == 0:
                p = get(at16)
                end = get((p+8)&(N-1))
                begin = get(p)
                a, d = (end + N - begin + 40) & (N-1), p
                arithmetic = end-begin+40 != a
            else:
                p, c = get(at16), get(at32)
                bound = get((p+8)&(N-1) if member == 2 else p)
                same = (c ^ bound) == 0
                # Literal action table: 0 keep, 1 add, 2 subtract, 3 second bound.
                action = ((1, 0), (2, 3))[member-2][same]
                if action == 0: a = c
                elif action == 1: a = (c+8)&(N-1); arithmetic = c+8 >= N
                elif action == 2: a = (c+N-8)&(N-1); arithmetic = c < 8
                else: a = get((p+8)&(N-1))
                d = p
                if action != 0: store = at32
            if store is not None:
                # Whole-image integer overlay, distinct from the oracle's slice write.
                shift = 8*offset(store)
                mask = (N-1) << shift
                output = ((int.from_bytes(image, 'little') & ~mask) | (a << shift)).to_bytes(128, 'little')
            wanted = struct.pack('<3Q', 1, a, d) + output
            counts['admitted_per_member'][member] += 1
            counts['preserved_rdx'] += member == 1
            witnesses['read_skips_absent_bounds'] += member == 1 and offset(at16) is None
            witnesses['span_skips_absent_cursor'] += member == 0 and offset(at32) is None
            witnesses['advance_skips_absent_first'] += member == 2 and offset(p) is None
            witnesses['unequal_retreat_skips_absent_last'] += member == 3 and c != bound and offset((p+8)&(N-1)) is None
            witnesses['wrapped_field'] += (member != 1 and obj+16 >= N) or (member != 0 and obj+32 >= N)
            witnesses['arithmetic_wrap'] += arithmetic
            witnesses['high_result'] += a >= N//2
            witnesses['write_overlaps_read'] += store is not None and any(j != 1 and r < store+8 and store < r+8 for j, r in enumerate(reads))
            witnesses['advance_equal_no_write'] += member == 2 and store is None
        except LookupError:
            wanted = bytes(24) + image
            counts['refusals'] += 1
        need(wanted == rawout[idx*152:(idx+1)*152], f'fixture {idx}')
        counts['cases'] += 1
        counts['changed_images'] += output != image
    need(all(counts[k] == frozen[k] for k in counts), 'frozen counts')
    need(sha(rawin) == frozen['inputs_sha256'] and sha(rawout) == frozen['expected_sha256'], 'frozen bytes')
    binary = (repo/'artifacts/node/94/hl-node').read_bytes()
    need(len(binary) == 91774280 and sha(binary) == TARGET, 'target')
    shoff = struct.unpack_from('<Q', binary, 40)[0]
    shsize, shnum, strindex = struct.unpack_from('<HHH', binary, 58)
    need(shsize == 64, 'ELF64')
    sections = [struct.unpack_from('<IIQQQQIIQQ', binary, shoff+i*64) for i in range(shnum)]
    ns = sections[strindex]; names = binary[ns[4]:ns[4]+ns[5]]
    def name(s): return names[s[0]:].split(b'\0',1)[0].decode()
    def mapped(address, length):
        found = [s for s in sections if s[1] != 8 and s[3] <= address and address+length <= s[3]+s[5]]
        need(len(found) == 1, 'mapping')
        s = found[0]; off = s[4]+address-s[3]
        return binary[off:off+length], s
    phoff = struct.unpack_from('<Q',binary,32)[0]
    phsize,phnum = struct.unpack_from('<HH',binary,54)
    need(phsize == 56,'program shape')
    programs = [struct.unpack_from('<IIQQQQQQ',binary,phoff+i*56) for i in range(phnum)]
    body_records=[]
    for start, body, padding in zip(STARTS,BODIES,[12,4,5,7]):
        expected=bytes.fromhex(body); actual,s=mapped(start,len(expected))
        need(actual==expected and name(s)=='.text','complete body')
        need(mapped(start+len(expected),padding)[0]==b'\xcc'*padding,'padding')
        body_records.append({'start':start,'bytes':len(actual),'sha256':sha(actual)})
    need(sum(r['bytes'] for r in body_records)==100,'full family')
    relas=[]
    for s in sections:
        need(s[1]!=9,'unexpected REL')
        if s[1]==4:
            need(s[9]==24 and s[5]%24==0,'RELA shape')
            for at in range(s[4],s[4]+s[5],24):
                r=(at,*struct.unpack_from('<QQq',binary,at))
                need(r[2]&0xffffffff in [1,6,7,8,18],'relocation width')
                relas.append(r)
    need(len(relas)==80300,'RELA count')
    naming=[r for r in relas if r[3] in STARTS]
    need(len(naming)==4 and sorted(r[3] for r in naming)==STARTS,'entry slots')
    for r in naming:
        _,addr,info,_=r; raw,s=mapped(addr,8)
        need(info==8 and raw==bytes(8) and name(s)=='.data.rel.ro','slot bytes/type')
        need([q for q in relas if q[1]<addr+8 and addr<q[1]+8]==[r],'unique writer')
        need(sum(p[0]==1 and p[3]<=addr and addr+8<=p[3]+p[5] for p in programs)==1,'slot PT_LOAD')
    for start,body,padding in zip(STARTS,BODIES,[12,4,5,7]):
        end=start+len(bytes.fromhex(body))+padding
        need(not any(r[1]<end and start<r[1]+8 for r in relas),'code writer')
    # Independently inspect actual relative-PC FDE words selected by the retained
    # record, while the standalone static verifier performs the complete census.
    static=json.loads((packet/'static.json').read_text()); frames=[]
    for member,start,body in zip(static['members'],STARTS,BODIES):
        rec=member['records']['fde']; at=rec['file_offset']
        length,cie_delta,relpc,extent=struct.unpack_from('<IIiI',binary,at)
        need(at+8+relpc==start and extent==len(bytes.fromhex(body)),'FDE extent')
        cie=at+4-cie_delta
        need(cie==member['frame']['cie'],'CIE reference')
        need(binary[at:at+length+4].hex()==rec['hex'],'FDE full bytes')
        frames.append({'fde':at,'cie':cie,'start':start,'bytes':extent})
    paths=[repo/'src/node94-cursor-family/lib.rs',repo/'src/node94-cursor-family/input_only_driver.rs']+[packet/x for x in ['PROOF.md','README.md','oracle.py','frozen.json','verify_static.py','static.json']]
    return {'target_sha256':TARGET,'reviewed_hashes':{str(p.relative_to(repo)):sha(p.read_bytes()) for p in paths},'method':'Interval qword reader, XOR equality/action table, whole-image integer overlay; standalone struct-only ELF/RELA and relative FDE words, no packet import.',**counts,'witnesses':witnesses,'fixture_mismatches':0,'body_records':body_records,'frames':frames,'slots':naming,'rela_records':len(relas),'captured_execution':False,'instruction_emulation':False,'native_replay':False,'assessment':'No blocker: complete RAX/RDX, selective reads, aliases, wrapping arithmetic and atomic safe refusals agree. Finite vectors supplement the full ordinary-memory proof.'}
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--repo',type=Path,default=Path.cwd());parser.add_argument('--out',type=Path);args=parser.parse_args()
    result=inspect(args.repo.resolve());result['review_script_sha256']=sha(Path(__file__).read_bytes());raw=json.dumps(result,indent=2,sort_keys=True)+'\n'
    if args.out:args.out.write_text(raw)
    else:print(raw,end='')
if __name__=='__main__':main()
