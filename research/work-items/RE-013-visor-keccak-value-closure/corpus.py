#!/usr/bin/env python3
"""Independent mathematical bit-plane oracle, not a native instruction evaluator.

Coordinates follow Keccak reference 3.0 sections 1.2/1.3. This uses 64 planes
of 25 bits, coordinate rho/pi, generated offsets, and an 8-bit LFSR, whereas
the already-existing MIT provider uses 25 u64 lanes and a fixed 24-lane cycle.
No provider, native disassembly, native constants, or expected stream is read
to compute an answer. Official vectors are a separately checked input fixture.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def constants():
    lfsr, result = 1, []
    for _ in range(24):
        rc = 0
        for j in range(7):
            rc ^= (lfsr & 1) << ((1 << j)-1)
            lfsr = ((lfsr << 1) ^ (0x71 if lfsr & 0x80 else 0)) & 255
        result.append(rc)
    return result


def coordinates():
    offsets = {(0,0):0}
    x,y = 1,0
    for t in range(24):
        offsets[x,y] = ((t+1)*(t+2)//2) % 64
        x,y = y,(2*x+3*y)%5
    require(len(offsets)==25 and (x,y)==(1,0),'rho orbit')
    return [(x+5*y,y+5*((2*x+3*y)%5),offsets[x,y]) for y in range(5) for x in range(5)]


RC = constants()
COORDS = coordinates()


def ror5(value, n):
    return ((value >> n) | (value << (5-n))) & 31


def permutation(planes):
    """Pure 1600-bit permutation specification; planes[z] holds a[x,y,z]."""
    require(len(planes)==64 and all(0<=v<1<<25 for v in planes),'plane domain')
    a = list(planes)
    for rc in RC:
        c = [(v ^ (v>>5) ^ (v>>10) ^ (v>>15) ^ (v>>20)) & 31 for v in a]
        theta = []
        for z,v in enumerate(a):
            d = ror5(c[z],4) ^ ror5(c[(z-1)%64],1)
            theta.append(v ^ (d | d<<5 | d<<10 | d<<15 | d<<20))
        b = [0]*64
        for source,dest,rotation in COORDS:
            for z in range(64):
                b[z] |= ((theta[(z-rotation)%64] >> source) & 1) << dest
        a = []
        for z,v in enumerate(b):
            out = 0
            for y in range(5):
                row = (v >> (5*y)) & 31
                out |= (row ^ ((~ror5(row,1)) & ror5(row,2))) << (5*y)
            a.append(out ^ ((rc >> z) & 1))
    return a


def digest(message):
    # pad10*1 on byte-aligned messages: first bit and final rate-block bit.
    padded = bytearray(message)
    padded.append(1)
    padded.extend(b'\0' * ((-len(padded)) % 136))
    padded[-1] ^= 128
    a = [0]*64
    for start in range(0,len(padded),136):
        for byte_index,byte in enumerate(padded[start:start+136]):
            lane,z0 = divmod(byte_index,8)
            for bit in range(8):
                a[8*z0+bit] ^= ((byte>>bit)&1) << lane
        a = permutation(a)
    return bytes(sum(((a[8*(i%8)+bit]>>(i//8))&1)<<bit for bit in range(8)) for i in range(32))


def finite_certificate():
    # Independent coordinate formulas, not native instruction interpretation.
    require(sorted(s for s,d,r in COORDS)==list(range(25)),'rho sources')
    require(sorted(d for s,d,r in COORDS)==list(range(25)),'pi bijection')
    for row in range(32):
        actual=row ^ ((~ror5(row,1)) & ror5(row,2))
        expected=sum((((row>>x)&1) ^ ((1^((row>>((x+1)%5))&1)) & ((row>>((x+2)%5))&1))) << x for x in range(5))
        require(actual==expected,'chi truth table')
    for bit in range(1600):
        lane,z=divmod(bit,64);x,y=lane%5,lane//5
        # Single-bit theta's output consists of itself plus two 5-lane columns.
        c=[0]*64;c[z]=1<<x
        planes=[]
        for zz in range(64):
            d=ror5(c[zz],4)^ror5(c[(zz-1)%64],1)
            planes.append((int(zz==z)<<lane) ^ (d|d<<5|d<<10|d<<15|d<<20))
        expected=[0]*64;expected[z]^=1<<lane
        for yy in range(5):
            expected[z]^=1<<((x+1)%5+5*yy)
            expected[(z+1)%64]^=1<<((x-1)%5+5*yy)
        require(planes==expected,'theta linear basis')
    for tail in range(136):
        block=bytearray(136);block[tail]^=1;block[135]^=128
        require(block[tail]==(129 if tail==135 else 1),'padding collision')
        require(sum(v.bit_count() for v in block)==2,'padding bit count')
    return dict(theta_basis_vectors=1600,chi_rows=32,rho_pi_coordinates=25,padding_tails=136,
                round_constants=[f'{x:016x}' for x in RC],coordinates=COORDS)


def cases():
    inputs, labels, seen = [], [], {}
    def add(message, label):
        key=bytes(message)
        if key in seen:
            labels[seen[key]].append(label)
            return
        seen[key]=len(inputs);inputs.append(key);labels.append([label])
    vectors=json.loads((HERE/'official-vectors.json').read_text())
    for v in vectors['vectors']:
        add(bytes.fromhex(v['input_hex']),f"official-byte-length-{v['bytes']}")
    for b in range(256):add(bytes([b]),f'single-byte-{b}')
    for n in range(408):
        add(bytes(n),f'zero-length-{n}')
        add(bytes([255])*n,f'ones-length-{n}')
        add(bytes((i*197+n*29+17)&255 for i in range(n)),f'pattern-length-{n}')
    for n in (135,136,137,271,272,273):
        for i in (0,1,7,8,31,32,63,64,127,128,n-1):
            if i<n:
                for bit in (0,7):
                    b=bytearray(n);b[i]=1<<bit;add(b,f'sparse-{n}-{i}-{bit}')
    for n in (543,544,545,1087,1088,1089,4095,4096,4097):
        add(bytes((i*i+11*i+91)&255 for i in range(n)),f'multiblock-{n}')
    for i in range(128):
        n=2+(i*103)%1200
        # Reproducible input generator only, not an oracle/provider dependency.
        b=bytearray();counter=0
        while len(b)<n:
            b.extend(hashlib.sha256(f'visor-keccak-input-v1:{i}:{counter}'.encode()).digest());counter+=1
        add(b[:n],f'deterministic-{i}')
    add(b'abc','ascii-abc');add(b'\0abc\0','embedded-nul')
    return inputs,labels,vectors


def generate(out):
    require(not out.exists(),'fresh corpus output required')
    certificate=finite_certificate()
    inputs,labels,vectors=cases()
    answers=[digest(x) for x in inputs]
    lookup=dict(zip(inputs,answers,strict=True))
    for v in vectors['vectors']:
        require(lookup[bytes.fromhex(v['input_hex'])].hex()==v['expected_hex'],'official KAT mismatch')
    # Opaque IDs: semantic labels appear only in provenance, never driver input.
    ids=[hashlib.sha256(b'visor-keccak-case-v1'+i.to_bytes(8,'little')).hexdigest()[:24] for i in range(len(inputs))]
    require(len(set(ids))==len(ids),'ID uniqueness')
    iraw=''.join(f'{i}\t{x.hex() or "-"}\n' for i,x in zip(ids,inputs,strict=True)).encode()
    eraw=''.join(f'{i}\t{x.hex()}\n' for i,x in zip(ids,answers,strict=True)).encode()
    out.mkdir(parents=True)
    for name,raw in [('inputs.tsv.gz',iraw),('expected.tsv.gz',eraw)]:
        (out/name).write_bytes(gzip.compress(raw,mtime=0))
    provenance=dict(cases=[dict(id=i,labels=l,bytes=len(x)) for i,l,x in zip(ids,labels,inputs,strict=True)],
                    official_checks=len(vectors['vectors']),inputs_sha256=sha(iraw),expected_sha256=sha(eraw))
    (out/'provenance.json').write_text(json.dumps(provenance,separators=(',',':'),sort_keys=True)+'\n')
    (out/'mathematical-certificate.json').write_text(json.dumps(certificate,separators=(',',':'),sort_keys=True)+'\n')
    print(json.dumps(dict(status='PASS mathematical specification only',cases=len(inputs),official_checks=len(vectors['vectors']),
                          inputs_sha256=sha(iraw),expected_sha256=sha(eraw))))


if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True)
    generate(ap.parse_args().out)
