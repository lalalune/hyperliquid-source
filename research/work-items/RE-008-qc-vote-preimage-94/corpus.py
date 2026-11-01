#!/usr/bin/env python3
"""Independent mathematical fixture derivation, frozen before new Rust.

This is newly authored value-level Python, not an x86 interpreter. Preimages
come from PROOF's native field map. Digest fixtures use standard Keccak-f1600
equations with generated rotation/round constants, not captured execution.
"""
import argparse
import gzip
import hashlib
import itertools
from pathlib import Path

PREFIX = b"Hyperliquid Consensus Payload"
BOUNDARIES = (0, 1, 250, 251, 65535, 65536, (1<<32)-1, 1<<32, (1<<64)-1)
MASK = (1<<64)-1

def variable_word(n):
    if not 0 <= n <= MASK:
        raise ValueError("u64 domain")
    if n <= 250:
        return bytes([n])
    for width, marker in ((2,251),(4,252),(8,253)):
        if n < 1 << (8*width):
            return bytes([marker]) + n.to_bytes(width,"little")
    raise ValueError("unreachable u64 width")

def preimage(version, start, round_, signer, block_hash):
    if len(signer)!=20 or len(block_hash)!=32:
        raise ValueError("fixed widths")
    result = (PREFIX + bytes([1]) + signer + variable_word(version)
              + variable_word(start) + variable_word(round_) + block_hash)
    if not 85 <= len(result) <= 109:
        raise ValueError("finite bound")
    return result

def rotations():
    result={(0,0):0}
    x,y=1,0
    for t in range(24):
        result[x,y]=((t+1)*(t+2)//2)%64
        x,y=y,(2*x+3*y)%5
    return result

def constants():
    result=[]
    lfsr=1
    for _ in range(24):
        word=0
        for j in range(7):
            if lfsr&1:
                word ^= 1 << ((1<<j)-1)
            lfsr=((lfsr<<1) ^ (0x71 if lfsr&0x80 else 0)) & 255
        result.append(word)
    return result

def rol(word,n):
    return ((word << n) | (word >> ((64-n)%64))) & MASK

def keccak256(message):
    # Independent coordinate-grid derivation; no imported crypto implementation.
    padded=bytearray(message)
    padded.append(1)
    padded.extend(bytes((-len(padded))%136))
    padded[-1] ^= 128
    a=[0]*25
    rho=rotations()
    for at in range(0,len(padded),136):
        block=padded[at:at+136]
        for i in range(17):
            a[i] ^= int.from_bytes(block[8*i:8*i+8],"little")
        for rc in constants():
            c=[a[x]^a[x+5]^a[x+10]^a[x+15]^a[x+20] for x in range(5)]
            d=[c[(x-1)%5]^rol(c[(x+1)%5],1) for x in range(5)]
            b=[0]*25
            for x in range(5):
                for y in range(5):
                    b[y+5*((2*x+3*y)%5)] = rol(a[x+5*y]^d[x],rho[x,y])
            for x in range(5):
                for y in range(5):
                    a[x+5*y] = b[x+5*y] ^ ((~b[(x+1)%5+5*y]) & b[(x+2)%5+5*y])
            a[0] ^= rc
    return b"".join(x.to_bytes(8,"little") for x in a)[:32]

def rows():
    if keccak256(b"").hex() != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470":
        raise ValueError("empty Keccak known answer")
    if keccak256(b"abc").hex() != "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45":
        raise ValueError("abc Keccak known answer")
    signer=bytes(range(20)); block_hash=bytes(255-i for i in range(32))
    cases=[(f"boundary-{i}",v,s,r,signer,block_hash)
           for i,(v,s,r) in enumerate(itertools.product(BOUNDARIES,repeat=3))]
    cases += [("zero",0,0,0,bytes(20),bytes(32)),
              ("maximum",MASK,MASK,MASK,bytes([255])*20,bytes([255])*32)]
    for i in range(20):
        changed=bytearray(signer); changed[i]^=128
        cases.append((f"signer-bit-{i}",250,251,65536,bytes(changed),block_hash))
    for i in range(32):
        changed=bytearray(block_hash); changed[i]^=128
        cases.append((f"hash-bit-{i}",250,251,65536,signer,bytes(changed)))
    result=["case\tversion\tstart_round\tround\tsigner20\thash32\tpreimage\tdigest32"]
    for name,v,s,r,signer,block_hash in cases:
        p=preimage(v,s,r,signer,block_hash)
        result.append("\t".join((name,str(v),str(s),str(r),signer.hex(),block_hash.hex(),p.hex(),keccak256(p).hex())))
    return ("\n".join(result)+"\n").encode()

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    raw=rows()
    with a.out.open("xb") as f:
        f.write(gzip.compress(raw,mtime=0))
    print(f"{len(raw.splitlines())-1} frozen cases; uncompressed SHA256 {hashlib.sha256(raw).hexdigest()}")
