"""Independent byte-product and binary-string expectations, frozen before Rust."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
MODULUS = 2**64


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def constants():
    return [bytes.fromhex(m['constant_hex']) for m in json.loads((PACKET/'static.json').read_text())['members']]


def corpus():
    values = constants()
    rows = []
    for mask in range(65536):
        chunk = bytes(c if mask // 2**j % 2 else (c+1) % 256 for j,c in enumerate(values[0]))
        address = int.from_bytes(hashlib.sha256(b'mask'+mask.to_bytes(2,'little')).digest()[:8],'little')
        rows.append((0,address,chunk))
    addresses = [0,1,2**31,2**32-1,2**32,2**63-1,2**63,MODULUS-58,MODULUS-57,MODULUS-56,MODULUS-55,MODULUS-1]
    for index, value in enumerate(values):
        for position in range(16):
            for byte in range(256):
                chunk = value[:position]+bytes([byte])+value[position+1:]
                rows.append((index,addresses[(position+byte)%len(addresses)],chunk))
        for address in addresses:
            for other in values:
                rows.append((index,address,other))
        for bit in range(64):
            for address in [2**bit-1,2**bit,min(MODULUS-1,2**bit+1)]:
                rows.append((index,address,value))
        for j in range(256):
            raw=hashlib.sha256(b'family'+bytes([index,j])).digest()
            rows.append((index,int.from_bytes(raw[16:24],'little'),raw[:16]))
    return rows


def fixtures():
    values=constants();rows=corpus();inputs=bytearray();expected=bytearray();matches=wrapped=zero_matches=0
    for index,address,chunk in rows:
        digits=['1' if a==b else '0' for a,b in zip(chunk,values[index])]
        equal=1
        for digit in digits:
            equal *= int(digit)
        mask=int(''.join(reversed(digits)),2)
        destination=(address+56)%MODULUS
        inputs.extend(struct.pack('<QQ16s',index,address,chunk))
        expected.extend(struct.pack('<3Q',equal*destination,destination,mask))
        matches+=equal;wrapped+=address+56>=MODULUS;zero_matches+=equal and destination==0
    record={'cases':len(rows),'members':len(values),'complete_masks_member_zero':65536,'full_matches':matches,'wrapped_destinations':wrapped,'full_match_zero_returns':zero_matches,'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),'captured_code_executed':False}
    return bytes(inputs),bytes(expected),record


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--freeze',action='store_true');args=ap.parse_args()
    inputs,expected,record=fixtures()
    if args.freeze:
        require(not (ROOT/'src/node94-chunk-equality-family').exists(),'Rust source already exists')
        record.update(oracle_sha256_at_freeze=sha(Path(__file__).read_bytes()),static_sha256_at_freeze=sha((PACKET/'static.json').read_bytes()),source_directory_existed_at_freeze=False)
        for name,raw in [('inputs.bin.gz',inputs),('expected.bin.gz',expected)]:
            with (PACKET/name).open('xb') as f:f.write(gzip.compress(raw,mtime=0))
        with (PACKET/'frozen.json').open('x') as f:f.write(json.dumps(record,indent=2)+'\n')
    else:
        frozen=json.loads((PACKET/'frozen.json').read_text());require(all(frozen[k]==v for k,v in record.items()),'frozen metadata drift')
        require(frozen['oracle_sha256_at_freeze']==sha(Path(__file__).read_bytes()),'oracle source drift')
        for name,raw in [('inputs.bin.gz',inputs),('expected.bin.gz',expected)]:require(gzip.decompress((PACKET/name).read_bytes())==raw,'frozen stream drift')
    print(json.dumps(record,indent=2))


if __name__=='__main__':main()
