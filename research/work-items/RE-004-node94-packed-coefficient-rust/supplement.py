"""Explicitly post-Rust boundary extension; the original oracle/freeze are unchanged."""
import datetime
import gzip
import hashlib
import json
from pathlib import Path
import oracle

PACKET = oracle.PACKET


def fixture_bytes():
    original = set(gzip.decompress((PACKET/'frozen/inputs.tsv.gz').read_bytes()).splitlines())
    cases=set()
    for rank in (1,2,3):
        for top_bit in range(32):
            for lower_bit in (31,32,47,63):
                for side in (0,1):
                    for count in (0,1,32):
                        a=[0]*4;b=[0]*4
                        a[rank]=2**top_bit
                        a[rank-1] |= 2**lower_bit
                        a[0] |= 0x1234567
                        b[0]=0x7654321
                        if side:a,b=b,a
                        words=(*a,*b,count)
                        row='\t'.join(['1',*(f'{w:016x}' for w in words)]).encode()
                        if row not in original:cases.add(words)
    inputs=[];expected=[]
    for words in sorted(cases):
        output,_=oracle.relation(1,words[:4],words[4:8],words[8])
        inputs.append('\t'.join(['1',*(f'{w:016x}' for w in words)]))
        expected.append(','.join(f'{w:016x}' for w in output))
    return ('\n'.join(inputs)+'\n').encode(), ('\n'.join(expected)+'\n').encode()


def freeze():
    source=oracle.ROOT/'src/node94-packed-coefficient/lib.rs'
    oracle.require(source.exists(),'Supplement must disclose post-Rust timing')
    folder=PACKET/'supplemental';folder.mkdir(exist_ok=True)
    oracle.require(not (folder/'SUPPLEMENT-FREEZE.json').exists(),'Supplement already frozen')
    old=json.loads((PACKET/'frozen/ORACLE-FREEZE.json').read_text())
    oracle.require(oracle.digest(PACKET/'oracle.py')==old['oracle_source_sha256'],'Original oracle changed')
    inputs,expected=fixture_bytes()
    for name,raw in (('inputs.tsv',inputs),('expected.txt',expected)):
        (folder/(name+'.gz')).write_bytes(gzip.compress(raw,mtime=0))
    record={'frozen_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'rust_source_present':True,
      'reason':'Initial wrong_lower_limb native mutant was ineffective. Add selected-high-rank low-leading-bit plus preceding-limb high-bit inputs; expectations come from the unchanged pre-Rust affine oracle.',
      'cases':len(inputs.splitlines()),'supplement_source_sha256':oracle.digest(__file__),
      'rust_source_sha256':oracle.digest(source),'original_oracle_source_sha256':old['oracle_source_sha256'],
      'original_freeze_sha256':oracle.digest(PACKET/'frozen/ORACLE-FREEZE.json'),
      'inputs_sha256':hashlib.sha256(inputs).hexdigest(),'expected_sha256':hashlib.sha256(expected).hexdigest()}
    (folder/'SUPPLEMENT-FREEZE.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))


if __name__=='__main__':freeze()
