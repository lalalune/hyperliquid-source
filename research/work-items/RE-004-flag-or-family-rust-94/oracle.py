"""Pre-Rust fixed data-window lookup and base-two digit union expectations."""
import argparse,gzip,hashlib,json,random,struct
from pathlib import Path
PACKET=Path(__file__).resolve().parent
ROOT=PACKET.parents[2]
MOD=2**64
U32=2**32-1


def require(ok,message):
    if not ok:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def members():return json.loads((PACKET/'static.json').read_text())['members']


def corpus():
    rows=[];ms=members();old_values=[0,U32,0xaaaaaaaa,0x55555555]
    for bit in range(32):old_values += [2**bit,U32-2**bit]
    addresses=[0,1,2**32-1,2**32,2**63-1,2**63,MOD-1]
    for kind,m in enumerate(ms):
        table=m['table_va'];field=m['field_offset']
        biases=addresses+[MOD-table-1,MOD-table,MOD-table+1]
        objects=addresses+[MOD-field-1,MOD-field,MOD-field+1]
        for index in range(256):
            for j,old in enumerate(old_values):rows.append((kind,index,biases[(index+j)%len(biases)],objects[(3*index+j)%len(objects)],old))
            for bit in range(8,64):
                old=(index*0x01010101+bit*0x01020305)%2**32
                rows.append((kind,2**bit+index,biases[bit%len(biases)],objects[(index+bit)%len(objects)],old))
        for bit in range(64):
            for value in [2**bit-1,2**bit,min(MOD-1,2**bit+1)]:rows.append((kind,value,value,(MOD-1-value),U32))
    rng=random.Random(0x15625e0)
    for _ in range(3072):rows.append((rng.randrange(3),rng.getrandbits(64),rng.getrandbits(64),rng.getrandbits(64),rng.getrandbits(32)))
    return rows


def fixtures():
    ms=members();tables=[bytes.fromhex(m['table_hex']) for m in ms];rows=corpus();inputs=bytearray();expected=bytearray();high_index=high_mask=multi=wrapped_base=wrapped_store=0
    for kind,index,bias,object_,old in rows:
        n=index%256;raw=tables[kind][4*n:4*n+4];mask=sum(byte*256**j for j,byte in enumerate(raw))
        new=sum(2**j for j in range(32) if old//2**j%2 or mask//2**j%2)
        table=(bias+ms[kind]['table_va'])%MOD;address=(object_+ms[kind]['field_offset'])%MOD
        inputs.extend(struct.pack('<5Q',kind,index,bias,object_,old));expected.extend(struct.pack('<4Q',mask,table,address,new))
        high_index+=index>=256;high_mask+=mask>=2**31;multi+=mask.bit_count()>1;wrapped_base+=bias+ms[kind]['table_va']>=MOD;wrapped_store+=object_+ms[kind]['field_offset']>=MOD
    record={'cases':len(rows),'members':3,'indices_per_member':256,'high_index_bits_cases':high_index,'selected_high_bit_masks':high_mask,'selected_multi_bit_words':multi,'wrapped_table_base':wrapped_base,'wrapped_store_address':wrapped_store,'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),'oracle_sha256_at_freeze':sha(Path(__file__).read_bytes()),'static_sha256_at_freeze':sha((PACKET/'static.json').read_bytes()),'source_directory_existed_at_freeze':False,'captured_code_executed':False}
    return bytes(inputs),bytes(expected),record


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--freeze',action='store_true');args=ap.parse_args();inputs,outputs,record=fixtures()
    if args.freeze:
        require(not(ROOT/'src/node94-flag-or-family').exists(),'Rust exists before freeze')
        for name,raw in [('inputs',inputs),('expected',outputs)]:
            with (PACKET/(name+'.bin.gz')).open('xb') as f:f.write(gzip.compress(raw,mtime=0))
        with (PACKET/'frozen.json').open('x') as f:f.write(json.dumps(record,indent=2)+'\n')
    else:
        require(json.loads((PACKET/'frozen.json').read_text())==record,'frozen metadata drift')
        for name,raw in [('inputs',inputs),('expected',outputs)]:require(gzip.decompress((PACKET/(name+'.bin.gz')).read_bytes())==raw,'frozen streams')
    print(json.dumps(record,indent=2))


if __name__=='__main__':main()
