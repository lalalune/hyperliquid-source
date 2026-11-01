"""Pre-Rust parity/interval relation; no instruction interpretation or Rust import."""
from pathlib import Path
import gzip
import hashlib
import json
import random
import struct

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
N = 1 << 64
A, B = 0x21bf92, 0x21bfa3


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def corpus():
    biases = {0, 1, 255, 256, (1 << 32)-1, 1 << 32, (1 << 32)+1,
              (1 << 63)-1, 1 << 63, (1 << 63)+1, N-1, N-2}
    for address in [A, B]:
        biases.update(N-address+d for d in [-1, 0, 1])
    rows = {(bias, tag) for bias in biases for tag in range(256)}
    for bit in range(64):
        for delta in [-1, 0, 1]:
            for tag in [0, 1, 2, 127, 128, 254, 255]:
                rows.add((((1 << bit)+delta) % N, tag))
    rng = random.Random(0x14b4e20)
    rows.update((rng.getrandbits(64), tag) for tag in range(256) for _ in range(4))
    return sorted(rows)


def relation(bias, tag, window):
    # Adjacent even/odd inputs form reversed length pairs; no XOR formulation.
    length = 3*tag + (17 if tag % 2 == 0 else 11)
    offset = 17 if tag > 0 else 0
    rax = divmod(bias + A + offset, N)[1]
    rsi = divmod(bias + B, N)[1]
    interval = [window[i] for i in range(offset, offset+length)]
    return struct.pack('<4Q', rax, length, tag, rsi) + bytes(interval) + bytes(779-length)


def fixtures():
    window = bytes.fromhex((PACKET/'captured-window.hex').read_text())
    require(len(window) == 796, 'complete data union')
    inputs, expected = bytearray(), bytearray()
    tags = {}; wrapped = 0; zero_address = 0; counts = 0
    for bias, tag in corpus():
        inputs.extend(struct.pack('<QB',bias,tag)+window)
        result = relation(bias,tag,window);expected.extend(result)
        tags[tag] = tags.get(tag,0)+1;counts += 1
        rax,_,_,rsi=struct.unpack_from('<4Q',result)
        wrapped += bias+B >= N;zero_address += rax == 0 or rsi == 0
    return bytes(inputs), bytes(expected), {
        'cases':counts,'input_record_bytes':805,'output_record_bytes':811,
        'every_byte_tag':len(tags)==256,'cases_per_tag':tags,
        'wrapped_address_cases':wrapped,'numeric_zero_address_cases':zero_address,
        'maximum_span':{'tag':254,'length':779,'window_end':796},
        'inputs_sha256':sha(inputs),'expected_sha256':sha(expected),'data_sha256':sha(window),
        'oracle_sha256_at_freeze':sha(Path(__file__).read_bytes()),
        'static_sha256_at_freeze':sha((PACKET/'static.json').read_bytes()),
        'target_sha256':'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
        'captured_execution':False,'instruction_emulation':False}


if __name__ == '__main__':
    require(not (ROOT/'src/node94-error-label-selector').exists(), 'freeze before Rust')
    inputs,expected,record=fixtures();record['rust_source_existed_at_freeze']=False
    for name,raw in [('inputs',inputs),('expected',expected)]:
        with (PACKET/(name+'.bin.gz')).open('xb') as f:
            f.write(gzip.compress(raw,compresslevel=1,mtime=0))
    with (PACKET/'frozen.json').open('xb') as f:
        f.write((json.dumps(record,indent=2,sort_keys=True)+'\n').encode())
    print(json.dumps({k:v for k,v in record.items() if k!='cases_per_tag'},sort_keys=True))
