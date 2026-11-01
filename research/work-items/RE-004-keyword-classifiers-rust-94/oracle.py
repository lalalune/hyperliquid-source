"""Pre-Rust base-256 keyword lookup and immutable output-image relation."""
import gzip
import struct
from verify_static import ROOT, PACKET, TARGET, encoded, require, sha

MOD = 2 ** 64
SIZE = 64
HEADER = struct.Struct('<BQQQQB')
WORDS = ((b'until', b'required_matches'), (b'vip', b'mm'), (b'input', b'gas_limit'))
# Dictionary keys are complete base-256 integers, independently of Rust's
# selected byte-slice equality. Length remains a separate full-u64 key.
KEYS = {(kind, len(word), sum(b * 256 ** i for i, b in enumerate(word))): tag
        for kind, words in enumerate(WORDS) for tag, word in enumerate(words)}


def expected(row):
    kind, image_base, out, source, length, admitted, initial = row
    def answer(error, value=0, data=initial):
        return struct.pack('<BQ', error, value) + data
    if admitted and image_base + admitted > MOD:
        return answer(1)
    selected = next((len(word) for word in WORDS[kind] if len(word) == length), 0)
    if selected:
        offset = source - image_base
        if offset < 0 or offset + selected > admitted:
            return answer(2)
        number = sum(initial[offset + j] * 256 ** j for j in range(selected))
        tag = KEYS.get((kind, length, number), 2)
    else:
        tag = 2
    at = out - image_base
    if at < 0 or at + 2 > admitted:
        return answer(3)
    final = bytes(9 if j == at else tag if j == at + 1 else initial[j] for j in range(SIZE))
    return answer(0, out, final)


def corpus():
    rows = set()
    def add(kind, word=b'', image_base=4096, source=16, out=48, length=None, admitted=SIZE, seed=37):
        image = bytearray((seed + 23 * j) % 256 for j in range(SIZE))
        if 0 <= source and source + len(word) <= SIZE:
            image[source:source + len(word)] = word
        rows.add((kind, image_base, (image_base + out) % MOD, (image_base + source) % MOD,
                  len(word) if length is None else length, admitted, bytes(image)))
    for kind, words in enumerate(WORDS):
        for word in words:
            for position in range(len(word)):
                for byte in range(256):
                    add(kind, word[:position] + bytes([byte]) + word[position + 1:])
            for source in range(8, 16):
                for delta in range(-2, len(word) + 2):
                    add(kind, word, source=source, out=source + delta)
            for image_base in (0, 4096, MOD - SIZE):
                for source in (0, 1, SIZE - len(word), SIZE - len(word) + 1, SIZE, MOD - 1):
                    for out in (0, 1, 62, 63, 64, MOD - 1):
                        add(kind, word, image_base=image_base, source=source, out=out)
            for admitted in (0, 1, 2, 15, 16, 17, 18, 19, 20, 21, 24, 25, 31, 32, 48, 49, 50, 63, 64):
                add(kind, word, admitted=admitted)
            for high in (1 << 32, 1 << 63):
                add(kind, word, length=high + len(word))
        for length in (0,1,2,3,4,5,6,8,9,15,16,17,1 << 32,1 << 63,MOD - 1):
            for source in (0,16,64,MOD - 1):
                add(kind, length=length, source=source)
        for image_base in (MOD - SIZE + 1, MOD - 2, MOD - 1):
            add(kind, words[0], image_base=image_base)
        for index in range(256):
            raw = bytes.fromhex(sha(f'keyword94:{kind}:{index}'.encode()))
            length = (len(words[raw[0] % 2]) if raw[1] % 2 else int.from_bytes(raw[2:10], 'little'))
            add(kind, raw[10:26][:min(length,16)], length=length, source=raw[26] % 65,
                out=raw[27] % 65, admitted=raw[28] % 65, seed=raw[29])
    return sorted(rows)


def fixtures():
    rows=corpus(); outputs=[expected(row) for row in rows]
    inputs=b''.join(HEADER.pack(*row[:6])+row[6] for row in rows); raw=b''.join(outputs)
    counts={str(code):sum(row[0]==code for row in outputs) for code in range(4)}
    require(all(counts.values()), 'missing safe outcome')
    kinds={str(k):sum(r[0]==k for r in rows) for k in range(3)}
    tags={str(k):{str(t):sum(r[0]==k and o[0]==0 and o[9+(r[2]-r[1])+1]==t for r,o in zip(rows,outputs)) for t in range(3)} for k in range(3)}
    require(all(n for row in tags.values() for n in row.values()), 'missing classifier output')
    return inputs,raw,{'target_sha256':TARGET,'cases':len(rows),'image_bytes':SIZE,
        'input_record_bytes':HEADER.size+SIZE,'output_record_bytes':9+SIZE,
        'outcome_counts':counts,'cases_by_classifier':kinds,'normal_tags_by_classifier':tags,
        'inputs_sha256':sha(inputs),'expected_sha256':sha(raw),
        'oracle':'full-length/base-256 dictionary followed by immutable final-byte relation',
        'single_position_byte_substitutions':sum(map(len,sum((list(x) for x in WORDS),[])))*256,
        'refusals':'new atomic image/input/output admission, not original faults'}


def main():
    import sys
    require(sys.argv[1:] == ['--freeze'],'only --freeze supported')
    require(not (ROOT/'src/node94-keyword-classifiers').exists(),'freeze before Rust')
    inputs,outputs,record=fixtures()
    record.update(oracle_sha256_at_freeze=sha((PACKET/'oracle.py').read_bytes()),
                  static_sha256_at_freeze=sha((PACKET/'static.json').read_bytes()),rust_source_existed_at_freeze=False)
    for name,raw in [('inputs',inputs),('expected',outputs)]:
        with (PACKET/(name+'.bin.gz')).open('xb') as file:file.write(gzip.compress(raw,mtime=0))
    with (PACKET/'frozen.json').open('xb') as file:file.write(encoded(record))
    print(encoded(record).decode(),end='')


if __name__ == '__main__':main()
