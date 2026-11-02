"""RE-001: conditional add_tx key-hit preparation; static synthetic inputs only."""
import hashlib
import struct
from evm_amount_scale import ROOT, BINARY, SHA256, Image
from fde_extents import eh_frame_records

PACKET = ROOT/'research/work-items/RE-001-mempool-hit-preparation-94'
START, END = 0x44b9a50, 0x44ba838
OWNER_SHA = '218edce6acc923be5ce11329fa38c8afe421292f2dc83f70945906a0c6ce8e88'
MASK = (1 << 64)-1

def require(ok, message):
    if not ok:
        raise ValueError(message)

def constant(image, site, opcode):
    raw = image.read(site, 10)
    require(raw[:2] == opcode, 'unsupported movabs')
    return int.from_bytes(raw[2:], 'little')

def conditional(image, site, equal, target):
    raw = image.read(site, 6)
    require(raw[:2] in (b'\x0f\x84', b'\x0f\x85'), 'unsupported equality branch')
    require(site+6+struct.unpack_from('<i', raw, 2)[0] == target, 'branch target changed')
    return equal if raw[1] == 0x84 else not equal

def first_match_action(image, record_word):
    """Assume the FIRST tree comparison already matched; no membership claim."""
    require(type(record_word) is int and 0 <= record_word <= MASK, 'raw u64 required')
    marker = constant(image, 0x44b9b40, b'\x48\xb8')
    require(image.read(0x44b9b4a, 4) == bytes.fromhex('49394500'), 'record comparison changed')
    return 'prepare_first' if conditional(image, 0x44b9b4e, record_word == marker, 0x44b9c01) else 'second_lookup'

def prepare_hit(image, kind, payload, key, canary=0xa5):
    """Lower selected original stores, not allocator/drop/logger or tree traversal.

    Return only the 41 defined bytes. Other bytes in the native 80-byte result
    remain unknown, including any helper writes; do not normalize them to zero.
    """
    require(kind in ('first', 'second'), 'unknown matched tree')
    require(type(payload) is int and 0 <= payload < 256, 'raw u8 required')
    require(type(key) is bytes and len(key) == 32, '32-byte synthetic key required')
    require(type(canary) is int and 0 <= canary < 256, 'canary byte required')
    base_site, lea_site = ((0x44b9c06, 0x44b9c10) if kind == 'first' else (0x44b9bf1, 0x44b9bfb))
    base = constant(image, base_site, b'\x49\xbe')
    raw = image.read(lea_site, 4)
    require(raw[:3] == bytes.fromhex('498d4e'), 'tag lea changed')
    tag = (base+int.from_bytes(raw[3:], 'little', signed=True)) & MASK
    ram = bytearray([canary]*256)
    defined = set()
    def store(site, prefix, value):
        raw = image.read(site, len(prefix)+1)
        require(raw[:-1] == prefix, 'unsupported stack store')
        off = raw[-1]
        require(off+len(value) <= len(ram), 'stack store outside synthetic RAM')
        ram[off:off+len(value)] = value
        defined.update(range(off, off+len(value)))
    store(0x44b9c14, bytes.fromhex('48894c24'), tag.to_bytes(8, 'little'))
    store(0x44b9c19, bytes.fromhex('884424'), bytes([payload]))
    require(image.read(0x44b9c22, 3) == bytes.fromhex('0f1000'), 'first key load changed')
    require(image.read(0x44b9c25, 4) == bytes.fromhex('0f104810'), 'second key load changed')
    store(0x44b9c29, bytes.fromhex('0f114424'), key[:16])
    store(0x44b9c2e, bytes.fromhex('0f114c24'), key[16:])
    raw = image.read(0x44b9c4e, 4)
    require(raw[:3] == bytes.fromhex('498d46'), 'comparison lea changed')
    compared = (base+int.from_bytes(raw[3:], 'little', signed=True)) & MASK
    raw = image.read(0x44b9c52, 5)
    require(raw[:4] == bytes.fromhex('48394424'), 'tag comparison changed')
    off = raw[-1]
    require(set(range(off, off+8)) <= defined, 'comparison reads undefined bytes')
    actual = int.from_bytes(ram[off:off+8], 'little')
    error = conditional(image, 0x44b9c57, actual == compared, 0x44b9cde)
    return dict(tag=tag, compared_tag=compared, prefix=bytes(ram[0x40:0x69]).hex(),
                defined_offsets=sorted(defined), route='err_preparation' if error else 'ok_preparation')

def observe(data):
    image = Image(data)
    _, fdes = eh_frame_records(data)
    fs = [f for f in fdes if f['start'] == START]
    require(len(fs) == 1 and fs[0]['end'] == END, 'hit owner FDE changed')
    require(hashlib.sha256(image.read(START, END-START)).hexdigest() == OWNER_SHA, 'hit owner changed')
    for va, value in ((0x6f4e29, b'err'), (0x6f4e2c, b'ok'), (0x6f4f2e, b'add_tx')):
        require(image.read(va, len(value)) == value, 'metric label changed')
    calls = {0x44b9cd4: 0x4708c40, 0x44b9d62: 0x4706b70}
    for site, target in calls.items():
        raw = image.read(site, 5)
        require(raw[0] == 0xe8 and site+5+struct.unpack_from('<i', raw, 1)[0] == target, 'helper call changed')
    require(image.read(0x44b9daf, 1) == b'\xc3', 'return changed')
    return dict(target_sha256=SHA256, owners=[dict(start=hex(START), end_exclusive=hex(END), sha256=OWNER_SHA,
                fde=hex(fs[0]['fde']), cie=hex(fs[0]['cie']))],
                first_marker_actions={hex(n): first_match_action(image, n) for n in (0, 1 << 63, (1 << 63)+1, MASK)},
                examples={k: prepare_hit(image, k, 255, bytes(range(32))) for k in ('first', 'second')},
                direct_call_edges={hex(k): hex(v) for k, v in calls.items()}, captured_binaries_executed=False,
                limits='Conditional already-matched tree paths only. Tree validity/membership, payload meaning, destructor/logger effects, complete 80-byte result ABI, later validation and acceptance remain unclosed.')

def build(data):
    require(hashlib.sha256(data).hexdigest() == SHA256, 'wrong node94 SHA-256')
    return observe(data)

if __name__ == '__main__':
    import argparse, json
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True)
    a = p.parse_args()
    from pathlib import Path
    Path(a.out).write_text(json.dumps(build((ROOT/BINARY).read_bytes()), indent=2)+'\n', encoding='utf8')
