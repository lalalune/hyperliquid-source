#!/usr/bin/env python3
"""Successful ClientBlocks wire structure; static operands, never target execution."""
import argparse
import copy
import itertools
import json
import random
import capstone
import verify


def contract(data):
    im = verify.Image(data)
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs.detail = True
    ins = lambda a: next(cs.disasm(im.get(a, 15), a))
    imm = lambda a: ins(a).operands[-1].imm
    calls = lambda a, b: [i.operands[0].imm for i in cs.disasm(im.get(a, b-a), a)
                         if i.mnemonic == 'call' and i.operands[0].type == capstone.x86.X86_OP_IMM]
    qc_calls = calls(0x5968d37, 0x5968ddd)
    verify.require(qc_calls[-1] == 0x5821430 and all(x == 0x5821250 for x in qc_calls[:-1]), 'QC wire scalar/hash calls')
    verify.require(calls(0x5821030, 0x582106b) == [0x5821540, 0x5821540], 'signature two u256 calls')
    limbs = calls(0x5821540, 0x5821705)
    verify.require(limbs == [0x5821250]*4, 'u256 four u64 calls')
    bindings = {
        0x4fbadad: 0x4fb7760, 0x4fbaed0: 0x5824840,
        0x4fb778c: 0x5821020, 0x4fb77ff: 0x59d5ea0, 0x4fb79b3: 0x4fbb010,
        0x59d5ebc: 0x581fec0, 0x59d5f13: 0x5824340, 0x59d5f3c: 0x4ece880,
        0x59d5f80: 0x5821150, 0x59d5fb7: 0x5968d20, 0x59d60ec: 0x5968f10,
        0x59d6275: 0x4e05180, 0x4e051f6: 0x5968d20,
        0x4fbb03c: 0x5821020, 0x4fbb0af: 0x59d5ea0, 0x4fbb1de: 0x5968d20,
        0x5968f35: 0x5821250, 0x5968f50: 0x5968d20, 0x5969038: 0x58258f0,
        0x5968e97: 0x4de6470, 0x4de6489: 0x5825e60,
        0x5820efc: 0x542efe0, 0x5820d1c: 0x542c290,
        0x542c2aa: 0x5821250, 0x4e04ea7: 0x5821430,
        0x4e04ef4: 0x5824b60, 0x5824b79: 0x5821250,
    }
    verify.require(all(imm(a) == b for a, b in bindings.items()), 'nested decoder call bindings')
    return {'address_bytes': ins(0x581ff04).operands[-1].mem.disp,
            'hash_bytes': ins(0x582147f).operands[-1].mem.disp,
            'qc_scalar_fields': len(qc_calls)-1, 'signature_limbs': 2*len(limbs),
            'timeout_tag': imm(0x59d5f9e), 'proof_some': imm(0x4fb799e),
            'qc_some': imm(0x4e051df), 'qc_nonzero_reject': ins(0x59d5fa9).mnemonic,
            'bindings': {hex(a): hex(b) for a, b in bindings.items()}}


class WireError(ValueError):
    pass


class Reader:
    """Structure reader; no claim about native error payloads, rollback or budgets."""
    def __init__(self, raw, shape):
        self.raw, self.shape, self.pos = raw, shape, 0

    def take(self, n):
        if n < 0 or n > len(self.raw)-self.pos:
            raise WireError('incomplete field')
        out = self.raw[self.pos:self.pos+n]
        self.pos += n
        return out

    def integer(self, bits=64):
        marker = self.take(1)[0]
        if marker <= 250:
            return marker
        widths = {251: 2, 252: 4, 253: 8}
        if marker not in widths or widths[marker]*8 > bits:
            raise WireError('invalid unsigned scalar marker')
        return int.from_bytes(self.take(widths[marker]), 'little')

    def vector(self, element):
        size = self.integer()
        # Every vector here has a nonzero minimal element size. This is a
        # relation-runner bound, not a native allocation or budget assertion.
        if size > len(self.raw)-self.pos:
            raise WireError('incomplete vector')
        return [element() for _ in range(size)]

    def signature(self):
        return [self.integer() for _ in range(self.shape['signature_limbs'])] + [self.take(1)[0]]

    def qc(self):
        fields = [self.integer() for _ in range(self.shape['qc_scalar_fields'])]
        digest = self.take(self.shape['hash_bytes']).hex()
        votes = self.vector(lambda: [self.take(self.shape['address_bytes']).hex(), self.signature()])
        return [fields, digest, votes]

    def optional(self, reader, some):
        tag = self.take(1)[0]
        if tag == 0:
            return None
        if tag != some:
            raise WireError('invalid option discriminant')
        return reader()

    def tc(self):
        scalar, qc = self.integer(), self.qc()
        votes = self.vector(lambda: [self.take(self.shape['address_bytes']).hex(), self.integer(), self.signature()])
        return [scalar, qc, votes]

    def header(self):
        address = self.take(self.shape['address_bytes']).hex()
        hashes = self.vector(lambda: self.take(self.shape['hash_bytes']).hex())
        seconds = self.integer()
        seconds = (seconds >> 1) ^ -(seconds & 1)
        nanos = self.integer(32)
        tag = self.integer(32)
        if tag == self.shape['timeout_tag']:
            parent = [1, self.tc(), self.optional(self.qc, self.shape['qc_some'])]
        else:
            reject = tag != 0 if self.shape['qc_nonzero_reject'] == 'jne' else tag == 0
            if reject:
                raise WireError('invalid BlockParent discriminant')
            parent = [0, self.qc()]
        return [address, hashes, [seconds, nanos], parent]

    def proof(self):
        return [self.signature(), self.header(), self.qc()]

    def client(self):
        block = [self.signature(), self.header(), self.optional(self.proof, self.shape['proof_some'])]
        attached = self.vector(lambda: [self.take(self.shape['hash_bytes']).hex(), self.take(self.integer()).hex()])
        return [block, attached]

    def response(self):
        if self.integer(32) != 0 or self.integer(32) != 0:
            raise WireError('outside successful ClientBlocks scope')
        return self.vector(self.client)


def encode_integer(n):
    """Independent canonical fixture encoder, not a reconstructed native writer."""
    if n < 0 or n >= 1 << 64:
        raise ValueError(n)
    if n < 251:
        return bytes([n])
    for width, marker in [(2, 251), (4, 252), (8, 253)]:
        if n < 1 << (8*width):
            return bytes([marker]) + n.to_bytes(width, 'little')


def encode_vector(xs, encoder):
    return encode_integer(len(xs)) + b''.join(map(encoder, xs))


def encode_signature(sig):
    assert len(sig) == 9
    return b''.join(encode_integer(x) for x in sig[:8]) + bytes([sig[8]])


def encode_qc(qc):
    fields, digest, rows = qc
    assert len(fields) == 5
    return b''.join(map(encode_integer, fields)) + bytes.fromhex(digest) + encode_vector(rows, lambda r: bytes.fromhex(r[0]) + encode_signature(r[1]))


def encode_header(h):
    address, hashes, timestamp, parent = h
    seconds, nanos = timestamp
    prefix = bytes.fromhex(address) + encode_vector(hashes, bytes.fromhex) + encode_integer((seconds << 1) ^ (seconds >> 63)) + encode_integer(nanos)
    if parent[0] == 0:
        return prefix + b'\0' + encode_qc(parent[1])
    scalar, qc, votes = parent[1]
    tail = encode_integer(scalar) + encode_qc(qc) + encode_vector(votes, lambda r: bytes.fromhex(r[0]) + encode_integer(r[1]) + encode_signature(r[2]))
    return prefix + b'\1' + tail + encode_optional(parent[2], encode_qc)


def encode_optional(value, encoder):
    return b'\0' if value is None else b'\1' + encoder(value)


def encode_proof(p):
    return encode_signature(p[0]) + encode_header(p[1]) + encode_qc(p[2])


def encode_client(c):
    block, attached = c
    return encode_signature(block[0]) + encode_header(block[1]) + encode_optional(block[2], encode_proof) + encode_vector(attached, lambda row: bytes.fromhex(row[0]) + encode_integer(len(bytes.fromhex(row[1]))) + bytes.fromhex(row[1]))


def encode_response(clients):
    return b'\0\0' + encode_vector(clients, encode_client)


def sample(seed, timeout=False, optional_qc=False, proof=False, hash_count=0, attachment_count=0, votes=0):
    rng = random.Random(seed)
    values = [0, 1, 250, 251, 65535, 65536, (1 << 32)-1, 1 << 32, (1 << 64)-1]
    sig = lambda: [rng.choice(values) for _ in range(8)] + [rng.randrange(256)]
    raw = lambda n: bytes(rng.randrange(256) for _ in range(n)).hex()
    def qc():
        return [[rng.choice(values) for _ in range(5)], raw(32), [[i.to_bytes(20, 'big').hex(), sig()] for i in range(votes)]]
    def header(is_timeout, extra):
        parent = ([1, [rng.choice(values), qc(), [[i.to_bytes(20, 'big').hex(), rng.choice(values), sig()] for i in range(votes)]], qc() if extra else None]
                  if is_timeout else [0, qc()])
        return [raw(20), [raw(32) for _ in range(hash_count)], [rng.choice([-86401, -1, 0, 59, 86400]), rng.choice([0, 1, 999999999])], parent]
    return [[sig(), header(timeout, optional_qc), [sig(), header(not timeout, optional_qc), qc()] if proof else None],
            [[raw(32), raw(rng.choice([0, 1, 2, 250, 251, 256]))] for _ in range(attachment_count)]]


def decode(raw, shape):
    r = Reader(raw, shape)
    value = r.response()
    if r.pos != len(raw):
        raise WireError('trailing fixture data')
    return value


def evaluate(data):
    shape = contract(data)
    verify.require({k: v for k, v in shape.items() if k != 'bindings'} == {
        'address_bytes': 20, 'hash_bytes': 32, 'qc_scalar_fields': 5, 'signature_limbs': 8,
        'timeout_tag': 1, 'proof_some': 1, 'qc_some': 1, 'qc_nonzero_reject': 'jne'}, 'native grammar operands')
    fixtures = [[]]
    for i, flags in enumerate(itertools.product([False, True], repeat=3)):
        for count in [0, 1, 2]:
            for votes in [0, 1, 3, 20]:
                fixtures.append([sample(i*100+count*21+votes, *flags, hash_count=count, attachment_count=count, votes=votes)])
    fixtures += [[sample(seed), sample(seed+1, True, True, True, 2, 2, 3)] for seed in range(24)]
    total_bytes = 0
    digests = []
    for clients in fixtures:
        raw = encode_response(clients)
        verify.require(decode(raw, shape) == clients, 'independent fixture encoding / operand-derived structure')
        total_bytes += len(raw)
        digests.append(verify.sha(raw))
    # Literal, hand-counted minimal successful structure: eight 0 limbs plus
    # recovery byte; raw20; empty hashes; epoch0/nanos0; QC parent; five0;
    # raw32; empty votes; absent proof; empty attachment vector.
    minimal = b'\0\0\1' + bytes(73)
    value = decode(minimal, shape)
    verify.require(value[0][0][0] == [0]*9 and len(minimal) == 76, 'literal minimal fixture')
    truncations = 0
    representatives = [minimal] + [encode_response([sample(87, a, b, c, 1, 1, 1)]) for a, b, c in itertools.product([False, True], repeat=3)]
    for raw in representatives:
        for cut in range(len(raw)):
            try:
                decode(raw[:cut], shape)
            except WireError:
                truncations += 1
            else:
                raise AssertionError('accepted incomplete structural fixture')
    # Native decoder does not enforce whole-input consumption: this assertion
    # explicitly concerns Reader.decode's fixture framing, not native behavior.
    trailing_reader = Reader(minimal+b'\xaa\xbb', shape)
    trailing_reader.response()
    verify.require(trailing_reader.pos == 76, 'structural consumption boundary')
    mutants = []
    im = verify.Image(data)
    targets = [(0x59d5fa0, 2, sample(86, True), 'TC parent tag'),
               (0x4fb79a1, 2, sample(86, False, False, True), 'commit proof Some tag'),
               (0x4e051e1, 2, sample(86, True, True), 'optional QC Some tag'),
               (0x59d5faa, 0x84, sample(86), 'QC parent zero-discriminant admission branch')]
    for address, byte, client, meaning in targets:
        changed = bytearray(data)
        changed[im.off(address)] = byte
        raw = encode_response([client])
        other = contract(changed)
        try:
            after = decode(raw, other)
            different = after != [client]
        except WireError as e:
            after, different = str(e), True
        verify.require(different, 'changed grammar decision survived')
        mutants.append({'va': hex(address), 'new_byte': byte, 'meaning': meaning, 'result': after})
    return {'native_contract': shape, 'fixtures': len(fixtures), 'fixture_bytes': total_bytes,
            'fixture_sha256': digests, 'literal_minimal_bytes': len(minimal),
            'incomplete_prefixes_rejected': truncations, 'counterfactuals': mutants,
            'limits': 'Static structure relation, no target execution/emulation. Decoder budget disabled; allocation succeeds. Primitive scalar/error mechanics, calendar admission, duplicate-voter normalization, cryptographic validity, whole-input policy and transport framing are separate boundaries. Fixture votes are unique and ascending, at most20; ordinary timestamps near epoch are admitted by the separately studied timestamp boundary. Wire vote lists are represented before map normalization; opaque attachment bytes have no assigned transaction interpretation.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    data = verify.TARGET.read_bytes()
    verify.require(verify.sha(data) == verify.DIGEST, 'wrong target')
    text = verify.encoded(evaluate(data))
    if args.write:
        (verify.PACKET / 'relations.json').write_text(text)
    else:
        verify.require((verify.PACKET / 'relations.json').read_text() == text, 'relations drift')
    print('PASS: complete ClientBlocks successful-wire structure')
