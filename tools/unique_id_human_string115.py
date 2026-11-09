#!/usr/bin/env python3
"""Node #115 `rocksdb::UniqueIdToHumanString` +
`rocksdb::InternalUniqueIdToHumanString`.

Reconstructs two vendored RocksDB functions from the node #115 binary
(artifact SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):

* `rocksdb::UniqueIdToHumanString` at 0x61b0660..0x61b06fd (157 bytes,
  census node115-vendor-61b0660, body SHA-256
  dff45f9ad14f2a5a82be48f8b9f54a5c176d70aa7837386df40b45b4fde5b65e):
  takes the 16-byte (or 24-byte) binary unique id as a `std::string`
  and returns it as uppercase hex with a '-' after every 16 hex
  characters (every 64 bits), e.g. the upstream header's example
  "6474DF650323BDF0-B48E64F3039308CA-17284B32E7F7444B" for a 24-byte
  id. The binary copies the string's (data, size) into a `Slice`,
  calls `Slice::ToString(true)` (0x61c7e30, census
  node115-vendor-61c7e30), then inserts '-' at positions 16, 33,
  50, ... while the position is below the current size
  (`_M_replace(pos, 0, "-", 1)` at 0x61b06c1; the '-' byte is the
  `.rodata` byte at 0x4496cf). For a 16-byte id that is one dash:
  32 hex chars become "XXXXXXXXXXXXXXXX-XXXXXXXXXXXXXXXX" (33 chars).
  The function also works on any unique-id prefix: a shorter input
  gets dashes only where a full 16-char group precedes them.

* `rocksdb::InternalUniqueIdToHumanString` at 0x61b0750..0x61b10e3
  (2451 bytes, census node115-vendor-61b0750, body SHA-256
  4a8a644b3202dfa5ba7f96df2b0c905604f0cbbb10831d94f97df47738fd776d):
  takes a `UniqueIdPtr` (a `{uint64_t *ptr, bool extended}` struct
  passed by value: pointer in `rsi`, `extended` in `rdx` — see
  RocksDB 8.1.1 `table/unique_id_impl.h`, where `UniqueIdPtr`
  wraps either a `UniqueId64x2` (`extended` false) or a
  `UniqueId64x3` (`extended` true)) and returns the internal id for
  debugging as "{w0,w1}" or "{w0,w1,w2}" with plain decimal words,
  comma-separated, wrapped in '{' and '}'. The words are the
  UniqueId in memory order; per open PR #5834,
  `GetSstInternalUniqueId` derives them as (session_id2,
  file_number ^ Hash2x64(db_id, seed=session_id).high,
  Hash2x64(db_id, seed=session_id).low). The decimal formatting is
  the libstdc++ `std::to_string(unsigned long long)` inline: a
  divide-by-10000 digit count, then a divide-by-100 fill from the
  end using the 200-byte two-digit pair table ("00".."99") that
  the binary copies to the stack from thirteen 16-byte `.rodata`
  chunks (0x451750, 0x453230, 0x456910, 0x453e00, 0x451db0,
  0x452ba0, 0x455590, 0x456240, 0x456920, 0x4528d0, 0x456250,
  0x453240, 0x454870, with the thirteenth overlapping the twelfth
  at table offset 185). The separators are the `.rodata` bytes ','
  at 0x43b529 and '}' at 0x432097, and the opening '{' is the
  immediate 0x7b at 0x61b0790. All three in-binary callers pass
  `extended` false (`xor %edx,%edx` at 0x5f58ddf, 0x6120ec5 and
  0x6120efd), so the live form is the two-word "{w0,w1}"; the
  three-word form is the same code path with the flag set and is
  modeled and tested here too.

The census `source_body_sha256` values are reproduced exactly by
hashing each body with its relocation fields zeroed (see
`RELOCATION_OFFSETS` below), so `raw_equal` false is fully
explained for both claimed functions and for `Slice::ToString`:
the linked bodies differ from the source bodies only in the call
displacements. The FDE ranges match the census ranges exactly;
note the census end of `InternalUniqueIdToHumanString`
(0x61b10e3) is the true FDE end. The 17-byte nibble-to-hex-char
helper at 0x61c7da0 (`v <= 9 ? '0'+v : 'A'+v-10`) has no census
record; its bytes are verified directly from the binary.

No binary is executed by this tool; the models below are checked
against each other and against the binary's bytes.
"""

import argparse
import hashlib
import json
import random
import struct
from pathlib import Path

M64 = (1 << 64) - 1

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
CENSUS_PATH = (
    "research/work-items/RE-002-node115-vendor-census/census.json"
)

# (name, start, end, target_body_sha256); None means no census record.
FUNCTIONS = [
    ("UniqueIdToHumanString", 0x61B0660, 0x61B06FD,
     "dff45f9ad14f2a5a82be48f8b9f54a5c176d70aa7837386df40b45b4fde5b65e"),
    ("InternalUniqueIdToHumanString", 0x61B0750, 0x61B10E3,
     "4a8a644b3202dfa5ba7f96df2b0c905604f0cbbb10831d94f97df47738fd776d"),
    ("Slice::ToString", 0x61C7E30, 0x61C7FB6,
     "be77a499a67f1547cec8e5c371d76772fc82ea3211c529b90628fde535cc7602"),
    ("toHex", 0x61C7DA0, 0x61C7DB1, None),
]

# Relocation offsets (4-byte fields) whose zeroing reproduces each
# census source_body_sha256, taken from the census records.
RELOCATION_OFFSETS = {
    0x61B0660: (54, 73, 98, 141, 153),
    0x61B0750: None,  # filled from the census record at runtime
    0x61C7E30: (64, 116, 202, 262, 292, 337, 386),
}
SOURCE_BODY_SHA256 = {
    0x61B0660:
        "fbd8209f5030c5d05e9400a1d2b532a4eeffe87f24fbf11389e2467e5a643614",
    0x61B0750:
        "d2a3ea09ef40e5f697adfd0caf0fcab0528b697efca48fae9ce7d38e1a22cdfc",
    0x61C7E30:
        "ee9e7225241f805d76ce0bba5ead648bb2c844d4ecc218a50f31622ad33d1079",
}

# The decimal two-digit pair table ("00".."99"), byte-identical to
# the table the binary reconstructs on the stack at rsp+0x20 in
# 0x61b0750 (verified against the .rodata chunks; see the tests).
_PAIR_TABLE = b"".join(b"%02d" % i for i in range(100))


def to_hex(v):
    """Nibble -> uppercase hex char (0x61c7da0).

    `lea 0x30(%rdi)` / `lea 0x37(%rdi)` / `cmovbe`: v <= 9 gives
    '0'+v, otherwise 'A'+v-10.
    """
    assert 0 <= v <= 15
    return chr(0x30 + v) if v <= 9 else chr(0x37 + v)


def slice_to_string(data, hex_flag):
    """Transliteration of `rocksdb::Slice::ToString(bool)` (0x61c7e30).

    With the flag set, the bytes are hex-encoded two chars per byte
    (high nibble first, via `to_hex`); with it clear, the raw bytes
    are copied into the string unchanged (`_M_replace(0, 0, data,
    len)` at 0x61c7f48).
    """
    if not hex_flag:
        return data.decode("latin-1")
    out = []
    for byte in data:
        out.append(to_hex(byte >> 4))
        out.append(to_hex(byte & 0xF))
    return "".join(out)


def slice_to_string_model(data, hex_flag):
    """Independent model of `Slice::ToString(bool)`."""
    if not hex_flag:
        return data.decode("latin-1")
    return data.hex().upper()


def unique_id_to_human_string(id_bytes):
    """Transliteration of `rocksdb::UniqueIdToHumanString` (0x61b0660).

    Hex-encodes via `Slice::ToString(true)`, then inserts '-' at
    positions 16, 33, 50, ... exactly as the binary loop does:
    `_M_replace(pos, 0, "-", 1)` while pos < current size, then
    pos += 17 (0x61b06a1..0x61b06ce).
    """
    buf = list(slice_to_string(id_bytes, True))
    pos = 16
    while pos < len(buf):
        buf.insert(pos, "-")
        pos += 17
    return "".join(buf)


def unique_id_to_human_string_model(id_bytes):
    """Independent model: uppercase hex in 16-char groups joined '-'."""
    hx = id_bytes.hex().upper()
    if not hx:
        return ""
    return "-".join(hx[i:i + 16] for i in range(0, len(hx), 16))


def _decimal_digit_count(n):
    """Digit count of `n`, as the binary computes it (0x61b0799..).

    1..4 digits by direct comparison, then a divide-by-10000 loop
    (magic 0x346dc5d63886594b, shift 11) counting 4 per division,
    with +5/+6/+7 for a final quotient of <=999999 / <=9999999 /
    <=99999999.
    """
    if n <= 9:
        return 1
    if n <= 99:
        return 2
    if n <= 999:
        return 3
    if n <= 9999:
        return 4
    esi = 1
    rdx = n
    while True:
        rcx = rdx
        eax = esi
        esi += 4
        rdx = rdx // 10000
        if rcx <= 99999:
            return esi
        if rcx <= 999999:
            return eax + 5
        if rcx <= 9999999:
            return eax + 6
        if rcx <= 99999999:
            return eax + 7


def format_u64_decimal(n):
    """Transliteration of the `std::to_string` inline in 0x61b0750.

    Fills the digit buffer from the end, two digits at a time by
    dividing by 100 (magic 0x28f5c28f5c28f5c3, shift 2) and reading
    the pair from the two-digit table; the loop runs while the
    pre-division value exceeds 9999, and the tail writes the final
    one or two most-significant digits at the buffer start.
    """
    count = _decimal_digit_count(n)
    buf = bytearray(count)
    pos = count
    value = n
    if value > 99:
        while True:
            q, r = divmod(value, 100)
            buf[pos - 2] = _PAIR_TABLE[2 * r]
            buf[pos - 1] = _PAIR_TABLE[2 * r + 1]
            pos -= 2
            old = value
            value = q
            if old <= 9999:
                break
    if value > 9:
        buf[pos - 2] = _PAIR_TABLE[2 * value]
        buf[pos - 1] = _PAIR_TABLE[2 * value + 1]
    else:
        buf[pos - 1] = 0x30 + value
    return bytes(buf).decode("ascii")


def internal_unique_id_to_human_string(words, extended):
    """Transliteration of `InternalUniqueIdToHumanString` (0x61b0750).

    `words` is the UniqueId in memory order; `extended` is the
    `UniqueIdPtr.extended` flag (false for UniqueId64x2, true for
    UniqueId64x3). The third word is read only when `extended` is
    set (the binary tests `r14b` at 0x61b0c0a before formatting it).
    """
    out = "{"
    out += format_u64_decimal(words[0])
    out += ","
    out += format_u64_decimal(words[1])
    if extended:
        out += ","
        out += format_u64_decimal(words[2])
    out += "}"
    return out


def internal_unique_id_to_human_string_model(words, extended):
    """Independent model: plain decimal words, comma-separated."""
    if extended:
        return "{%d,%d,%d}" % (words[0], words[1], words[2])
    return "{%d,%d}" % (words[0], words[1])


def generate_cases():
    """2,400 deterministic cases: 1,200 hex/dash, 1,200 internal."""
    rng = random.Random(1150750)
    cases = []
    index = 0

    def add(kind, **fields):
        nonlocal index
        case = {"kind": kind, "index": index}
        case.update(fields)
        cases.append(case)
        index += 1

    # --- human_hex: fixed boundary lengths first. ---
    fixed_hex = [
        b"",
        b"\x00",
        b"\x00" * 8,
        b"\x00" * 16,
        b"\xff" * 16,
        bytes.fromhex("6474df650323bdf0b48e64f3039308ca17284b32e7f7444b"),
        b"\x00" * 24,
        b"\xff" * 24,
        b"\xab" * 7,
        b"\xab" * 9,
        b"\xab" * 15,
        b"\xab" * 17,
        b"\xab" * 31,
        b"\xab" * 32,
        b"\xab" * 33,
        b"\xab" * 47,
        b"\xab" * 48,
        b"\xab" * 49,
        bytes(range(16)),
        bytes(range(24)),
    ]
    for data in fixed_hex:
        add("human_hex", id_hex=data.hex(),
            out=unique_id_to_human_string_model(data))
    lengths = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
               16, 17, 18, 20, 23, 24, 25, 30, 31, 32, 33, 40, 47, 48]
    while index < 1200:
        data = bytes(rng.randrange(256) for _ in range(rng.choice(lengths)))
        add("human_hex", id_hex=data.hex(),
            out=unique_id_to_human_string_model(data))

    # --- human_internal: fixed boundary words first. ---
    boundary = [0, 1, 9, 10, 99, 100, 999, 1000, 9999, 10000, 99999,
                100000, 999999, 1000000, 99999999, 100000000,
                999999999, 1000000000, 2 ** 32 - 1, 2 ** 32, 2 ** 63 - 1,
                2 ** 63, 2 ** 64 - 1]
    fixed_triples = [(0, 0, 0), (M64, M64, M64), (1, 2, 3)]
    for w in boundary:
        fixed_triples.append((w, w, w))
        fixed_triples.append((w, 0, M64))
        fixed_triples.append((0, w, 0))
    for words in fixed_triples:
        for extended in (False, True):
            add("human_internal",
                w0_hex="%016x" % words[0], w1_hex="%016x" % words[1],
                w2_hex="%016x" % words[2], extended=int(extended),
                out=internal_unique_id_to_human_string_model(words,
                                                             extended))
    while index < 2400:
        words = (rng.randrange(1 << 64), rng.randrange(1 << 64),
                 rng.randrange(1 << 64))
        extended = bool(rng.randrange(2))
        add("human_internal",
            w0_hex="%016x" % words[0], w1_hex="%016x" % words[1],
            w2_hex="%016x" % words[2], extended=int(extended),
            out=internal_unique_id_to_human_string_model(words,
                                                         extended))
    return cases


def read_binary(binary_path):
    data = Path(binary_path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != ARTIFACT_SHA256:
        raise ValueError("artifact digest mismatch: %s" % digest)
    return data


def verify_binary(binary_path):
    """Bind every claimed function body to the census target hash."""
    data = read_binary(binary_path)
    for name, start, end, target in FUNCTIONS:
        if target is None:
            continue
        body = data[start - 0x1000:end - 0x1000]
        digest = hashlib.sha256(body).hexdigest()
        if digest != target:
            raise ValueError("body hash mismatch for %s: %s" % (name,
                                                                 digest))
    return True


def find_callers(binary_path, target):
    """Whole-.text E8 scan for direct call sites landing on `target`."""
    data = read_binary(binary_path)
    text_va, text_off, text_size = 0x1419300, 0x1418300, 0x4FD88A0
    text = data[text_off:text_off + text_size]
    sites = []
    for i in range(len(text) - 5):
        if text[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", text, i + 1)[0]
        if text_va + i + 5 + rel == target:
            sites.append(text_va + i)
    return sites


def verify(binary_path):
    """Transliteration vs model over all cases; returns mismatches."""
    data = read_binary(binary_path)
    mismatches = 0
    cases = generate_cases()
    for case in cases:
        if case["kind"] == "human_hex":
            got = unique_id_to_human_string(bytes.fromhex(case["id_hex"]))
            want = case["out"]
        else:
            words = (int(case["w0_hex"], 16), int(case["w1_hex"], 16),
                     int(case["w2_hex"], 16))
            got = internal_unique_id_to_human_string(
                words, bool(case["extended"]))
            want = case["out"]
        if got != want:
            mismatches += 1
            print("mismatch: %r got %r want %r" % (case, got, want))
    checks = {
        "doc_example": unique_id_to_human_string(
            bytes.fromhex(
                "6474df650323bdf0b48e64f3039308ca17284b32e7f7444b")),
        "hex_16_zero": unique_id_to_human_string(b"\x00" * 16),
        "hex_empty": unique_id_to_human_string(b""),
        "internal_zero": internal_unique_id_to_human_string((0, 0, 0),
                                                            False),
        "internal_extended_max": internal_unique_id_to_human_string(
            (M64, M64, M64), True),
        "internal_mixed": internal_unique_id_to_human_string(
            (123456789, 987654321012345678, 42), True),
    }
    expected = {
        "doc_example": "6474DF650323BDF0-B48E64F3039308CA-17284B32E7F7444B",
        "hex_16_zero": "0000000000000000-0000000000000000",
        "hex_empty": "",
        "internal_zero": "{0,0}",
        "internal_extended_max":
            "{18446744073709551615,18446744073709551615,"
            "18446744073709551615}",
        "internal_mixed": "{123456789,987654321012345678,42}",
    }
    for key, value in expected.items():
        if checks[key] != value:
            raise ValueError("check value mismatch: %s = %s"
                             % (key, checks[key]))
    # .rodata ground truths: '-' at 0x4496cf, ',' at 0x43b529,
    # '}' at 0x432097 (VAs equal file offsets in the first LOAD).
    assert data[0x4496CF:0x4496D0] == b"-"
    assert data[0x43B529:0x43B52A] == b","
    assert data[0x432097:0x432098] == b"}"
    # The decimal pair table, reconstructed with the binary's chunk
    # layout (13 chunks of 16 bytes; the 13th lands at offset 185,
    # overlapping the 12th chunk's last 7 bytes).
    chunks = [0x451750, 0x453230, 0x456910, 0x453E00, 0x451DB0, 0x452BA0,
              0x455590, 0x456240, 0x456920, 0x4528D0, 0x456250, 0x453240,
              0x454870]
    table = bytearray(201)
    for j, chunk in enumerate(chunks):
        off = j * 16 if j < 12 else 185
        table[off:off + 16] = data[chunk:chunk + 16]
    assert bytes(table[:200]) == _PAIR_TABLE
    print("%d cases agree (%d mismatches)" % (len(cases), mismatches))
    for key, value in checks.items():
        print("  %s = %s" % (key, value))
    return mismatches


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--binary", default="work/hl-node-115.bin")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.verify:
        raise SystemExit(1 if verify(args.binary) else 0)
    if args.out is not None:
        verify_binary(args.binary)
        cases = generate_cases()
        mismatches = 0
        for case in cases:
            if case["kind"] == "human_hex":
                good = (unique_id_to_human_string(
                    bytes.fromhex(case["id_hex"])) == case["out"])
            else:
                words = (int(case["w0_hex"], 16),
                         int(case["w1_hex"], 16),
                         int(case["w2_hex"], 16))
                good = (internal_unique_id_to_human_string(
                    words, bool(case["extended"])) == case["out"])
            if not good:
                mismatches += 1
        result = {
            "artifact": "node115",
            "artifact_sha256": ARTIFACT_SHA256,
            "functions": [
                {"name": name, "start": "0x%x" % s, "end": "0x%x" % e,
                 "body_sha256": t,
                 "scope": "human-string formatting of node #115 UniqueIds"}
                for name, s, e, t in FUNCTIONS if t is not None
            ],
            "cases": {
                "human_hex": 1200,
                "human_internal": 1200,
                "total": len(cases),
            },
            "total_cases": len(cases),
            "mismatches": mismatches,
            "check_values": {
                "doc_example": unique_id_to_human_string(
                    bytes.fromhex("6474df650323bdf0b48e64f3039308ca"
                                  "17284b32e7f7444b")),
                "hex_16_zero": unique_id_to_human_string(b"\x00" * 16),
                "internal_zero": internal_unique_id_to_human_string(
                    (0, 0, 0), False),
                "internal_extended_max": internal_unique_id_to_human_string(
                    (M64, M64, M64), True),
            },
        }
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "result.json").write_text(
            json.dumps(result, indent=1) + "\n")
        print("wrote %s (%d cases, %d mismatches)"
              % (args.out / "result.json", len(cases), mismatches))
        raise SystemExit(1 if mismatches else 0)
    parser.print_help()
    raise SystemExit(2)


if __name__ == "__main__":
    main()
