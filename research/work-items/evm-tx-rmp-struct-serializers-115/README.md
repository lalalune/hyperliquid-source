# evm: rmp struct serializers of the EVM transaction bodies and the block header (node #115)

This packet makes the MessagePack (rmp-serde) encoding of node #115's EVM transaction bodies and block header
reconstructible. For the Legacy, EIP-2930, EIP-1559, EIP-4844 and EIP-7702 bodies, a destination-call record and the
block header, we now know the struct field order, the field names, the field offsets, which callee serializes each
field, the map/array header rule, and the presence rules for optional fields. We also know the exact header count:
the block header adds the raw optional tags to the count instead of the presence bits. The tool reproduces all of
this from the ELF bytes and proves it against the original code. The two copies that write into the `Vec<u8>`
directly are covered too: their exact header byte, name bytes and reserve calls. 15 bodies, 15,000 cases,
0 mismatches, 96/96 negative controls detected, 2,570/2,570 body instructions reached.

- Component ID: `evm` (struct serializers under the EVM transaction / header types; leaf writers belong to
  `serialization`)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: lalalune/hyperliquid-source main `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`;
  no reference source used (field names come from the binary's own name texts)
- Claim status: observation (bytes, call sites, name texts, offsets, constants) + verified reconstruction
  (behavior model compared with the original bytes on every case); the role names of callees are inference
- Scope included: 15 bodies (tables below), the whole body of each one: entry, header, every field, every
  optional-field branch, every inline byte write and reserve call, every error exit and the success exit.
  Excluded: the callees themselves (rmp leaf writers, nested field serializers and the RawVec reserve helper run
  as recording contract stubs); the inline-Vec block header 0x22da880 (see Next question);
  the 5 `Serializer`-by-value callers of field writer 0x233b960 named in `evm-tx-type-name-codec-115`.

## Reproduce

From the repository root, on any platform with Python 3.10+ (standard library only, no binutils, nothing executed):

```
python3 tools/evm_tx_rmp_structs_115.py --out research/work-items/evm-tx-rmp-struct-serializers-115
python3 -m unittest tests.test_evm_tx_rmp_structs_115
```

The tool checks the node #115 SHA-256 first and fails on any other input. It writes all seven evidence files
byte-identically, independent of `PYTHONHASHSEED`, `TZ` and `PATH` (checked with two runs, `diff -r` clean). One run
takes about 25 s. Output: `15000 cases, 0 mismatches, 96/96 controls, 2570/2570 body instructions`.

| file | content |
| --- | --- |
| `bodies.tsv` | the 15 bodies: FDE extent, size, instruction count, instructions reached, copy family, struct, header count (or `computed`), direct calls, name texts, result-tag immediate |
| `fields.tsv` | 123 field rows: body, field index, name, `lea` site of the name text, how the field is written, callee role, callee address, call site, struct offset |
| `roles.tsv` | 30 callee roles and their address in copy family a and b |
| `cases-sample.tsv` | every 4th case (3,250 rows): flag byte, faulting call, word 0, call count, result record, full normalized call list |
| `inline-cases-sample.tsv` | every 4th inline-Vec case (500 rows): flag, fault, prefix length, capacity, reserve slack, final length and capacity, result, appended bytes, call list |
| `controls.tsv` | 96 negative controls (23 model mutants + 73 single-byte flips of the original code) and the case that caught each |
| `unreached.tsv` | body instructions never reached (header only: all 2,570 were reached) |
| `summary.json` | totals, per-body ok/error/map/array/name counts, and a SHA-256 over all 15,000 case results |

## Evidence

Coordinates are virtual addresses in node #115. Every body boundary is an `.eh_frame` FDE start/end, parsed with
the repository's `tools/fde_extents.py`. The instruction stream is decoded from the `.text` bytes by the tool's own
fixed-table decoder, the same one used by the earlier rmp packets. No objdump output enters any evidence file.

### Bodies

| body | family | struct | bytes | insns | header count | calls |
| --- | --- | --- | ---: | ---: | --- | ---: |
| 0x22daf00 | a | block header | 1190 | 278 | computed | 30 |
| 0x22f2a20 | a | destination call | 501 | 131 | 5 | 11 |
| 0x2331bf0 | a | Legacy | 623 | 149 | 7 (6 without chainId) | 14 |
| 0x2332eb0 | a | EIP-2930 | 659 | 154 | 8 | 15 |
| 0x2332430 | a | EIP-1559 | 691 | 160 | 9 | 16 |
| 0x2333150 | a | EIP-4844 | 756 | 172 | 11 | 18 |
| 0x2333c30 | a | EIP-7702 | 722 | 166 | 10 | 17 |
| 0x44dad80 | b | destination call | 501 | 131 | 5 | 11 |
| 0x44ec9f0 | b | Legacy | 604 | 151 | 7 (6 without chainId) | 14 |
| 0x44ed9b0 | b | EIP-2930 | 629 | 156 | 8 | 15 |
| 0x44ed300 | b | EIP-1559 | 673 | 164 | 9 | 16 |
| 0x44ee450 | b | EIP-4844 | 732 | 176 | 11 | 18 |
| 0x44eeb50 | b | EIP-7702 | 701 | 170 | 10 | 17 |

How the bodies were found: the 0x233a820 / 0x44f76c0 keyed byte-field writers are callers-of-callers of the
r…0349 bytes-hex packet. An `e8 rel32` scan of `.text` gives 7 + 6 callers. The 0x233b960 / 0x44fbb50 callers
(0x2331e60, 0x23326f0, 0x2332ac0, 0x2333450, 0x2333850, 0x44ecc50, 0x44ed5b0, 0x44edc30, 0x44ee010, 0x44ee730)
appear in `evm-tx-type-name-codec-115` and are not touched here. All 13 addresses were checked against
`research/work-items`, the open and merged PR file lists, and our unsubmitted drafts. None of them appears there.

### Inline-Vec copies (0x22f2c20 family a, 0x44da780 family b; 833 bytes, 206 instructions each)

Here the serializer IS the `Vec<u8>` (`cap`, `ptr`, `len` at +0/+8/+0x10) and the struct-as-map flag is at +0x1b.
The body writes the header and four of the five names itself:

- Header byte: `movzbl 0x1b(%rdx),%ebp ; xor $0x1,%bpl ; shl $0x4,%bpl ; or $0x85,%bpl`. The result is 0x85
  (fixmap 5) for flag 1 and 0x95 (fixarray 5) for flag 0. Any other flag gives a different byte, e.g. 2 → 0xb5
  (a fixstr marker), 0xff → 0xe5. The non-inline copies call `hdr_map` for every non-zero flag instead.
- Each byte push calls the reserve helper (0x231e050 / 0x43bd910, `(vec, len, add, 1, 1)`) only when `cap == len`.
- Name pushes, only when the flag is 1: fixstr marker 0xb5 / 0xb4 / 0xa9, then `sub len, cap ; cmp $n-1 ; jbe` →
  reserve `n` (21 / 20 / 9) when the spare room is below the name length. Then the name is stored with
  `movups` + immediates (bytes from .rodata 0x5eae24 / 0x5eae39 and `movabs` texts).
- "nonce" goes through the Vec string writer (0x25e8bf0 / 0x41c6610), and "data" through keyed writer
  0x233b960 / 0x44fbb50. The value calls are 0x298bad0 / 0x3d40650 (b256), then write_uint
  0x25e9f10 / 0x3d51450 for u32 @0x50 and u64 @0x40 / @0x48.
- Errors and Ok use the same shapes as the other bodies. The reserve helper never returns an error.

The inline model predicts the reserve calls (`len`, `add`), every appended byte, the final `len` and `cap`, the
callee calls and the result record. Inline cases use every slack from 0 to 48 plus 120 above the prefix, so each
spare-room threshold is hit exactly. Controls: 5 model mutants (`inline-header-bool`, `inline-reserve-lt`,
`inline-error-raw`, `keys-when-nonzero`, `chain-id-u64`) and 8 byte flips (the `or $0x85` and `xor $1`
immediates, the 0xb5 marker, the `cmp $0x14` spare test).

### Calling convention (observed, every body)

- Entry: `rdi` = 24-byte result record, `rsi` = struct, `rdx` = `&mut Serializer`, whose byte `+0xb` is the
  struct-as-map flag. The flag is tested twice per body: `cmpb $0x0,0xb(..)` picks the header writer
  (non-zero → `hdr_map` 0x25e7670 / 0x3d4f6d0, zero → `hdr_seq` 0x25e7940 / 0x3d50270), and `cmpb $0x1,0xb(..)`
  guards every name write (`str` 0x25e8750 / 0x41c6110). Flag values 2..255 therefore give a **map header without
  names**. All 13,000 cases include such flags, and the `keys-when-nonzero` / `map-when-one` mutants are caught.
- Header writers and `uint` (0x25e9c70 / 0x3d517e0) return a 3-word slot whose word 0 is `2` on success. `str`
  returns `rax`/`rdx`, `rax == 2` on success. Nested and keyed field serializers return a slot whose word 0 is
  `0x8000000000000004` on success.
- Result: Ok writes only word 0 = `0x8000000000000004` (words 1..2 untouched). A writer error becomes
  `(0x8000000000000000, w0, w1)`. A nested error is copied whole (`movups` + word 2). Nothing after the first
  failing call runs.

### Field layouts (offsets into the struct; from `fields.tsv`)

- destination call: `destination_recipient` @0x20 (b256 serializer 0x298c640 by reference),
  `destination_chain_id` u32 @0x50 (`mov 0x50(%r14),%edx` → `uint`), `gas_limit` u64 @0x40, `nonce` u64 @0x48,
  `data` @0x0 via keyed byte writer 0x233a820 (name "data" passed to the callee).
- Legacy: `chainId` @0x0 (Option; skipped when word 0 is 0; header count `7 - (w0 == 0)` via `cmpq $1; sbb`),
  `nonce` @0x60 and `gas` @0x68 (u64 copied to the stack, passed by reference to 0x29fe9c0), `gasPrice` u128 @0x30
  (family a passes `&S[0x30]` to 0x2968180, family b copies the 16 bytes to the stack for 0x43c3e10), `to` @0x70
  (0x26e5610), `value` @0x40 and `input` @0x10 via keyed writers 0x233b370 / 0x233a820.
- EIP-2930: chainId @0x50, nonce @0x58, gasPrice u128 @0x40, gas @0x60, to @0x80, value @0x0, inner field @0x68
  (0x233a0e0, also used by 1559/4844/7702: inferred access list), input @0x20.
- EIP-1559: chainId @0x60, nonce @0x68, gas @0x70, maxFeePerGas @0x40, maxPriorityFeePerGas @0x50, inner @0x90
  (0x233af30), value @0x0, inner @0x78 (0x233a0e0), input @0x20.
- EIP-4844: chainId @0x70, nonce @0x78, gas @0x80, the two fee caps @0x40/@0x50, inner @0xb8 (0x2339dc0), value @0x0,
  inner @0x88 (0x233a0e0), @0xa0 (0x233a080), @0x60 (0x233b8a0), input @0x20.
- EIP-7702: chainId @0x60, nonce @0x68, gas @0x70, fee caps @0x40/@0x50, inner @0xa8 (0x2339dc0), value @0x0,
  inner @0x78 (0x233a0e0), @0x90 (0x233bc40), input @0x20.
- Block header: 15 always-present fields (parentHash @0x60, sha3Uncles @0x80, miner @0x268 (0x298ac30),
  stateRoot @0xa0, transactionsRoot @0xc0, receiptsRoot @0xe0, inner @0x100, difficulty @0x200, inner @0x220,
  @0x228, @0x230, @0x238, extraData @0x40, mixHash @0x240, inner @0x260). Then 8 optional ones in this order:
  inner @0x0 (present iff u64 != 0), withdrawalsRoot tag byte @0x27c (present iff byte == 1), inner @0x10,
  inner @0x20 (u64 != 0), parentBeaconBlockRoot @0x29d, requestsHash @0x2be, blockAccessListHash @0x2df
  (byte == 1), inner @0x30 (u64 != 0). The optional names are passed to keyed writer 0x233b3d0.
  The four tag bytes are 0x21 apart, the layout of `Option<[u8; 32]>`.

### Block header count (observed, 0x22daf00..0x22daf53)

```
movzbl 0x27c(%rsi),%eax ; cmpq $0x1,(%rsi) ; sbb $0x0,%eax ; add 0x10(%rsi),%eax ; add 0x20(%rsi),%eax
movzbl 0x29d / 0x2be / 0x2df(%rsi) summed ; add ; mov 0x30(%rsi),%eax ; lea (%rax,%rcx,1),%edx ; add $0x10,%edx
```

So `count = (16 - (w0 == 0) + b27c + lo32(w10) + lo32(w20) + b29d + b2be + b2df + lo32(w30)) mod 2^32`.
The presence tests use `cmpq $0x0` and `cmpb $0x1`. For canonical Rust values (tags 0/1) the two rules agree.
With a non-canonical tag they disagree: a tag byte of 2 counts 2 but skips the field, and a word of `1 << 32`
counts 0 but writes the field. The case generator draws tags from {0, 1, 2, 0xff, random} and words from
{0, 1, 2, 2^32, 2^32 + 1, 0xffffffff, random}. The `count-presence-only` and `opt-byte-nonzero` mutants are caught.

## Implementation and comparison

Independent Rust implementation: not yet implemented. The reconstruction is an executable Python model.

- `model(case)`: a declarative field table per struct (`STRUCTS`, 7 structs, 73 field rows) plus the rules above:
  header selection, names only at flag 1, Legacy chainId and block-header presence and count, u64 stack copy,
  family-dependent u128 passing, u32 chain id, error shapes, early return. It predicts the ordered callee list with
  normalized arguments and the 24-byte result record.
- Evaluator: a concrete x86-64 subset interpreter (shared with the earlier rmp packets) runs the ORIGINAL bytes
  of each body. Every callee is a recording contract stub chosen by the role table (`ROLES`, 30 roles, family a
  and b addresses). The stub records the arguments its role defines: struct pointers as `S+off`, stack copies by
  content, name texts read through the passed pointer and length, header counts as 32 bits. It returns ok words or
  the case's error triple, and clobbers caller-saved registers.
- A case passes only if the call lists match (count, roles, every argument), the result record matches bytes
  for bytes (including untouched words), the six callee-saved registers and `rsp` are restored, `rax` returns
  the record pointer, and the struct and serializer bytes are unchanged.
- Cases: 1,000 per body = 13,000. The flag byte cycles through 0, 1, 2, 0x80, 0xff and random values. The fault
  position cycles over every call index plus "no fault". Error words include the other kind's ok word (2 for a
  nested serializer, `0x8000000000000004` for a writer), so a body that compares against the wrong ok constant
  is caught. Struct bytes are random, with edge values on the copied integers and option tags.
- Static checks (fail the run if violated), all from bytes: each body's direct-call sequence must equal the
  sequence implied by its field table, and every callee must belong to the body's own copy family. The `lea` +
  `mov $len` name texts must equal the table names in order. The `+0xb` flag tests must be exactly `$0` and `$1`.
  The fixed header count must appear as `mov $n,%edx`. For the block header, `add $0x10` and the four `movzbl` tag
  offsets must be present. A result-tag immediate must be present.

Negative controls (all must be detected, else the tool fails):

- 18 model mutants for the 13 non-inline bodies (plus the 5 inline ones above): count-presence-only, opt-byte-nonzero, keys-when-nonzero, map-when-one, opt-always,
  opt-when-one, count-plus-one, swap-first-two, str-error-three-words, slot-error-raw, nested-error-wrapped,
  continue-after-error, u64-copy-16, u128-pointer, chain-id-u64, ok-writes-all-words, keyed-key-in-body,
  value-off-plus-8.
- 65 single-byte flips of the non-inline bodies (plus the 8 inline ones above), at most 5 per body: the header-count immediate, the first name-length
  immediate, the `cmpb $1` flag immediate, the flag offset byte `0x0b`, and the first `lea d8(%r14)` field
  displacement (xor 0x08).
- Out-of-range and corrupted input (unit tests): a node binary with one flipped byte (digest refused), a body
  address that is not an FDE start, a role address moved to the other family, a misspelled field name, a wrong
  header count, a wrong header tag offset, and a result slot off the stack. Each one is refused.

## Results and limitations

| measure | value |
| --- | ---: |
| bodies | 15 (6 structs x 2 families + block header + 2 inline-Vec copies) |
| body instructions reached / total | 2,570 / 2,570 |
| cases | 15,000 (13,000 + 2,000 inline) |
| mismatches | 0 |
| negative controls detected | 96 / 96 (23 model + 73 byte) |
| unit tests | 29 pass, 0 skip |

- Gate: no progress gate is requested. The callees are stubs, so this proves the struct-level behavior only. The
  nested serializers (u64/u128/b256/b160/TxKind/access list/...) and the leaf writers are separate work. The
  writers 0x25e8750 / 0x41c6110 and the keyed byte writers are covered by earlier packets.
- Role names are inference: `u64`, `u128`, `b256`, `b160`, `tx_kind`, `if_access_list` and the `if_*` block-header
  names come from the field name or position next to them, not from symbols. Unnamed inner fields write their own
  names inside the callee, and this packet does not open them.
- Struct type names (Legacy, EIP-1559, ...) are inferred from the name sets and header counts. The binary has no
  type name here.
- Non-canonical tags (option byte 2, word 2^32) cannot come from safe Rust values. They are modelled because the
  code's count and presence rules differ there, which is what pins the exact instructions.

Next question: the inline-Vec block header 0x22da880 (1,661 bytes, 375 instructions). It uses the same header-byte
recipe, so does it compute its map/array header from the raw tags too, and how does it encode a count above 15
(a fixmap no longer fits)? Then come the nested serializers this packet stubs (0x29fe9c0 u64, 0x2968180 u128,
0x26e5610 TxKind, 0x233a0e0 access list).
