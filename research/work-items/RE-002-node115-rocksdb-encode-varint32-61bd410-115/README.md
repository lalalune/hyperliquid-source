# RE-002 — node #115 rocksdb `EncodeVarint32` at 0x61bd410

Bounded reconstruction of one vendor routine inside the pinned node artifact.

| field | value |
|---|---|
| artifact | `artifacts/node/115/hl-node` |
| artifact SHA-256 | `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` |
| symbol | `_ZN7rocksdb14EncodeVarint32EPcj` (rocksdb `util/coding.cc`) |
| member | `6cca28ae25285154-coding.o` |
| rlib | `liblibrocksdb_sys-b032f986857674dc.rlib` |
| crate / version | `librocksdb-sys` / `0.11.0+8.1.1` |
| window | `0x61bd410..0x61bd4e9` (217 bytes, 62 instructions) |
| FDE | `pc=00000000061bd410..00000000061bd4e9` |
| body key | `target_body_sha256 == source_body_sha256` (`84a0d0d2…ec`), `raw_equal`, 0 relocations, 3 identical source objects |
| form | leaf: no calls, no relocations, no memory reads |

## Question

What bytes does the 217-byte leaf routine at `0x61bd410` write for a `uint32_t`
value, and what do its callers do with the end pointer it returns?

## Answer

```
char* EncodeVarint32(char* dst, uint32_t v)   # returns dst + n, never a count

v <= 0x7f          -> 1 byte    0x7f     00..7f
v <= 0x3fff        -> 2 bytes   3fff     ff 7f
v <= 0x1fffff      -> 3 bytes   1fffff   ff ff 7f
v <= 0x0fffffff    -> 4 bytes   fffffff  ff ff ff 7f        (one 32-bit store)
otherwise          -> 5 bytes   ffffffff ff ff ff ff 0f
```

i.e. LEB128 for a 32-bit input, with the last byte of each class carrying no
continuation bit.

### Five build-specific details the source alone does not pin

`semantics.tsv` anchors each of these to the instruction that carries it
(19 rows: claim, address, size, bytes, decoded instruction, note); `verify.py`
and the tests re-read every anchor's bytes from the digest-verified artifact and
re-decode them with Capstone.

1. **The 4-byte class writes with a single unaligned 32-bit store.** The four
   bytes are composed in registers (`movzbl` / `shl $0x8` / `or` at
   `0x61bd47c..0x61bd49d`) and written by one `mov %ecx,(%rax)` at `0x61bd4a0`.
   The 1-, 2-, 3- and 5-byte classes each use one byte store per byte
   (`0x61bd41c`, `0x61bd448/44b`, `0x61bd4b4..4ba`, `0x61bd4ce..4e0`). The
   ledger's `single_32bit_store` column is exactly `nbytes == 4`, so the table
   ties the claim to the instruction.
2. **The class bounds are inclusive and tested with an unsigned `ja`.** Each
   test is `cmp $bound,%esi` followed by a jump on *unsigned above*, so the
   bound value itself stays in the smaller class — `0x7f` is 1 byte, `0x3fff`
   is 2, `0x1fffff` is 3, `0x0fffffff` is 4. A model that used signed
   comparisons or off-by-one bounds differs on exactly those values, which the
   ledger keeps verbatim.
3. **Continuation bits are or-ed in, and the final byte is stored unmasked.**
   `or $0xffffff80` sets bit 7 of each non-final byte (`0x61bd435`, `0x61bd45a`,
   `0x61bd46d`, `0x61bd4c8`); the last byte of every multi-byte class is a plain
   byte move, which is safe only because the class bound guarantees its value is
   `<= 0x7f`.
4. **The fifth byte is `v >> 28`.** `shr $0x1c,%esi` at `0x61bd4cb` means only
   the low nibble of the top byte can be non-zero for a `uint32_t`: `0xffffffff`
   encodes as `ff ff ff ff 0f`.
5. **There are three return tails, not one.** `mov %rdx,%rax / ret` appears at
   `0x61bd423`, `0x61bd44e` and `0x61bd4be`. The 4- and 5-byte classes jump to
   the first (`0x61bd4a2`, `0x61bd4e4`) and the 1-byte class falls into it, but
   the 2- and 3-byte classes have their own identical copies. Every class still
   computes `rdx = dst + n` first, so the returned value is the end pointer.

The routine reads no memory at all: every memory operand in the body is the last
operand of its instruction, i.e. a store (a test asserts this, exempting `lea`
as address arithmetic).

## Caller census

165 direct calls, 0 tail jumps, each validated at the instruction boundary with
Capstone and attributed to the enclosing `.eh_frame` FDE (`callers.tsv`); 45
distinct caller FDEs.

| consumer | sites | first use | continuation |
|---|---|---|---|
| `arithmetic` | 139 | `sub rax,<base>` (132 of them) | the difference is compared with a limit, then the base pointer is moved |
| `register-copy` | 24 | `mov r12,rax`, `mov rcx,rax`, … | copied for later use |
| `store` | 2 | `mov [rbp-…],rax` | spilled, reloaded later |
| `overwritten` | 0 | — | **no call site discards the end pointer** |

The dominant pattern is the contract: the callers subtract their buffer's base
pointer from the returned end pointer to recover the encoded length
(`mov rdx,rax; sub rax,<base>; cmp rax,<limit>; jb …`). `records.json` records
that count and a test re-derives it from `caller_use.tsv`, so the claim cannot
drift from the table.

## Evidence in this directory

| file | what it holds |
|---|---|
| `main.txt` | the raw `objdump -d` excerpt for the window (64 lines, 62 instructions) |
| `frames.txt` | the `.eh_frame` FDE `0x61bd410..0x61bd4e9` |
| `relocations.txt` | no relocations; the raw-equal body digests |
| `callers.tsv` | the 165 call sites with their enclosing FDE bounds |
| `caller_use.tsv` | the consumer class, distance, first use and continuation per site |
| `functions.tsv` | empty: this routine calls nothing |
| `semantics.tsv` | 19 claim anchors (claim → address → bytes → decoded instruction) |
| `cases.tsv` | 300 reviewable cases (60 per class) with `nbytes` and `single_32bit_store` |
| `records.json` | observations vs inferences, the derived census, the unknowns |
| `census.py` | regenerates `callers.tsv`, `caller_use.tsv`, `frames.txt`, `relocations.txt` |
| `semantics.py` | regenerates `semantics.tsv` from the artifact |
| `export_excerpts.py` | regenerates `main.txt` from the artifact |
| `verify.py` | re-checks the manifest, the anchors, the census and the model |
| `MANIFEST.sha256` | every file here, plus the model and its tests |

## Validation

* `python3 research/work-items/RE-002-node115-rocksdb-encode-varint32-61bd410-115/verify.py`
  → re-checks the manifest, the excerpt, the 19 anchors, the 165-call census and
  the model against the artifact.
* `python3 -m unittest discover -s tests -p test_encode_varint32_61bd410_115.py`
  → 27 tests, `OK`.
* The model in `tools/encode_varint32_61bd410_115.py` is a closed form **plus**
  an emulator that executes the routine's own decoded bytes (including the
  register-source `movzbl`, the `or $0xffffff80` continuation bits and the
  32-bit store) on a small machine model that raises on any instruction it does
  not implement. The two agree on the whole 2,400-case sweep, on every committed
  ledger row, and on 3,000 random values.
* The tests also round-trip every encoded value through an independently written
  LEB128 decoder, check that every byte but the last carries the continuation
  bit, and assert the `single_32bit_store` predicate equals `nbytes == 4`.
* The excerpt's concatenated bytes are asserted equal to the binary's own bytes
  for the window, in both `verify.py` and the tests, and the class bounds are
  asserted through the Capstone decoder rather than through objdump's text.

## Limits

* Static only: the artifact is never executed, and no source build is claimed.
  The emulator is deliberately narrow: it implements the instructions this
  routine uses and raises on anything else.
* Reading `dst` as `char*` and `v` as `uint32_t` is an **inference** from the
  mangled signature and the 7-bit shifts; the packet does not prove the C
  types.
* The routine writes up to 5 bytes and performs no bounds check of its own; the
  callers' buffer reservations are not verified here, and which classes are
  reachable at each call site at run time is not characterized.
* The sibling windows in the same object — `GetVarint32PtrFallback`
  (`0x61bd4f0`) and `GetVarint64Ptr` (`0x61bd540`) — are separate windows and
  are not covered by this packet.
* The body is byte-identical in 3 identical source objects; only `0x61bd410`
  is bound.

## Provenance

`librocksdb-sys` / RocksDB is public (Apache-2.0 / GPL-2.0 dual-licensed).
Nothing inferred is copied from unlicensed sources, and the files added here are
MIT under the root license. No private keys, tokens or live datasets are
included.
