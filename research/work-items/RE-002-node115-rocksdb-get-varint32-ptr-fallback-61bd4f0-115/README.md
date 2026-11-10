# RE-002 — node #115 rocksdb `GetVarint32PtrFallback` at 0x61bd4f0

Bounded reconstruction of one vendor routine inside the pinned node artifact —
the decode side of the varint pair whose encoder (0x61bd410) is a separate
window.

| field | value |
|---|---|
| artifact | `artifacts/node/115/hl-node` |
| artifact SHA-256 | `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` |
| symbol | `_ZN7rocksdb22GetVarint32PtrFallbackEPKcS1_Pj` (rocksdb `util/coding.cc`) |
| member | `6cca28ae25285154-coding.o` |
| rlib | `liblibrocksdb_sys-b032f986857674dc.rlib` |
| crate / version | `librocksdb-sys` / `0.11.0+8.1.1` |
| window | `0x61bd4f0..0x61bd53b` (75 bytes, 27 instructions) |
| FDE | `pc=00000000061bd4f0..00000000061bd53b` |
| body key | `target_body_sha256 == source_body_sha256` (`21d63f1e…e6`), `raw_equal`, 0 relocations, 3 identical source objects |
| form | leaf: no calls, no relocations, one byte load per input byte, one 32-bit store |

## Question

Given `(p, limit, value)`, when does the 75-byte leaf routine at `0x61bd4f0`
decode a varint, what does it store, what does it return, and when does it
return nullptr?

## Answer

```
const char* GetVarint32PtrFallback(const char* p, const char* limit,
                                   uint32_t* value)

  if (p >= limit) return nullptr;            # checked before any byte is read
  shift = 0; acc = 0;
  for (;;) {
      b = *p++;                              # rax advances before the test
      if (b & 0x80) {                        # bit 7: another byte follows
          acc  |= (b & 0x7f) << shift;       # in 32-bit registers
          shift += 7;
          if (shift > 28) return nullptr;    # a fifth continuation byte
          if (p >= limit) return nullptr;    # truncated at the limit
          continue;
      }
      *value = (b << shift) | acc;           # one 32-bit store
      return p;                              # the pointer past the varint
  }
```

So the routine is the bounded LEB128 decoder, and **nullptr has three
distinct causes**, all of which the ledger exercises:

| condition | instruction | example |
|---|---|---|
| `p >= limit` before the first byte | 0x61bd4fa | `("", 0)`, `([0x01], 0)` |
| the varint runs off the limit | 0x61bd51b | `([0x80], 1)` |
| a fifth continuation byte (shift > 28) | 0x61bd516 | `([0x80] × 5, 5)` |

### Four build-specific details

`semantics.tsv` anchors each of these to the instruction that carries it (24
rows: claim, address, size, bytes, decoded instruction, note); `verify.py` and
the tests re-read every anchor's bytes from the digest-verified artifact and
re-decode them with Capstone.

1. **The bound is checked before the first byte is read, and again after every
   continuation byte.** `cmp %rsi,%rdi / jae 0x61bd538` returns nullptr
   immediately, and `cmp %rsi,%rax / jae 0x61bd538` (0x61bd518/51b) rejects a
   varint that reaches the limit — so a truncated varint is *rejected*, never
   answered with the bytes seen so far. Both jumps are unsigned (`jae`), and
   the two `cmp` operands are in the reverse order from the usual AT&T pairing,
   which is why the comparison reads as "pointer ≥ limit".
2. **The continuation test is the sign bit of the byte just read.** `test
   %dil,%dil` (0x61bd524) is an 8-bit AND, so SF is bit 7 of the byte, and `js`
   (0x61bd527) branches on it: any byte ≥ 0x80 continues. The pointer is
   advanced (`add $0x1,%rax`, 0x61bd520) *before* that test, which is why the
   success value is already past the last byte.
3. **The shift guard allows at most four continuation bytes.** Each
   continuation byte does `add $0x7,%ecx` and then `cmp $0x1c,%ecx / ja`
   (0x61bd50d/13/16): a shift above 28 is a failure, so a fifth continuation
   byte returns nullptr and 5 bytes is the longest varint accepted.
4. **The value is assembled and stored as a 32-bit word, so it is silently
   masked to 32 bits.** The accumulator (`or %edi,%r8d`), the final shift
   (`shl %cl,%edi`) and the store (`mov %edi,(%rdx)`, `mov dword ptr [rdx],edi`)
   are all 32-bit. A hand-built 5-byte varint whose last byte has bits above
   0x0f therefore loses everything from bit 32 up: `80 80 80 80 20` decodes to
   **0** and `80 80 80 80 7f` to **0xf0000000**. The encoder never emits such a
   byte (its fifth byte is `v >> 28`, 0x61bd4cb), so this asymmetry only shows
   on corrupt or hand-crafted input — and it is a plausible robustness argument
   for treating a 5-byte varint's top byte as bounded by 0x0f, but the routine
   does not enforce that.

The store claim is checked positively: a successful decoded run writes exactly
the four bytes of the output word (`{len, len+1, len+2, len+3}`) and nothing
else, and a failed run writes nothing at all. Unlike its sibling encoder at
0x61bd410, this routine *does* read memory: one byte load per input byte.

## Caller census

149 direct calls, 0 tail jumps, each validated at the instruction boundary with
Capstone and attributed to the enclosing `.eh_frame` FDE (`callers.tsv`); 45
distinct caller FDEs.

| consumer | sites | first use | continuation |
|---|---|---|---|
| `compare` | 27 | `test rax, rax` | `je …` — **the nullptr contract is checked at the call site** |
| `register-copy` | 95 | `mov r12,rax`, `mov rcx,rax`, … | the advanced pointer is carried on |
| `store` | 19 | `mov [..],rax` | spilled |
| `arithmetic` | 3 | `sub rbp,rax` | subtracted from a base to size a consumed range |
| `dead` | 4 | — | the call's only effect is the stored value |
| `overwritten` | 1 | `mov eax,[rbp-0x2f0]` | rax overwritten before use |

That is the contract read off the call sites: 27 callers test the returned
pointer for zero and branch away, so the failure return is *observable*, not
theoretical. `records.json` records the null-check and discarded counts and a
test re-derives both from `caller_use.tsv`, so the prose cannot drift from the
table.

## Evidence in this directory

| file | what it holds |
|---|---|
| `main.txt` | the raw `objdump -d` excerpt for the window (27 instructions) |
| `frames.txt` | the `.eh_frame` FDE `0x61bd4f0..0x61bd53b` |
| `relocations.txt` | no relocations; the raw-equal body digests |
| `callers.tsv` | the 149 call sites with their enclosing FDE bounds |
| `caller_use.tsv` | the consumer class, distance, first use, continuation and FDE per site |
| `functions.tsv` | empty: this routine calls nothing |
| `semantics.tsv` | 24 claim anchors (claim → address → bytes → decoded instruction) |
| `cases.tsv` | 300 reviewable cases (50 per family: 1..5-byte varints + the nullptr family) with limit, outcome, value and next index |
| `records.json` | observations vs inferences, the derived census, the unknowns |
| `census.py` | regenerates `callers.tsv`, `caller_use.tsv`, `frames.txt`, `relocations.txt` |
| `semantics.py` | regenerates `semantics.tsv` from the artifact |
| `export_excerpts.py` | regenerates `main.txt` from the artifact |
| `verify.py` | re-checks the manifest, the anchors, the census and the model |
| `MANIFEST.sha256` | every file here, plus the model and its tests |

## Validation

* `python3 research/work-items/RE-002-node115-rocksdb-get-varint32-ptr-fallback-61bd4f0-115/verify.py`
  → re-checks the manifest, the excerpt, the 24 anchors, the 149-call census and
  the model against the artifact.
* `python3 -m unittest discover -s tests -p test_get_varint32_ptr_fallback_61bd4f0_115.py`
  → 31 tests, `OK`.
* `tools/get_varint32_ptr_fallback_61bd4f0_115.py` holds a closed-form model
  **plus** an emulator that executes the routine's own decoded bytes on a small
  machine model that raises on any instruction it does not implement. The two
  agree on all 2,400 sweep cases, on every committed ledger row, and on 3,000
  random `(buffer, limit)` pairs.
* The tests pin the nullptr causes, the boundary values of every family, the
  32-bit truncation (`80 80 80 80 20 → 0`), the exactly-one-word write set and
  the empty write set on failure — each in terms of the decoded execution, not
  of the model alone.
* The excerpt's concatenated bytes are asserted equal to the binary's own bytes
  for the window, in both `verify.py` and the tests; the claim anchors are
  re-decoded with Capstone rather than compared as objdump text.

## Limits

* Static only: the artifact is never executed and no source build is claimed.
  The emulator is deliberately narrow and raises on anything it does not model.
* Reading `p`/`limit` as `const char*` and `value` as `uint32_t*` is an
  **inference** from the mangled signature, the `movzbl` byte load and the
  32-bit store; the packet does not prove the C types.
* Which call sites can reach the failure return at run time is not
  characterized: that depends on the buffers the callers are handed.
* The sibling windows in the same object — `EncodeVarint32` (`0x61bd410`) and
  `GetVarint64Ptr` (`0x61bd540`) — are separate windows and are not covered.
* The body is byte-identical in 3 identical source objects; only `0x61bd4f0` is
  bound.
* The caller-side classification stops at the *first* use of rax; a pointer that
  is copied and then discarded is classified by that first use.

## Provenance

`librocksdb-sys` / RocksDB is public (Apache-2.0 / GPL-2.0 dual-licensed).
Nothing inferred is copied from unlicensed sources, and the files added here are
MIT under the root license. No private keys, tokens or live datasets are
included.
