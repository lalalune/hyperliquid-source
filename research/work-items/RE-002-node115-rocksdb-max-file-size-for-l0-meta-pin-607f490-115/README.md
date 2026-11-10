# RE-002 — node #115 rocksdb `MaxFileSizeForL0MetaPin` at 0x607f490

Bounded reconstruction of one vendor routine inside the pinned node artifact.

| field | value |
|---|---|
| artifact | `artifacts/node/115/hl-node` |
| artifact SHA-256 | `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` |
| symbol | `_ZN7rocksdb23MaxFileSizeForL0MetaPinERKNS_16MutableCFOptionsE` |
| member | `d7ece8bd5f9dc186-cf_options.o` |
| rlib | `liblibrocksdb_sys-b032f986857674dc.rlib` |
| crate / version | `librocksdb-sys` / `0.11.0+8.1.1` |
| window | `0x607f490..0x607f4bb` (43 bytes, 11 instructions) |
| FDE | `pc=000000000607f490..000000000607f4bb` |
| body key | `target_body_sha256 == source_body_sha256` (`af82ff31…75`), `raw_equal`, 0 relocations, 3 identical source copies |
| form | leaf: no calls, no stores, no relocations, one `ret` |

## Question

What does the 43-byte leaf routine at `0x607f490` return for the options
pointer it is given, and what do its callers do with the result?

## Answer

```
value = *(uint64_t *)rdi                  # mov (%rdi),%rdx      @0x607f494

result = 0xFFFFFFFFFFFFFFFF               # mov $-1,%rax         @0x607f497
if value > 0xAAAAAAAAAAAAAAAB:            # cmp %rdx,%rcx; jb    @0x607f4a8/4ab
    return result                         #   (unsigned compare)

result = 3 * (value >> 1)                 # mov/and/shr/add      @0x607f4ad..4b7
return result
```

The accepted path is three halves of the loaded field: `value >> 1` (the
`shr $1,%rax`) added to `2 * (value >> 1)` (the `and $-2` on `%rdx` that
clears the low bit), i.e. **`3 * (value >> 1)`**, computed with a shift and an
add rather than a multiply.

### Three build-specific details the source alone does not pin

`semantics.tsv` anchors each of these to the instruction that carries it
(11 rows: claim, address, size, bytes, decoded instruction, note). `verify.py`
and the tests re-read every anchor's bytes from the digest-verified artifact
and re-decode them with Capstone.

1. **The guard is unsigned and the threshold is exact.** `cmp %rdx,%rcx` +
   `jb` compares `0xAAAAAAAAAAAAAAAB` with the value as unsigned, so the
   sentinel is returned exactly when `threshold < value`. The threshold is
   `floor((2^64-1)/3)`, the largest input for which `3 * (value >> 1)` still
   fits in 64 bits — so `value == threshold` is **accepted** and its result is
   `0xFFFFFFFFFFFFFFFF`, which fits exactly.
2. **The halving happens before the tripling.** The shift is applied to the
   value first, so an odd input truncates: `5 → 6` (not `7`) and `7 → 9` (not
   `10`). A model written as `(3 * value) >> 1` returns a different answer for
   every odd input; the ledger's `parity` family is that axis.
3. **The largest accepted input is indistinguishable from a rejection.** The
   accepted result for `value == 0xAAAAAAAAAAAAAAAB` is all ones, the same bit
   pattern the guard returns. Nothing in the routine's return value tells the
   two cases apart; only the input does.

The routine reads **exactly one** memory operand — `mov (%rdi),%rdx` — so the
whole function is a pure function of the first 8 bytes of the options struct.

## Caller census

12 direct calls, 0 tail jumps, in **11 distinct caller FDEs** (two call sites
share the FDE `0x5f95b80..0x5f98c8d`). Each site is Capstone-validated at the
instruction boundary and attributed to the `.eh_frame` FDE that encloses it
(`callers.tsv`); `caller_use.tsv` records how each caller first consumes the
returned value, decoded forward inside its own FDE.

| consumer | sites | first use | continuation |
|---|---|---|---|
| `register-copy` | 4 | `mov r13,rax`, `mov rcx,rax`, … | copied into a register for later use |
| `stack-arg` | 4 | `push rax` (or stored then pushed) | passed on as a stack argument |
| `store` | 3 | `mov [rbp-0x348],rax`, … | spilled and reloaded later |
| `overwritten` | 1 | `mov [rbp-0x6c8],rax` | the result is **dead** at `0x5f96072` |

So eleven of the twelve sites carry the value forward and one discards it — a
consumer-set fact about *this* binary that no source reading supplies, and one
that a reconstruction of the surrounding code would get wrong if it assumed
every call site consumes the result.

## Evidence in this directory

| file | what it holds |
|---|---|
| `main.txt` | the raw `objdump -d` excerpt for the window (13 lines, 11 instructions) |
| `frames.txt` | the `.eh_frame` FDE `0x607f490..0x607f4bb` |
| `relocations.txt` | no relocations; the raw-equal body digests |
| `callers.tsv` | the 12 call sites with their enclosing FDE bounds |
| `caller_use.tsv` | the consumer class, distance, and continuation per site |
| `functions.tsv` | empty: this routine calls nothing |
| `semantics.tsv` | 11 claim anchors (claim → address → bytes → decoded instruction) |
| `cases.tsv` | 300 reviewable cases (75 per family), the committed ledger |
| `records.json` | observations vs inferences, the derived census, the unknowns |
| `census.py` | regenerates `callers.tsv`, `caller_use.tsv`, `frames.txt`, `relocations.txt` |
| `semantics.py` | regenerates `semantics.tsv` from the artifact |
| `export_excerpts.py` | regenerates `main.txt` from the artifact |
| `verify.py` | re-checks the manifest, the anchors, the census and the model |
| `MANIFEST.sha256` | every file here, plus the model and its tests |

## Validation

* `python3 research/work-items/RE-002-node115-rocksdb-max-file-size-for-l0-meta-pin-607f490-115/verify.py`
  → manifest, anchors, census and model re-checked against the artifact.
* `python3 -m unittest discover -s tests -p test_max_file_size_for_l0_meta_pin_607f490_115.py`
  → 23 tests, all passing.
* The model in `tools/max_file_size_for_l0_meta_pin_607f490_115.py` is a
  closed form **plus** an emulator that executes the routine's own decoded
  instruction bytes on a small machine model that implements exactly the
  instructions present and raises on any other. The two agree on the whole
  2,400-case sweep, on every committed ledger row, and on 20,000 random
  64-bit inputs.
* The excerpt's bytes are compared against the binary's own bytes for the
  window, and the streams's concatenated bytes must equal them, in both
  `verify.py` and the tests.

## Limits

* Static only: the artifact is never executed, and no source build is
  claimed. The emulator models only the instructions this routine uses.
* The identity of the field read at `*rdi` as `MutableCFOptions::max_file_size`
  is an **inference** from the mangled signature and is recorded as such in
  `records.json`; what each caller does with the value beyond its first read is
  not traced.
* Because the guard's threshold input and the sentinel share a bit pattern,
  no caller-side observation can distinguish those two cases.
* The body is byte-identical in 3 identical source objects; only `0x607f490`
  is bound.

## Provenance

`librocksdb-sys` / RocksDB is public (Apache-2.0 / GPL-2.0 dual-licensed).
Nothing inferred is copied from unlicensed sources, and the files added here
are MIT under the root license. No private keys, tokens or live datasets are
included.
