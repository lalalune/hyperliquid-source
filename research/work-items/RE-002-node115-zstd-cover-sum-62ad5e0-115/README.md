# RE-002 — node #115 zstd `COVER_sum` at 0x62ad5e0

Bounded reconstruction of one vendor routine inside the pinned node artifact.

| field | value |
|---|---|
| artifact | `artifacts/node/115/hl-node` |
| artifact SHA-256 | `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` |
| symbol | `COVER_sum` |
| member | `ebb58710e9060628-cover.o` |
| rlib | `libzstd_sys-c8c5b6f4c7c3aee0.rlib` |
| crate / versions | `zstd-sys` / `2.0.15+zstd.1.5.7`, `2.1.2+zstd.1.5.7` |
| window | `0x62ad5e0..0x62ad641` (97 bytes, 32 instructions) |
| FDE | `pc=00000000062ad5e0..00000000062ad641` |
| body key | `target_body_sha256 == source_body_sha256` (`4a82aa15…2c`), `raw_equal`, 0 relocations, 3 identical source copies |
| form | leaf: no calls, no stores, no relocations |

## Question

What does the 97-byte leaf routine at `0x62ad5e0` return for a `splits`
pointer and a count, and what do its callers depend on?

## Answer

```
result = sum(splits[0:n]) mod 2**64
```

with three special cases visible in the code layout:

```
n == 0                       -> 0                 # 0x62ad5e4 test; je 0x62ad638 (xor %eax,%eax)
n == 1                       -> splits[0]         # 0x62ad5e8 cmp $1; je 0x62ad63b -> the shared add
n >= 2                       -> vector pairs      # 0x62ad5f2 pxor; 0x62ad600 movdqu/paddq loop
   even n                    -> the pair sum alone
   odd  n                    -> pair sum + splits[n-1]   # 0x62ad623 test; 0x62ad629 and ~1; 0x62ad62c add
```

The vector loop runs `n >> 1` times over 16-byte `movdqu` loads, adding two
`size_t` elements per pass with `paddq`, folds the two 64-bit lanes together
(`psrldq $0x8` then `paddq`), keeps the low lane (`movq %xmm0,%rax`), and — for
an odd count — adds the remaining element with a single scalar `add`.

### Four build-specific details the source alone does not pin

`semantics.tsv` anchors each of these to the instruction that carries it
(19 rows: claim, address, size, bytes, decoded instruction, note); `verify.py`
and the tests re-read every anchor's bytes from the digest-verified artifact and
re-decode them with Capstone.

1. **The vector loop covers exactly `2*(n>>1)` elements.** The count is derived
   as `shr $1,%edx` then `shl $0x4,%rdx` plus the base pointer
   (`0x62ad5f6..0x62ad5fc`), so a pair loop covers all of an even count and all
   but one of an odd count. The leftover is added **after** the horizontal fold,
   at index `n & ~1` (`and $0xfffffffe,%esi`), not before it.
2. **The `n == 1` case is folded into that same scalar add.** `0x62ad63b`
   zeroes `%esi` and jumps to `0x62ad62c`, so the routine has **exactly one**
   `add` whose source is memory. A second scalar path would have to be
   reconstructed separately; here there is only one site to get right.
3. **The addition is per-64-bit-lane and wraps.** `paddq` adds 64-bit lanes
   with no carry into the neighbouring lane, and the horizontal fold is another
   `paddq`, so the result is the sum modulo 2\*\*64 — the same value a serial
   wrapping scalar sum produces, and independent of the order of the elements.
   The tests assert the wrap explicitly (`M64 + 1 == 0`) and that reordering
   changes nothing.
4. **`n == 0` returns zero without reading `splits`.** The early return is a
   jump to `xor %eax,%eax` (`0x62ad638`), so an empty slice needs no valid
   pointer; the routine also performs no stores at all, so it cannot disturb the
   arrays it reads.

## Caller census

3 direct calls, 0 tail jumps, **all three inside a single caller FDE**
(`0x62ac520..0x62ac9c9`). Each site is Capstone-validated at the instruction
boundary and attributed to the `.eh_frame` FDE that encloses it (`callers.tsv`);
`caller_use.tsv` records how each caller first consumes the returned value.

| consumer | sites | first use | continuation |
|---|---|---|---|
| `register-copy` | 2 | `mov r12,rax`, `mov rcx,rax` | copied into a register for later use |
| `store` | 1 | `mov [rbp-0x70],rax` | spilled, reloaded later |
| `overwritten` | 0 | — | **no call site discards the sum** |

Unlike the sibling packet where one call site threw the result away, every
caller here consumes the value it gets back, so a wrong sum propagates into all
three call sites' continuations rather than being caught by one of them.

## Evidence in this directory

| file | what it holds |
|---|---|
| `main.txt` | the raw `objdump -d` excerpt for the window (33 lines, 32 instructions) |
| `frames.txt` | the `.eh_frame` FDE `0x62ad5e0..0x62ad641` |
| `relocations.txt` | no relocations; the raw-equal body digests |
| `callers.tsv` | the 3 call sites with their enclosing FDE bounds |
| `caller_use.tsv` | the consumer class, distance, and continuation per site |
| `functions.tsv` | empty: this routine calls nothing |
| `semantics.tsv` | 19 claim anchors (claim → address → bytes → decoded instruction) |
| `cases.tsv` | 300 reviewable cases (75 per family), the committed ledger |
| `records.json` | observations vs inferences, the derived census, the unknowns |
| `census.py` | regenerates `callers.tsv`, `caller_use.tsv`, `frames.txt`, `relocations.txt` |
| `semantics.py` | regenerates `semantics.tsv` from the artifact |
| `export_excerpts.py` | regenerates `main.txt` from the artifact |
| `verify.py` | re-checks the manifest, the anchors, the census and the model |
| `MANIFEST.sha256` | every file here, plus the model and its tests |

## Validation

* `python3 research/work-items/RE-002-node115-zstd-cover-sum-62ad5e0-115/verify.py`
  → re-checks the manifest, the excerpt, the 19 anchors, the census and the model
  against the artifact.
* `python3 -m unittest discover -s tests -p test_cover_sum_62ad5e0_115.py`
  → all tests pass.
* The model in `tools/cover_sum_62ad5e0_115.py` is a closed form **plus** an
  emulator that executes the routine's own decoded instruction bytes on a small
  machine model that implements exactly the instructions present (including
  `movdqu`/`paddq`/`psrldq`) and raises on any other. The two agree on the whole
  2,400-case sweep, on every committed ledger row, and on 3,000 random arrays.
* The excerpt's concatenated bytes are asserted equal to the binary's own bytes
  for the window, in both `verify.py` and the tests.
* The ledger is stratified so each family exercises one path: `empty` (n = 0),
  `single` (n = 1), `pairs` (even n ≥ 2, vector only) and `odd` (odd n ≥ 3,
  vector + tail).

## Limits

* Static only: the artifact is never executed, and no source build is claimed.
  The emulator is deliberately narrow — it implements the instructions this
  routine uses and raises on anything else.
* Reading the elements as `size_t` and the result as a byte total is an
  **inference** from the symbol name and the callers' use of the value; it is
  recorded as such in `records.json`, and what each caller does with the sum
  beyond its first read is not traced.
* The routine uses an unaligned load, so it is alignment-independent; the
  runtime alignment of the array is not observable statically either way.
* The body is byte-identical in 3 identical source objects; only `0x62ad5e0`
  is bound.

## Provenance

`zstd-sys` / zstd is public (BSD-3-Clause / MIT dual-licensed). Nothing inferred
is copied from unlicensed sources, and the files added here are MIT under the
root license. No private keys, tokens or live datasets are included.
