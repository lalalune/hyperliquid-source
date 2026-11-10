# RE-002 — node #115 libz `_tr_flush_bits` at 0x630b9c0

Bounded reconstruction of one vendor routine inside the pinned node artifact —
zlib's pending-bit flush, the `bi_flush` step of `deflate_trees.c`: emit the
whole bytes still sitting in the bit buffer and keep the sub-byte remainder.

| field | value |
|---|---|
| artifact | `artifacts/node/115/hl-node` |
| artifact SHA-256 | `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` |
| symbol | `_tr_flush_bits` (C linkage — no mangling) |
| member | `b9b191b8e1a44c35-trees.o` |
| rlib | `liblibz_sys-bddd9d79cb3dc319.rlib` |
| crate / versions | `libz-sys` / `1.1.22`, `1.1.31` |
| window | `0x630b9c0..0x630ba48` (136 bytes, 32 instructions) |
| FDE | `pc=000000000630b9c0..000000000630ba48` |
| body key | `target_body_sha256 == source_body_sha256` (`ad48f742…66`), `raw_equal`, 0 relocations, 3 identical source objects |
| form | leaf: no calls, no relocations, one `.eh_frame` FDE |

Version note carried verbatim from the vendor census: node115 embeds
`ZLIB_VERSION "1.3.1"`, and these bodies are identical in the zlib 1.3.2 bundled
by libz-sys 1.1.31 — so this window fixes behaviour but **does not pin a zlib
release**.

## Question

What does the 136-byte leaf routine at `0x630b9c0` do to a `deflate_state`, what
does it leave in `rax`, and what does it assume about its caller?

## Answer

```
void _tr_flush_bits(deflate_state *s)          # rax is a leftover, not a value

  if (s->bi_valid == 16) {                     # 630b9ca/9cd: tested FIRST
      pending_out[pending++] = (Byte)bi_buf;      # low byte
      pending_out[pending++] = (Byte)(bi_buf>>8); # high byte  (630ba1e)
      s->bi_buf = 0;  s->bi_valid = 0;            # 2- and 4-byte zero stores
  } else if ((int32_t)s->bi_valid <= 7) {      # 630b9cf/9d2: SIGNED test
      return;                                     # nothing to emit
  } else {                                     # every other positive value
      pending_out[pending++] = (Byte)bi_buf;
      s->bi_valid -= 8;                           # 4-byte RMW
      s->bi_buf  >>= 8;                           # 2-byte RMW
  }
```

| `bi_valid` | emitted | effect | `rax` at exit |
|---|---|---|---|
| `16` | 2 bytes (`bi_buf & 0xff`, then `bi_buf >> 8`) | `bi_buf = 0`, `bi_valid = 0` | `0` |
| `8 .. 15` | 1 byte (`bi_buf & 0xff`) | `bi_valid -= 8`, `bi_buf >>= 8` | old `pending` |
| `0 .. 7` | none | unchanged | `bi_valid` |
| `17 .. 0x7fffffff` | 1 byte | `bi_valid -= 8` (17→9, 24→16, 100→92) | old `pending` |
| `0x80000000 .. 0xffffffff` | none | unchanged | `bi_valid` |

### Seven build-specific details, each anchored to an instruction

`semantics.tsv` anchors every step to the instruction that carries it (20 rows:
claim, address, size, bytes, decoded instruction, note); `verify.py` and the
tests re-read every anchor's bytes from the digest-verified artifact and
re-decode them with Capstone.

1. **The dispatch is three-way and the order matters.** `cmp $0x10,%eax` +
   `je` (0x630b9ca/9cd) tests the exact value 16 *first* and takes the two-byte
   path; only then does `cmp $0x7,%eax` + `jle` (0x630b9cf/9d2) test for the
   nothing-to-do case. A value of 16 that were tested by the second test alone
   would land in the one-byte path instead.
2. **The `<= 7` test is SIGNED.** `cmp $0x7,%eax` + `jle` compares a 32-bit
   *unsigned count* as if it were signed, so every value with bit 31 set
   (`0x80000000 .. 0xffffffff`) is "negative", satisfies `<= 7`, and emits
   **nothing**. An unsigned `jbe` model differs on exactly those values, and the
   ledger's `negative` family keeps four of them verbatim.
3. **The counter is incremented before the byte is stored.** `lea 0x1(%rax),%rsi`
   + `mov %rsi,0x28(%rdi)` (0x630b9e3/9e7) commit `pending + 1` first, and the
   store then uses the **pre-increment** index (`mov %cl,(%rdx,%rax,1)`,
   0x630b9eb) — so the byte lands at `pending_out[old_pending]`, not one past it.
   A test asserts the store addresses directly.
4. **The two-byte emit is little-endian, in ascending address order.** The low
   byte comes from `movzwl` + `%cl`; the high byte from `movzbl 0x1731(%rdi)`
   (0x630ba1e), the second byte of `bi_buf`. So `pending_out[p] = bi_buf & 0xff`
   and `pending_out[p+1] = bi_buf >> 8` — e.g. `bi_buf = 0x1234` emits `34 12`.
5. **The one-byte path shifts the bit buffer in place with a 2-byte RMW.**
   `shrw $0x8,0x1730(%rdi)` (0x630b9f5) moves the high byte into the low byte,
   and `subl $0x8,0x1734(%rdi)` (0x630b9ee) drops exactly the eight bits it just
   emitted. Both are read-modify-writes at their own widths (2 and 4 bytes).
6. **The 16-bit path overwrites both fields at their own widths.**
   `mov %ax,0x1730(%rdi)` (0x630ba36, 2 bytes of zero) and `movl $0x0,0x1734(%rdi)`
   (0x630ba3d, 4 bytes of zero) — the fields are replaced, not masked or merged.
7. **`rax` is not a return value.** It is left holding `bi_valid` on the
   nothing-to-do path, the *old* `pending` on the one-byte path, and 0 on the
   two-byte path — three different leftovers on three paths. Consistently, the
   census finds that **all 26 call sites overwrite `rax` before reading it**.

There is **no bounds check**: nothing reads `pending_buf_size` (`+0x20`) and no
pointer is compared with a limit, so "there is room for two more bytes" is
entirely the caller's obligation. Struct offsets pinned by the accesses:
`pending_out` `+0x10` (pointer), `pending` `+0x28` (u64), `bi_buf` `+0x1730`
(u16), `bi_valid` `+0x1734` (u32).

## Caller census

26 direct calls, 0 tail jumps, in **4 caller FDEs** (the routine is called
repeatedly from a few large functions), each validated at the instruction
boundary with Capstone and attributed to its enclosing FDE.

| consumer | sites | first use | continuation |
|---|---|---|---|
| `overwritten` | 26 | `mov`/`lea`/`add` writing `rax` | `rax` clobbered by an unrelated value before it could be read |
| `dead` | 0 | — | — |
| *reads the return* | **0** | — | — |

`records.json` records `sites_reading_the_return: 0` and `discarded_sites: 26`,
and `verify.py` re-derives both from `caller_use.tsv`.

## Evidence in this directory

| file | what it holds |
|---|---|
| `main.txt` | the raw `objdump -d` excerpt for the window (32 instructions) |
| `frames.txt` | the `.eh_frame` FDE `0x630b9c0..0x630ba48` |
| `relocations.txt` | no relocations; the raw-equal body digests |
| `callers.tsv` | the 26 call sites with their enclosing FDE bounds |
| `caller_use.tsv` | the consumer class, distance, use and continuation per site |
| `functions.tsv` | empty: this routine calls nothing |
| `semantics.tsv` | 20 claim anchors (claim → address → bytes → decoded instruction) |
| `cases.tsv` | 300 reviewable cases (60 per family) with the input fields, the emitted bytes, the new field values and the `rax` leftover |
| `records.json` | observations vs inferences, the derived census, the layout and the unknowns |
| `census.py` | regenerates `callers.tsv`, `caller_use.tsv`, `frames.txt`, `relocations.txt` |
| `semantics.py` | regenerates `semantics.tsv` from the artifact |
| `export_excerpts.py` | regenerates `main.txt` from the artifact |
| `verify.py` | re-checks the manifest, the anchors, the census and the model |
| `MANIFEST.sha256` | every file here, plus the model and its tests |

## Validation

* `python3 research/work-items/RE-002-node115-libz-tr-flush-bits-630b9c0-115/verify.py`
  → `verify OK: 15 manifest rows, 26 callers / 26 consumers {'overwritten': 26},
  20 claim anchors, model + 300-case ledger {'lower': 60, 'upper': 60,
  'anomalous': 60, 'negative': 60, 'sixteen': 60} + excerpt (32 instructions,
  body ad48f7422e3d…, 2400-case sweep)`.
* `python3 -m unittest discover -s tests -p test_tr_flush_bits_630b9c0_115.py`
  → 31 tests, `OK`.
* `tools/tr_flush_bits_630b9c0_115.py` holds a closed-form model **plus** an
  emulator that executes the routine's own decoded bytes on a small machine model
  that raises on any instruction it does not implement. The two agree on all
  2,400 sweep cases (five families), on all 300 committed ledger rows, and on
  3,000 random `(bi_valid, bi_buf, pending)` triples.
* Meeting this routine required four machinery upgrades, each policed by the
  differential: memory operands now carry their real access width (from a
  Capstone decode, because objdump's text hides it — `subl $x,0x1734(%rdi)` is a
  4-byte RMW while `shrw $x,0x1730(%rdi)` is a 2-byte one), `jl/jle/jg/jge` are
  implemented with a proper overflow flag (this routine's dispatch depends on a
  **signed** comparison), arithmetic supports a memory destination, and stores are
  sized by the memory operand rather than by the source register.
* The tests pin the three-way dispatch and its order, the signed-`jle`
  behaviour on `0x80000000..0xffffffff`, the out-of-range one-byte values
  (17→9, 24→16, 100→92), the little-endian two-byte emit, the store addresses
  (pre-increment index), the field write widths, and the three distinct `rax`
  leftovers.
* The model here is a *closed form* rather than a memory-modelled execution of
  every mispredicted path, but every claim it makes is checked against the
  decoded execution of the routine's own bytes, not against the formula alone.

## Limits

* Static only: the artifact is never executed and no source build is claimed.
  The emulator is deliberately narrow and raises on anything it does not model.
* The **zlib release is not pinned** by this window (see the version note above).
* The caller's obligation (room for two more bytes, `bi_valid <= 16`) is
  inferred from the absence of checks and zlib's contract, not verified against a
  caller; whether `pending_out` can be null in some caller state is not
  characterized; and which of the 26 call sites are reachable for a given
  compression is not characterized.
* The body is byte-identical in 3 identical source objects with only `0x630b9c0`
  bound, and out-of-invariant `bi_valid` values are documented from the bytes
  rather than justified as reachable from a conforming caller.

## Provenance

`libz-sys` / zlib is public (zlib licence). Nothing inferred is copied from
unlicensed sources, and the files added here are MIT under the root license. No
private keys, tokens or live datasets are included.
