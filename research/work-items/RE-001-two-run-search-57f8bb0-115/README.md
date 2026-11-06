# RE-001: node #115 two-run search 0x57f8bb0

Task RE-001. Bounded question: what does the whole 284-byte
routine at `0x57f8bb0` (FDE `0x57f8bb0..0x57f8ccc`) compute
from its descriptor and key arguments, end to end, and who
calls it?

## Answer, pinned to the target binary

The routine binary-searches 40-byte records keyed by each
record's first qword. Its first argument is a descriptor: the
buffer base pointer at `+0x8`, and three u64 words `f0` at
`+0x0`, `f2` at `+0x10`, `f3` at `+0x18`. The second argument
points at the key qword. The records form one logical sequence
stored in two physical runs of the buffer, in this order:

- run A: physical indices `[start, start + skip)`;
- run B: physical indices `[0, len1)`;

where, in u64 arithmetic,

- `start = f2 - f0` if `f2 >= f0`, else `start = f2`;
- `skip = f0 - start`;
- `len1 = f3 - skip`.

It returns `(rax, rdx)`: `rax` is 0 on an exact match and 1
otherwise; `rdx` is the logical index of the match, or the
insertion index that would keep the logical sequence sorted.
The search order is exact:

1. **Empty.** If `f3 == 0`, return `(1, 0)` without reading
   any record.
2. **Single run.** If `f3 <= skip` (run B empty, or the
   length subtraction borrows), search run A only, with
   length `f3`, and return its local result unchanged.
3. **Head comparison.** Otherwise the key is first compared
   against record 0, the head of run B:
   - equal: return `(0, skip)`;
   - record 0 greater than the key: the key can only belong
     to run A. If `skip == 0`, return `(1, 0)`; otherwise
     search run A with length `skip` and return its local
     result unchanged;
   - record 0 smaller than the key: binary-search run B and
     return `(flag, skip + local index)`.

Each run search is one shared loop shape, transcribed
operation for operation in the model: it halves a
`(lo, size)` window against the record keys with an unsigned
comparison, then resolves the final record — one exact-match
test and, for a smaller final record, a `+1` insertion
adjustment from the compare's carry. With duplicate keys the
returned index is whichever copy that loop settles on (the
model tests pin two such cases: the head equality returns
`skip` when record 0 is a copy, and the run-A loop settles
on the second of two copies).

## The engine call site

The block engine (FDE `0x5a06600..0x5a07eb6`) calls the
routine at `0x5a07616` with its `rbp` as the descriptor and
its `r13` as the key pointer (window shipped as
`caller.txt`). On return it tests bit 0 of `rax` and skips
the current item when the bit is set; it then compares
`rdx` against the qword at `r15 + 0x418` and skips the item
when `rdx` is not below it; only then does it add the
pointer at `r15 + 0x410` to `rdx` and continue into a clamp
against `rbx`. Only these window instructions are claimed;
what the descriptor or the `r15` object denote in the
engine is not.

## Transfers

The routine makes no call of any kind and no tail jump out;
every direct jump lands inside the routine, and it has no
landing-pad block of its own inside the FDE range. Its
address is not stored as a qword anywhere in the binary
and appears in no `R_X86_64_RELATIVE` addend (census).

## Consumers (site-only)

The census finds exactly four direct call sites and no
tail jumps:

- `0x4dcea39`, inside caller `0x4dce8b0..0x4dced3e`, which
  moves its `r14` into `rdi` and the address of a stack
  slot at `0xc0(%rsp)` into `rsi`;
- `0x4dd4749`, inside caller `0x4dd45c0..0x4dd4a4e`, with
  the same two moves;
- `0x5a05df6`, inside caller `0x5a04e40..0x5a065f8`, which
  moves its `rbp` into `rdi` and its `r13` into `rsi`;
- `0x5a07616`, inside the block engine
  `0x5a06600..0x5a07eb6`, with the same two moves (the
  window is shipped as `caller.txt`).

Only the sites, FDE ranges, and the pinned moves above are
claimed; wider caller semantics are not.

## NOT claimed

What the descriptor, the buffer, or the records denote in
any caller's terms; that the buffer is any particular
source-level container type (the two-run layout is the
binary's arithmetic, not a recovered type); caller
semantics beyond the sites, FDE ranges, pinned moves and
the shipped engine window; behaviour on inputs whose field
arithmetic makes the routine read outside the supplied
buffer (the model raises on those); or sortedness of the
logical sequence on any particular call — the result is a
match or insertion index only if the sequence is sorted,
which the routine itself does not check.

## Verification

Tool versions: GNU objdump/readelf (Binutils 2.42), Python
3.12.3. Reproduce from the repository root:

    python3 research/work-items/RE-001-two-run-search-57f8bb0-115/export_excerpts.py
    python3 research/work-items/RE-001-two-run-search-57f8bb0-115/census.py
    python3 research/work-items/RE-001-two-run-search-57f8bb0-115/verify.py
    python3 tests/test_two_run_search_57f8bb0_115.py

`verify.py` reports ALL CHECKS PASSED (digest, provenance,
manifest, excerpt regeneration byte-for-byte from a fresh
objdump run, every excerpt instruction byte-for-byte against
the raw binary, FDE ranges, census including the per-site
caller-function check against the smallest enclosing FDE,
records, model tests). Model
`tools/two_run_search_57f8bb0_115.py` with
`tests/test_two_run_search_57f8bb0_115.py` (533 checks pass:
the empty return, single-run matches and insertions, the
wrapped head routing, both boundary lengths, the skip-zero
return, two duplicate settlements, a 500-case seeded sweep
against the logical binary-search contract, and the input
guards). Repository-wide gates (`make verify`, `make
test`, `make catalogue-check`) are not claimed: their
baseline is affected by missing LFS material and by the
absence of cargo/rustc on this machine.

## Concrete next step

What the four callers do with the returned index beyond the
pinned gates — in the engine, how the clamped value derived
from `rdx` and the `r15 + 0x408`/`+0x410`/`+0x418` fields
selects the 40-byte row the engine continues with — and
what collection the descriptor's two runs hold on each
call path.
