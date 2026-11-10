# RE-002 — node #115 zstd `BIT_reloadDStream_internal` at 0x628f710

Bounded reconstruction of one vendor routine inside the pinned node artifact —
zstd's bitstream renormalisation, the step that slides the 64-bit reader window
forward only as far as the stream has actually been consumed.

| field | value |
|---|---|
| artifact | `artifacts/node/115/hl-node` |
| artifact SHA-256 | `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` |
| symbol | `BIT_reloadDStream_internal` (C linkage — no mangling) |
| member | `865a32d3ef5dbaad-huf_decompress.o` |
| rlib | `liblibzstd_sys-c8c5b6f4c7c3aee0.rlib` |
| crate / versions | `zstd-sys` / `2.0.15+zstd.1.5.7`, `2.1.2+zstd.1.5.7` |
| window | `0x628f710..0x628f732` (34 bytes, 12 instructions) |
| FDE | `pc=000000000628f710..000000000628f732` |
| body key | `target_body_sha256 == source_body_sha256` (`38e87a35…39`), `raw_equal`, 0 relocations, 3 identical source objects |
| form | leaf: no calls, no relocations, **no `endbr64`** (never an indirect-branch target) |

## Question

What does the 34-byte leaf routine at `0x628f710` do to a stream structure,
what does it return, and what does it require of its caller?

## Answer

All twelve instructions:

```
0x628f710  mov 0x8(%rdi),%edx    edx = bitD->bitsConsumed        (u32 at +0x08)
0x628f713  mov 0x10(%rdi),%rax   rax = bitD->ptr                 (ptr at +0x10)
0x628f717  mov %edx,%ecx         ecx = bitsConsumed  (zero-extends)
0x628f719  and $0x7,%edx         edx = bitsConsumed & 7      -> the new bitPos
0x628f71c  shr $0x3,%ecx         ecx = bitsConsumed >> 3     -> whole bytes
0x628f71f  mov %edx,0x8(%rdi)    bitD->bitsConsumed = bitPos
0x628f722  sub %rcx,%rax         rax = ptr - whole bytes     -> moves BACKWARD
0x628f725  mov %rax,0x10(%rdi)   bitD->ptr = rax
0x628f729  mov (%rax),%rax       rax = *(u64*)rax            MEM_readLEST
0x628f72c  mov %rax,(%rdi)       bitD->bitContainer = rax    (8 bytes at +0x00)
0x628f72f  xor %eax,%eax         return the constant 0
0x628f731  ret
```

In words: split `bitsConsumed` into whole bytes (`>> 3`) and a sub-byte remainder
(`& 7`); rewind the byte pointer by the whole bytes; keep the remainder as the
new `bitsConsumed`; reload the whole 64-bit container from the rewound pointer;
return 0. `semantics.tsv` anchors each step to the instruction that carries it
(12 anchors, re-decoded from the digest-verified artifact by `verify.py` and the
tests).

### Five build-specific details

1. **The remainder survives, the whole bytes are spent on the rewind.** Only
   `bitsConsumed & 7` is written back (0x628f71f), so after the call
   `bitsConsumed ∈ [0,7]`. `mov %edx,%ecx` (0x628f717) zero-extends into the
   64-bit register, so the rewind is an *unsigned* division by 8 of a 32-bit
   field and can never go negative — a signed shift or a sign-extending copy
   would rewind by a different amount for values ≥ 0x80000000 (the ledger keeps
   `0x80000000` and `0xffffffff` verbatim).
2. **The pointer moves backwards, not forwards.** `sub %rcx,%rax` from the
   current `ptr` re-reads bytes that were already delivered. This is what makes
   the reader window overlap the buffer: renormalisation slides the window
   forward exactly as far as the stream advanced, so the same bytes are read
   again together with the new ones.
3. **The reload is one unconditional 8-byte little-endian load that REPLACES the
   container.** `mov (%rax),%rax` then `mov %rax,(%rdi)`: no shift, no OR with
   the previous bits, no byte-wise merge. A test asserts the decoded run's whole
   access set: three loads (4 bytes at `+0x08` for `bitsConsumed`, 8 bytes at
   `+0x10` for `ptr`, and 8 bytes **at the rewound pointer** for the container)
   and three stores (4, 8 and 8 bytes at `+0x08`, `+0x10` and `+0x00`).
4. **The return value is the constant 0.** `xor %eax,%eax` is the only path: the
   body contains **no comparison and no conditional branch at all** (a test
   asserts that over the decoded stream), so it cannot report any other status.
   Consistently, the caller census finds that **all 16 call sites discard the
   returned value**.
5. **There is no bounds check.** Nothing compares the pointer with `limitPtr`
   (`+0x18`, never touched by this body) or with `start` before the rewind and
   the 8-byte read, so "the rewound pointer still has 8 readable bytes" is
   entirely the caller's obligation. The name says *internal*; this is the
   unchecked path.

Struct layout pinned by the offsets: `bitContainer` `+0x00` (8 bytes),
`bitsConsumed` `+0x08` (u32), `ptr` `+0x10` (pointer). The window also does not
begin with `endbr64`, which is consistent with an internal static function that
is never an indirect-branch target — unlike the sibling varint windows in this
binary.

## Caller census

16 direct calls, 0 tail jumps, in **6 caller FDEs**, each validated at the
instruction boundary with Capstone and attributed to its enclosing FDE.

| consumer | sites | first use | continuation |
|---|---|---|---|
| `overwritten` | 10 | `mov rax, [rsp+0xd0]`, `lea rax, [rip-…]` | rax clobbered by an unrelated value before the status could be read |
| `dead` | 6 | — | never read inside the enclosing FDE |
| *reads the return* | **0** | — | — |

That is the census side of detail 4: a routine returning a constant has no
caller that branches on it. `records.json` records `sites_reading_the_return: 0`
and `discarded_sites: 16`, and `verify.py` re-derives both from `caller_use.tsv`,
so the prose cannot drift from the table.

## Evidence in this directory

| file | what it holds |
|---|---|
| `main.txt` | the raw `objdump -d` excerpt for the window (12 instructions) |
| `frames.txt` | the `.eh_frame` FDE `0x628f710..0x628f732` |
| `relocations.txt` | no relocations; the raw-equal body digests |
| `callers.tsv` | the 16 call sites with their enclosing FDE bounds |
| `caller_use.tsv` | the consumer class, distance, use and continuation per site |
| `functions.tsv` | empty: this routine calls nothing |
| `semantics.tsv` | 12 claim anchors (claim → address → bytes → decoded instruction) |
| `cases.tsv` | 300 reviewable cases (75 per family) with the bits consumed, bytes rewound, new bit position, rewound pointer, loaded container and status |
| `records.json` | observations vs inferences, the derived census, the layout and the unknowns |
| `census.py` | regenerates `callers.tsv`, `caller_use.tsv`, `frames.txt`, `relocations.txt` |
| `semantics.py` | regenerates `semantics.tsv` from the artifact |
| `export_excerpts.py` | regenerates `main.txt` from the artifact |
| `verify.py` | re-checks the manifest, the anchors, the census and the model |
| `MANIFEST.sha256` | every file here, plus the model and its tests |

## Validation

* `python3 research/work-items/RE-002-node115-zstd-bit-reload-dstream-internal-628f710-115/verify.py`
  → `verify OK: 15 manifest rows, 16 callers / 16 consumers {'dead': 6,
  'overwritten': 10}, 12 claim anchors, model + 300-case ledger {'sub_byte': 75,
  'aligned': 75, 'mixed': 75, 'extreme': 75} + excerpt (12 instructions, body
  38e87a35b78b…, 2400-case sweep)`.
* `python3 -m unittest discover -s tests -p test_bit_reload_dstream_internal_628f710_115.py`
  → 27 tests, `OK`.
* `tools/bit_reload_dstream_internal_628f710_115.py` holds a closed-form model
  **plus** an emulator that executes the routine's own decoded bytes on a small
  machine model that raises on any instruction it does not implement. The two
  agree on all 2,400 sweep cases (four families: sub-byte counts, whole-byte
  counts, mixed values and extreme values up to `0xffffffff`), on all 300
  committed ledger rows, and on 3,000 random `(bits, word)` pairs.
* The emulator is seeded with the 8-byte word at the address the *model*
  predicts: if the routine rewound to a different address it would read
  uninitialised memory and the machine would raise, so model/emulator agreement
  is a real check rather than a restatement of the same formula.
* The tests also pin the split identity (`bits_after == bits & 7`,
  `bytes_consumed == bits >> 3`), the constant status, the exact access set, and
  the absence of any comparison or conditional branch in the decoded body.
* The excerpt's concatenated bytes are asserted equal to the binary's own bytes
  for the window, in both `verify.py` and the tests.

## Limits

* Static only: the artifact is never executed and no source build is claimed.
  The emulator is deliberately narrow and raises on anything it does not model.
* The caller's obligation (that the rewound pointer still has 8 readable bytes,
  and that `bitsConsumed` is a sane value for the current window) is **inferred**
  from the absence of checks in the body; it is not verified against any caller,
  and whether a sibling body performs the checks this one omits is not
  established here.
* The `BIT_DStream_status` interpretation (0 = unfinished) is an inference from
  the constant and the callers' indifference, not from a symbol.
* The exact zstd release is not pinned: the body is raw-equal across the
  candidate versions and reads no version string.
* Which of the 16 call sites are reachable for a given frame is not
  characterized, and the body is byte-identical in 3 identical source objects
  with only `0x628f710` bound.

## Provenance

`zstd-sys` / zstd is public (BSD-3-Clause / GPL-2.0 dual-licensed). Nothing
inferred is copied from unlicensed sources, and the files added here are MIT
under the root license. No private keys, tokens or live datasets are included.
