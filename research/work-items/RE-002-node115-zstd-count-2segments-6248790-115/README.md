# RE-002-node115-zstd-count-2segments-6248790-115

Bounded reconstruction of one vendor routine in the pinned node #115 artifact.

| | |
|---|---|
| artifact | `artifacts/node/115/hl-node` |
| SHA-256 | `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` |
| symbol | `ZSTD_count_2segments` (C linkage, no mangling) |
| member | `7c9960efb53c0b35-zstd_lazy.o` |
| rlib / crate | `liblibzstd_sys-c8c5b6f4c7c3aee0.rlib` / `zstd-sys` |
| versions in the bundle | `2.0.15+zstd.1.5.7`, `2.1.2+zstd.1.5.7` |
| window | `0x6248790..0x624899a` (522 bytes, 150 instructions, one `.eh_frame` FDE) |
| body | `240b4390c750b88bffb838623b0da0b2168f950182ba9b4567817fb0eea41ff5` (raw-equal, 0 relocations, 3 identical source objects) |

`ZSTD_count_2segments` counts how many bytes an input cursor `ip` and a match
cursor `match` agree on, where `match` points into the *dictionary tail* that ends
at `mEnd`. If both cursors reach `mEnd` while still agreeing, the match cursor
wraps back to `mStart` and counting continues against the start of the current
block. The routine returns the number of **input** bytes matched, and it writes
nothing at all.

```
rdi = ip     rsi = match     rdx = iEnd     rcx = mEnd     r8 = mStart
```

| phase | what happens | exit |
|---|---|---|
| 1 | `vEnd = min(iEnd, ip + (mEnd - match))`; count the agreeing bytes of `(ip, match)` below `vEnd` | first difference → return `len1` |
| wrap | the cursors reached `mEnd` (`match + len1 == mEnd`) | otherwise `len1` is returned |
| 2 | count the agreeing bytes of `(ip + len1, mStart)` below `iEnd` | first difference or `iEnd` → return `len1 + len2` |

### Seven build-specific details, each anchored to an instruction

`semantics.tsv` holds 40 anchors (claim, address, size, bytes, decoded
instruction, note); `verify.py` and the tests re-read every anchor's bytes from
the digest-verified artifact and re-decode them with Capstone.

1. **The bound is an UNSIGNED minimum.** `cmovbe %r9,%rdx` at `0x62487a4` picks
   `iEnd` when `iEnd <= ip+(mEnd-match)` as an unsigned comparison, so a pointer
   with bit 63 set is never treated as negative. The test
   `test_the_bound_uses_an_unsigned_comparison` runs a geometry that straddles
   bit 63 (timestamps: `iEnd` below it, `ip+(mEnd-match)` above): the binary
   answers 3, the unsigned answer, while a signed model would take the wrapped
   value and count 11.
2. **The first differing byte comes from `tzcnt`, not `bsf`.** Four sites
   (`0x62487e1`, `0x624881a`, `0x624889b`, `0x624894f`); each is preceded by a
   `cmp`/`je`/`jne` on the same two words, so the zero input that would
   distinguish `tzcnt` from `bsf` cannot occur - but the zero-safe BMI1
   instruction is the one the compiler chose. `verify.py` asserts that no `bsf`
   appears in the window.
3. **Every fast loop is guarded by a narrowed bound.** The 8-byte loop needs
   `ip < vEnd-7` (`0x62487a8`/`0x62487af`), the dword tail `cursor < vEnd-3`
   (`0x6248836`) and the word tail `cursor < vEnd-1` (`0x624884a`), so no read
   crosses `vEnd`; phase 2 repeats the shape against `iEnd-7` (`0x62487fb`). A
   `vEnd` below 7 would make `vEnd-7` wrap to a huge value and the unsigned
   `jae` would then **not** be taken, so control would enter the 8-byte loop at
   `0x62487b1` instead of the byte tail - recorded as an inference, since a real
   heap address is never below 7. (An earlier revision of this packet stated the
   opposite direction; the 2026-11-10 review caught it.)
4. **The byte tail advances by `sete`.** `movzx (%r11),%ebx` /
   `cmp (%rax),%bl` / `sete %al` / `add %r11,%rax` (`0x6248880`-`0x624888c`)
   add 1 on agreement and 0 otherwise, which is exactly what stops the tail at
   the first difference.
5. **The return is the input-side length.** Every exit computes `cursor - ip`
   (`0x62487ec`, `0x6248868`, `0x62488e8`), and the phase-2 exits use the `ip`
   already advanced by `len1` at `0x62487f8`. The test
   `test_the_return_is_the_input_side_length_only` moves `mStart` (8 → 200) and
   the answer does not change, so no match-side distance is involved.
6. **Phase 2 has its own cursors.** `r8` (mStart) is untouched by phase 1 and is
   phase 2's only match-side cursor; `r10` holds `mEnd` for the wrap tests at
   `0x62487f3` and `0x624886f` and is then reused as a scratch word
   (`mov (%rdx),%r10` at `0x6248944`).
7. **The routine writes no caller memory.** No instruction in the window has a
   memory destination, and the access capture over the whole sweep records loads
   only, of widths 1, 2, 4 and 8, all inside the two modelled regions. The only
   memory writes are the two callee-saved spills - `push %rbp` (`0x6248796`)
   and `push %rbx` (`0x624879d`) - matched by four pops (`0x6248825`/`0x6248826`
   on the first return path, `0x6248874`/`0x6248875` on the second). `verify.py`
   pins both the empty explicit-store set and the two pushes, because the store
   capture alone cannot see a push (the emulator models it on its own stack).

Two further facts about the window itself:

* There is **no `endbr64`**: this is a static function with no CET landing pad,
  and the four bytes immediately below the window are `cc cc cc cc` (int3
  padding), which confirms `0x6248790` is a real function start rather than a cut
  into a larger body.
* objdump prints 153 instruction lines for this window; three of them
  (`0x624882f`, `0x624887e`, `0x624892d`) are the trailing byte(s) of an over-long
  padding nop with no mnemonic. The packet's instruction stream folds those bytes
  into the instruction above, giving 150 instructions whose bytes concatenate to
  exactly the 522-byte window.

### The caller census

56 direct calls, no tail jumps, in **12 caller FDEs** (the routine is called from
a few very large functions). Every site is validated at an instruction boundary
with Capstone and attributed to its enclosing FDE.

| consumer | sites | first use | meaning |
|---|---|---|---|
| `arithmetic` | 44 | `add`/`sub`/`lea` on `rax` | folded into a running total, a length, or an address base (9 sites read it as `lea rX,[rax+4]`) |
| `register-copy` | 12 | `mov`, e.g. `mov r10, rax` | kept in another register and used later |
| *discarded* | **0** | — | no site ignores the value |

`records.json` records `direct_calls: 56`, `sites_reading_the_return: 56`,
`discarded_sites: 0` and a `value-returning` contract; `verify.py` re-derives the
consumer counts from `caller_use.tsv`, pins the nine sites whose first read is a
memory base (`lea rX,[rax+4]`) and asserts that every row's first use names a rax
register. (The first version of this census classified nine rows wrongly -
`classify_rax_use` could not see `%rax` as the base of a memory operand - and the
2026-11-10 review found it; the corrected counts below are the reviewer's
independent re-derivation as well as the tool's.)

### Evidence

| file | what it holds |
|---|---|
| `main.txt` | raw `objdump -d` excerpt of the whole routine |
| `frames.txt` | the one `.eh_frame` entry, `pc=0000000006248790..000000000624899a` |
| `relocations.txt` | no relocations; the raw-equal body digests |
| `callers.tsv` | the 56 call sites and their enclosing FDEs |
| `caller_use.tsv` | per site: consumer class, distance, the first use, what follows |
| `functions.tsv` | empty: the routine calls nothing |
| `semantics.tsv` | 40 anchors binding every claim to an instruction |
| `cases.tsv` | the 300-case ledger (60 per family, boundary rows verbatim) |
| `records.json` | bound context, register roles, census, observations/inferences, unknowns |
| `census.py` | regenerates the census tables from the artifact |
| `export_excerpts.py` | regenerates `main.txt` |
| `semantics.py` | regenerates `semantics.tsv` |
| `verify.py` | the packet's self-check |
| `MANIFEST.sha256` | SHA-256 of every packet file, plus the model and the tests |

Observations are separated from inferences in `records.json`; the unknowns list
includes the reachability of individual call sites, whether every caller keeps
the pointer invariant, and the real dictionary geometry.

### Validation

Run at the branch head, with the tree otherwise clean:

```
python3 research/work-items/RE-002-node115-zstd-count-2segments-6248790-115/verify.py
  -> verify OK: 16 manifest rows, 56 callers / 56 consumers
     {'register-copy': 12, 'arithmetic': 44}, 40 claim anchors,
     model + 300-case ledger {'prefix': 60, 'wrap': 60, 'wrap_iend': 60,
     'empty_tail': 60, 'iend_first': 60} + excerpt (150 instructions, body
     240b4390c750..., 2400-case sweep)
python3 -m unittest discover -s tests -p test_zstd_count_2segments_6248790_115.py
  -> Ran 32 tests, OK
make catalogue-check   -> Catalogue and progress tables match pinned inputs.
make verify            -> Verified 3728 evidence-packet manifests and 29769 entries
```

The model is a closed form **plus** an emulator that executes the routine's own
decoded bytes and raises on any instruction it does not implement; the two agree
on all 2,400 sweep cases, all 300 committed ledger rows, and a 3,000-case
random-content differential. Meeting this routine required three machinery
changes, each policed by the differential:

1. `tzcnt` (BMI1) is implemented with its zero behaviour (the operand width),
   not as `bsf`;
2. `cmovbe` and `sete` are implemented with the flags they read;
3. `push`/`pop` are modelled as a real stack, and the model asserts the pushes and
   pops balance - a fourth test asserts each of the two return paths restores
   both callee-saved registers.

The tests also pin the guards' narrowed bounds, the `sete` advance, the
distance-independence of the answer, the absence of any store, and the read
bounds over every boundary case.

### Limits

The **zstd revision is not pinned** by this window: the bundle records
`zstd-sys` `2.0.15+zstd.1.5.7` and `2.1.2+zstd.1.5.7`, and this body is
byte-identical in both. Three identical source objects exist; only `0x6248790` is
bound here. Nothing was executed from the vendor image: the captured node was
parsed and disassembled only, and no source build is claimed. The caller invariant
(`match >= mStart`, `mEnd` inside the tail, room for phase 2 to read forward) is
inferred from the absence of checks, not verified at the call sites.

Provenance: `zstd-sys`/zstd is public (BSD-3-Clause / MIT). No unlicensed inferred
code is copied; the new files are MIT under the root license.
