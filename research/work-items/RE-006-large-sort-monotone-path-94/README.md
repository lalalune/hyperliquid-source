# RE-006: unsigned monotone ordering path of the pending-key sort core

- Component: `orderbook`; consequential RE-006 follow-on to the scratch
  wrapper, on the same unpublished contribution branch.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: upstream main `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`, plus
  unchanged scratch-contract commit `ed934aad66a65db76164ae67c5ab46de85274e23`.
- Reference pin: `999556f6e0a474b8312db96ec3149e1c44e97c23`; no inferred
  implementation was consulted or copied.
- Claim: an addressed conditional static proof for raw unsigned qwords,
  supported by complete native boundaries and frozen consequence controls.
  No generic sorting, arbitrary-array output, Rust reconstruction, target
  execution, runtime equivalence, matched-byte credit or gate is claimed.

## Concrete gap resolved

The collector sends twenty-one or more projected order keys through the
scratch wrapper to `0x4dbd490`. Previously that core's comparisons and input
mutation were unknown. For `21 <= n <=4096`, this packet establishes:

1. A fully nondecreasing unsigned array, including equal adjacent keys, is
   returned unchanged with no input writes and no lower helper call.
2. A fully strictly decreasing unsigned array is reversed in place, producing
   ascending qwords, then returns without a lower helper call. Four-pair
   SIMD swaps preserve each qword's bits; scalar swaps finish the tail and
   an odd center is untouched.
3. Run discovery includes ties in its nondecreasing arm and stops at a tie
   in its decreasing arm. If a first run has fewer than
   `min(ceil(n/2),64)` elements, control reaches an unresolved fallback before
   any reversal. Accepted prefixes are normalized; subsequent arbitrary-array
   processing remains outside the result.

This result belongs with the scratch packet in one PR: together they establish
the selected call's argument/resource contract and a complete ordering path
actually implemented by its core. Scratch commit `ed934aad` remains intact;
this packet and its focused test are an additive follow-on.

## Reproduce, provenance and freeze

From the repository root:

```sh
python3 -B research/work-items/RE-006-large-sort-monotone-path-94/verify.py \
  --llvm /workspace/.tools/llvm19/usr/lib/llvm-19/bin/llvm-objdump
python3 -O -B research/work-items/RE-006-large-sort-monotone-path-94/verify.py \
  --llvm /workspace/.tools/llvm19/usr/lib/llvm-19/bin/llvm-objdump
python3 -m unittest discover -s tests -p test_large_sort_monotone_path94.py -v
```

GNU Binutils 2.44 and LLVM 19.1.7 are static disassemblers. The verifier pins
the unchanged authored scratch verifier by SHA-256 before importing its ELF,
FDE, native-rendering and CFG helpers. No tooling or imported evidence changes.
Native filename replacement is the only text redaction; byte masks are empty.
Python models operate on synthetic lists and never evaluate captured code.

Before authoring `first_run_model`, 96 explicit fixture recipes/input hashes
and expected results were frozen from the addressed native analysis. The
76 complete-output hashes use an independent unsigned `sorted` oracle;
20 strict-descending tie boundaries have only first-run expectations, with
no fabricated whole-array result. Seventeen actual-operand mutations were
also frozen. The immutable pre-model hashes are enforced:

| File | SHA-256 |
| --- | --- |
| `fixtures.json` | `086d75c7e15d84bd83c9575640b02286fd53b291d390badab30f0054af34b542` |
| `mutations.json` | `e9e6463d91c93b48cf1cde206f2a79ab08418f78f11b1d016331ba1c26169548` |

Author environment: Linux x86-64/glibc 2.41, Python 3.12.14. Authoring:
OpenAI / `gpt-6.1-sol`, `xhigh`, UI `GPT-6.1 Sol Extra High`, Codex cloud;
identity is parent-supplied and user-confirmed. No model-backed app behavior.

## Native boundary and scope

The complete core FDE is `[0x4dbd490,0x4dbdb5e)`, 1,742 bytes / 421
instructions, FDE `0xf4b840`, CIE `0xce1518`, no LSDA. GNU and LLVM agree
on every instruction boundary and byte, without normalization masks. Exact
linked VAs, section-derived file offsets, bytes, FDE/CIE records, all six
calls and the full normal local graph are in `records.json`. Body extent and
input identity do not establish a recovered source symbol.

The full body is retained to validate the selected entry-to-return paths and
to identify excluded branches. The six call sites use two relocated helper
slots; all six are unreachable in the two admitted graphs. Lower helper
internals are unnecessary for these paths and remain unproved.

Premises: the wrapper's ordinary success path supplies the authenticated core;
`n` is in 21..4096; the input is respectively wholly nondecreasing or wholly
strictly decreasing in unsigned u64 order; its `8*n` bytes are readable and,
for reversal, writable; pointer arithmetic is valid/nonwrapping; input and
the core's stack frame do not alias; input remains stable except for the
observed reversal; and there is no abnormal control transfer or external
mutation. Runtime reachability and upstream collection invariants remain
unknown. No price, quantity or economic-unit semantics are assumed.

## Addressed comparator and admission proof

At entry, `0x4dbd4b4` takes its `n <2` return only outside this domain.
`0x4dbd4eb` takes the large-count threshold formula only for `n >=4097`;
that branch is excluded. The selected threshold at stack `+0x18` is
`c=min(n-(n>>1),64)`. Thus `2 <= c <= n` throughout the claim.

The first walk starts with processed count `r12=0`, previous-run word
`r10=1`, and run-stack count `r11=0`. At `0x4dbd570..0x4dbd624`, remaining
count is `n` and is at least `c` and two, so the natural-run scan is reached
without reading the small-input flag or calling a helper.

`0x4dbd64c` and `0x4dbd64f` load the first two **qwords**. The comparison
`cmp rdx,r8` at `0x4dbd653` uses an unsigned `jae` at `0x4dbd656`:

| Route | Extension comparison | Continuing condition | Equality |
| --- | --- | --- | --- |
| Nondecreasing | `cmp rsi,rdi` at `0x4dbd6ac`; `jb` at `0x4dbd6af` exits | next >= previous, unsigned | Continues |
| Strictly decreasing | `cmp rsi,rdi` at `0x4dbd6dc`; `jae` at `0x4dbd6df` exits | next < previous, unsigned | Exits |

Both loops begin at index two, read one qword at that index, then increment
and compare with remaining count. They therefore read exactly the full run
without an out-of-span read. `0x4dbd6e9` sets its length to the remaining
count when the end is reached. The run-length check at `0x4dbd6f1` is strict
`r <c`, so equality is accepted. A complete monotone run has `r=n >=c`.
Nondecreasing full runs take `0x4dbd6fa ->0x4dbd7f7`, bypassing all input
stores. A complete strictly decreasing run enters the reversal.

## Reversal width and tail proof

For accepted decreasing run length `r`, `0x4dbd715` computes
`h=floor(r/2)`. In the complete domain `h >=10`, so `0x4dbd71c` enters the
four-pair loop with `k=h & ~3`. Each iteration of
`0x4dbd750..0x4dbd79b` loads four left qwords and four opposite right
qwords before storing them in swapped/reversed order. For group index `i`,
the destination/source identities are:

```text
left[i..i+4]       <- [old[r-1-i], old[r-2-i], old[r-3-i], old[r-4-i]]
right[r-4-i..r-i]  <- [old[i+3], old[i+2], old[i+1], old[i]]
```

The four `pshufd ...,0x4e` instructions exchange the two 64-bit lanes of
each 128-bit chunk: dword indices `[2,3,0,1]`. Each qword's internal bits
are preserved. Four 16-byte unaligned stores perform four pairs per pass.
Left position advances 32 bytes and the opposite index decreases four.
The loop performs `k/4` passes.

If `h !=k`, `0x4dbd7a2..0x4dbd7e8` swaps qword pairs
`(i,r-1-i)` for `i=k..h-1`, with eight-byte loads and stores. There are
`h-k` pairs, from zero through three. All swapped indices are distinct and
inside the run; the odd center is never addressed by a store. Exactly `2*h`
input qword locations are written. The scalar tail also handles short
accepted descending prefixes; its special two-word edge is outside the
complete-array domain but retained in the full graph.

The four-way loop is exercised by lengths 21..4096, including every tail
count and the 512/513 wrapper boundary. Tests of the independent model use
the frozen full-output hashes, rather than calculating expected output with
the same block/tail loops.

## Terminal marker, no-call and no-write proof

The normalized run is encoded as `2*r+1`: `0x4dbd7ed` after reversal,
or `0x4dbd7fa` on the nondecreasing arm. It is odd and fits in u64 for this
domain. The complete path has these two phases:

1. Initial phase: `r12=0`, `r11=0`, previous run `r10=1`. The scheduling
   arithmetic at `0x4dbd810` receives the new odd `2*n+1`. Its first BSR
   operand is `n*ceil(2^62/n)`, a nonzero value below `2^63` for this domain.
   With `r11 <2`, `0x4dbd847` bypasses all merging and records the run.
   `0x4dbdb03..0x4dbdb09` consumes `(2*n+1)>>1=n` and retains the odd word.
2. Sentinel phase: remaining count at `0x4dbd583` is zero, so
   `0x4dbd586 ->0x4dbd600` sets a zero priority and sentinel word one.
   Now `r11=1`, so `0x4dbd60c` again bypasses merging. At
   `0x4dbdafb`, processed count equals `n`; `0x4dbdb15` tests the retained
   odd run word and jumps directly to the epilogue/RET at `0x4dbdb5d`.

`admitted_monotone_graphs` applies the addressed branch facts to the complete
native graph. Each selected edge must exist in that graph; RET must be
reachable, and all six call sites must be absent. Both first/sentinel choices
and loop/end choices are retained in this finite graph; loop termination and
phase values are proved above, rather than inferred from graph reachability.
This is a conditional manual proof, not symbolic target execution.

Every explicit memory destination on each admitted path is audited. On the
nondecreasing path all are stack destinations; there are no input stores.
On the decreasing path the only non-stack store sites are vector stores
`0x4dbd770`, `0x4dbd775`, `0x4dbd77e`, `0x4dbd789` and scalar stores
`0x4dbd7d7`, `0x4dbd7da`. Synthetic corrupt call/store records are rejected
by these qualifiers. The input/stack nonalias premise is necessary.

## Checks, ownership and limits

Checks and exact outputs are recorded in `checks.json`. Normal and optimized
replay regenerate the four exports; seventeen pre-model operand corruptions
are rejected below whole-target admission. Frozen cases cover unsigned
high-bit crossings, all-equal and repeated keys, strict descending runs,
tie stops on either side of inclusive run admission, SIMD/tail boundaries,
64/65, 512/513 and 4095/4096. Count admission/BSR inequalities are checked
for all 4,076 lengths in 21..4096. These consequence checks do not establish
runtime equivalence. A model refusal outside this domain is its API choice.

Ownership was rechecked against 84 open PR bodies before extending the
scratch work; only predecessor collector PR #1430 named the delegate and it
leaves the inner core unresolved. Final current body hashes and reviewed
relationships are in `overlap.json`. Scratch files and their manifest remain
unchanged. Repository-wide testing remains coordinated; no full-suite or
hosted-CI result is invented.

Unresolved: arbitrary arrays and later runs/merges; n below 21 or above 4096;
the large-count threshold formula; lower fallback helper semantics; overall
sort stability; failure recovery/input preservation; runtime reachability;
independent Rust reconstruction and whole-node equivalence. No component
gate, generated progress or byte-window registry changes.

Next question: recover one fallback/merge helper reached by a first run
shorter than `c`, preserving the observed unsigned equality rules and the
qualified six-argument scratch interface.
