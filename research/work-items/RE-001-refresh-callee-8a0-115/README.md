# RE-001: map node #115 stats-snapshot refresh 0x5eef8a0

Task ID: RE-001 (node #115 function map). Bounded question: what does
the refresh routine at 0x5eef8a0 do end to end — which budget it
computes, how it walks the handler chain, what snapshot it fills,
and how the result is published — and which callers drive it?

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (`artifacts/node/115/hl-node` in `provenance/artifacts.json`).
- Base commit: upstream `main` 05bc2de30.
- Claim status: observed file bytes, selected FDE intervals,
  relocations, instruction shapes and encoded call-site tables;
  inferred field roles, conditional dataflow, arithmetic and state
  transitions; actual runtime values, handler identities and full
  execution remain unresolved.
- Scope included: the refresh routine 0x5eef8a0 (FDE
  0x5eef8a0..0x5eefd49, 1193 bytes), its shared exception-cleanup
  fragment (own FDE 0x5eef854..0x5eef89d), the snapshot filler
  0x5eef380, the string-move helper 0x5eebb20, the produce identity
  0x5d427e0, the +0x70/+0x78 chain identities 0x5d2efc0/0x5d2ef10,
  the +0x80/+0x88 constant identities 0x5d3ef70/0x5d3ef80, the pid
  wrapper 0x60d5e80, the range functions 0x5eeb290/0x5eeb750, the
  record helpers 0x5eee520/0x5eee560/0x5eee570, the handler walker
  0x5d4d490, the three direct callers and the two snapshot
  consumers (FDE ranges only).
- Scope excluded: the bodies of the consumers 0x5eefda0 and
  0x5ef8360, the internals of the slot +0x98 handler, the slot
  +0xb8 producer and the slot +0x70/+0x78/+0x80/+0x88 producers,
  and every other routine in the binary.

## Reproduce

From the repository root:

```sh
python3 research/work-items/RE-001-refresh-callee-8a0-115/export_excerpts.py
python3 research/work-items/RE-001-refresh-callee-8a0-115/census.py
python3 research/work-items/RE-001-refresh-callee-8a0-115/verify.py
python3 tests/test_refresh_callee_8a0_115.py
```

`verify.py` prints `ALL CHECKS PASSED` on success. The excerpts
were produced with GNU objdump 2.42, e.g.

```sh
objdump -d --start-address=0x5eef8a0 --stop-address=0x5eefd49 work/hl-node-115.bin
```

Mnemonics such as `endbr64` in the excerpts are genuine
instructions present in the target binary, not placeholders: every
excerpt line is verified byte-for-byte against the raw binary by
`verify.py`, and the raw disassembly text is stored unmodified.

## Observations

The refresh routine takes an owner pointer in `rdi` and a flag byte
in `sil`. It reads a subobject pointer from `owner+0x128`; when
that pointer is null it returns at once. Otherwise it locks the
mutex at `subobject+0x160` for the whole refresh, computes a
budget, walks a handler chain, and either fills the snapshot at
`subobject+0x188` (progress path) or bumps a no-progress counter
(no-progress path). It then locks the second mutex at
`subobject+0x0`, copies the 312-byte snapshot to the published
location at `subobject+0x28` (the string member is assigned, not
bitwise copied), unlocks both mutexes and returns nothing.

Budget (unsigned 64-bit arithmetic). The flag selects two
regimes: `sil == 0` is slow (500 ns per unit, 180,000,000 ns
cap); `sil != 0` is fast (10 ns per unit, 10,000,000 ns cap).
When the low counter at `subobject+0x2c0` is below the high
counter at `subobject+0x2c8`, the allowed staleness is
`min(cap, (high - low) * per_unit)`; otherwise it is the cap.
The derivation is pinned instruction by instruction: `cmp $0x1,
%sil` followed by `sbb` gives -1 for `sil == 0` and 0 otherwise;
`and $0x1ea` then `add $0xa` gives 500 vs 10, and the second
`sbb`/`and $0xa21fe80`/`add $0x989680` gives 180,000,000 vs
10,000,000.

Handler-chain walk. The head link is at `subobject+0x2d8`; each
link's vtable slot `+0x98` is compared against the walker
`0x5d4d490`, whose address the `R_X86_64_RELATIVE` record at
`0x64ecf80` installs in the global at `0x64ecf80` (file bytes
zero). While the slot matches, the walk follows `link+0x20`;
the first mismatching link's slot is called with `(rdi = link)`,
or the fourth link's slot unconditionally. The walker itself is
pinned whole in `walker.txt` (it walks `+0x20` links comparing
slot `+0x98` the same way and tail-jumps to the first differing
link's slot or the ninth link's slot).

Progress check. After the slot call returns value `V`, the
routine computes `delta = V - counter_hi` (unsigned). When
`delta < allowed` it stores `V` at `counter_lo` and fills the
snapshot; otherwise it calls `0x5eee570` (which increments the
no-progress counter at `snapshot+0x124`) and publishes the
existing snapshot. On the progress path the filler runs, then
the produce chain runs, then the slot is called a second time
and its return is stored at `counter_hi` and at
`snapshot+0x130` via `0x5eee560`.

Snapshot fill (0x5eef380, called with `(snapshot,
*(subobject+0x2d0), *(subobject+0x2d8))`). The filler zeroes
the snapshot header (`+0x00..+0x20`) and body
(`+0x40..+0x138`, copied from a zeroed stack scratch), resets
the string at `+0x20` to empty (string move plus `_M_dispose`),
writes the sequence at `+0x120` (old value + 1) and the chain
head at `+0x128`, then builds the name string
`name@0x<ptr>#<pid>` through an `ostringstream`: the name comes
from virtual slot `+0x10` of the object at `subobject+0x2d0`,
`"@"` is the single byte `0x40` at file address `0x43f946`,
the pointer is that same object, `"#"` is the single byte
`0x23` at file address `0x4393ae`, and the number is the return
of `0x60d5e80`, which is `getpid()` sign-extended. The filled
string is moved into `snapshot+0x20` with `0x5eebb20`.

Produce chain (slot `+0xb8`). Before the produce call the
routine builds a 32-byte record at `rsp+0x10` with `0x5eee520`:
`{ptr = snapshot, 0x5eeb290, 0x5eeb750}`. It then walks the
`+0x38` chain starting at the object at `subobject+0x2d0`,
comparing each link's slot `+0xb8` against the identity
`0x5d427e0` (installed by the `RELATIVE` record at `0x64ece08`);
the first differing link's slot is called with `(rdi = link,
rsi = &record, rdx = &0x100)`, or the tenth link's slot
unconditionally. The identity itself walks the same chain and
tail-jumps to the first differing slot.

Fill chains (slot `+0x70`, `+0x78`, `+0x80`, `+0x88`). Each
starts at the object at `subobject+0x2d0` and walks `+0x38`
links (at most five links for `+0x70`/`+0x78`); the first link
whose slot differs from the identity is called with
`(rdi = link)`, or the last link's slot unconditionally. The
results land at `snapshot+0x00` (`+0x70`, identity
`0x5d2efc0`), `snapshot+0x08` (`+0x78`, identity `0x5d2ef10`),
`snapshot+0x10` (`+0x88`, identity `0x5d3ef80` returning 0)
and `snapshot+0x18` (`+0x80`, identity `0x5d3ef70`
returning -1).

Record helpers. `0x5eee520` builds the produce record;
`0x5eee560` stores the produced value at `snapshot+0x130`;
`0x5eee570` increments the counter at `snapshot+0x124`.
The range functions stored in the record are `0x5eeb290`
(increments a bucket counter selected by `*(r8)+0x20`, default
index 13, and adds `*(rcx)` to the bucket's `+0x40` field) and
`0x5eeb750` (on `edx` 0 stores the global at `0x64cc428`, on 1
stores `rsi`, on 2 stores `*(rsi)`, otherwise returns 0).

Exception cleanup. The three landing pads at the end of the
main routine jump into the shared cleanup fragment
`0x5eef854..0x5eef89d` (its own FDE): it calls the destructor
held at `rsp+0x20` with `(rdi = r14, rsi = r14, edx = 3)` when
non-null, unlocks the refresh mutex, checks the stack canary,
and resumes unwinding with `_Unwind_Resume`. A mutex-lock
failure throws `__throw_system_error`; a canary mismatch calls
`__stack_chk_fail`.

Callers. Exactly three direct calls (exhaustive executable-LOAD
scan, objdump-confirmed): `0x5d7e0d7` in the stats-emit caller
`0x5d7dfc0..0x5d7e627` (pinned in open PR #3037; it passes
`(node+0x8d8, 0)`, i.e. the slow budget, once per flagged
version node), `0x5ef03d5` in `0x5ef0390..0x5ef0608`, and
`0x5ef9565` in `0x5ef9520..0x5ef9760`. Both new callers first
check `*(rdi+0x128)` is non-null, pass the inverted low bit of
their own flag argument (`xor $0x1,%edx`), then lock the
publish mutex, copy the published snapshot to a stack buffer
(the same 312-byte copy shape, string assigned), unlock, and
hand the copy to a consumer (`0x5eefda0` with `*(owner+0x780)`
for the first, `0x5ef8360` for the second), returning 1 — or
return 0 at once when the subobject is null.

## Inferences

- The two counters at `subobject+0x2c0`/`+0x2c8` behave as a
  consumed value and a latest-observed value: the entry gap
  sizes the budget, the slot return is compared against the
  high counter, and the progress path advances both.
- The snapshot at `subobject+0x188` is a working copy and the
  one at `subobject+0x28` is the published copy: the refresh
  writes the working copy under the refresh mutex and copies it
  to the published location only while holding the publish
  mutex, which is also the mutex the two new callers lock to
  read it.
- The callers' inverted flag means their flag 1 selects the
  fast budget and their flag 0 the slow budget.
- The name string `name@0x<ptr>#<pid>` identifies the snapshot
  by the producing object's name, address and process id.

## Unknowns

- What the owner, the subobject, or the snapshot fields denote
  beyond the pinned offsets.
- What the slot `+0x98` handler, the slot `+0xb8` producer, or
  the slot `+0x70`/`+0x78`/`+0x80`/`+0x88` producers compute.
- What the consumers at `0x5eefda0` and `0x5ef8360` do with the
  copied snapshot (their bodies are not pinned here).
- What the range functions at `0x5eeb290` and `0x5eeb750`
  denote beyond their pinned arithmetic.
- The exact throw-site mapping of the three landing pads in the
  main routine.
- Behaviour on a null owner, a chain that ends before a
  dispatch, or a mutex lock failure (the lock failure throws;
  the model raises instead).
