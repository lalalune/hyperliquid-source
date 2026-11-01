# RE-004-pxpriv-admission-94: PxPriv admission decision in node 94

## Claim status

| Statement | Status |
|---|---|
| PxPriv admits exactly the nonzero values: u64 inputs in `[1, 2^64-1]`, i64 inputs in `[1, 2^63-1]` | Observed: the guard tests in all nine callers implement exactly this rule (see below). |
| i64 rejection is two-step: negatives fail the conversion to an intermediate u64 (converting diagnostic), zero fails the nonzero check (i64 diagnostic) | Observed: distinct branches and distinct diagnostics for the two cases. |
| Narrow inputs are extended then judged by the same 64-bit rule | Observed in family C: sign/zero extension precedes the shared check. |
| The underlying representation is NonZeroU64 | Inference only. The only binary hint is the `NonZeroU64 ... for PxPriv` fragment, which is referenced by three table-referenced functions that are not part of the admission guards (see Out of scope). The nonzero admission is consistent with it, but not proof of it. |
| Upstream parsing imposes no further range bound on admitted values | Unresolved. The guards shown here are the last check before acceptance in these nine callers; an upstream parser could still narrow the set before it reaches them. |
| The three NonZeroU64-fragment functions' triggering condition | Unresolved (see Out of scope). |
| Tags other than 1/2 of the family A/B dispatch | Unresolved: other visitor kinds, not decoded. The non-1/2 arm (`0x2813125`) stores a float-sized value (movsd) with tag byte 3, consistent with an f64 arm, but that is inference only; the sub-parse tag-3 path (cmp rax,3 to the `0x28131af` return-1 block) was not decoded either. |

## Baseline

- Worktree HEAD: `2993e46a0a1cb87fda91cbfb4addc6f158bb0561` (main clone, no upstream sync).
- Target: node #94 only, `artifacts/node/94/hl-node`, 91,774,280 bytes,
  SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Static analysis only. No node execution, no network, no disassembler inside
  the generator (it decodes only branch/call/LEA/GOT-load byte patterns).
- This work item answers the explicit Next question of
  `RE-004-qty-newtype-sign-guards-94`, which excluded "the three PxPriv
  pieces (they use a different multi-step decision)" and asked what exact set
  of i64/u64 inputs each PxPriv caller admits.

## The model

```
visit u64 value v:  v == 0  -> reject, diagnostic "invalid value 0 for PxPriv when visiting u64"
                    v != 0  -> admit
visit i64 value v:  v < 0   -> reject, diagnostic "invalid value {v} for PxPriv converting to
                               intermediate u64 when visiting i64"   (step 1: conversion fails)
                    v == 0  -> reject, diagnostic "invalid value 0 for PxPriv when visiting i64"
                               (step 2: nonzero check fails)
                    v > 0   -> admit
```

Combined admitted set: u64 `[1, 2^64-1]`, i64 `[1, 2^63-1]`. No upper bound
is tested at these guards. The admitted value is stored with tag 9 (the Ok
niche) in family C, and returned with status 0 in families A/B; errors return
status 1 through a shared epilogue.

## Scope

Included:

- The three diagnostic fragments in `.rodata` (piece VA = the `0x0e` length
  byte; literal `"invalid value "`; `c0` marker; suffix):
  - u64: piece `0x1e66a6`, marker `c0 1d`, suffix `" for PxPriv when visiting u64"`.
  - i64: piece `0x1f7a73`, marker `c0 1d`, suffix `" for PxPriv when visiting i64"`.
  - converting: piece `0x1ff8fb`, marker `c0 3c`, suffix
    `" for PxPriv converting to intermediate u64 when visiting i64"`.
- Nine error constructors, one per (family group, diagnostic), in two shapes:
  - Form 1 (families A/B): builds a descriptor `{type-pointer, value, piece}`
    and calls the shared formatter through GOT slot `0x576e040`, then a second
    call (`0x1eba7f0` for the `0x22e4` group, `0x33ddca0` for the `0x3252`
    group). Form 1a (70B) returns `(eax=1, rdx=payload)`; form 1b (62B, u64
    only) returns `rax=payload` and the caller moves it to `r14`.
    GOT type-pointer slot: `0x576e9d0` (converting) vs `0x576ea30` (i64 and
    u64 share it). All three slots are `R_X86_64_RELATIVE` relocations.
  - Form 2 (family C only, 69B): fills the caller-provided out struct by
    calling `0x2aea9d0`, which writes tag byte 6 plus fields at `+0x8/+0x10/+0x18`.
- Nine callers in three families, 27 direct call sites (3 per constructor):
  - A (`0x2812c00`, `0x2813320`, `0x2813af0`; 1733B): text-style parser with
    two tag dispatches (tag 1 -> u64 path, tag 2 -> i64 path, other -> out of
    scope). The second dispatch re-tests the value with the same decision.
  - B (`0x35938d0`, `0x3593fa0`, `0x35947f0`; 1733B): same structure as A.
  - C (`0x2e625e0`, `0x2e957e0`, `0x2ee1ec0`; 896B): binary-reader style with
    ten narrow entries (see below) converging on one shared check.
- Family C narrow entries: u8 (register and stream forms), u16, u32, u64
  (zero-extended, u64 rule); i8 (register and stream forms), i16, i32, i64
  (sign-extended, i64 rule). The i8-stream entry funnels into the 64-bit
  path; the u32 entry tests before its byte swap (zero is unaffected by the
  swap, so the decision is identical).
- Branch inventory (`branches.tsv`): every branch into a guard block, every
  fall-through entry, every constructor call, and the dispatch rows — 219
  rows across the nine callers, each re-verified by the generator from the
  instruction bytes at the recorded source address.

Excluded (observed but not claimed, or not decoded):

- The `NonZeroU64 ... for PxPriv` fragment (`0x1ebe57`, `0x0a` length byte +
  `"NonZeroU64"` + `c0 0b` + `" for PxPriv"`). It IS referenced: three LEAs
  (`0x23943f2`, `0x32853e2`, `0x45ac832`) in three 141-byte functions
  (`0x23943d0`, `0x32853c0`, `0x45ac810`), each passing it to the shared
  formatter slot `0x576e040` and then dispatching through a vtable call.
  Those functions have no direct call from any admission caller and are
  reached through 24-byte-spaced table entries (three absolute pointers per
  function). Their triggering condition was not decoded; they are not part
  of the admission decision mapped here.
- Tags other than 1/2 of the A/B dispatch (including the float-sized
  non-1/2 arm and the sub-parse tag-3 path), the parser-loop exit
  that shares the Ok block, and any upstream range narrowing.
- Dynamic reachability: no execution was performed, so which inputs actually
  reach these guards at runtime is not established.

## Copy equivalence

Within each family, the three copies are guard-identical: the full
instruction sequences were compared after relativizing internal branch
targets and resolving absolute call targets, and the guard regions
(dispatch, value tests, error blocks, Ok block, joins) show zero
differences. The only per-copy differences are outside the guards: family C
copies call different float helpers and use different tag-1 string
addresses. The generator re-verifies all 219 branch rows and all 30 narrow
anchors for every copy, so this equivalence is machine-checked, not just
eyeballed.

## Overlap check

No overlap with prior claims: every address in every `evidence.json` under
`research/work-items/` in the main tree and in worktrees `hl-wt-calls123`
through `hl-wt-calls155` was collected (scalar addresses and FDE-range
records) and tested against all 18 FDEs claimed here (9 callers + 9
constructors). Result: 0 hits. The prior packet's 16 constructors and the
three PxPriv pieces are disjoint from this item's sets. This item's topic
also does not overlap any open PR topic found in the upstream scan
(fixed-eight rounding, funding, snapshot, EVM precompile/settlement, and the
other listed items); in particular it reuses nothing from PR #1543's topic,
addresses, tables, or model — only its documentation and verification format
(see below).

## Format note

The documentation and verification format follows the published shape of
PR #1543 (RE-004 fixed-eight float formatting): claim-status table, scope
in/out, reproduce commands, deterministic regeneration, case-table family,
generator plus unit tests with corruption controls. The subject matter,
addresses, tables, and model here are entirely independent; nothing from
that PR's content is reused.

## Reproduce

From the repository root (worktree HEAD above):

```sh
python3 tools/pxpriv_admission94.py --out /tmp/pxpriv-out
python3 -m unittest tests.test_pxpriv_admission94 -v
cd research/work-items/RE-004-pxpriv-admission-94 && sha256sum -c MANIFEST.sha256
```

Branch rows can be cross-checked by hand with objdump, e.g.:

```sh
objdump -d -M intel --start-address=0x2812c00 --stop-address=0x28132c5 \
  artifacts/node/94/hl-node
```

and comparing the branch/call targets against `branches.tsv`. FDE identity
is locked two ways in `evidence.json`: the unwind-index FDE/CIE virtual
addresses and the `objdump --dwarf=frames` section offsets (FDE VA minus the
`.eh_frame` base `0xce1518` equals the section offset; likewise for CIE —
note the A/B callers use the non-zero CIE at offset `0x002dc714`, while the
C callers and all nine constructors use CIE 0).

## Deterministic regeneration

The generator writes only to the directory given by `--out` and embeds no
paths, timestamps, or environment data. Regenerating twice with different
`PYTHONHASHSEED` and `TZ` values produces byte-identical output:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/pxpriv_admission94.py --out /tmp/px-a
PYTHONHASHSEED=99 TZ=Asia/Seoul python3 tools/pxpriv_admission94.py --out /tmp/px-b
diff -r /tmp/px-a /tmp/px-b
```

The unit test `test_packet_files_regenerate_byte_for_byte` asserts the same
for all six generated files, and asserts that `MANIFEST.sha256` covers
exactly the remaining files in this directory with matching hashes.

## Results and limitations

- Denominators, all machine-checked by the generator: 3/3 diagnostic
  fragments, 9/9 constructors (shape, GOT slot, piece LEA, formatter slot,
  second call, FDE/CIE offsets), 27/27 direct call sites, 9/9 callers (3
  call sites each, expected constructor set each), 219/219 branch rows,
  30/30 narrow anchors.
- The generator fails closed: any tampered byte in a recorded pattern, LEA,
  call, branch, constructor shape, or the target digest raises
  `EvidenceError` instead of emitting output. The unit tests exercise six
  such tamper controls and assert each one fails.
- Limitations: static analysis only (no execution, so runtime reachability
  is unproven); the admitted set is the set these guards accept, and an
  upstream parser could narrow it further; non-1/2 dispatch tags and the
  NonZeroU64-fragment functions are explicitly out of scope; the NonZeroU64
  representation link is inference, not observation.

## Next question

What triggers the three NonZeroU64-fragment functions (`0x23943d0`,
`0x32853c0`, `0x45ac810`), and do they ever reject a value that the
admission guards above would accept? Answering that requires decoding their
callers (table-driven, not direct calls) and the vtable method at
`[rax+0x18]` they invoke after formatting.
