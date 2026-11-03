# RE-004: node115 quantity-change bookkeeping and a clear-to-zero caller

Component: assets/quantities. Target: Linux x86-64 node #115, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
This independently authored static packet resolves one bookkeeping question;
it does not implement Rust quantities or claim a component gate.

Question: how does the quantity-associated change hook update a zero/nonzero
occupancy word, an optional absolute-value total, and a notification call;
and where does one actual caller place its clear operation relative to them?

## Measured evidence and coordinates

- Change hook: complete FDE `[0x4206f70,0x4207104)`, 404 bytes.
- One direct caller: complete FDE `[0x4205de0,0x4205f44)`, 356 bytes.
- Total export denominator: **760 bytes /220 native instructions**. This is
  exported evidence, not recovered or source/target-matched implementation.

Addresses are original ELF virtual addresses. `records.json` retains unique
file mappings, body hashes, raw FDE/CIE, LSDA addresses, every measured direct
and RIP-relative call and its dynamic relocation. Independent Python unwind
parsing and GNU readelf agree on each entire extent. Native instruction bytes
cover every exported byte contiguously. FDE bounds are not semantic closure.
At `0x420708b`, a real LEA names Location `0x6482770`; its actual RELATIVE
relocation resolves the full `l1/src/qtys/impl_sz.rs:39:1` string and metadata.
This associates the body with quantities without inventing its original name.

The local incoming convention retains old raw word RSI in R12, new raw word
RDX in RBX, and first argument RDI in R14. RCX addresses the occupancy word;
R8 gates an optional helper-owned accumulator path; R9 points at a descriptor.
Valid native objects and normally returning ABI-preserving helpers are assumed.
No stable public ABI, quantity unit or original struct identity is claimed.

## Zero/nonzero occupancy relation

Before optional accumulator lookup, the following branches update `[RCX]`:

| Old word | New word | Local counter operation |
| --- | --- | --- |
| zero | nonzero | unsigned saturating increment |
| nonzero | zero | decrement only if the counter is nonzero |
| zero | zero | no local store |
| nonzero | nonzero | no local store |

At `0x4206fbe`, INC forms the incremented word, MOV initializes the fallback
register to all ones, and CMOVNE selects the increment only if it is nonzero.
MOV does not change flags. Thus UINT64_MAX remains UINT64_MAX, not zero.
The separate decrement at `0x4206fb9` is reached only when old!=0, new==0 and
counter!=0. Zero stays zero. Sign alone does not change these occupancy tests.
The original counter's capacity and synchronization remain unknown.

## Optional absolute-value total and ordered stores

R8==0 at `0x4206fd2` skips this path. Otherwise `0x3ccaf90` and `0x3f15db0`
resolve a pointer returned in RAX. Their lookup, lifetime and failure semantics
are not measured; this packet does not assume arbitrary R8 is a valid index.

For old/new signed words other than INT64_MIN, NEG/CMOVS produces their
nonnegative absolute values. A negative result after that sequence, precisely
the INT64_MIN pattern, selects the diagnostic-helper path at `0x42070df`.
No normally returning rejoin exists inside the exported body after that call;
its actual nonreturn/unwind behavior remains unclosed.

The normal-return local arithmetic/store sequence is:

1. Read the signed total, subtract abs(old), and branch on signed overflow.
2. On the overflow arm select the signed endpoint and call relocated slot
   `0x64e4ea8`. If that helper returns, rejoin and store the selected value at
   `0x4207010`. On the ordinary arm store the subtraction result there.
3. Only after that store, form abs(new). Thus the old contribution has already
   been removed locally when the new-word diagnostic route is selected.
4. Add abs(new), branch on signed overflow, and select the signed endpoint.
   The overflow arm calls the same relocated slot before its final store;
   if the helper returns, the clamped value is written at `0x42070d6`.

Conditioned on the helper returns and valid signed absolute inputs, the
relation is `sat_add(sat_sub(total,abs(old)),abs(new))`. It is **two-stage
saturation**, not clamping a single combined expression. For example, total
INT64_MIN with old=new=INT64_MAX produces -1 under the two-stage arithmetic,
whereas clamping the combined mathematical expression would leave INT64_MIN.
This is an interpretation of the measured integer instructions, not a captured
execution result or a claim that those boundary states are valid live inputs.

With nonnegative absolute operands, subtraction overflow can only clamp toward
INT64_MIN, and addition overflow toward INT64_MAX. The raw code's endpoint
construction is retained, rather than assuming a wrapping or trapping API.
The diagnostic slot is not named a harmless logger: divergence, panic or unwind
would prevent the described later normal-return stores. No atomic update,
transaction guarantee or complete helper side-effect closure is claimed.

## Notification and concrete clear caller

After accumulator handling, `0x4207031..0x4207043` selects a callback only when
descriptor word `+0x18` is nonzero **and old != new**. It copies 20 descriptor
bytes and calls `0x4483500` with that copy, R14 and the new word. The callback's
meaning and side effects remain unknown. In particular, a sign flip can keep
occupancy and absolute magnitude unchanged while still selecting this callback.

At `0x4205f01`, the retained caller actually calls `0x4206f70`. Its zero-tag
entry path loads the old word from returned record+0x10. If that word is
nonzero, the caller first writes zero to record+0x10 and clears 16 bytes at
record+0x20. It then joins `0x4205ee0`, prepares descriptor/context arguments,
sets EDX=0 (new word), points RCX at original object+0x20 (counter), forwards
its saved RDX argument in R8, and invokes the change hook. An originally zero
old word reaches that preparation without those record stores. Other record
tags skip the hook. The producing iterator `0x45050e0`, original record types,
collection validity and complete clear/drop semantics are unresolved.

This is one confirmed caller, not an exhaustive call census. It establishes
that this caller's record clear can precede accumulator/notification helper
execution; it does not prove rollback, transactionality or a security defect.

## Reproduce and negative controls

Python3.12.3, GNU binutils2.42; static analysis only:

```sh
python3 research/work-items/RE-004-node115-quantity-bookkeeping/collect.py --output work/quantity-bookkeeping --check
python3 -m unittest discover -s tests -p test_node115_quantity_bookkeeping.py -v
```

The collector authenticates the entire target before native tools or output,
uses a private non-executable copy, agrees on unwind/relocations with readelf,
and checks every claim anchor starts at a decoded native instruction. Native
text exports trim trailing whitespace only AFTER complete byte decoding;
addresses, operands and instruction bytes are unchanged. No target instructions
are evaluated, emulated or executed.

Five focused tests check retained facts, exact regeneration of native exports,
wrong-identity rejection before output, corruption of all 21 anchor groups,
and ten specific counterfactual sites. The latter invert transition/zero
conditions, replace saturating CMOVNE with CMOVE, invert signed-overflow
branches, corrupt the intermediate store, change the notification predicate,
remove the caller's EDX zeroing and change its zero record store to one. These
are evidence-sensitivity controls, not differential source execution.

No Rust implementation, source build, normalization mask, byte-equivalence
claim, live protocol, signing, chain action or component-gate advancement is
included. New analysis/code is independently authored under root MIT; no
unlicensed inferred source was consulted. Next: close accumulator lookup and
notification contracts, establish quantity units and the caller's record schema.
