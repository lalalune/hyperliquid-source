# RE-001: CID-labelled two-stage global lookup and opaque output layout

- Component: foundation collections/global lookup. Question: which real node94
  range implements the CID-labelled lookup, how do its two missing-key paths
  differ, and what output layout is actually established by the copy?
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base and unchanged reference pins:
  `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Actual FDE: `0x1405240..0x1405508`, **712 bytes**, file offset `0x1404240`;
  body SHA-256 `9cae55631949d40aa442489b253d07eff3e125c1d80959130b07fbe11e99ee5e`.
- Scope: one complete enclosing function, its observed searches, output stores,
  helper/source/format callback bindings and unresolved edges. No full global
  registry, key parsing, alias loading, caller census or helper closure.
- No independent Rust implementation, captured execution or progress gate.

## What the reference does not establish

The unlicensed inferred `base/cid.rs` names a strict chain-alias lookup and
labels the copied value `ResolvedCid { canonical: Cid(u128), tag: u32 }`.
The binary does establish **20 copied bytes**, but a 16+4 instruction split
alone does not identify those as a canonical integer plus tag, or recover that
Rust layout. Here the inner value cursor advances by **20**, while the output
stores a tag at `+0` and payload at `+1..+0x14`. Any future typed reconstruction
must justify its field identity, padding, alignment and ABI against those facts;
copying the inferred type would skip that work. This packet keeps the value
opaque. It does not substitute an address type or certify another Rust type.

Likewise, an ordinary `tables.get(...).and_then(...)` model would lose the
observed distinction: absent outer keys write the zero output tag, while absent
inner keys enter the source-bound diagnostic path. The strict reference variant
suggests this distinction; the packet establishes it with actual edges and
fields instead of treating that inferred source as proof. Both behaviors and
the layout belong to this one bounded lookup question.

## Actual inputs and outer search

The function saves original RSI/RDX as two query limbs and CL as an 8-bit outer
key, with RDI as the output pointer. It reads global initialization state at
`0x577ab48`, uses atomic operations on byte `0x577ab28`, and reads root/height
from `0x577ab30` / `0x577ab38`. Slow initialization/locking and unlock paths
are retained; their concurrency semantics and valid global states are not proved.

In the outer B-tree-like search:

- node count is loaded as a WORD at `+0x112`;
- the first key byte is at `+0x114`, zero-extended before comparison;
- a value cursor advances 24 bytes per visited key;
- child pointers are accessed at `+0x120 + index*8` while height permits descent.

The two compared outer keys are zero-extended bytes, even though the comparison
uses signed relation instructions on the extended registers. Empty root or
failed descent leads to `0x140545f`, which stores **only** byte tag zero at
output `+0`, then follows release/return. It does not initialize a payload for
that case. B-tree-like is a layout/control-flow inference, not proof of a
concrete standard-library instantiation or all valid node invariants.

## Inner 128-bit comparison and value copy

For an existing outer entry, its root and height feed the second search:
WORD count `+0x196`, key stride 16, and child pointers `+0x1a0 + index*8`.
The value cursor begins at node `+0xa4` and advances **20** before each key's
result is selected, so the first value is at `+0xb8`, not `+0xa4`.

At `0x1405345..0x1405364`, the two 64-bit key limbs are compared through
CMP/SBB sequences. Let E and Q be the unsigned 128-bit integers formed from
entry/query high and low limbs. The first borrow is
`entry_high < query_high + borrow(entry_low < query_low)`; the second reverses
those operands. Subtracting the reverse borrow from the first yields raw byte
**1 for E<Q, 0 for equality, 255 for E>Q**. Each high-limb order decides the
result unless equal, when low-limb order decides; these nine relation cases
cover the algebra over arbitrary unsigned 64-bit limbs. This is a conditional
instruction-level arithmetic interpretation, not target execution or proof of
the tree traversal's complete validity/reachability.

Equality takes `0x14053aa`: load four bytes from value cursor `+0x10` and
sixteen from cursor `+0`, write them to output `+0x11` and `+1`, then write
byte tag **1** at output `+0`. The function returns RDI in RAX after release.
No interpretation of the 20 payload bytes is established. Missing/empty inner
root or failed descent instead reaches `0x1405491`, whose diagnostic descriptor
is bound to `base/src/cid.rs:69:17`; it is not the outer zero-tag path.

## Source, formatting and helper edges

The diagnostic descriptor at `0x1edfe6` has raw bytes
`0c` + `missing cid ` + `c0` + `07` + ` chain=` + `c0 00`. These length-tagged
fragments and two formatter callbacks are retained without claiming full
rendered output. Slots `0x576eff8` and `0x576f000` resolve to `0x1456d60` and
`0x14824a0`; their concrete formatter/type semantics remain unknown.

The diagnostic call uses slot `0x576e098` -> `0x157b810` and Location slot
`0x5668db8` -> path `0x1e4c4a`, length 44,
`/home/ubuntu/hl/code_Mainnet/base/src/cid.rs`, line 69 column 17.
The slow initialization path references Location `0x5668cd8` -> the stamped
std sync once path at `0x1f87cf`, length 76, line 219 column 20, and calls
slot `0x576e8b8` -> `0x4ee3b20`. Unlock helper slot `0x576ef38` resolves to
`0x4e0f2c0`. These are seven exact RELATIVE bindings, not certified helper
names or a complete side-effect/concurrency analysis. Unwind cleanup is kept
in the raw range and remains part of the unclosed helper/exception scope.

## Reproduce and validate

From repo root, materialize pinned LFS inputs and expose GNU binutils:

```sh
python3 -B tools/cid_lookup_static.py --output work/cid-lookup-layout-94
python3 -B tests/test_cid_lookup_static.py
make doctor verify test catalogue-check
make reproduce
shasum -a 256 -c research/work-items/RE-001-cid-lookup-layout-94/SHA256SUMS
```

Python 3.12.14, GNU readelf/objdump 2.47.20260726 on macOS. The generator
reads/authenticates a complete snapshot and feeds that snapshot to
`readelf -wf` and `objdump -d -M intel --insn-width=16 --start-address=...
--stop-address=...` using a private temporary file. It never spawns or emulates
captured code. Existing MIT `foundation_millis.decode_export` checks complete
bytes, contiguity and end bounds, and all controls/RIP sites must be decoded
instruction starts. Only temporary paths are replaced by
`<authenticated-node94>`; no instruction/data normalization masks are applied.
Independent transient Capstone 5.0.6 consumed all 712 bytes in **168 instructions**.

`frames.txt` and `1405240.objdump.txt` preserve native range evidence;
`records.json` retains the full target identity, original coordinates/body
hash, input/field/output observations, instruction bytes, RIP targets, source
Locations, helper bindings and limits. SHA256SUMS includes all durable files
and both independently authored source files.

Five focused tests pass: actual range/width/tag/source bindings; **625** limb
boundary combinations plus explicit representatives of all nine high/low order
relations against independent unsigned 128-bit comparison; **26** actual
instruction/data/Location byte changes below the digest admission gate;
**7** actual relocated-addend changes; and native packet regeneration.
The algebra/predicate checks do not run the target or compare a rebuilt function.
Required suite/reproduction results are recorded in the PR after completion.

No captures, imported source, submodule pins, generated catalogue/progress or
component gates change. No concrete value type, implementation build, binary
comparison, runtime equivalence or hosted-CI success is claimed. Next bind a
real caller's output consumption and the table initializer's value producer
before assigning the opaque payload a Rust representation or semantic fields.
