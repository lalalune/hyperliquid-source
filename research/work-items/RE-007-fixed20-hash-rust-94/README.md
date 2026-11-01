# RE-007: actual lookup fixed20 hash in Rust

## Bounded question and result

For node #94, which bytes and seed words feed the hash consumed by the row
selector, and what numeric result does that **fresh, exactly 20-byte** path
produce? This closes the actual call boundary left external by draft #1460,
then independently reconstructs the fixed20 value relation in the existing
`src/node94-margin-risk` component. Its public API is
`hash20::table_hash20([K0, K1], &query) -> u64`.

Target: Linux x86-64 node #94, 91,774,280 bytes, SHA256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All native addresses below are ELF virtual addresses. Native intake began at
main `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; selector/component baseline is
`54735068738b50c515b09550b78164c12762107d`. No reference implementation source
was copied; new source, fixtures and oracle are independently authored.

This is a supplied-seed helper and synthetic composition result. It does not
establish runtime seed creation, actual table producer invariants, native Rust
ABI, returned-row lifetime, Once behavior or a whole lookup. Whole-lookup
admitted vectors remain **zero**, and no component gate advances.

## Native route and input premises

1. In reserve caller `0x3708bf0`, name incoming RDI `D` and RSI `Q` only as
   opaque pointers. `0x3708c03` preserves Q in R14 without changing RSI;
   `0x3708c09` adds `0xf8` to RDI and `0x3708c10` calls lookup `0x36f57f0`.
   Thus the lookup map view is `M=D+0xf8`.
2. With nonzero map count, `0x36f5802` preserves Q in RBX for later key
   equality. `0x36f5805` forms `M+0x20`, `0x36f580c` places it in RDI, and
   `0x36f580f` directly calls actual adapter `0x399c7a0`; RSI is still Q.
3. `0x399c7a4` reads 16 seed bytes from `M+0x20`: LE u64 K0 at `D+0x118`
   and K1 at `D+0x120`. Shuffles/constants at `0x399c7a8..0x399c7c7`
   initialize v0/v2/v1/v3 storage. Constant vectors are at `0x204ec0` and
   `0x203e70`. No seed creation or global seed fetch occurs in this adapter.
4. `0x399c7d3..0x399c7e4` zero length, tail and tail count in the fresh
   72-byte stack state. `0x399c7e9` sets EDX=20; `0x399c7ee` calls actual
   writer `0x3a00700` with that state and the original Q.
5. The fresh writer's `0x3a0070c -> 0x3a0073d -> 0x3a007f5` route reads
   two LE u64s at Q+0/Q+8, compresses each once and retains the LE u32 at
   Q+16. No collection-length prefix is absorbed. At `0x399c7f3..0x399c801`
   the adapter forms `(20 << 56) | tail`; it compresses once, XORs `0xff`
   into v2 at `0x399c84a`, executes three final rounds, and returns the
   four-word XOR in RAX at `0x399c8d0..0x399c8e4`.
6. Lookup receives H at `0x36f5814`, derives H>>57 at `0x36f5817`, and
   uses H&mask to begin the previously reconstructed selector.

Correspondence requires stable, valid readable seed16/query20 storage,
ordinary call/return behavior, disjoint writable helper and call frames, and
no asynchronous mutation. Seed/query overlap with each other is not excluded;
aliases with writable native frames are excluded. The Rust API's owned seed
words and immutable `[u8;20]` are safe API choices, not recovered native layout
or ownership. The API admits every supplied u64 pair and every 20-byte array.

## Complete functions and credited work

| Role | Half-open FDE extent | Bytes | GNU = LLVM instructions |
| --- | --- | ---: | ---: |
| Actual adapter | `0x399c7a0..0x399c8e5` | 325 | 83 |
| Actual writer | `0x3a00700..0x3a008d7` | 471 | 141 |
| Credited sibling adapter | `0x2840fb0..0x28410f5` | 325 | credited separately |
| Credited sibling writer | `0x288e280..0x288e457` | 471 | credited separately |

Actual body hashes are `b0fba5048fca7feae64d4b962c60f657bf34572092771448b3f31535b390f250`
and `46001f65ce48b616e874560625e13f23d66afeb8acc11f10e0b26be987353ea3`.
`native-freeze.json` records six complete FDE/body/CIE identities, caller
extents, literal coordinates and 20 pre-model byte controls. `native.py`
authenticates the artifact and those records. Complete GNU 2.44 and LLVM 19.1.7
exports agree on all 224 actual instruction extents and every raw byte, with
GNU continuation lines joined and trailing whitespace trimmed in the durable
text exports; original raw streams remain under ignored work. FDEs are unwind extents, not full source ownership.

Merged [#1077](https://github.com/lalalune/hyperliquid-source/pull/1077),
`RE-001-address-hash20-94`, already proved the sibling's fresh20 SipHash-1-3
mathematics and Python model; its head was `8ae5d2d7`, merge `5b236d28`.
That foundation is credited. This contribution binds the actual lookup route
and independently compiles Rust; it does not claim new discovery of SipHash math.

The actual adapter matches the sibling outside three rel32 operand ranges
(offsets `0x11`, `0x23`, `0x4f`, 12 bytes); 314/325 bytes are raw equal. Two
references resolve to the same constants; the third selects the actual writer.
**The writers are not wholly identical:** actual `0x3a00721` compares R8 with 4
(`49 83 f8 04`), sibling `0x288e2a1` compares R11 with 4 (`49 83 fb 04`).
Only byte `+0x23` differs. The proved fresh ntail=0 route skips that comparison;
only that route transfers the sibling proof. Nonzero-tail/incremental writers
remain open.

Fresh ownership review inspected 194 open PR bodies at 2026-11-01 22:57:54 UTC,
with main still `56c0ec67`. #1460 supplies H and explicitly excludes hashing.
#1423's overlapping-read/product-high mixer, #1451's signed-tail modulo helper,
#1373's other inline registry lookup and #1541's different Visor target do not
claim this actual adapter/writer. No competing declared implementation was found.

## Freeze, independent oracle and compiled comparison

The local sequence was native freeze, pure expected-output freeze, hash source,
composition freeze, input-only composition driver, then guarded compilation.
These are hash-pinned local sequence records, not external timestamp attestations.

| Evidence | SHA256 |
| --- | --- |
| Native pre-model freeze | `07719944d888e2820c856c79e6ef91de8de5b8eb3b20df81187518f83788de8f` |
| 990 inputs/outputs, oracle and controls before new Rust | `bb9c60696d5dd557299b7a4309868717c3eec6b31f3c17fdd8f413cf6c8a7582` |
| 1,980 composition inputs/outputs before composition driver | `ecf9483b158c444f3557e7015ad66e4f4e925c16e9d52e360984bbfdde0755ae` |
| Compiled current component/input snapshot | `698b62bcd67c59ae1c59dfe52a32f1f4b4202e09f5d08e689c5b30cbbb4dc036` |
| Retained actual report payload | `af48d894134da7dc627a9ff7f1ceacd1fe6d43ed13e3aab400643625a51a6b17` |

`pre-source-context.json.gz.b64` preserves the exact frozen oracle, fixtures and
original path relationship. The pure oracle uses canonical v0/v1/v2/v3 tuples,
integer residues modulo 2^64 and a little-endian byte polynomial. Rust uses a
private v0/v2/v1/v3 array and explicit wrapping additions/rotates. Expected
answers remain outside both input-only drivers. No captured instruction
interpreter or target executable was invoked.

The hash corpus has six supplied seed pairs × 165 messages: zero, ff, ramp,
high-tail, low-body and 160 independent message-bit changes. All 990 are unique.
The old zero-seed/ramp literal H=`0x639e355ae68c0100` is credited to the existing
synthetic fixture, not new native execution or runtime admission.

Each hash case yields a hit and a different-key miss in a one-entry logical
32-bucket table, giving 1,980 compositions. The stored key is hashed under the
**same seed pair as that frame's query**, including class-boundary misses.
Its control byte and bucket derive from that hash. Native mask is 31 and
`C+j = controls[j&31]` through j=46; the state input is the word at the native
late state load (an entry snapshot requires stability until that load). The
membership oracle checks the first group independently of the Rust probe loop.
These are synthetic seed/table premises rather than native producer-admitted maps.

Observed Rust 1.94.1 results, opt0/opt3 with two repeated builds per profile:

- Four × 990 hash comparisons and four × 1,980 compositions, zero mismatches.
- 13 operative source mutants each emit a normal wrong u64 at its pre-source
  witness; each actual wrong value equals the independently frozen wrong-math
  value. This is 13 compiled witnesses, not every mutant on every case.
- One normal wiring control emits unchanged H but passes H^1 to the selector:
  frozen witness 4 changes Bucket0 to SharedDefault. It returns no API error.
- Three malformed-driver framing controls exit 2 with empty stdout. These are
  driver policy controls, separate from native arithmetic/selection evidence.
- Cargo: 41 tests in debug and 41 in release, including the new public-API test
  against 30 pre-source boundary outputs; zero failed, zero doctests.

All 66 actual commands/132 channels are retained losslessly as text base64 of
gzip payloads, along with the exact compiler/input tree. Tool hashes, explicit
build environment, input/output hashes and exact arguments are in the report.
Default Python replay rederives all expectations, validates actual values,
checks full mutant input trees and verifies the selected current source hashes.
Repeated same-opt driver hashes agree; repeated rlib hashes differ. No complete
build-byte determinism, native machine-code match or new byte-window coverage
is claimed. The earlier ignored v1 report `d8d3e30c…` had 40 component tests;
this durable 41-test receipt is distinct and does not rewrite it.

## Reproduce and limits

See [VALIDATION.md](VALIDATION.md) for exact commands, receipts and check scope.
`observed.py` replays without a compiler. `verify.py --prepare` freezes the
current component and external literal input before any build; its guarded
build checks that snapshot before each client invocation. Only the selected
hash/selector/test sources and drivers are tied to the durable receipt during
ordinary replay, so later unrelated component additions do not silently alter
this historical build.

The new module initially blocked the old selector packet's whole-current-tree
test. [SNAPSHOT-HISTORY.md](../RE-007-row-selector-rust-94/SNAPSHOT-HISTORY.md)
records the exact failure and minimal repair: retain all original 74 snapshot
files rather than replacing old fixtures. Its original source, freeze, report,
outputs and 894/7 denominators remain unchanged.

Remaining gaps: actual seed production/entropy and object lifetime; table
construction, resize/count/mirror/entry invariants; generic writer domains;
Once/concurrency and final row lifetime/aliasing; native ABI and allocation
layout. No economic units, complete risk engine, runtime safety, whole lookup,
full node build, hosted CI success or gate completion is established here.
No new dependencies, installers, target execution or live runtime inputs were
used. Rustfmt and Clippy were unavailable in the approved tool set and were
not run.
