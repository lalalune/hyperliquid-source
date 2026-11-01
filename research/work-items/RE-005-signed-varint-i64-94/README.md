# RE-005: complete node94 signed64 slice decoding

The prior varint/Reader packets left signed values and their error conversion
unreconstructed. This packet closes the logical value/error/cursor relation of
the complete node94 leaf at ELF VA`0x4b6fa60..0x4b6fbc5`,357bytes/99instructions,
SHA-256`d22b30b24c723356b830ec168251b150e482ceec091c5ebc05b4f40f1afbba4f`.
It adds independently authored Rust with the real existing unsigned Reader
as a source dependency. No full serialization or component gate is claimed.

Target: Linux x86-64 node94,91,774,280bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base:`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. Addresses are ELF virtual
addresses before load bias. Original source names/types/ABI remain unknown.

## Actual native closure and scope

`native/target.objdump`,`rows.json` and the initial/complete closure records
retain every primary instruction. Fresh immutable target admission binds its
actual FDE/CIE and executable section/PT_LOAD mapping. Both four-entry jump
tables are actual image data: primary`0x706714` and Reader`0x6f6ed8`. All
80,300 RELA records are checked; kinds1/6/7/8/18 are actual eight-byte writes,
with kind18 retained as TPOFF64. No relocation patches any selected body/table.
Both helper slots have globally unique symbol-zero RELATIVE writes:

| Slot | Complete helper | Size | Status |
| --- | --- | ---: | --- |
| `0x57745e0` | `0x466d980..0x466dabc` | 316 | Previously established u64 Reader |
| `0x57745e8` | `0x466dac0..0x466dace` | 14 | Previously established error builder |

The330 supporting bytes/100instructions are dependencies, not newly recovered
signed bytes. Their complete bodies, tables and calls close all normal helper
paths; no opaque callback/stub is substituted. Existing Reader source and its
manifest remain read-only. Old RE-005/w3 surveys already recorded this primary's
dispatch/FDE, but did not establish its complete signed/error relation or Rust.
They are credited rather than re-claimed as a new address discovery.

The actual qualified call`0x46102d2`, inside complete FDE
`0x4610290..0x46104d2`, passes the inner cursor and DL0 and later uses the returned
word in signed arithmetic. Enclosing behavior/units are not reconstructed.
Fresh exact-address start/end and signed/zigzag ownership checks found no
overlapping implementation. Existing u8/bool1454, unsigned outer1365 and merged
raw Reader1325 scopes stay separate.

## Complete logical relation

The independent native proof is`preparation/independent-PROOF.md`. Its normal
domain requires a valid immutable nonwrapping slice of length<=isize::MAX,
writable cursor, separated valid output/stack/code/data, and ordinary return.
Raw DL0 selects little endian; every nonzero byte selects big endian. No outer
limit/counter is supplied or inferred by this bare slice decoder.

Tag values below251 are payloads themselves. FB/FC/FD load unsigned payloads
of2/4/8bytes; nonminimal representations are accepted. For every unsigned64
payload u, the returned signed value is u/2 for even u and-(u/2+1) for odd u.
This covers both i64 endpoints without signed-overflow assumptions.

Length>8 uses the primary fast path; its invalid FE/FF errors do not consume
the marker. Length<=8 calls the true Reader, which consumes a nonempty marker
before shortage or type rejection. Empty input consumes nothing and needs1.
Both raw error-code bytes c become c+6 only when c<6, otherwise surviving:

| Remaining length | Marker | Expected | Found | Consumed |
| --- | --- | ---: | ---: | ---: |
| >8 | FE/FF | 8 | 10/12 | 0 |
| 1..8 | FE/FF | 9 | 10/12 | 1 |

Only rawtag18 signed value/bits, rawtag0 additional bytes, rawtag3 expected/found
bytes, and residual cursor/slice are projected. Null means outside the logical
projection. It never means an actual byte was zero, unwritten or unchanged:
the native error path copies inactive stack-derived bytes. No nominal enum
layout, padding, arbitrary aliases, fault/unwind behavior or clobbers are modeled.
Repeated calls simply read the remaining slice; fast FE/FF can repeat without
consumption, while slow errors can advance to a later value.

## Independent authority and actual build scope

Before any new signed Rust, an independent worker closed the native relation
and froze27,671 distinct raw stimuli/89,218 observations. Exact freeze SHA:
`28294f3fcd101cd27d2b4ef5954f5cabf4299dacd8f8585611bc64ce6130e63d`.
Original authority/input/expectation bytes are unchanged inside deterministic
gzip files, with decompressed hashes. The original generator, native admission,
proof and pre-source origin witness remain intact. A second integer/byte
formulation also rechecked every frozen observation before source review.

Coverage includes every initial tag at lengths1..12, all256 raw DL bytes,
both signed endpoints/parities, payload powers/boundaries/nonminimal encodings,
every byte value at every u64 payload position, shortages, reserved markers,
threshold transitions and bounded repeated calls1..4. These finite cases
support the separate complete native/source proofs, not an execution census.

Twenty unchanged first-call projections were extracted after source authoring
from that pre-Rust authority; this ordering is explicit in the unit receipt.
One ordinary unit method covers those twenty cases. The production client
receives only`id|rawDL|wirehex|calls` and emits twelve sorted compact JSONL fields
for every call, including signed bits and the entire tail. Expectations and
semantic roles never enter its arguments. This is data flow, not an OS sandbox.

The new manifest's only dependency is the actual existing MIT
`hl-bincode-varint0.1.0` at`../bincode-varint`. Its source hash is96a4b43f…a279.
The new crate has no_std, but its real dependency uses std, so the composed
research build requires std. Cargo1.89.0(d96b80636), hash638ab451…405b, genuinely
generated the offline lock and validated locked offline metadata with explicit
authenticated rustc/rustdoc1.94.1 and an empty owned Cargo home. Exactly two
local packages resolve; no registry or fictional workspace is involved.

The reviewed qualifier builds both real libraries directly at O0/O3, links the
input-only client, compares all89,218 observations, runs the one ordinary method
per profile and compiles three normally returning wrong variants. It repeats
only the signed O3 rlib with the unchanged qualified dependency, so any raw-equal
claim is specifically signed-rlib reproducibility. A separate actual locked,
offline Cargo build validates the real manifest/lock recipe. Ancestor/component
Cargo configs are rejected; all tracked physical modes/bytes, seven real child
pins,103 research Rust provider payloads, two installed manifests and actual
compiler/Cargo/C-driver/selected-bfd/objdump identities are guarded before/after.

Source/client and complete collector/reference/runner passed independent
prebuild review. At this source checkpoint, actual source compilation and the
eleven new native/static methods are still pending. No green build is inferred.

## Reproduce and limits

```sh
python3 -B tools/signed_varint_i64_contract.py --output /tmp/new-signed64-native
python3 -B -m unittest tests.test_signed_varint_i64_contract -v
python3 -B tools/signed_varint_i64_rust.py \
  --rustc /tmp/hl-resume-20261101/toolchain/prefix/bin/rustc \
  --cargo /workspace/mayhem-build-repeat/toolchain/rust/bin/cargo \
  --provider-audit /tmp/hl-resume-20261101/toolchain/PROVIDER-AUDIT.json \
  --output /tmp/new-signed64-qualification
```

The native output parent must exist and output paths must be absent. To reproduce
the original pure mathematical generator, copy its unmodified bytes plus the
retained proof/admission into a new directory as`generate.py`,`PROOF.md` and
`NATIVE-REVIEW.json`, then run it there; never overwrite original frozen evidence.
No can1357 implementation was copied. New proof/code is MIT; captured bytes and
disassembly retain their original rights. Research toolchain identity is not
the original compiler. New Rust target-byte identity is unmeasured; no selected
byte registry, progress record or full-component gate changes. Captured target
execution, new instruction evaluators, expanded/full suite and hosted CI are
NOT RUN. Next question: how do real callers account for signed field limits and
decoding budgets around this now-closed bare slice relation?
