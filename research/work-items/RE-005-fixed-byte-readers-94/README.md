# RE-005: complete paired fixed20/fixed32 slice readers

The existing varint Reader and stream-message studies leave fixed-width raw
prefix reads and their result-buffer effects unimplemented. This packet closes
the complete logical relation of one paired node94 family, with independently
authored safe Rust: fixed20 at`0x466c140..0x466c1a6` (102 bytes/32 instructions,
SHA`bb3c6ab56de3c09eb51017ac988e6a43a4d06286835baa5d3f27e19a5064015a`)
and fixed32 at`0x466c1b0..0x466c223` (115 bytes/37 instructions,
SHA`14f7a11f50bba370abd61ae08c76346b828217584ce9a296bcce3df0040cd7a5`).
The outcome is217 bytes/69 instructions, not two width-only contributions.

Target node94 is91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All addresses are ELF virtual addresses before load bias. Base main:
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. No source type/schema, ABI or
business meaning is inferred from the20/32-byte widths.

## Native admission and prior scope

Every instruction is retained in`native/`, with complete FDE/CIE and executable
section/PT_LOAD mappings. Both leaves are call-free, with eight conditional
branches and six return routes in total, no external code/data/helper edge or
jump table. All80,300 actual RELA records are scanned as eight-byte intervals;
admitted kinds1/6/7/8/18 retain their actual kinds, including18=TPOFF64. None
patches either selected body or retained caller. No relocation is invented or
masked to manufacture a match.

Whole native listings qualify two real incoming instruction boundaries:
`0x4c80b0b` in93-byte FDE`0x4c80b00..0x4c80b5d` calls fixed20 and tests18;
`0x4779f20` in436-byte FDE`0x4779eb0..0x477a064` calls fixed32 and tests1,
using payload from+1 or error from+8. These529 caller-context bytes establish
use, not complete caller reconstruction or a complete xref census. Initial
byte-pattern candidates remain labeled unqualified; only these two sites were
qualified against their full listings and frame bounds.

Existing kind5 Rust implements charged fixed8 varint reads and a24-byte result
map. Existing bincode Rust covers unsigned integer paths. Neither is a generic
fixed20/32 prefix reader or this distinct21/33-byte result relation. Old static
stream-message context is credited rather than re-claimed as new discovery.
Fresh quoted0x-address and named PR checks found no overlapping implementation.
No timestamp or unrelated caller scope is carried here.

## Complete normal-domain relation

Independent proof:`preparation/independent-PROOF.md`. Native mode is exactly
the low32 dword at reader+0; limit/counter are u64 at+8/+32, and pointer/length
are at+16/+24. Only mode==1 enables charging, not every nonzero word. All u32
machine-state controls are admitted without asserting valid source enum values;
unaccessed header bytes+4..7 are outside the portable interface.

With width N, enabled overflow C>u64::MAX-N returns charge without changing C.
Otherwise C+N is stored before limit comparison. An over-limit result or later
shortage retains that increment. Every failure preserves the slice. If length
is below N, additional=N-length; otherwise the exact N-byte prefix is copied
without endian conversion and the slice advances N. This covers arbitrary
initially over-limit counters and repeated calls, including successful prefixes
followed by errors and eventual count overflow.

The result must be a supplied initialized separated21/33-byte window, with
valid nonwrapping readable input/cursor/control/code/data roles and ordinary
return. No arbitrary aliases, faults/unwind, concurrency or uninitialized caller
observations are admitted. These premises justify comparing every result byte:

| Width | Route | Exact result assignments; all others preserve supplied bytes |
| --- | --- | --- |
|20|charge|out[0]=2|
|20|end|out[0]=0; out[8..16]=LE64(additional)|
|20|value|out[0]=18; out[1..21]=prefix|
|32|charge|out[0]=1; out[8]=2|
|32|end|out[0]=1; out[8]=0; out[16..24]=LE64(additional)|
|32|value|out[0]=0; out[1..33]=prefix|

This does not assume real caller padding was initialized. Own logical names
value/end/charge and the Rust enum are not original nominal types or ABI.
Source/native copy and cursor store order commute only under the stated
separated normal domain; no intermediate-state/fault claim is made.

## Independent authority and source checkpoint

Before new Rust, an independent worker freshly admitted both native bodies,
callers and all RELA, proved the full relation and froze50,391 distinct raw
stimuli/122,634 observations. Freeze SHA-256:
`e67df596434c9fcc71516be10d67542b5d21375e1051aa5a252742ca1a2df72d`.
The original authority, raw inputs and canonical expectations remain unchanged
inside deterministic gzip files. Source path absence and clean56c0 head are
recorded inside the original seal. An alternative raw-parse/bytearray/int-to-LE
formulation checked every row; this is a second method by the same independent
reviewer, not an invented second reviewer or native execution.

Cases cover both widths, raw mode bit/byte bases including0x80000000,
0x80000001 and u32::MAX, u64 power, overflow and limit boundaries, every copied payload
position/octet, shortages, supplied output octets/position bases and bounded
repeated calls. Counts:25,134 value,63,222 end and34,278 charge observations.
The finite corpus supports the separate all-domain proof; it is not exhaustive
execution of every u32/u64/input string.

Before source authoring, twenty unchanged multi-call stimuli/50 observations
were selected from that authority for one ordinary unit method. Its immutable
selection receipt identifies all16 named cases plus four high-mode cases.
The input-only observer receives eight raw fields and emits twelve canonical
JSONL keys, exact u64 integers, the entire result and remaining tail. No answer,
semantic role or plan enters the client; this is data flow, not an OS sandbox.

`SOURCE-PROOF.md` relates the new dependency-free no_std functions to the native
relation. The real manifest and genuine offline lock resolve one local package.
Hash-verified Cargo1.89.0 with explicit authenticated rustc/rustdoc1.94.1 passed
lock generation and locked offline metadata in an empty owned Cargo home. The
observer and ordinary harness use std; the library uses no allocator or unsafe.
No registry, placeholder dependency, original object or inferred implementation
source is substituted. The selected research compiler is not the original one.

Complete source/native/reference/qualifier/docs passed independent prebuild
review. A staged whitespace check then found one excess final blank line in
the qualifier; the original review and AST-identical correction/addendum remain
retained. No source semantics or recipe changed. The actual run used clean C1
`8949248669089b6c88551efcb4e32179e3f95742` and passed all40 recorded commands:

| Actual check | Measured result |
| --- | --- |
| O0/O3 input-only clients | Each50,391 stimuli/122,634 observations exactly match pre-Rust expected bytes |
| Ordinary tests | One20-stimulus/50-observation method per profile; two successful executions |
| Native/static methods | All12 pass on the actual target, including11 corruption controls |
| Comparator controls | Result-byte alteration detected; missing/extra rows rejected |
| Normally returning wrong variants | Rollback charge33,092; clear result97,494; wrong32-byte success tag14,448 mismatches of122,634 each |
| Wrong-variant ordinary methods | Each aborts at a genuine assertion with exit101; fixture dimensions are not completed negative executions |
| Genuine Cargo recipe | Locked offline build of one dependency-free local package passes |
| Optimized repeat | Raw-equal15,326-byte rlibs, SHA`9ee8f1b02d27036518636d052d79d152d2ab645cd3e2161276df7ba4cc1efe8c`, no normalization |

Full result SHA-256:
`91f04b4963d589eceb0eb342ed3ff202ea4e322063d8d52c6ac71b10bd69d334`.
The complete before/after maps match10,866 actual tracked physical inputs,
seven clean pinned children,103 provider payloads, two installed manifests and
the actual compiler/Cargo/C-driver/bfd/objdump identities. All80 raw streams,
full results, inputs/expectations, six direct rlib/object/IR sets and actual
Cargo artifacts are retained byte-for-byte in`observed/qualification.zip`.
Twelve real public reader definitions are bound across the six sets to the
actual own object and IR. No original compiled-code correspondence is inferred.
Transient executable hashes are retained; their files are not archived.

An independent private replay also matched both existing clients:80 novel,
83 serialized cases including reordered duplicates,332 full-result observations
per profile. These were sealed after author source creation and before that
reviewer read the Rust. Only the public summary is included; private inputs
and answers remain private. No new compiler or captured execution was involved.
Final`make doctor`,`make verify`,`make catalogue-check` and`make reproduce`
all pass on clean C2`7e9b221170f05f4aa307252b7efb905acf2e0b10`.
Their measured child times sum to38.371 seconds. Complete before/after maps
match10,878 actual tracked physical inputs, seven clean pinned children,
103 provider payloads, two installed manifests and all actual compiler/Cargo/
host tools. The four commands, all eight raw streams, maps and exact wrapper
are retained in`observed/final-static.zip`. No compiler or the twelve already
passing native methods were repeated. All eleven source/driver/fixture/
manifest/qualifier/read-only-helper input hashes remain unchanged from C1;
later changes only retain measured evidence and its documentation.

## Reproduce and limits

```sh
python3 -B tools/fixed_byte_readers_contract.py --output /tmp/new-fixed217-native
python3 -B -m unittest tests.test_fixed_byte_readers_contract -v
python3 -B tools/fixed_byte_readers_rust.py \
  --rustc /tmp/hl-resume-20261101/toolchain/prefix/bin/rustc \
  --cargo /workspace/mayhem-build-repeat/toolchain/rust/bin/cargo \
  --provider-audit /tmp/hl-resume-20261101/toolchain/PROVIDER-AUDIT.json \
  --output /tmp/new-fixed217-qualification
```

New output paths must be absent and the native output parent must exist. The
qualifier checks only the scoped native methods and own Rust, with guarded
physical source/pins/provider/host identities and real offline Cargo build.
Existing unsigned checkers cannot bind this217-byte result/cursor relation;
the small task-specific collector and qualifier supply that evidence using
existing ELF/FDE helpers. No global tooling/provider/workflow change is made.

Do not rerun the archived origin-sealing generator after source exists or in
the original review directory: it records a historical clean/path-absent
witness. For a post-source mathematical cross-check, copy the unchanged
alternative checker, original FREEZE and decompressed inputs/expected files
into a new directory under their original names and run the checker there.
Its new receipt is a later replay; preserve the original seal/review receipts.

New code/proofs are MIT. Captured evidence retains original rights. No
can1357 implementation source was copied. Own compiled target-byte identity
is unmeasured; no selected-byte registry/catalogue/progress change or full
component gate. Original source/compiler/ABI, arbitrary aliases, faults/unwind,
full callers/codec/node remain open. Captured execution, new instruction
evaluators, expanded/full suite and hosted CI are NOT RUN. Next question:
which enclosing schema paths use these now-closed raw-prefix stores?
