# Node94 selector and two-field response payload

This independently authored component reconstructs the normal logical state
relation of `0x466c770..0x466c8ae`: **318 bytes / 86 instruction rows** on node94
SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
It closes the response tag-2 payload gap after the separately established outer
selector. No whole gossip message or original nominal type/ABI is recovered.

`decode_tagged_pair` first charges1 when the mode's low DWORD equals1, then
consumes an available selector. Selector0 succeeds without scalar calls and
preserves the complete suffix. Selector1 decodes two little-endian unsigned
fields in order. The first failure prevents the second call; a second failure
preserves the first prefix/counter effects without publishing a partial value.
Other selectors produce raw error5 with the exact observed52-byte diagnostic
and allowed selector set[0,1] derived from branch comparisons.

Each scalar uses the real unchanged accepted `hl-bincode-varint` dependency,
composed privately with the established wrapper's charge8 and current-suffix
fast/slow rule. Existing wrapper/Reader/error semantics remain separately
credited, including PR1365 scope; no generic wrapper API/source is copied or
changed and no dependency bytes are new recovery credit.

The fixed costs1/8/8 differ from encoded wire widths. Each nonoverflow sum is
assigned before testing the limit, and a failed-limit assignment remains.
Overflow rejects before a store. `CounterStores` records the production
assignments in order, up to three; higher mode bits have no effect. Budget
errors precede reads, including empty input. Active raw tags are18success,
0need,2budget,3scalar type,5invalid selector. Scalar need/type errors retain the
accepted Reader/fast consumption and code differences at each current suffix.

The safe `TagZero` / `TagOne{first,second}` types and protocol names are chosen.
The literal `core::option::Option<node::gossip_rpc::GossipStatus>` is observed
data, not proof that an original Rust Option/type/layout has been recovered.
The fixed16-byte context is bound as opaque data only; allowed selectors follow
from branches without interpreting a Location/range descriptor. Inactive
selector-error fields and forwarded scalar padding are excluded, including the
budget route's inactive word8=1 and diagnostic52/context writes. Source exposes
logical active fields, no original pointer identity or complete raw memory.

The domain requires valid immutable nonwrapping slices of at most isize::MAX,
separated mutable state/output, fixed code/data and ordinary scalar-helper
returns. The primary has no allocation or other opaque call. Original ABI,
compiler/machine-byte identity, faults/aliases and full component gates remain
unqualified. New code/docs use root MIT; captured snippets retain their rights.
No unlicensed inferred implementation has been copied.

The independent29,858-input authority and native proofs were sealed before new
Rust. The23-row ordinary fixture subset was frozen unchanged before lib.rs.
The stdin-only example receives five TSV fields and emits16 canonical active
JSON fields; expected records never enter it. Private holdouts remain unread by
this author. On clean source checkpoint
`91e02c8d019aaeec403e4e1633777837d3d7f53e`, O0 and O3 each matched all29,858
records byte for byte; seven ordinary methods passed per direct profile and
under actual offline locked Cargo debug/release. Eight normally compiled wrong
libraries produced complete mismatching outputs and failed ordinary assertions.
One extra optimized own-library rebuild was raw equal. The independent peer
verified all63command pairs and43artifact identities and replayed64novel inputs
plus three duplicate rows on both existing clients without a rebuild. Public
retention contains only safe private-replay counts/hashes. Expanded evaluator tests,
captured execution and hosted CI are NOT_RUN. All full component gates are false.
