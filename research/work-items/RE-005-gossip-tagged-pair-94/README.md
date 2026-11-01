# RE-005 response selector and two-field payload gap

The response tag-2 route calls 0x466c770. This packet resolves that complete
318-byte / 86-row helper's selector-first consumption, fixed1/8/8 budget costs,
ordered two-u64 decoding and error forwarding in independently authored Rust.
The target is node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`;
the primary body SHA is
`47be169576f57402f5681a43722cf6b25f16d52e33187c39a6a2ccf7990569fb`.

The body spans 0x466c770..0x466c8ae. Its two direct calls both target the
already-established u64 wrapper0x466bd10. The229-byte wrapper,316-byte Reader
and14-byte error helper are credited scalar context, not new recovery or a
duplicate of PR1365. The existing612-byte response selector and its four-arm
table supply the caller binding only. No shared crate, caller or wrapper API
is edited. The genuine accepted decoder crate is linked unchanged.

The two RIP references bind the exact52-byte diagnostic at0x6f86ca and opaque
context address0x203f40. The first16 context bytes are retained without a
Location/range-descriptor layout claim. The actual diagnostic contains
core::option::Option<node::gossip_rpc::GossipStatus>; that observed name does
not recover an original nominal type or ABI. Allowed selectors[0,1] follow
from comparisons rather than interpreting context bytes. Earlier exploratory
24/32-byte data windows are explicitly broader than the chosen16-byte context
and include following unrelated data; they are not descriptor-size claims.

`independent/FREEZE.json` seals29,858 distinct complete inputs before Rust,
plus native/data/caller proofs and the independent source-peer native theorem.
Expected output includes16 active logical fields, ordered actual counter
stores and the full unread suffix. Two complete corpora use lossless zlib
transport; the unchanged seal authenticates decompressed original bytes.
Twenty-three public unit rows were frozen unchanged before source. Private
holdouts remain unread by this author and are excluded from the packet.

`collect.py` authenticates the full target and exact FDE/CIE/code bounds,
readable executable mappings, the52/16-byte data, two scalar jump tables,
response table, selected calls and real Reader/error GOT slots. It scans all
80,300 actual RELA writes and rejects code/data/slot overlap, including writes
starting before a selected range. Its copied-input tests never execute a target.
`run.py` is narrowly scoped to this native gap: genuine dependency builds,
input-only comparisons and wrong-source/assertion controls. It retains actual
commands and streams while guarding complete tracked physical inputs, seven
genuine pins,103 provider payloads,two manifests and resolved host tools.

The normal domain is valid immutable nonwrapping input of at most isize::MAX,
separated mutable state/output, fixed code/data and ordinary scalar returns.
There is no allocation helper in the primary. Inactive selector-error words,
forwarded error padding, entry-register residue, native pointers/types/layout,
faults, compiler/machine-byte identity and whole gossip grammar remain outside
the projection. No original output-memory or full-component gate is asserted.

Current status: source review passed; full runner prebuild review and actual
builds are pending. Expanded evaluator tests,captured execution and hosted CI
are NOT_RUN. All full component gates remain false. Planned exact command:

```sh
python3 -B research/work-items/RE-005-gossip-tagged-pair-94/run.py --out work/gossip-tagged-pair-318-run1
```

New source/docs are independently authored MIT project work. Captured evidence
retains its original rights; no unlicensed inferred implementation is copied.
