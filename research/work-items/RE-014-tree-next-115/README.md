# RE-014: node115 generic iterator next and weighted-policy caller contract

Component: consensus iterator dependency, not a consensus-policy completion.
Target Linuxx86-64 node115,
SHA256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base8fd8db680ec4bfef40996e5616bce3d5156d0b86. New code/evidence is MIT;
original capture rights and imports remain unchanged.

## Gap and boundary

Main's weighted fast-fold Rust handles supplied spans while its static packet
leaves generic next37c4430..37c4644 unresolved. Here the whole532-byte FDE is
interpreted, including lazy left descent, parent climbing, right-subtree left
descent, eight-level loop unrolling, paired key/value addresses and all iterator
state writes. Its actual call at422e363 and the outer source-associated policy
context are retained as context, not a second recovered operation. Lookup,
first-provider behavior and full weighted-policy/consensus roles remain open.

The input is a bounded, explicitly laid-out synthetic node arena and a72-byte
state. Empty remaining returns a null key pointer before checking the tag.
Otherwise remaining decrements before the low32-bit tag1 check. A lazy cursor
initializes its leftmost leaf and clears the two cursor words. Parent climbing
uses each child's u16 edge index; the next successful item updates the cursor
through the right subtree or advances its leaf index. No normal helper calls
occur. Two panic-call sites are stopped BEFORE their unclosed calls and are
reported as project-owned boundary tags, not native error returns.

## Actual layout and normalization

State:+0rawtag(low32observed),+8currentnode,+10height or lazyroot pointer,
+18nextindex or lazyheight,+40remaining. The +20..+3f words are observed opaque
state and remain compared. Nodes:+0parent pointer,+8u64 values(stride8),
+60opaque20-byte key slots(stride20),+13cu16parent edge,+13eu16length,
+140child pointer slots. These observations do not establish an original Rust
Node/iterator enum or allocation ABI. Keys are synthetic, not user keys.

Node pointers normalize to1-based arena IDs; returned key and value addresses
normalize INDEPENDENTLY to(nodeID,byteoffset). Comparator observers then read
20key bytes and the u64value; these reads are not counted as iterator instructions.
All nine state words are compared. Null-key returns ignore unspecified RDX.
Only final snapshots are compared, not intermediate writes, caller-saved/stack
register payloads, aliases, concurrency or unwind behavior.

The maintained instruction interpreter runs original bytes with unknown saved
register/stack masks, read-only node spans, bounded state/stack writes and no
helper substitutes. No decoder extension is needed for this task. Every
unknown read/flag, escaped branch, call or budget failure remains a failure.
COW controls change actual key/value strides, node/parent field offsets,
remaining/tag behavior, next index and right-subtree selection. The capture
stays read-only and is authenticated before/after collection.

## Fixture scope and checks

The canonical native collection has3181recipes, including whole successive
walks and one-step snapshots, zero/max remaining, noncanonical high tag bits,
lazy/ready cursors, balanced6-child shapes and raw sparse towers through17.
The latter and inconsistent remaining/tag cases are machine-boundary tests,
not claims of valid stdBTree values. Core visited/unvisited rows and explicit
case/observation denominators are in FREEZE.json; caller FDEs are unexecuted.
No full component gate advances and no global key ordering or role is inferred.

FREEZE-NOTE.md records source chronology and exact-frame deduplication.
Normal replay/build and focused tests use pinned owned rustc1.94.1/
LLVM21.1.8 macOSarm64,Python3.12.14/Capstone5.0.6 and GNUobjdump. This research
compiler is not an original node build recipe; no Cargo graph is fabricated.
Exact commands, hashes, corruption controls and observed results belong in
validation.txt and machine-readable reports. Shared PR2334 baseline full-suite
receipt is not exact-head or hosted CI for this different packet.

Next: compose this next helper with independently closed lookup/first-provider
semantics before claiming the complete generic weighted-policy path.

All layout offsets above are hexadecimal. The actual core visited denominator
is121/126. Unvisited: normal jump0x37c4621, calls0x37c462d/0x37c463c and
UD2s0x37c4633/0x37c4642. The jump remains an explicit path gap, not padding.
The normal return RAX/RDX and final state are compared; panic boundaries stop
before the calls and do not assert unwind or native error-return equivalence.

## Independent implementation and reproduction

`src/node115-tree-next/lib.rs` is an owned safe arena projection, not byte
transplantation or an inferred original Rust layout. `client_fixture.rs` is an
input-only synthetic layout adapter; it never accepts expected answers.
`rust-results.json` binds source, adapter, driver, compiler and frozen stream
hashes. See the source README for build/replay commands and preconditions.
`audit.py` authenticates complete three-FDE bytes, unwind records, both actual
caller transfers and the source Location; context-only owners stay unexecuted.
The pre-Rust freeze is Git commit01f02902. Neither source labels nor static
call relationships imply runtime reachability or full consensus semantics.
