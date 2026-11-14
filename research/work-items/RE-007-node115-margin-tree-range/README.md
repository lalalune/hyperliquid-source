# Margin-tree range boundaries and selected row

This advances backlog HL115-045 under RE-007. Target: Linux x86-64 node #115,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `a8616af9432b8d8517b2af677880e117b7c28ef3`.

The prior flat range implementation and packet in #3261 explicitly exclude the
tree branch of `0x3cd80d0`. The flat composition in #4281 does not close this
branch; #5722 references range selection as a dependency of vault conversion.
This packet closes the distinct tree search `0x35c14a0`, its leaf-edge result,
and the actual reverse-edge selection used by both `0x38b5300` and `0x38b54b0`.
It does not repeat the previously recovered margin arithmetic.

## Native contract

The outer `0x3cd80d0` checks bound ordering first. Reversed finite bounds and
equal doubly excluded bounds produce tag 0. On the tree representation,
`0x3cd8166` passes the root, height and both bound pairs to `0x35c14a0`, then
tags its result 2. An absent root produces two null endpoint handles. Direct
entry to the tree helper with invalid bounds instead reaches a panic; the source
exposes both the helper and the outer behavior.

Each valid node supplies unsigned 64-bit keys at `+0x168 + 8*i`, a 16-bit
count at `+0x1c2`, and internal child pointers at `+0x1c8 + 8*i`. Search first
descends a common child while both boundary edges coincide. Once the edges
diverge, it descends two frontiers separately until they reach leaves.
The returned lower/upper triples are `(leaf, height=0, edge_index)`. They are
edges, not pointers to necessarily present leaf values.

The four signed-relative jump tables at `0x797cac`, `0x797cbc`, `0x797ccc` and
`0x797cdc` are decoded and checked. Public bound tags are included=0,
excluded=1 and unbounded=2. At an exact lower match, included chooses the
preceding child with its last edge; excluded chooses the following child with
its first edge. At an exact upper match, included chooses the following child
with its first edge; excluded chooses the preceding child with its last edge.
Internal states 2 and 3 therefore have different endpoint meanings in lower
and upper searches. The source preserves these transitions rather than treating
every result as a leaf-only key match.

Both concrete margin consumers obtain the table pointer from object `+0x10`,
request an unbounded lower and included upper query, and select the last entry
from the returned range. If the final leaf edge index is zero, the consumers
walk parent pointers at `+0x160`, using the 16-bit parent edge at `+0x1c0`,
until a nonzero edge is reached. Thus an internal separator's value can be the
selected tier. Values are 32-byte records from node offset zero: edge `i`
identifies value `i-1`. The existing arithmetic reads that selected value's
qword `+0x10` and byte `+0x18`; it is not reimplemented here.

## Source and independent checks

`src/node115-margin-tree-range` accepts raw node buffers addressed by synthetic
identities. It never dereferences native pointers. The validation wrapper checks
the representation premises: finite consistent height, present unique nodes,
strictly ordered unique keys, correct child bounds and parent links. These
checks make the offline source view safe; they are not a claim that the original
traversal validates malformed input. In particular, duplicate keys are outside
this valid-tree domain. Insertion, duplicate replacement and representation
conversion remain part of HL115-046.

Four Rust tests pass in debug and release, with strict Clippy. The main test
checks all 1,849 lower/upper pairs formed by 43 bounds against an independently
flattened in-order sequence on a height-two tree. A separate test verifies exact
upper matches and row ownership, including separators stored at the root and
at both internal children. Empty roots/leaves, single-leaf absence, unsigned
extremes, invalid bounds, duplicate keys and inconsistent parent/child metadata
are covered. No native code is executed or emulated.

The static packet checks four windows: 2,627 bytes, 678 instructions, 91 facts
and 48 deliberately corrupted instruction/table controls. All controls are
rejected. Instruction parsing is pinned to the original ELF digest and FDEs.

```sh
PYTHONPATH=/path/to/capstone python3 research/work-items/RE-007-node115-margin-tree-range/verify.py --target /path/to/original/hl-node
cargo test --offline --manifest-path src/node115-margin-tree-range/Cargo.toml
cargo test --offline --release --manifest-path src/node115-margin-tree-range/Cargo.toml
cargo clippy --offline --manifest-path src/node115-margin-tree-range/Cargo.toml --all-targets -- -D warnings
```

## Limits

Allocator behavior, table constructors, duplicate replacement, conversion
thresholds, concurrent mutation and full margin/risk behavior are unresolved.
This is a valid-tree search and selected-row contract, not runtime equivalence
or a completed component gate. Existing full-scope gates remain false.
