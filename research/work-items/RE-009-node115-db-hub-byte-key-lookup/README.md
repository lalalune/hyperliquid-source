# RE-009: node115 DB-hub byte-key lookup

This work turns the existing node115 DB-hub byte-key search evidence into an
independently authored Rust relation and checks it against frozen boundary
vectors.

- Component: `storage`, task RE-009.
- Target: Linux x86-64 node115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Existing evidence:
  `research/work-items/RE-009-node115-db-hub-byte-key`.
- Claim status: bytes, FDE extent, body digest and branch operands are
  observations; tree and API names are project-authored inferences.

## Reproduce

From the repository root with Python 3.12 and Rust 1.95:

```sh
python3 tools/artifacts.py verify
python3 tools/re009_db_hub_lookup115.py
python3 -m unittest tests.test_re009_db_hub_lookup115 -v
(cd src/node115-db-hub-byte-key && cargo test --offline --locked)
(cd src/node115-db-hub-byte-key && cargo test --offline --locked --release)
(cd src/node115-db-hub-byte-key && cargo fmt --all --check)
(cd src/node115-db-hub-byte-key && cargo clippy --offline --locked --all-targets -- -D warnings)
(cd src/node115-db-hub-byte-key && cargo build --offline --locked --release --lib)
python3 tools/catalogue.py --check
```

The Python verifier checks the complete target SHA-256, the selected 841-byte
FDE body, three instruction windows and all 1,284 frozen lookup cases. It does
not execute the captured node.

## Evidence

The selected FDE `0x1692ca0..0x1692fe9` has body SHA-256
`01f207a1ef95d113cf325e6b26a93e18260f89a6d96269823b1b70f75383be75`.
At `0x1692d20`, the native body zero-extends only the low byte of the incoming
word. At `0x1692d24..0x1692d92`, it scans a sorted key byte array, returns the
value at an equal key index, or descends through the child array at the first
key greater than or equal to the query. No matching key selects child index
equal to the node count.

The selected body scans the root before testing the remaining height. Therefore
height zero can return a root match but cannot descend. For a nonmatch,
`sub height, 1` followed by an unsigned-borrow branch is the missing-key path.
A null root or null selected child reaches the same recorded failure region.

The safe model rejects invalid node layouts that the native code assumes are
valid. The selected relation does not establish the persistence API, value
contents, complete tree constructors, concurrent mutation or malformed memory
behavior.

## Implementation and comparison

Implementation: `src/node115-db-hub-byte-key`.

- `Node::new` enforces one value per sorted unique byte key and `n + 1` child
  slots.
- `lookup` represents only the low query byte, first-greater-or-equal scan,
  equal-value selection, exact height behavior and child descent.
- The crate is `no_std`, allocation-free, dependency-free and forbids unsafe
  code.
- The frozen cases cover empty, singleton, edge, complete byte-alphabet,
  zero-height and high-query-bit inputs.

Before this change, `src/node115-db-hub-byte-key` did not exist and the
existing static evidence packet recorded no Rust implementation for this
relation. After the change, the bounded relation is executable and checked
against 1,284 frozen cases.

Compiled source/target byte identity, call-target equivalence, the complete
DB-hub API and database I/O remain unmeasured. No progress gate changes.

## Results and limitations

The selected denominators are one FDE body, three raw windows and 1,284 lookup
cases. Those are not function, storage or node coverage counts. The source tree,
allocator, helper closure, persistence semantics and malformed runtime state
remain open.

Next question: identify the constructor and ownership contract of the value
object returned at the equal-key route, then bind one real DB-hub read caller
without executing the target.
