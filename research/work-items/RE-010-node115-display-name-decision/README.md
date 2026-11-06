# RE-010: node115 display-name decision

This work implements the already recovered `setDisplayName` branch order as a
bounded, independently authored Rust decision function.

- Component: `action-dispatch`, task RE-010.
- Target: Linux x86-64 node115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Existing evidence: `research/work-items/RE-010-display-name-path-115`.
- Claim status: bytes, FDE extents, body hashes and branch vectors are
  observations; the safe API names are project-authored inferences.

## Reproduce

From the repository root with Python 3.12 and Rust 1.95:

```sh
python3 tools/artifacts.py verify
python3 tools/re010_display_name_decision115.py
python3 -m unittest tests.test_re010_display_name_decision115 -v
(cd src/node115-display-name-decision && cargo test --offline --locked)
(cd src/node115-display-name-decision && cargo test --offline --locked --release)
(cd src/node115-display-name-decision && cargo fmt --all --check)
(cd src/node115-display-name-decision && cargo clippy --offline --locked --all-targets -- -D warnings)
(cd src/node115-display-name-decision && cargo build --offline --locked --release --lib)
python3 tools/catalogue.py --check
```

## Evidence

The display wrapper `0x2392200..0x2392308` is 264 bytes with SHA-256
`483533a7ffcc753a1eca1d168a2e937f8523919de2a2d23a06e0c453a44be3a5`.
The display core `0x2c76380..0x2c766dc` is 860 bytes with SHA-256
`c62228768dba0728cc302de45383c29ed52c692c394939651959ca7e905dc677`.

The selected decision order is:

| Condition | Outer word | Result word | Mutation |
| --- | ---: | ---: | --- |
| Prior key rejection | 15 | 288 | none |
| Length at least 101 | 15 | 344 | none |
| Length zero | 14 | 418 | erase |
| Length 21 through 100 | 15 | 226 | none |
| Length 1 or 2 | 15 | 227 | none |
| Length 3 through 20 and duplicate | 15 | 228 | none |
| Length 3 through 20 and unique | 14 | 418 | upsert |

The existing `branch-vectors.tsv` retains all fourteen selected boundary rows.
The new verifier authenticates both complete FDE bodies and the raw wrapper/core
decision windows before checking those rows.

The table is not a complete predicate cross product. Prior rejection at length
zero, duplicate at lengths 1-2 and duplicate at lengths 21-100 are inferred
from the verified native branch order and exercised as synthetic boundary
controls; they are not represented as captured target observations.
The Python tests skip when the authenticated node115 binary is not materialized.

## Implementation and comparison

Implementation: `src/node115-display-name-decision`.

- `classify` receives the length and two already-evaluated predicates.
- It preserves the native decision priority and returns path, outer word,
  result word and logical mutation category.
- The crate is `no_std`, allocation-free, dependency-free and forbids unsafe.
- Tests cover the frozen vectors, every boundary, `u64::MAX`, prior-rejection
  dominance and the complete 0 through 101 length range.

The JSON decoder, account-key comparisons, string ownership, container scan,
allocator, erase/upsert helpers, transaction rollback and wire response remain
outside this relation. Compiled source/target identity and whole action
equivalence are not claimed.

## Results and limitations

The scoped denominator is two complete FDE bodies, two raw windows and fourteen
frozen branch vectors, plus deterministic boundary checks. These are not
function or component coverage counts. No progress gate changes.

Next question: bind the identity helper and duplicate predicate inputs to the
actual decoded action object, then reconstruct the storage mutation as a
separate validated relation.
