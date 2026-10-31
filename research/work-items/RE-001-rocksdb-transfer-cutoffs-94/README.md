# RE-001: RocksDB transfer diagnostic entry cutoffs

- Component: node runtime / EVM KVS. Question: which cumulative-counter values
  enter the captured large-transfer diagnostic arms?
- Node #94 SHA-256:
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference
  `999556f6e0a474b8312db96ec3149e1c44e97c23` consulted only as a lead.
- Status: observed instruction/data bindings and unsigned integer predicates;
  counter semantics and eventual process behavior remain unresolved.

## Reproduce

From the repository root with CPython 3.12.14:

```sh
python tools/rocksdb_cutoffs_static.py --out work/rocksdb-cutoffs-94.json
python -m unittest discover -s tests -p test_rocksdb_cutoffs_static.py -v
python research/work-items/RE-001-rocksdb-transfer-cutoffs-94/export_disassembly.py
```

Verifier and tests use the standard library. The optional exporter uses Capstone
5.0.6, x86-64 Intel syntax. Inspected Windows wheel SHA-256:
`761c3deae00b22ac697081cdae1383bb90659dd0d79387a09cf5bdbb22b17064`.
Only static parsing/disassembly runs; no captured program or TCP/DB action runs.

`excerpts.capstone.txt` retains **643 bytes / 95 instructions** across five
predicate/diagnostic selections, raw original FDE/CIE records and enclosing body
hashes. Complete enclosing frames were decoded solely to validate instruction
boundaries: **102,104 bytes / 17,234 instructions**. Those larger numbers do not
measure recovered async semantics. Addresses are unrelocated ELF VAs; selected
`.text` offsets are VA minus `0x1000`. No normalization masks are used.

## Observations

| Compare VA | Shift | Large-arm entry | Captured source Location | Diagnostic |
| --- | --- | --- | --- | --- |
| `0x1fd6660` | 10 | `0x1fd6668` | `node/src/evm_kvs.rs:96:9` | `rocksdb from tcp stream large` |
| `0x2266b45` | 11 | `0x2266b56` | `node/src/evm_kvs.rs:151:13` | `rocksdb from tcp stream too large, exiting` |
| `0x435aca3` | 11 | `0x435acbe` | same | same |
| `0x47475b2` | 11 | `0x4747c06` | same | same |
| `0x4b2dc3e` | 11 | `0x4b2dc4f` | same | same |

Each uses a 64-bit logical right shift and `CMP RAX,0x2e90edc` with unsigned
JBE/JA. Intervening MOV/MOVABS instructions preserve comparison flags. The
warning input loads `[RBX+0x68]`; the four other inputs load `[RCX]`. These are
raw observed words, not a recovered portable Rust counter type.

All five arms bind their actual RIP-relative template and source Location.
The templates are at `0x1f2116` and `0x1e65ff`; original prefix bytes, format
markers and terminators are retained in `records.json`. Source pointers resolve
through RELATIVE relocations to the captured EVM KVS path at `0x1f3f0f`.
All five calls use slot `0x576e978`, whose RELATIVE target is `0x143d010`.
The downstream critical-message implementation is outside this packet.

## Predicate interpretation and comparison

Let `K=48,828,124`. For unsigned 64-bit `x` and these shifts:

`(x >> s) > K` iff `x >= (K+1) * 2**s`.

Thus the warning arm starts at **50,000,000,000**, and the four other arms start
at **100,000,000,000**. Equality to those values enters the selected arm.
The reference `base/fu.rs` getter `K << 11` instead evaluates to 99,999,997,952,
the lower edge of the preceding bucket. A getter alone does not establish the
comparison's strictness; 2,048 additional values remain outside the large arm.
Individual-KV warning constants in reference `node/evm_kvs.rs` address a
different quantity and are not declared erroneous here. No reference code is
copied or modified.

The integer identity covers the abstract u64 primitive domain, not reachable
counter populations or executed node calls. Tests explicitly cover zero, maximum
u64, both sides of the threshold, and every residue in the preceding 1,024- or
2,048-value bucket. Six focused methods also mutate actual captured shift,
comparison, unsigned branch, input load, flag-preserving gap, template/source
binding, call relocation, FDE and target identity. The retained controls pass.

## Required checks and limits

Required Makefile-equivalent Python commands were attempted on Windows (make
is absent). Full suite: **363 tests in 111.028 seconds; 7 failures, 16 errors, 21 skips**.
All six new tests pass. This independent main-based branch excludes unmerged
#227, so its Windows output fixes are not present. Doctor
reports missing native tools. Eight artifact size/digest checks pass, then
missing GPG prevents signature verification. Imports reject the Windows
reference checkout (reserved `node/aux.rs` and hydrated LFS inputs preserved).
Catalogue fails on native backslash paths; reproduce stops at artifact
verification. Neither signature verification nor these checks is marked passed.

Counter updates, overflow behavior, framing/compression overhead, actual logging,
error propagation and process exit remain unproved. In particular, the literal
word `exiting` is not proof that the process exits. The message helper may apply
its own policy. No native execution, complete stream/storage protocol, Rust
reconstruction, hosted CI or progress gate is claimed. Next question: establish
counter-update ownership and downstream outcome before describing an effective
transfer limit.
