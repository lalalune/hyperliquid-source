# RE-001/storage: DB wrapper labels, lookup keys and construction gating

- Bounded question: how do the observed DB code byte and global state byte
  select label data, a lookup key and the optional construction arm?
- Node #94 SHA-256:
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference
  `999556f6e0a474b8312db96ec3149e1c44e97c23`, `db/db_hub.rs`, is a lead only.
- Status: static instruction/data observations and a raw branch model.
  No full storage ABI, database execution, Rust component or progress gate.

The earlier RE-009 storage/state-root packet explicitly leaves the db_hub
masks and reconstruction semantics unvalidated. This follows that open question;
it does not redo its Location ownership or hashing inventory.

## Reproduce

From repository root, CPython 3.12.14 on Windows:

```sh
python tools/db_code_routing_static.py --out work/db-code-routing-94.json
python -m unittest discover -s tests -p test_db_code_routing_static.py -v
python research/work-items/RE-001-db-code-routing-94/export_disassembly.py
```

The verifier/tests use the standard library. The optional raw export requires
Capstone 5.0.6, x86-64 Intel syntax. The inspected Windows wheel SHA-256 was
`761c3deae00b22ac697081cdae1383bb90659dd0d79387a09cf5bdbb22b17064`
(`capstone-5.0.6-py3-none-win_amd64.whl`). No captured code or database runs.

## Original ranges and bindings

ELF VAs, end exclusive; `.text` file offsets are VA minus `0x1000`:

| Start | End | Bytes |
| --- | --- | ---: |
| `0x358cea0` | `0x358d2d9` | 1081 |
| `0x358d2e0` | `0x358d719` | 1081 |
| `0x358d720` | `0x358db59` | 1081 |
| `0x459c6b0` | `0x459cae9` | 1081 |
| `0x459caf0` | `0x459cf29` | 1081 |
| `0x459cf30` | `0x459d369` | 1081 |

`records.json` contains each body hash, FDE/CIE address, selected table and
source Location. `wrappers.capstone.txt` retains **all 6,486 bytes / 1,440
instructions**, raw FDE/CIE records, and six 13-byte caller windows. Every
selected instruction address is checked against complete contiguous FDE decoding.
The caller windows are likewise checked after decoding their complete owner
FDEs. No component body-equivalence or normalized matching count is asserted.

Each wrapper references `db/src/db_hub.rs:60:18` in its missing-key arm. Both
label tables are backed by RELATIVE relocations: `0x56f1920` points to the
pool at `0x594ff2`, and `0x572d7e0` to `0x6f7394`.

## Findings

1. **The observed table span contains 28 labels.** Each of the first 28 slots
   points to `pool+2*index`. Both copies agree byte-for-byte. Index 4 is `Ps`;
   index 27 is the distinct lowercase `ps`. The reference enum/ALL list stops
   at index 26 and misses this latter table entry. The wrapper indexes the
   pointer table by the input byte and copies exactly one word from that pointer.
   This establishes the table span, not a complete enum-validity/reachability
   proof. The six concrete callers below do not supply index 27.
2. **Raw lookup keys use the two code masks.** Primary `0x081ffeff` selects
   key byte 0; otherwise auxiliary `0x00e00100` selects 1; otherwise key 2.
   Across indices 0..27 the counts are 21/4/3. Index 27 selects key 0.
   This does not establish filesystem paths or complete BTreeMap behavior.
3. **The third mask is indexed by global state, not the DB code.** The wrappers
   load global state via slot `0x576e928` -> `0x577b288`, then read byte `+0x48`
   after the initialization check/returning slow path. Let `c` be the DB code,
   `g` that raw byte and `a=(g-10) mod 256`. The construction arm is selected iff
   `c` is 21, 22 or 23, and either `a>=22` or bit `a` of `0x0020ff01` is zero.
   Equivalently the excluded global bytes are 10, 18..25 and 31.

The model compares the actual byte/shift/or/test operations with an independent
set-form predicate across **7,168 raw pairs** (28 code indices x 256 global
bytes): **0 mismatches**, 738 construction-arm pairs. This is exhaustive only
over that declared predicate domain, not native executions or reachable runtime
states. The global byte's business meaning is unknown.

For a concrete counterexample to a code-only rule, code 21 selects construction
with `g=0` and bypass with `g=10`. The reference's code-only timed-liner mask
cannot represent this dependence. The name/type of the optional state remains
inference: bypass writes the sign-bit sentinel, while the other arm calls
formatting/construction helpers whose full contracts are not recovered.

Six actual caller windows pass codes 24,25,26,23,21,22, respectively. In
particular the first three, at `0x3269c5c`, `0x3269e77` and `0x326a086`, always
bypass the construction arm for every modeled global byte. The reference's
`wrap_home` instead constructs state for those three codes under its code-only
rule. The caller constants, target displacements and intervening RDX setup are
retained; there is no invented code-27 caller or executed checkpoint operation.

## Controls and required checks

Six focused test methods pass. Controls alter actual label bytes, the 28th
pointer addend, all three masks, global/code gate instructions, a concrete caller
constant, the global relocation, FDE length and target identity. The two table
copies and all six wrapper bodies are checked. No reference implementation is copied.

Make is absent; its Python commands were invoked directly. Full suite:
**363 tests in 167.094 seconds; 7 failures, 16 errors, 21 skips**. All six new
tests pass. This main-based independent branch does not include unmerged #227;
remaining problems include missing binutils, Windows output/path expectations
and temporary-directory cleanup. Full suite or hosted CI success is not claimed.

Doctor reports missing prerequisites. Eight artifact size/digest checks pass,
then missing GPG prevents signature verification. Imports fail on the Windows
reference checkout (reserved `node/aux.rs`, hydrated LFS inputs retained unstaged).
Catalogue fails on native backslash paths. Reproduce is attempted and stops at
artifact verification. No original imports, pins, expected packets or gates change.

Unresolved: complete enum domain, index-27 reachability, global state meaning,
initialization/concurrency behavior, optional-state types, all callee effects,
storage compatibility and a reproducible Rust build. Next question: trace the
global-state producer and the construction-arm consumers before naming the policy.
