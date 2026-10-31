# RE-001: four-byte records and conditional batch bounds at 0x56319fd

- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Linked-VA candidate: `[0x56319fd,0x5631ef2)`, 1,269 bytes / 324 rows,
  SHA-256 `00933a9b47d97b4ac90e7845469b6a4b0e3d76357432bf6e86f65d7bd215c425`.
- Scope: exact record-field/ordered write transfers, divide-by-7/10 expressions,
  zero-quotient/input-order exits and conditional per-batch access bounds.
- Status: partial fixed-artifact static research; no component gate requested.

## Problem and resulting contract

[PR #981](https://github.com/lalalune/hyperliquid-source/pull/981) establishes
the two boundary candidates in this unwindless gap while leaving semantics
unresolved. [#1022](https://github.com/lalalune/hyperliquid-source/pull/1022)
analyzes the first 1,149-byte candidate's fixed byte emission. This packet
independently reads the maintained base bytes for the second candidate; it
imports neither unmerged analyzer and leaves both published heads unchanged.

The second candidate reads four-byte runtime records: a 16-bit payload at
bytes0..1, a shift byte at2, and an independent unsigned cursor advance at3.
Twenty WORD stores occur per executed inner body, five per lane. Each always
writes two bytes, including when a cursor advances only one. The ordered
write events preserve that overlap and the final extra physical byte; no
logical-byte count is substituted for the store width.

Its batch arithmetic uses all four fixed output-end operands and the exact
unsigned divide-by-10 sequence, while input distance is divided by7. The
guard returns before the body when the selected quotient is zero; only a
positive quotient reaches three unsigned input-order checks. No table,
input-refill or output-lane access occurs on the first zero-quotient exit.
State/frame accesses and the twelve state writebacks still occur.

[PROOF.md](PROOF.md) binds these observations to the actual source operands
and gives the full all-u64 division identities and conditional bound:

```
q = min(floor((I0-L)/7), floor(min_j(Ej-Oj)/10))
stop = O3 + 5q
1 <= J <= q
last written byte in lane i < Oi_initial + 10q <= Ei
refill cursor >= initial_I0 - 7q >= L
```

The capacity interpretation assumes genuine nonwrapping regions, selected
advance bytes in1..2 and nonzero post-shift BSF operands, plus the stated
input/table/frame/image separation. The machine does not validate all those
premises. They remain unverified conditions on an unrecovered caller/table
producer. Raw advances are0..255; zero can defeat progress and values above2
can defeat this capacity bound. These are proof-domain gaps, not target bugs.

The raw transfer is retained independently of that conditional theorem. Each
record's payload, shift and advance uses are checked against a width-explicit
term DAG over all324 rows, complete local CFG and six symbolic phases. This
does not evaluate a concrete CPU state, choose runtime table contents or run
a loop. No original algorithm, source type, ABI or function name is inferred.

## Reproduce and validation

Recorded environment: Linux x86-64, Python3.12.14, GNU objdump2.44. From the
repository root, use an owned short TMPDIR (the author used `/tmp/hvrec`):

```sh
mkdir -p /tmp/hvrec work
PYTHONDONTWRITEBYTECODE=1 TMPDIR=/tmp/hvrec python3 -B \
  tools/node94_gap56319fd_variable_records.py --output-dir work/variable-records
PYTHONDONTWRITEBYTECODE=1 TMPDIR=/tmp/hvrec python3 -B -m unittest discover \
  -s tests -p test_node94_gap56319fd_variable_records.py -v
make --jobs=1 'PYTHON=python3 -B' doctor verify test catalogue-check reproduce
```

`REPORT.json`, `instructions.json` and `native.objdump` are the fresh producer
outputs; `OUTPUT-MANIFEST.json` binds them. `MANIFEST.json` binds the complete
packet/source/test files. The producer admits one original ELF descriptor/mmap,
copies only1,269 bytes to the native decoder, and checks the full input hash
again afterward. GNU never reopens the original ELF pathname. Pre/post hashes
are not an atomic snapshot guarantee against transient in-place writes.

The twelve focused tests use genuine target bytes and fresh native decodes
of private tiny mutations: wrong reciprocal/shift, omitted output minima,
zero/input-order operands, record fields, payload stride/source, WORD-to-BYTE
store, refill arithmetic, aligned-but-wrong backedge, state writes and saved
registers. They verify the mutable exit-stop cutpoint, reject a restored wrong
private GNU view, and exercise actual CLI reproducibility, bad-input refusal
and preservation of existing evidence. No target executable or emulator runs.

Focused results and exact source/input hashes are in `FOCUSED-VALIDATION.json`.
`PREPARATION-FAILURE.json` preserves an author read-inventory omission of the
saved-stop CMP; it was corrected before freeze. Final committed-tree required
checks are reported separately in the PR; focused success is not hosted CI.

## Limits and next question

Earlier FDE/boundary context is credited to #981. This packet does not establish
incoming callers, a runtime table producer, original source ownership, a Rust
implementation/build, whole-call termination, arbitrary-state safety, function
coverage, binary equivalence or any accepted progress gate. No unlicensed
inferred reference source was read or copied. The finite symbolic core is
independently authored and included standalone, with no unmerged dependency.

The next useful question is which caller constructs the state and records,
and whether it establishes the recorded advance, BSF, allocation and separation
conditions before this entry. That would qualify a wider caller contract.
