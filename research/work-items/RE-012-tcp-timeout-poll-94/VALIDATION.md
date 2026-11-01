# Validation record

Target: node #94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Environment: macOS arm64, Python 3.14.3, GNU objdump 2.47.20260726 and Apple
LLVM objdump 21.0.0. The raw native version strings and reused-parser hashes
are retained in `observed/records.json`.

Commands run from repository root:

```sh
python3 -B research/work-items/RE-012-tcp-timeout-poll-94/collect.py --out research/work-items/RE-012-tcp-timeout-poll-94/observed.next
python3 -B research/work-items/RE-012-tcp-timeout-poll-94/verify.py > research/work-items/RE-012-tcp-timeout-poll-94/validation.json
python3 -O -B research/work-items/RE-012-tcp-timeout-poll-94/verify.py > research/work-items/RE-012-tcp-timeout-poll-94/validation.optimized.json
cmp research/work-items/RE-012-tcp-timeout-poll-94/validation.json research/work-items/RE-012-tcp-timeout-poll-94/validation.optimized.json
```

The fresh `observed.next` export was checked for exactly the thirteen expected
files and replaced this packet's earlier development export as `observed`.
Both verifier invocations returned zero and their result JSON is byte-identical.
Each verifier invocation independently makes two new private input snapshots
and two full export trees, requiring both trees to match the retained thirteen
files exactly. This is four fresh regenerations across the two invocations,
not four independent semantic tests.

| Check | Result and denominator |
| --- | --- |
| Original/full temporary-copy SHA-256 | Matches pinned target; copy checked before and after native exports |
| Actual FDE range and direct index link | 6 / 6 |
| Native bytes versus authenticated target | 5,742 / 5,742 bytes, GNU and LLVM |
| Native instruction partitions | 1,225 / 1,225 rows after the stated LOCK grouping |
| Corruption/rejection controls | 59 / 59, both ordinary and optimized Python |
| Fresh regeneration | 2 / 2 equal retained files per verifier invocation |
| Witness-subset sensitivity | Unselected byte mutation accepted by subset check, rejected by complete byte comparison |

The 59 controls are 27 fixed-witness mutations, 2 dispatch-table mutations,
6 relocation-addend and 6 relocation-symbol-index mutations, 6 FDE-range
mutations, 1 unwind-index encoding mutation, 5 LSDA call-site fact mutations,
4 native-output/target-byte controls, wrong target digest and existing output.
Witness, table, relocation, FDE and LSDA controls call the relevant checker
directly below the full-image hash gate. LSDA controls detect a change from
the retained call-site facts; they do not claim the modified table is invalid
according to the entire exception-handling specification.

The first development comparison failed because LLVM emitted LOCK as a
separate one-byte row. That raw difference remains visible in the final
native exports: controller 191 GNU / 192 LLVM rows, write adapter 117 / 119,
cleanup context 66 / 68; the other ranges have equal row counts. The final
comparator joins only an adjacent `f0` / `lock` row and its next instruction.
No bytes, addresses, operands or whole instructions are excluded. A dangling
LOCK row is a negative control. This corrected the text-row interpretation;
it did not turn a byte mismatch into a match.

These are packet-level static checks. No captured binary, emulator, instruction
interpreter or network operation was run. No Rust component was compiled.
Repository-wide `make verify test catalogue-check` and `make reproduce` are
not claimed by this subtask; any enclosing submission must report those
separately. No generated catalogue/progress changes or acceptance-gate advance
are requested.
