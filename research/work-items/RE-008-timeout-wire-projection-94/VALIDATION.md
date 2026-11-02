# Observed validation

All commands ran in the isolated worktree rooted at
`/workspace/hyperliquid-re008-consensus-lane`, based on
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. New durable files are packet-local,
plus `tests/test_timeout_wire_projection94.py`. No captured program or
captured-instruction evaluator ran. Mutated ELF copies were mode 0600 and
were deleted with their temporary directory.

## Native evidence and controls

```sh
python3 research/work-items/RE-008-timeout-wire-projection-94/verify.py \
  --llvm /workspace/.tools/llvm19/usr/lib/llvm-19/bin/llvm-objdump \
  --report research/work-items/RE-008-timeout-wire-projection-94/validation.json
PYTHONHASHSEED=91 TZ=Pacific/Kiritimati python3 -O \
  research/work-items/RE-008-timeout-wire-projection-94/verify.py \
  --llvm /workspace/.tools/llvm19/usr/lib/llvm-19/bin/llvm-objdump \
  --report work/re008-timeout-wire/trimmed-optimized.json
```

Both commands exited 0: 55 controls rejected and two fresh native generations
per invocation matched every committed export/record byte. Each generation
contains 15 complete FDE bodies and 4 bounded caller corridors, 6036 selected
bytes / 1509 instruction rows; GNU and LLVM partitions agree without byte masks.
The full body hashes and FDE/CIE/index bindings also cover the three clipped
caller owners. This is static evidence reproduction, not a compiled match.

The optimized full JSON report was byte-identical to `validation.json`.
`validation-optimized.json` stores its command, environment, exit and raw-report
hash. The complete report bytes are preserved in `validation.json`.

The 55 controls are:

| Class | Count | What rejection establishes |
| --- | ---: | --- |
| Target identity and file-backed mapping | 2 | Wrong image and unavailable VA are refused |
| Semantic-window byte identity | 34 | Changed selected field/stride/width/caller windows are refused below the image hash; no semantic mutation claim |
| Dispatch table and tag data | 11 | Changed table entries or tag constant are refused |
| Native local CFG | 5 | Four real changed JNE destinations bypass mandatory operations, and one real entry RET makes success unreachable; both native decoders process the mutant with identity/witness/body guards disabled |
| Native FDE extent | 1 | Changed unwind range is refused with those equality guards disabled |
| Graph checker counterexamples | 2 | Vacuous and skipped-operation graphs are refused; these synthetic graph checks do not model x86 |

The native CFG controls are separate from the 34 window byte-identity controls. The
manual proof supplies instruction meanings; the checker proves only its stated
syntactic reachability/order properties. It does not prove feasible runtime
inputs, helper effects, exception behavior or a complete x86 semantics theorem.

## Repository checks

`repository-validation.json` records exact argv, exits and hashes for the
retained logs/result excerpts under `checks/`. The doctor and reproduction
receipts retain their full original output hashes and concise result excerpts.
Observed commands:

| Command | Exit | Outcome |
| --- | ---: | --- |
| `make doctor` | 0 | Static analysis tools available; exact rebuild evidence remains incomplete |
| `make verify` | 0 | All artifact hashes/signatures, 38 imported files and seven pinned source repositories verified |
| `make catalogue-check` | 0 | Generated scope/progress tables match pinned inputs |
| `make reproduce` | 0 | Inventories and refined literal classification reproduce retained evidence |
| `python3 -m unittest discover -s tests -p test_timeout_wire_projection94.py -v` | 0 | 5 tests pass; no external native export needed in this fast suite |

The root tests bind the authenticated target's field projection, selected
instruction witnesses, complete owner hashes/FDEs and retained raw bytes. Their
V boundary encodings and two-row ordering/152-byte example are synthetic formula
checks. A wrong raw-65-byte signature representation and a changed field order
are explicit counterexamples. They do not compare dynamic captured behavior.

Full `make test` is deferred to coordinator integration. Captured emulation
is opt-in and its enabling flags were unset; no inherent incompatibility with
the repository's default test command is claimed. Hosted CI, full-node builds,
Rust reconstruction and reconstructed-byte equivalence are not claimed.

## Input materialization and preserved setup failure

Initial `make verify` authenticated the retained captures but failed because
the new worktree had no initialized pinned reference. All seven local source
repositories were then compared against both `provenance/sources.json` and
the superproject's exact gitlinks before local materialization. The sole
reference LFS pointer's SHA-256 and size were compared against the source bytes
before copying. No input, source revision, submodule blob or mode was changed.

The freshly copied reference's real index initially reported a modified LFS
file despite the clean-filter hash matching the original pointer blob
`89786e68959fe5d9a2e56d3bd11096404778fcfa`; a fresh index was already clean.
Invocation-local standard LFS filters and refreshing the identical pointer's
index entry resolved that cached status. Those filters were passed only through
`GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_i`/`GIT_CONFIG_VALUE_i`, not persistent config.
The successful verification subsequently checked both real and fresh indexes.

## Remaining scope

The contract still depends on stable valid/disjoint memory, ordinary normal
callees and successful allocation. Clock/grow/allocator internals, unwind,
signature creation/recovery, decoding/canonicality, prefix/hash composition
and end-to-end consensus remain outside this packet. All completion gates stay
false. `scope-check.json` retains the ownership-search receipt and its limits.
