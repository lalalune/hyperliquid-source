# RE-001: node #115 index-authorized mempool block displacement

- Component: consensus mempool; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses; interval ends are exclusive.
- Evidence: complete FDE `0x2e1da10..0x2e1f73c`, 7,468 bytes. Only the collision policy below is interpreted; gates remain false.

## Finding

Registration does not reject every collision in its block-row scalar. A separate u64-to-32-byte index can authorize displacement, subject to a strict floor check. This is a mempool policy; it does not replace the consensus verifier's separately documented same-round rejection.

The input's raw variant at `+0x18` selects a qword at `+0x50` when it equals `0x8000000000000001`, otherwise at `+0xa0`. Define **H = min(U64_MAX, selected + 1)**. The wrapper first rejects H below owner `+0x2c8`. It also returns through its earlier raw-4 result when the incoming hash is already present; the displacement policy starts after that lookup misses. It then scans the block collection at owner `+0x208`, applying the same scalar projection, and stops at the **first equal H** in that collection's iteration order. U64_MAX-1 and U64_MAX therefore collide under this projection. No collision continues ordinary registration.

For an existing equal-H row, the wrapper requires both:

1. H is **strictly greater** than the floor at `+0x2c8`.
2. The auxiliary u64-keyed collection at owner `+0xc0` contains H and its 32-byte value exactly equals the incoming hash.

A missing index entry, unequal hash, or H equal to the floor follows the conflict result (outer raw 2, nested raw 0x10). The full equality combines two 16-byte SIMD comparisons: every byte participates. These conditions precede the removal call. The packet does not infer who populated the authorizing index or whether it is trusted under other invariants.

On the authorized route, it requests removal of the **old row's hash**, not the incoming hash, from owner `+0x208`. Tree and alternate collection representations have separate removal paths. A found result is converted for the exact 24-byte event `evicting displaced block`; a missing removal result skips that event. Both routes set the displacement flag and jump back to ordinary registration at `0x2e1e12c`, before transaction-list resolution and eventual insertion. Removal is thus requested before later registration can succeed or fail; atomic rollback is not established. The traversal and drop glue after the event remain context, not new collection invariants.

| Native interval | Observation |
| --- | --- |
| `0x2e1da3e..0x2e1da84` | Input selection, saturating scalar and lower floor gate |
| `0x2e1e040..0x2e1e123` | First equal scalar in the stored-row iterator |
| `0x2e1e193..0x2e1e269` | Strict floor check and u64-key tree lookup |
| `0x2e1ea2c..0x2e1ea88` | Alternate auxiliary-index lookup |
| `0x2e1eb2e..0x2e1eb60` | Both hash halves and full comparison mask |
| `0x2e1ecaf..0x2e1edaa` | Old-key removal and found-result event |
| `0x2e1f13c..0x2e1f19b` | Alternate removal path |
| `0x2e1f47c..0x2e1f48b` | Flag before re-entering normal registration |

“Height” is a plausible role for H, not a proven public field name. Generic map equality/repair, unknown-transaction rows, complete block acceptance, ownership invariants, index population, concurrent execution and rollback are outside the claim. Relations use supplied abstract iterator and lookup outcomes; captured instructions are never executed or emulated.

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Three changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-mempool-index-authorized-displacement/export_disassembly.py
python3 research/work-items/RE-001-node115-mempool-index-authorized-displacement/verify.py --controls
python3 research/work-items/RE-001-node115-mempool-index-authorized-displacement/relations.py
python3 -m unittest discover -s tests -p 'test_node115_mempool_index_authorized_displacement.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-mempool-index-authorized-displacement/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

The all-state audit is in `scope-audit.json` and `pr-census.json.bz2`. [PR #975](https://github.com/lalalune/hyperliquid-source/pull/975) and [PR #1280](https://github.com/lalalune/hyperliquid-source/pull/1280) cover a different consensus-verifier admission path and unknown-transaction handling. [PR #1567](https://github.com/lalalune/hyperliquid-source/pull/1567) and [PR #999](https://github.com/lalalune/hyperliquid-source/pull/999) cover client batch/proof buffering. [PR #2632](https://github.com/lalalune/hyperliquid-source/pull/2632) covers add-tx representation hysteresis. None establishes the selected mempool collision's strict-floor plus auxiliary-hash authorization and old-key removal ordering.

Open and closed PR metadata and available patches were inspected, including older-release analogues. GitHub omits many patches and caps a large historical file list; the audit records those limits. This is a bounded finding at that snapshot, not a guarantee about unpublished work or future submissions.

New analysis and verification are independently authored under the repository MIT license. Export/parsing/checking helpers adapt existing MIT research packets, especially registry-row-labels and quote-midpoint-product-guard. No unlicensed inferred source was copied. Binary and imported-reference rights remain unchanged. There is no source-to-target equivalence, full component completion or hosted-CI claim.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
