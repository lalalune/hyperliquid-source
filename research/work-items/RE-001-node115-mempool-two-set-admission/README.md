# RE-001: node #115 two-set mempool admission predicate

- Component: consensus mempool admission; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses; interval ends are exclusive.
- Evidence: helper `0x57bbfd0..0x57bc24c` (636 bytes) plus enclosing caller FDE `0x2e1a120..0x2e1b59f` (5,247 bytes), 5,883 bytes total. The caller is context, not a claim to its full reconstruction. Gates remain false.

## Finding

This closes the raw contract of the admission helper that prior add-tx work left opaque. Its three acceptance routes have a fixed precedence:

1. With configuration byte `+0x38 == 0`, a **nonempty** action vector bypasses both set lookups if every action's dword at `+0x10` equals `0xdc` and every qword at `+0x38` equals configuration qword `+0x30`.
2. Otherwise, membership of the supplied 20-byte key in the first set succeeds without checking action contents or requiring a nonempty vector.
3. Otherwise, membership in the second set succeeds only for a **nonempty** vector in which every action satisfies the selector policy below.

Missing both sets or failing the second-set action policy rejects. The caller at `0x2e1ad86` tests the raw result byte against `0x2e` before proceeding to its already documented insertion/representation maintenance. This helper's success is only that local admission result.

For the second-set route, the native code loads a **qword** tag at action `+0x10`, subtracts `0x86`, and substitutes `0x14` on unsigned underflow. Let that adjusted value be A. The action is allowed when `(A - 0x56) mod 2^32 < 2`, or when `A == 0x3c` and action byte `+0x18 == 2`. For ordinary small tags this means `0xdc`, `0xdd`, or `0xc2` with subtype 2. The pair test uses a 32-bit LEA/range comparison, whereas the subtype arm compares the full adjusted qword. Thus hypothetical noncanonical high tag bits behave differently on these arms; the packet records the instruction widths without claiming such tags are constructible through a source enum or decoder.

The vector pointer is descriptor `+8`, count is `+0x10`, and stride is `0x168`. The key is descriptor `+0x20..+0x34`. Set one uses configuration root/height `+0/+8`; set two uses `+0x18/+0x20`. Their inline searches compare 20-byte keys. Generic B-tree invariants and set population are not reconstructed.

Success writes only result byte `0x2e`. Rejection writes `0x26`, the 20-byte key at output `+1`, and the supplied 32-byte hash at output `+0x15`. Payload bytes on success are not initialized by this helper, and the caller reads only the tag for this decision. No public action names, “system” exception, authority or trust meaning is inferred from the raw fields.

| Boundary | Local result |
| --- | --- |
| Empty vector | Reject, even with secondary membership |
| Primary membership | Success, including empty or otherwise disallowed actions |
| Matching nonempty bypass list, configuration byte zero | Success without set membership |
| Same list, configuration byte nonzero | Set policy applies |
| Secondary member, any disallowed action | Reject the entire list |
| Secondary member, all allowed actions | Success |

The independent relations cover every subtype byte, small and selected high-bit tags, ordered two-action lists, empty vectors, configuration byte values and membership combinations. Actual operand mutations distinguish the bypass tag, the second tag in the pair, and the subtype value. Valid vector extents are assumed; multiplication overflow or malformed pointers are not analyzed.

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Three changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-mempool-two-set-admission/export_disassembly.py
python3 research/work-items/RE-001-node115-mempool-two-set-admission/verify.py --controls
python3 research/work-items/RE-001-node115-mempool-two-set-admission/relations.py
python3 -m unittest discover -s tests -p 'test_node115_mempool_two_set_admission.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-mempool-two-set-admission/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

The all-state audit is in `scope-audit.json` and `pr-census.json.bz2`. [PR #2632](https://github.com/lalalune/hyperliquid-source/pull/2632) names this helper as an opaque prerequisite and owns the later add-tx representation hysteresis. [PR #2577](https://github.com/lalalune/hyperliquid-source/pull/2577) covers a different global-action preflight. [PR #1250](https://github.com/lalalune/hyperliquid-source/pull/1250) and [PR #1260](https://github.com/lalalune/hyperliquid-source/pull/1260) cover signed-action/VoteGlobal handling, while [PR #2081](https://github.com/lalalune/hyperliquid-source/pull/2081) covers cache found-entry behavior. Those claims do not establish this helper's ordered three-route predicate. The separate FIFO replacement and block-displacement packets also do not own this admission question.

Open and closed PR metadata and available patches were inspected, including older-release analogues. GitHub omits patches and caps a large historical file list; limitations are recorded. This is a bounded finding at that snapshot, not a guarantee about unpublished or future work.

New analysis and verification are independently authored under the repository MIT license. Export/parsing/checking helpers adapt existing MIT research packets, especially registry-row-labels and quote-midpoint-product-guard. No unlicensed inferred source was copied. Binary and imported-reference rights remain unchanged. There is no source-to-target equivalence, full component completion or hosted-CI claim. Captured code is never executed or emulated; no live requests or signing are used.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
