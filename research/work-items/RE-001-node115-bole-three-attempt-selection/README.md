# RE-001: node #115 BOLE helper's three-attempt selection policy

- Component: BOLE-associated helper; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses; interval ends are exclusive.
- Measured evidence: one complete FDE, `0x2bb52a0..0x2bb68d6`, 5,686 bytes. Full-body authentication does not imply full recovery of the inner accounting.
- Scope: quantity preparation, retry selection and final-result normalization below. Component gates remain false.

## Finding

This helper prepares three local attempt descriptors: unscaled, binary64 `0.99`, and binary64 `0.9`, in that order. It tries at most three quantities. The scaled attempts apply their factor to a freshly selected base quantity on each iteration, **not** to the previous attempt's scaled result.

Each iteration reloads input qword `+8`. If the low byte of input qword `+0` is zero, it invokes helper `0x2bba100` afresh; a successful helper result supplies that attempt's base. A helper error becomes the attempt's raw tag `3` with the returned error byte. If that low byte is nonzero, the provided `+8` quantity is used directly. The helper's computation and side effects remain opaque.

After each attempt, the native code saves the latest result and applies a separate full-qword selector:

| Input qword `+0` | Latest raw result tag | Continue? |
| --- | --- | --- |
| Nonzero | Any | Stop after the first attempt |
| Zero | `3` or `4` | Try the next descriptor if fewer than three were tried |
| Zero | Any other | Stop and retain the latest result |

The retry test is the unsigned expression `(tag - 5) >= U64_MAX - 1`, which selects exactly tags 3 and 4. It is not a generic retry on every nonzero or error-shaped result. The width distinction also matters: a noncanonical mode word `256` has a zero low byte and calls the base helper, but the full nonzero qword stops further attempts. No claim is made that normal callers construct such a word.

For a scaled descriptor, the factor must lie in `[0,1]`; the two built-in factors satisfy that condition. The u64 base converts to binary64, multiplication occurs, a nonfinite product becomes zero, the value is clamped to `[0,2^64]`, and conversion truncates with unsigned saturation. For example, supplied per-attempt bases `[10000,20000,30000]` yield prepared quantities `[10000,19800,27000]`. This example isolates the selection contract; the opaque helper is not asserted to produce those bases in a live node.

On final return, raw tag `4` is normalized to tag `3` with byte `5` at output `+8`. Other tags retain the latest 0x110-byte payload copied from the saved result, and the final tag is written at output `+0`. There is no best-result comparison across attempts in this selected control flow. The unrelated inner raw `0x11` check is not the retry predicate and is not newly interpreted here.

| Native interval | Observation |
| --- | --- |
| `0x2bb532c..0x2bb538c` | Local attempt descriptors and two immediate f64 factors |
| `0x2bb5401..0x2bb54db` | Per-attempt reload and byte-wide base-helper selector |
| `0x2bb54db..0x2bb55d4` | Factor admission, multiplication, finite/clamp/u64 conversion |
| `0x2bb5985..0x2bb5a01` | Latest result, qword selector, exact retry set, three-attempt bound |
| `0x2bb67e2..0x2bb6818` | Final tag normalization and payload publication |

The source Location `l1/src/bole/user_state.rs:239:44` supports the BOLE component context. The caller's action name, inner accounting, rollback/isolation, units, and any liquidation or fill effects remain unresolved. The relation checker supplies explicit inner results and bases to test only this wrapper's policy.

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Three changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-bole-three-attempt-selection/export_disassembly.py
python3 research/work-items/RE-001-node115-bole-three-attempt-selection/verify.py --controls
python3 research/work-items/RE-001-node115-bole-three-attempt-selection/relations.py
python3 -m unittest discover -s tests -p 'test_node115_bole_three_attempt_selection.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-bole-three-attempt-selection/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

The all-state audit is in `scope-audit.json` and `pr-census.json.bz2`. [PR #2598](https://github.com/lalalune/hyperliquid-source/pull/2598) covers record-tail copying in this same FDE; it is credited as context. [PR #986](https://github.com/lalalune/hyperliquid-source/pull/986) covers a different outer raw-0x11 failure policy, [PR #1021](https://github.com/lalalune/hyperliquid-source/pull/1021) sweep/order amounts, [PR #944](https://github.com/lalalune/hyperliquid-source/pull/944) an enclosing BOLE step, and [PR #2274](https://github.com/lalalune/hyperliquid-source/pull/2274) free-entry selection. This packet closes the distinct three-descriptor, fresh-base, exact-tag retry contract; it does not reclaim those earlier policies.

The audit inspected open and closed PR metadata and available patches, including prior releases. GitHub omits many patches and caps a large historical PR's file list; these limitations are recorded. This is a bounded finding at the stated snapshot, not a guarantee about unpublished work or future submissions.

New analysis and verification are independently authored under the repository MIT license. Generic export/parsing/checking helpers adapt existing MIT research packets, especially registry-row-labels and quote-midpoint-product-guard. No unlicensed inferred source was copied. Binary and imported-reference rights remain unchanged. There is no source-to-target equivalence, full component completion or hosted-CI claim.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
