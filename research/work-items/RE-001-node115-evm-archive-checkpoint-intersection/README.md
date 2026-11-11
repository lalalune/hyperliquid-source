# RE-001: node #115 EVM archive checkpoint-name intersection

- Component: EVM checkpoint archive preparation; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Four complete FDEs: owner `0x38c40f0..0x38c51ee`; selection collector `0x3d71420..0x3d715dc`; membership predicate `0x38dddb0..0x38ddfe6`; selected-name projection `0x37c0160..0x37c033e`. ELF virtual addresses with exclusive ends. The owner is retained as context, not a claim to its whole behavior. Gates remain false.

## Finding

The archive preparation intersects two independently obtained inputs: checkpoint rows and names from the periodic-state directory. Membership uses the canonical unsigned-decimal rendering of a checkpoint's height, not its stored path, numeric parsing of the directory name, a prefix, or a range test.

The owner creates the name set through `0x15b54d0`, obtains checkpoint rows through `0x4468e30`, and passes the rows plus captured name set to `0x3d71420`. The provider and directory-reader internals are credited context. Each checkpoint row occupies 32 bytes and supplies its unsigned 64-bit height at `+0x18`.

The predicate `0x38dddb0` renders that height into decimal bytes, then performs lexicographic set lookup. It compares bytes up to the shorter length and requires equal lengths after matching bytes. Only exact equality returns true. The collector retains true results and appends row pointers in the supplied order; it neither deduplicates equal heights nor synthesizes missing rows. The owner invokes sorting before the filter for multi-row inputs, but this packet does not reconstruct the full sorting implementation or claim its correctness.

| Height | Available directory name | Selected? |
| --- | --- | --- |
| 0 | `0` | Yes |
| 1 | `1` | Yes |
| 1 | `01`, `+1`, `1/child`, or `1 ` alone | No |
| 18446744073709551615 | `18446744073709551615` | Yes |
| Any height | `TAR_COMPLETE` alone | No |

For a nonempty selection the owner reads the height of the first and last selected rows, then supplies those values to its archive-path formatting calls. These are endpoints in the retained order; a new numeric-sort claim is intentionally not made. The same height-to-decimal projection is applied to every selected row by `0x37c0160` when building the downstream argument list. Thus the tested name and projected argument derive from the same field, even if a checkpoint's other descriptor bytes differ.

An empty intersection returns an empty result before tar argument preparation. The already-present-final-file branch also returns an empty result before that preparation. The existence/classification helper is a boundary here; no claim is made about all file types, race behavior or filesystem success. Generic cleanup and post-command publication behavior remain outside this question.

## Limits

Valid native descriptors, name-set invariants, readable extents and unsigned 64-bit heights are assumed. This packet does not reconstruct checkpoint discovery, marker choice, directory traversal, path formatting/quoting, the complete sort, command execution, filesystem publication or retention. No captured code, command or filesystem operation described by the target is executed. Case counts refer to offline operand-derived relations, not observed target executions.

The decimal relation reproduces the native quotient/remainder decomposition using its multiplicative division constants and two-digit table, then compares it with Python's independent unsigned-decimal rendering. Membership probes include canonical and noncanonical names, empty results, repeated heights, reversed row order and uint64 extremes. Three changes to actual table/branch bytes distinguish zero rendering, keep/drop polarity and exact equality.

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Three changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-evm-archive-checkpoint-intersection/export_disassembly.py
python3 research/work-items/RE-001-node115-evm-archive-checkpoint-intersection/verify.py --controls
python3 research/work-items/RE-001-node115-evm-archive-checkpoint-intersection/relations.py
python3 -m unittest discover -s tests -p 'test_node115_evm_archive_checkpoint_intersection.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-evm-archive-checkpoint-intersection/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

The packet retains an all-state scope audit and census. [PR #2134](https://github.com/lalalune/hyperliquid-source/pull/2134) covers the checkpoint provider, caller scheduling and separate later pruning, while explicitly leaving the first archive helper opaque. [PR #1120](https://github.com/lalalune/hyperliquid-source/pull/1120) records older-release tar fragments and row-tail projection. [#608](https://github.com/lalalune/hyperliquid-source/pull/608) and [#1917](https://github.com/lalalune/hyperliquid-source/pull/1917) own marker and retention context. This packet adds the canonical-name intersection, preservation of selected row order and selected endpoint handoff, not those prior findings.

GPT-6.1 Terra inspected open and closed PR metadata and available file evidence, including older-release analogues. Missing patches, a capped historical file list and unavailable prior PRs limit the audit. New analysis and relations are independently authored under MIT; ELF/export/corruption scaffolding adapts existing MIT packets. No unlicensed inferred source is copied or input rights changed. Full component completion, source equivalence and hosted CI are not claimed.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
