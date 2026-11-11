# RE-001: node #115 stake-requirement raw selector 1 counts rows against a deadline

- Component: stake requirement selector; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses; interval ends are exclusive.
- Evidence: 1 complete FDEs, 1,761 bytes; boundaries/digests in `records.json`.
- Scope: the bounded policy below with unresolved helpers retained. All component gates remain false.

## Finding

The dispatch table at `0x60aeec` maps raw selectors 0, 1, 2 and 3 to `0x2c58c9f`, `0x2c58e0f`, `0x2c58cee` and `0x2c58dcd`. This packet studies **raw selector 1**. It obtains a row stream through opaque helpers and adds a zero-or-one contribution for each returned key, with checked u64 addition.

For each key, the observed policy is:

1. If map owner `+0x378` contains a row whose value byte is **zero**, contribute 1 immediately.
2. Otherwise query the timestamp map at owner `+0x358`. A missing timestamp contributes 1.
3. For a found 12-byte timestamp, call the time helper with integer offset **15,811,200** and a zero subsecond argument. That constant equals 183 × 86,400. The caller then attempts a date conversion; the helper/calendar internals remain outside this packet.
4. Compare the current triple at owner `+0x60/+0x64/+0x68` with the resulting deadline. The first 32-bit word is compared signed; the next two are unsigned. Equality is included. Contribute 1 iff the current triple is no later than the deadline.

If the intermediate range checks fail or the date conversion returns zero, the deadline is the **static triple `(0x7fffd6de, 86399, 999999999)`** at `0x4679d0`. A nearby stack zero is a temporary, not the final fallback. The numeric resemblance to a maximum date is not used as evidence for an original type name or calendar bound.

The sum at `0x2c58f53` uses ADD followed by a carry branch to the overflow panic. It is not saturating. Selector 0 calls an opaque row reducer, selector 2 checks account membership and selector 3 inspects another helper's raw result; those arms are retained in the complete FDE for context, not claimed as recovered requirement semantics. The iterator's chosen rows, the requirement's economic units, and the original selector enum names remain unresolved.

| Native interval | Observation |
| --- | --- |
| `0x2c58c81..0x2c58c9f` | Four-entry raw selector dispatch |
| `0x2c58f49..0x2c58f88` | Row iteration and checked contribution addition |
| `0x2c59030..0x2c59080` | Alternate-map zero-flag shortcut, shared with tree lookup |
| `0x2c59130..0x2c5919d` | Missing timestamp contributes; found timestamp/current triple |
| `0x2c591a1..0x2c591bd` | Offset helper arguments |
| `0x2c591bd..0x2c5927d` | Conversion checks and static fallback |
| `0x2c5927d..0x2c592a3` | Inclusive mixed signed/unsigned lexicographic comparison |

The relation checker supplies the helper-derived deadline explicitly. It verifies the caller's selection and comparison policy across raw signed-boundary words, unsigned boundaries, missing entries and fallback cases; it does not invent an implementation of the unresolved calendar helpers.

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Three changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-stake-requirement-deadline-count/export_disassembly.py
python3 research/work-items/RE-001-node115-stake-requirement-deadline-count/verify.py --controls
python3 research/work-items/RE-001-node115-stake-requirement-deadline-count/relations.py
python3 -m unittest discover -s tests -p 'test_node115_stake_requirement_deadline_count.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-stake-requirement-deadline-count/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

The all-state audit is in `scope-audit.json` and `pr-census.json.bz2`. [PR #2239](https://github.com/lalalune/hyperliquid-source/pull/2239) covered the requirement cursor while leaving `0x2c58c70` opaque. [PR #241](https://github.com/lalalune/hyperliquid-source/pull/241), [PR #706](https://github.com/lalalune/hyperliquid-source/pull/706) and [PR #707](https://github.com/lalalune/hyperliquid-source/pull/707) covered earlier-release requirement tables, cursors and multipliers. This packet isolates the raw-selector-1 row contribution and deadline comparison, with the prior table/cursor work credited.

The audit covers open and closed PR metadata and available patches. Missing patches and a capped historical file list are recorded limitations; unpublished work, alternative terminology and future submissions are not ruled out.

New analysis and verification are independently authored under the repository MIT license. Generic parsing/export/checking helpers adapt existing MIT packets. No unlicensed inferred source was copied. Binary and reference rights remain unchanged. There is no runtime equivalence, full component completion or hosted-CI claim.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
