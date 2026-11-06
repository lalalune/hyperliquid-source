# RE-001: node #115 begin-block monotonic reset-bucket handoff

- Component: begin-block row maintenance; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses; interval ends are exclusive.
- Measured evidence: two complete enclosing FDEs, 48,377 bytes. Complete-body authentication does not imply semantic recovery of every instruction. The bounded new caller interval is `0x2be5fea..0x2be61c0` inside owner `0x2bdf8f0`; guard `0x4229fe0` is supporting context.
- Scope: the per-row quotient/store/flag relation below. Component gates remain false.

## Finding

A begin-block loop uses a row pointer at owner `+0x7c8`, count at `+0x7d0`, and stride `0x510`. It selects a row only when qword `row+0x378` equals the raw `INT64_MIN` bit pattern. Other rows skip both division and the guard call.

For a selected row, the caller converts the captured packed date/time to a nonnegative millisecond-shaped scalar `t`, divides it by qword `row+0x3c0`, and compares the unsigned quotient `q` with qword `row+0x3c8`:

| Quotient relative to stored value | Store | Flag passed to guard |
| --- | --- | --- |
| `q > old` | Write `q` before calling the guard | `1` |
| `q == old` | Keep `old` | `0` |
| `q < old` | Keep `old` | `0` |

The guard call occurs for every selected row that completes division, including unchanged buckets. Its first check accepts only flag byte `1`, so equal and backward buckets return before entering guard work. This is a monotonic high-water mark, not an unconditional assignment of the current bucket. Store ordering is also material: a later guard path that skips its operation does not undo the caller's already advanced quotient.

The division uses the 32-bit instruction only when both the scalar and divisor fit in u32; otherwise it uses unsigned 64-bit division. **There is no divisor-zero guard at this site.** A zero divisor reaches DIV and cannot complete the store/handoff normally. No captured code was executed to induce this condition, and no claim is made that a legitimate row constructor can produce a zero divisor.

The scalar conversion is supporting context: packed signed year is extracted by arithmetic shift 13, ordinal by shift 4 and mask `0x1ff`; a Gregorian day calculation subtracts 719163, multiplies by 86400, adds the seconds word, multiplies by 1000, and adds the nanos word divided by one million. The final signed result is floored at zero. The retained relation checks valid positive-year examples against Python's separate datetime implementation and the multiplication/shift nanosecond quotient at u32 division boundaries. Invalid packed dates and the producer's validity guarantees are unresolved.

The caller supplies the exact 16-byte label `reset_recent_ois`. Its closure carries pointers to `row+0x4f0`, the captured timestamp, and `row+0x380`. The guard's existing time check and selected vector drain/clear path are authenticated as context. The name alone does not establish what financial data the vector contains or that a reset completes. The new result is when the caller advances and enables that guard.

| Native interval | Observation |
| --- | --- |
| `0x2be5fea..0x2be602a` | Row vector, stride and label binding |
| `0x2be6030..0x2be6090` | Optional store, strict flag, closure and guard call |
| `0x2be6090..0x2be60d5` | Row progression and sentinel selection |
| `0x2be60d5..0x2be617a` | Date/time conversion and nonnegative scalar |
| `0x2be617a..0x2be61c0` | Width-selected division and strict greater-than route |
| `0x4229ff1..0x422a000` | Guard immediately returns unless flag is 1 |

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Three changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-begin-block-monotonic-reset-bucket/export_disassembly.py
python3 research/work-items/RE-001-node115-begin-block-monotonic-reset-bucket/verify.py --controls
python3 research/work-items/RE-001-node115-begin-block-monotonic-reset-bucket/relations.py
python3 -m unittest discover -s tests -p 'test_node115_begin_block_monotonic_reset_bucket.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-begin-block-monotonic-reset-bucket/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

The all-state audit is in `scope-audit.json` and `pr-census.json.bz2`. [PR #1303](https://github.com/lalalune/hyperliquid-source/pull/1303) covered a predecessor shared bucket guard and explicitly named the reset-recent-OI context; its date guard is credited rather than reclaimed. [PR #899](https://github.com/lalalune/hyperliquid-source/pull/899) covered a funding bucket, [PR #842](https://github.com/lalalune/hyperliquid-source/pull/842) empty-user pruning, and [PR #1131](https://github.com/lalalune/hyperliquid-source/pull/1131) volume-day pruning. This caller's row sentinel, divisor, monotonic stored quotient and flag handoff were not found in the available prior claims.

The audit inspected open and closed PR metadata and available patches, including prior releases. GitHub omits many patches and caps a large historical PR's file list; these limitations are recorded. This is a bounded finding at the stated snapshot, not a guarantee about unpublished work or future submissions.

New analysis and verification are independently authored under the repository MIT license. Generic export/parsing/checking helpers adapt existing MIT research packets, especially registry-row-labels and quote-midpoint-product-guard. No unlicensed inferred source was copied. Binary and imported-reference rights remain unchanged. There is no source-to-target equivalence, full component completion or hosted-CI claim.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
