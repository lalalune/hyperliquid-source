# RE-001: node #115 position helper has four distinct raw-value transitions

- Component: position mutation helper; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses; interval ends are exclusive.
- Measured evidence: one complete FDE, `0x4203320..0x42038d3`, 1,459 bytes. Exact body digest and bindings are in `records.json`.
- Scope: the four-way policy below; component gates remain false.

## Finding

After an opaque lookup/insertion, this helper updates row qword `+0x30` before calling the already studied size-update hook at `0x4206f70`. The update is not one uniform addition or proportional rescale. It selects among zero, growth, reduction and opening/sign-crossing rules using a separately supplied old signed size and a signed delta.

The final entry argument is a three-pointer bundle: `[bundle+0]` points to the old i64 size, `[bundle+8]` points to the input record, and `[bundle+0x10]` points to the side byte. Input qword `+0x250` must be at most `I64_MAX`; otherwise the observed unwrap-panic path is taken. A zero side byte makes that magnitude positive; any nonzero byte makes it negative. The new signed size is `saturating_add(old, delta)`, with overflow calling the diagnostic helper at `0x4524e40` before continuing with the signed bound. The supplied old size is **not assumed to equal row+0x10** without a caller invariant.

| Condition on the computed new size | New row qword `+0x30` |
| --- | --- |
| New size is zero | Zero, irrespective of the previous value |
| Old and new share a sign; delta's chosen direction matches old | `saturating_u64_add(previous, input[+0x258])` |
| Old and new share a sign; direction opposes old | Convert `previous` to nonnegative i64 or panic, then scale by binary64 `new / old`; apply the finite/clamp/cast rules below |
| Old is zero or old and new have different signs | Checked unsigned `input[+0x248] * abs(new)`; zero multiplicand returns zero; nonzero product must fit and be at most `I64_MAX - 1`, otherwise panic |

Direction remains meaningful for a zero input magnitude. For example, opposite-direction zero magnitude takes the reduction branch with ratio 1, retaining its i64 input restriction; the same-direction branch instead performs the unsigned addition from `+0x258`. No premise tying that addition operand to the magnitude is invented.

In the reduction branch, both signed sizes convert separately to binary64, then division precedes multiplication by the previous value. A nonfinite product becomes zero. A finite product is clamped to `[-2^63, 2^63]`, converted with truncation and signed upper saturation, and finally floored at zero. The native upper-cast comparison uses the greatest binary64 below `2^63`. These are observed conversion rules, not an assertion about ambient floating-point rounding mode. The relation checker uses round-to-nearest/ties-to-even and separately checks exact dyadic ratios using rational arithmetic.

The minimum i64 old value has a special negation guard in same-direction classification. The crossing branch computes its absolute magnitude as an unsigned word, so the `I64_MIN` bit pattern is preserved as magnitude `2^63` rather than interpreted as a valid positive i64. Its product bound remains `I64_MAX-1`. Same-direction value overflow follows a diagnostic call and unsigned saturation to `U64_MAX`; it does not use the crossing cap.

| Native interval | Observation |
| --- | --- |
| `0x4203592..0x42035e2` | Supplied old-size pointer, raw side, magnitude restriction and signed sum |
| `0x42035e2..0x420363b` | Sign/direction split and unsigned growth |
| `0x4203666..0x420371f` | Reduction precondition, ratio, finite check, clamp and cast |
| `0x420373b..0x420377b` | Signed size overflow continuation |
| `0x420377b..0x42037ea` | Zero, opening and crossing rules |
| `0x42037ea..0x420380b` | Raw value is stored before the credited size hook |
| `0x420385e..0x4203889` | Unsigned value overflow continuation |

The source Locations include `l1/src/perp_meta.rs`, `l1/src/qtys/impl_sz.rs` and `l1/src/clearinghouse/clearinghouse.rs`. They support the component context; field names such as cost basis, realized profit or entry notional, accounting units, fee integration, and complete fill behavior remain unproved. Lookup/insertion, the supplied old-size invariant, downstream mutation and notifications remain unresolved or credited prior context.

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Four changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-position-sign-transition-value/export_disassembly.py
python3 research/work-items/RE-001-node115-position-sign-transition-value/verify.py --controls
python3 research/work-items/RE-001-node115-position-sign-transition-value/relations.py
python3 -m unittest discover -s tests -p 'test_node115_position_sign_transition_value.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-position-sign-transition-value/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

The all-state audit is in `scope-audit.json` and `pr-census.json.bz2`. [PR #1066](https://github.com/lalalune/hyperliquid-source/pull/1066) explicitly left a predecessor perp position-update helper stubbed. [PR #1155](https://github.com/lalalune/hyperliquid-source/pull/1155) covered analogous spot-balance proportional scaling; the isolated ratio is credited prior context. [PR #1135](https://github.com/lalalune/hyperliquid-source/pull/1135) covered downstream reduce-only cleanup on a sign change, [PR #2204](https://github.com/lalalune/hyperliquid-source/pull/2204) mapped the size hook and [PR #2880](https://github.com/lalalune/hyperliquid-source/pull/2880) reconstructs its quantity-change stores and frontiers, and [PR #1255](https://github.com/lalalune/hyperliquid-source/pull/1255) concerned a different margin transfer. The new result is this helper's complete four-way raw-value contract and differing arithmetic bounds, not a port of those individual claims.

The audit inspected open and closed PR metadata and available patches, including prior releases. GitHub omits many patches and caps a large historical PR's file list; these limitations are recorded. This is a bounded finding at the stated snapshot, not a guarantee about unpublished work or future submissions.

New analysis and verification are independently authored under the repository MIT license. Generic export/parsing/checking helpers adapt existing MIT research packets, especially registry-row-labels and quote-midpoint-product-guard. No unlicensed inferred source was copied. Binary and imported-reference rights remain unchanged. There is no source-to-target equivalence, full component completion or hosted-CI claim.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
