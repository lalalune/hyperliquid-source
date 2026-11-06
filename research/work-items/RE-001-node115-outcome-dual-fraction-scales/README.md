# RE-001: node #115 outcome settlement uses two fraction scales

- Component: outcome settlement; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses; ends are exclusive.
- Measured body: `0x3bf2be0..0x3bf442e`, 6,222 bytes, one complete FDE.
- Scope: the entry prerequisites and two independent numeric conversions before the downstream settlement loop. Helpers, payout accounting and original public types remain unresolved. All component gates remain false.

## Finding

The internal routine uses the original binary64 argument twice. It first multiplies by **1,000**, converts to an unsigned integer, and rejects only when that integer is greater than 1,000. It retains that integer and `1000 - integer`. Later, it independently multiplies the original argument by **100,000,000** and retains a second integer and `max(0, 100000000 - integer)`. The fine value is not reconstructed from the coarse value.

For each conversion, a nonfinite multiplication result becomes positive zero. Finite results are clamped to `[0, 2^64]`; truncation and saturation then produce a u64. The byte-bound constants include `2^63`, `2^64` and the largest binary64 value below `2^64`. Thus the conversion is not just an unchecked signed cast.

For example, under the documented binary64 arithmetic premise, an input near `0.0009` has a zero coarse value while retaining a nonzero fine value. The exact stored inputs and projected outputs are in `relations.json`; decimal display alone is not the fixture identity. An internal input of `1.0005` passes the coarse integer check, with a zero fine complement. **This does not mean an external action accepts that input:** prior work on the outer settlement wrapper documents a stricter `[0,1]` check. Likewise, the local handling of nonfinite values is not an external admission claim.

The conversion is also behind structural prerequisites. A record is found by the input key; the call to `0x46dfab0` returns two raw tagged values. Byte tag 1 from either propagates that result's byte error. The two result qwords at offsets `+8` and `+0x18` must agree, otherwise raw error 15 is returned. The coarse conversion and its raw error 18 occur next. Both indexed token records must then carry qword tag 1 at record offset `+0x60` before the fine conversion. A failed token tag returns raw error 0. The meaning of the referenced qwords, helper internals and original error names is not claimed.

| Native interval | Established observation |
| --- | --- |
| `0x3bf2c91..0x3bf2d28` | Opaque pair lookup; error propagation; equality prerequisite |
| `0x3bf2d28..0x3bf2d91` | Multiply original input by 1,000; finite test and clamp |
| `0x3bf2d91..0x3bf2dd3` | Unsigned truncation/saturation |
| `0x3bf2dd3..0x3bf2df8` | Reject integer > 1,000; save complementary pair |
| `0x3bf2df8..0x3bf2e57` | Checked token indices and both tag-one prerequisites |
| `0x3bf2e57..0x3bf2ee9` | Multiply original input by 100,000,000; independent conversion and saturating complement |

A complete native export is retained to expose surrounding control flow and cleanup. It is context, not a claim that the whole function or the per-user mutation loop has been recovered. Source Location records identify captured strings and coordinates only.

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` checks arithmetic statements using the target's actual constants and condition byte, compares bit-level finite classification and truncation with independent mathematical statements, and rejects three changed-operand counterfactuals. These are static relations, **not execution or emulation of captured instructions**, and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-outcome-dual-fraction-scales/export_disassembly.py
python3 research/work-items/RE-001-node115-outcome-dual-fraction-scales/verify.py --controls
python3 research/work-items/RE-001-node115-outcome-dual-fraction-scales/relations.py
python3 -m unittest discover -s tests -p 'test_node115_outcome_dual_fraction_scales.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-outcome-dual-fraction-scales/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

The all-state audit is in `scope-audit.json` and `pr-census.json.bz2`. [PR #997](https://github.com/lalalune/hyperliquid-source/pull/997) covered outer OutcomeDeploy admission while excluding the settlement payout body. [PR #1859](https://github.com/lalalune/hyperliquid-source/pull/1859) covered question settlement ordering and membership while leaving the external settlement wrapper opaque. [PR #460](https://github.com/lalalune/hyperliquid-source/pull/460), [PR #454](https://github.com/lalalune/hyperliquid-source/pull/454) and [PR #419](https://github.com/lalalune/hyperliquid-source/pull/419) address other outcome operations. This packet's new question is the independent dual-scale conversion inside the settlement routine. It does not claim the older outer gates as new work.

The audit inspected open and closed PR metadata and available patches, including prior releases. GitHub omits many patches and caps a large historical PR's file list; these limitations are recorded. The result is a bounded finding at the stated snapshot, not an absolute guarantee about unpublished work or future submissions.

New analysis and verification are independently authored under the repository MIT license. Generic export/parsing/checking helpers adapt existing MIT research packets, especially the registry-row-labels and quote-midpoint-product-guard packets. No unlicensed inferred source was copied. Binary and imported-reference rights remain unchanged. There is no source-to-target equivalence, full component completion or hosted-CI claim.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
