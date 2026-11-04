# RE-001: node #115 persisted-account decoder admission beyond the canonical writer

- Component: persistent account decoding; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses; interval ends are exclusive.
- Measured evidence: two complete FDEs, 6,374 bytes: decoder `0x3262b90` and byte-slice wrapper `0x3d48330`. Exact extents/digests are in `records.json`.
- Scope: field selection, duplicate/default/arity decisions and the wrapper boundary below. Component gates remain false.

## Finding

The previously reconstructed canonical account writer does not establish the native reader's acceptance policy. The native decoder has broader field and shape handling, while retaining strict duplicate-field decisions. The established account key and `b`/`n`/`c` schema are credited prior context.

For the fixed-map path, identified string keys dispatch as follows:

| Names | Field | Missing-field default |
| --- | --- | --- |
| `b`, `balance` | 32-byte balance carrier | 32 zero bytes |
| `n`, `nonce` | u64 nonce carrier | Zero |
| `c`, `code_hash` | 32-byte code-hash carrier | `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470` |
| Other identified string | Unknown field | Invoke skip helper `0x31d5e50`, continue only when it returns raw `9` |

Recognized fields may appear in any order. Short and long names share the same seen-state: `b` followed by `balance`, for example, is a duplicate. The duplicate branch runs **before** decoding that second value. Unknown values are delegated to the skip helper; this packet does not claim every arbitrary or malformed unknown value is accepted. An empty fixed map takes the documented defaults.

The fixed-array path reads fields in balance, nonce, code-hash order. Declared lengths 0, 1 and 2 use defaults for the missing tail; length 3 supplies all fields. These statements require each present value helper to succeed. With a declared length greater than 3, the native path rejects the extra element count after decoding the first three fields, without first decoding a fourth field. Invalid present values can fail earlier.

The wrapper at `0x3d48330` initializes a byte-slice decoder and its depth word to `0x20`, invokes `0x3262b90`, and branches only on the result. On success, it copies the 72-byte carrier and returns. **It does not compare the remaining-byte count to zero.** Thus this wrapper does not add whole-slice/trailing-byte rejection after a successful decoded account. This is a static control-flow result, not a claim that every appended byte sequence is harmless in a broader caller.

At the successful decoder boundary, output qword `+0` is raw success `0`; balance occupies `+8..+0x27`, code hash `+0x28..+0x47`, and nonce qword `+0x48`. The wrapper preserves the 72-byte payload. Value-helper grammar, all alternative MessagePack marker families, UTF-8 failure internals, depth-exhaustion grammar, and skip-helper recursion remain unresolved. No full codec or captured-node equivalence is claimed.

| Native interval | Observation |
| --- | --- |
| `0x3262be4..0x3262c13` | Fixed-map and fixed-array marker routes |
| `0x3262d79..0x3262d9c` | Unknown value skip and raw-result requirement |
| `0x3262e46..0x3262f38` | Field dispatch and shared duplicate gates |
| `0x326320c..0x3263266`, `0x32634b9..0x3263518` | Length dispatch, short and long aliases |
| `0x3263705..0x326381e`, `0x3263cec..0x3263e01` | Default fields and success layout |
| `0x32638ba..0x32638e0`, `0x326399c..0x3263a41`, `0x3264101..0x326414b` | Short arrays, defaults and extra-count rejection |
| `0x3d48347..0x3d4838b`, `0x3d48445..0x3d4847a` | Wrapper initialization and success copy without a remainder check |

The relation checker deliberately accepts already identified keys, decoded values and explicit helper outcomes. Its permutation, alias, duplicate-order, omission and arity checks verify these bounded decisions; they do not substitute an invented parser for the unresolved native helpers.

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Four changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-account-decoder-admission/export_disassembly.py
python3 research/work-items/RE-001-node115-account-decoder-admission/verify.py --controls
python3 research/work-items/RE-001-node115-account-decoder-admission/relations.py
python3 -m unittest discover -s tests -p 'test_node115_account_decoder_admission.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-account-decoder-admission/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

The all-state audit is in `scope-audit.json` and `pr-census.json.bz2`. [PR #730](https://github.com/lalalune/hyperliquid-source/pull/730) maps the canonical account writer and defaults. [PR #1864](https://github.com/lalalune/hyperliquid-source/pull/1864) implements a persistent-account codec but explicitly identifies its canonical-order and trailing restrictions as crate policy rather than established native acceptance. [PR #2147](https://github.com/lalalune/hyperliquid-source/pull/2147) covers the key, and [PR #2151](https://github.com/lalalune/hyperliquid-source/pull/2151), [PR #2171](https://github.com/lalalune/hyperliquid-source/pull/2171) and [PR #2187](https://github.com/lalalune/hyperliquid-source/pull/2187) cover backend/adapter boundaries. This packet closes native admission decisions left open there; it does not reclaim the known writer, key or generic read plumbing.

The audit inspected open and closed PR metadata and available patches, including prior releases. GitHub omits many patches and caps a large historical PR's file list; these limitations are recorded. This is a bounded finding at the stated snapshot, not a guarantee about unpublished work or future submissions.

New analysis and verification are independently authored under the repository MIT license. Generic export/parsing/checking helpers adapt existing MIT research packets, especially registry-row-labels and quote-midpoint-product-guard. No unlicensed inferred source was copied. Binary and imported-reference rights remain unchanged. There is no source-to-target equivalence, full component completion or hosted-CI claim.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
