# RE-015: configuration-number conversion, skipping and failure boundaries in node 94

This packet establishes that the configuration parser's numeric helpers distinguish grammar-only skipping from magnitude-checked conversion, allowing a reconstruction to preserve cursor movement, integer/float/error discriminants, negative zero and exponent-overflow failures instead of treating numeric tokens as a permissive character run or treating parser constants as configuration defaults.

- Component ID: `constants`, task `RE-015` (`global_constants/*`).
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository and public main `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference `can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`. Reference code supplied leads only; no implementation was copied.
- Claim status: byte, relocation and unwind observations; independently written abstract transfer model is an inference, not captured execution. Runtime equivalence unresolved.
- Scope included: digit-entry conversion and syntax-only skipping; fraction, exponent and overflow tails; result/cursor stores; error positioning, box construction and local cleanup bodies; associated powers and diagnostic pool references. The selected bodies form one numeric subpath, not the whole configuration loader.
- Scope excluded: caller whitespace and initial minus handling, object/name dispatch, the existing 76-name table, global publication and defaults, allocator/deallocator implementations, dynamically dispatched destruction, complete exception routing, node #115 and visor.

## Reproduce

Run from the repository root with the captured artifact present. The generator and tests use Python's standard library plus the repository's `elf_index.sections` and `fde_extents.eh_frame_records`. They do not invoke external programs or execute the capture. The input digest is checked before ELF parsing. Output contains no timestamps, machine paths or host-floating-point results.

```sh
python3 tools/config_number_path94.py --out research/work-items/RE-015-config-number-path-94
python3 -m unittest tests.test_config_number_path94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
```

For independent regeneration, substitute two distinct temporary directories for the placeholders. `diff` is a separate reviewer command; neither the generator nor the tests invoke it.

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/config_number_path94.py --out <first-output>
PYTHONHASHSEED=913 TZ=Pacific/Honolulu python3 tools/config_number_path94.py --out <second-output>
diff -r <first-output> <second-output>
```

The generated files are `evidence.json`, `functions.tsv`, `branches.tsv`, `calls.tsv`, `memory-stores.tsv`, `powers.tsv`, `source-locations.tsv`, `context-links.tsv` and `model-cases.tsv`. Compare each with its checked-in counterpart. `MANIFEST.sha256` hashes these files and this README; it excludes itself. The generator intentionally does not overwrite human documentation or its manifest.

Observed environment: Linux x86-64, Python 3.12.3. GNU objdump 2.42 was used for human inspection only. No objdump text contributes to a generated count, list or address. The closed decoder admits the encodings present in the selected bodies, retains every instruction's original bytes, and rejects unknown/truncated encodings or internal branches into operands. It is not a general x86 disassembler. Register indices on SSE records use the decoder's shared register-index labels; the opcode and prefixes determine the register class.

`python3 tools/doctor.py` reported `analysis_ready=true`, `exact_rebuild_ready=false` and `captured_binaries_executed=false`. No new infrastructure, package installation, target execution or public chain access was needed.

## Evidence

### Ownership and configuration connection

The starting `/static_config`, `/cham` and `NvTestnet` questions already have owned loader/name paths. They are context, not new findings here. See `research/work-items/constants`, `constants-aws-name-parse-94`, and the RE-015 format-prefix and instruction-start corrections. The plain name codec is also reserved by PR #1385; the HlChain reader by PR #1364. No selected FDE entry occurs in the existing work-item corpus, and public PR searches for the selected entries returned no matches at the recorded main revision.

`context-links.tsv` retains only direct-call boundary anchors from the already owned parser: calls at `0x164e41d` and `0x164e485` reach `0x164db50`; the object walk's call at `0x164edee` reaches `0x164dce0`. These caller bodies are neither selected nor re-exported as recovered code. The parent packet supplies their configuration context. Conversion here does **not** imply a numeric value is accepted as an AwsName. A caller can consume a valid number and then reject its type.

`0x164d740`, the existing after-cursor error helper, remains an explicitly marked external ownership boundary. This packet does not re-export its body. The separately selected shared helper `0x4eb9e40` exposes an after-cursor calculation. For local calls to the owned helper, the model assumes that same convention; the parent packet does not establish this equivalence. Predicted local error line/column values are conditional on that boundary assumption. Numeric cursor stores and error codes do not depend on it.

### Coordinates and path map

All addresses are linked ELF virtual addresses, not runtime addresses or file offsets. Byte reads resolve through exactly one allocated, file-backed section; `SHT_NOBITS` is excluded. FDE endpoints come from actual `.eh_frame` records using the shared parser, not merely the header's start table. Extents are unwind-described ranges, not a source ownership or all-functions census. Each full selected extent is hash-bound and partitioned into admitted instructions, including its local landing-pad bytes.

| Entry | Exclusive end | Bytes | Inferred role |
| --- | --- | ---: | --- |
| `0x164d800` | `0x164db42` | 834 | fraction or finish |
| `0x164db50` | `0x164dcd7` | 391 | integer prefix |
| `0x164dce0` | `0x164df2a` | 586 | syntax only number |
| `0x164df30` | `0x164e1b8` | 648 | exponent |
| `0x164e4d0` | `0x164e590` | 192 | error at cursor |
| `0x164e5e0` | `0x164e6c6` | 230 | error payload drop |
| `0x4eb9e40` | `0x4eb9ef8` | 184 | shared error after cursor |
| `0x4eb9f00` | `0x4eba1ba` | 698 | overflow integer fraction |
| `0x4eba440` | `0x4eba6c8` | 648 | shared exponent |
| `0x4ebaa20` | `0x4ebabf7` | 471 | overflow integer tail |
| `0x4ebac00` | `0x4ebad53` | 339 | overflow fraction tail |
| `0x4ebad60` | `0x4ebae07` | 167 | overflow exponent tail |
| `0x4ebae10` | `0x4ebaed0` | 192 | shared error at cursor |
| `0x4ebbe20` | `0x4ebbf06` | 230 | shared error cleanup |
| `0x4ebcd70` | `0x4ebcde9` | 121 | boxed error constructor |
| `0x4ebce50` | `0x4ebcf37` | 231 | shared error payload drop |

The connected numeric flow is:

```text
integer_prefix -> fraction_or_finish -> exponent
       |                  |                |
       v                  v                v
 overflow_integer_tail  overflow_fraction_tail  overflow_exponent_tail
       |                  |
       +-> overflow_integer_fraction -> shared_exponent

syntax_only_number -> return zero OR positioned boxed error
numeric helpers    -> typed value OR positioned boxed error
position writers   -> boxed_error_constructor
local unwind code  -> error_payload_drop / shared cleanup -> external runtime
```

`calls.tsv` records every direct/indirect call and external tail transfer in the selected extents. Its 83 sites comprise 32 selected, 3 previously owned, 45 external and 3 dynamic boundaries. The 3 dynamic calls are destructor pointers, not unresolved numeric dispatch. Relocation slots resolve from raw `R_X86_64_RELATIVE` entries, never the zero on-disk GOT contents. No outside callee body is counted as recovered. `branches.tsv` gives all 281 direct branch sites, destinations and conditional fallthroughs; this includes panic and cleanup blocks, not only the happy path.

### Numeric state and result discrimination

The common cursor reads the byte pointer at `+0x18`, slice length at `+0x20` and cursor at `+0x28`. Digit-entry consumes the initial byte before checking its class. It accepts a lone zero, but a second digit after that zero reaches syntax code 13 without consuming that second digit. Nonzero integers continue while the next byte is a decimal digit. A valid number prefix leaves its delimiter unconsumed.

The guard at `0x164dbc3` supplies the quotient boundary, followed by the last-digit comparison at `0x164dc2c`: the largest accumulated unsigned integer is `18446744073709551615`. Overflow transfers through slot `0x576fc80` to `0x4ebaa20`; it does not wrap the mantissa. The tail consumes remaining integer digits while counting a decimal scale. Fraction overflow transfers through `0x576fc78` to `0x4ebac00`; additional fractional digits are consumed without extending the mantissa or decrementing its scale further.

| Returned numeric tag | Payload at output +8 | Branch basis |
| --- | --- | --- |
| 1 | unsigned magnitude | positive integer finish; immediate at `0x164d865` |
| 2 | negative signed integer | negative nonzero magnitude through `2^63`; store path at `0x164d968` |
| 0 | binary64 bits | fraction/exponent, integer overflow, negative zero or negative magnitude beyond the signed domain |
| 3 | positioned error-box pointer | integer-prefix failure store at `0x164dc9c`, including propagated helper failure |

The exponent and overflow helpers internally use a different result shape: word 0 means a float payload, word 1 means an error pointer. The numeric wrapper translates the latter to tag 3. These tags are local parser result discriminants; they are not the configuration's name discriminants.

Negative zero takes the float path and applies sign mask `0x8000000000000000`. A negative magnitude exactly `2^63` still fits the signed return; larger magnitudes use the floating conversion. The separate syntax-only entry does not calculate a mantissa or magnitude. Its successful return word is zero; failure returns a positioned error pointer.

### Fraction, exponent and powers

A decimal point requires at least one following digit. An exponent marker requires a digit after its optional sign. The exponent's next digit is consumed **before** its overflow guard. At `0x164dfdd` and `0x164dfea`, the accepted exponent magnitude is bounded by `2147483647`. Arithmetic at `0x164e01b` through `0x164e041` combines it with the existing fractional scale using signed saturation.

Exponent-overflow tail `0x4ebad60` distinguishes positive exponent with nonzero mantissa from negative exponent or zero mantissa. The former builds range error 14 immediately, leaving any further digits. The latter consumes the remaining exponent digits and returns signed zero. This early failure is a cursor difference, not merely a numeric result difference.

Slot `0x576fc70` resolves to `0x7c9740`. `powers.tsv` exports all 309 binary64 entries, indexed 0 through 308. Each is independently checked against integer-rational round-to-nearest-even of the corresponding power of ten. The table boundary is obtained from the comparison at `0x164e06f`, not a guessed table length. For a negative scale outside the table, the path repeatedly divides by the constant at `0x20a350` (bits `7fe1ccf385ebc8a0`) and adds 308 to the scale. Zero terminates this loop. An excessive nonnegative scale on a nonzero value, or a multiply that produces infinity, reaches code 14.

The conversion vectors at `0x203e80` and `0x202ea0`, sign vector at `0x2082f0`, scaling constant at `0x20a350` and negative zero at `0x20a910` are retained as raw bytes. These are numeric parser machinery. Nothing establishes them as application configuration defaults. Long fractional tails are discarded, so no correctly rounded arbitrary-decimal conversion claim follows from the presence of a correctly rounded powers table.

### Failure and cleanup boundaries

| Condition | Typed numeric path | Syntax-only path | Cursor consequence |
| --- | --- | --- | --- |
| empty digit-entry input | code 5 | code 13 | unchanged |
| `01` | code 13 | code 13 | 1; after-cursor position includes the second digit |
| `1.` | code 5 | code 13 | 2 |
| `1.x` | code 13 | code 13 | 2; after-cursor position includes `x` |
| `1e+` | code 5 | code 13 | 3 |
| `1e-x` | code 13 | code 13 | 4; first invalid exponent byte already consumed |
| `1e309` | code 14 | successful skip | 5 |
| `1e2147483648999` | code 14 | successful skip | 12 typed; 15 skipped |
| `0e2147483648999` | signed zero | successful skip | all digits consumed |

These input/output rows are abstract predictions in `model-cases.tsv`, derived from the reviewed branches; they are not target replay results. The local after-cursor error-position descriptions depend on the explicitly assumed owned-helper boundary contract. Sign is an explicit model argument and has already been consumed by the caller. In particular a model token beginning with `-` is an invalid digit-entry input, not a claim that the outer JSON parser rejects negative numbers.

`0x164e4d0` and `0x4ebae10` count bytes up to the cursor: line starts at 1, column at 0; LF increments line and resets column. `0x4eb9e40` counts through `min(cursor+1, length)`. The counts are bytes, not Unicode scalars. Out-of-slice cursors and counter arithmetic guard failures reach external panic boundaries. The model rejects malformed cursor inputs rather than simulating these runtime panics.

`0x4ebcd70` copies a 24-byte error payload, appends line at +24 and column at +32, requests 40 bytes through slot `0x576dfd8`, and copies the complete object into the returned allocation. A null result reaches the failure call with alignment 8 and size 40, followed by a trap. The allocator's behavior is not recovered here.

The local cleanup bodies distinguish payload tag 0 (conditional buffer deallocation), tag 1 (tagged dynamic payload and optional destructor) and the other immediate variants (no payload destructor). For the numeric codes 5, 13 and 14, that last path applies. The generic tag-1 path retains its dynamic destructor and deallocation boundaries in `calls.tsv`. Cleanup and unwind-resume calls are visible; the language-specific exception table was not decoded, so this is not a proof of every possible unwind transition or destructor implementation.

`memory-stores.tsv` records 103 syntactic memory destinations of move/set instructions, including cursor, result and stack writes. It is not an alias analysis, does not count push/arithmetic writes, and does not establish absence of global mutation through external calls.

### Diagnostic pool references

`source-locations.tsv` records 24 RIP-relative references from selected bodies to location objects. It includes location bytes, relocated pool pointer, exact pool length/hash and line/column. Both referenced pool entries have suffixes under `serde_json-1.0.120`: `src/de.rs` and `src/read.rs`. Build-directory prefixes are omitted from text while the full original pool bytes remain digest-bound. The locations identify dependency-origin diagnostic strings; they are not function boundaries, application configuration strings or proof of unmodified upstream source.

## Implementation and comparison

Independent Rust reconstruction: **not yet implemented**. Cargo.lock, compiler/linker flags, two-build results, native differential execution, raw/normalized code comparison and whole-ELF comparison: **not yet implemented/measured**. No normalization masks or artificial byte transplantation are used.

The Python transfer model is written from the byte-level review. It uses exact integer rational arithmetic to model binary64 rounding, not the host FPU. Its floating predictions assume nearest-even rounding and gradual underflow. The captured process's MXCSR was not observed. The model collapses internal helper wrappers and records logical phases rather than a dynamic instruction trace. It does not emulate allocation, panic, caller type rejection or exception unwinding. Extremely long inputs that overflow the helper's signed scale counters are outside the model's claimed domain.

The reference's `global_constants/static_config.rs` contains a `skip_number` lead that consumes a run of number-like characters. Its local scan can consume `01` or `1e+`; the actual syntax-only helper has explicit leading-zero and required-digit failures. This comparison is limited to those fragments, not whole-parser equivalence. The binary also separates magnitude errors from skipping, so replacing both with a shared float parser would lose the observed distinction. No source from that unlicensed reference is incorporated.

The dedicated tests authenticate the artifact; reject unmapped, ambiguous and NOBITS-backed reads; reject truncated/unsupported instructions, branch-into-operand targets, changed body/FDE endpoints, altered thresholds/tags and branch polarity; reject missing/retargeted relocations and corrupt powers, constants, diagnostic strings or caller edges. Boundary controls exercise digit classes, sign/integer domains, negative zero, required digits, unconsumed delimiters, exponent overflow, lost fractional tails, byte positions and rational ties. The final test regenerates every evidence file and compares exact bytes with this packet. These tests validate the extraction and abstract contract, not target execution equivalence.

## Results and limitations

`evidence.json.metrics` reports 16 selected FDEs, 6,162 selected bytes, 1,648 decoded instructions, 281 direct branch sites, 83 call/tail sites, 103 move/set memory stores, 309 power entries, 24 diagnostic source sites and 957 abstract model cases. The denominator is the explicit selected FDE set, not all configuration functions, all node code or all reachable runtime helpers. Three already owned caller edges are boundary context only and excluded from the selected-function counts.

Validation: 32 dedicated unittest methods passed, with 0 failures, 0 errors and 0 skips under a Python-only PATH. Two regenerations with different hash seeds and time zones were byte-identical; all nine generated files matched the packet. Artifact verification, catalogue check and inventory/literal reproduction passed. No hosted CI or container result is claimed. The repository-wide unittest suite was deliberately not run under the execution's memory constraint.

This packet requests **no progress gate**. `constants` remains 0/4. The full component first task, all configuration defaults, loader publication and full binary equivalence remain unfinished; this numeric subpath does not satisfy those broader acceptance criteria. The existing name-discriminant table is not resubmitted.

Next question: with ownership coordinated for the outer parser, how do these numeric-success and numeric-failure results affect its invalid-type diagnostics and subsequent configuration fallback for unknown versus recognized object fields?
