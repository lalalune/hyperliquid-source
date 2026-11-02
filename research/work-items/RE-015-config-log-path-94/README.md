# RE-015: configuration-rooted log path construction in node 94

Node #94 selects custom or default log-path candidates, optionally constructs a separate prefix/severity/value when the prefix helper is reached, and propagates rolling-pattern and appender errors, giving a reconstruction the decisions needed for this path.

- Component ID: `constants`, task `RE-015` (`global_constants/*`), following
  the configuration directory into one downstream constructor. The builder's
  own source-level ownership is not established by a symbol.
- Target release and full SHA-256: Linux x86-64 node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository
  `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; inferred, unlicensed
  `can1357-hl` reference `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  Reference labels are leads only; no reference implementation is copied.
- Claim status: observations of file-backed bytes, decoded relative operands,
  FDE/LSDA records and selected local flow; template rendering, role names and
  scenario outcomes are explicitly identified as inferences. Runtime values
  and external helper behavior remain unresolved.
- Scope included and excluded: the selected configuration-rooted constructor,
  the optional-prefix helper, category and severity formatting wrappers, and
  two insertion helpers, the rolling-pattern validator and its mask helper,
  and the appender result builder through local result publication and error
  boundaries. The previously studied configuration initializer and upstream
  handle constructor, final formatting sink, string transform, allocator,
  component reader, final logger builder, exception actions, installation and
  actual file I/O are external boundaries. The existing 76-name inventory is not repeated. Node
  #115, visor, target execution and component-gate changes are excluded.

## Reproduce

Use the repository root, materialized pinned inputs, Linux x86-64 and Python
3.12.3. The collector first verifies the complete target size and SHA-256,
then reads bytes with the repository's `tools/elf_index.py` and
`tools/fde_extents.py`. It rejects NOBITS as a byte source. Its closed x86
length/transfer reader is adapted from the independently authored MIT collector
in PR #1588, with additional encodings needed here; no disassembler text is
read. Its output contains no local paths, timestamps or randomized ordering.

```sh
python3 tools/config_log_path94.py --out research/work-items/RE-015-config-log-path-94
python3 -m unittest tests.test_config_log_path94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
(cd research/work-items/RE-015-config-log-path-94 && sha256sum -c MANIFEST.sha256)
```

For independent regeneration, replace the placeholders with two writable
relative directory names. The generator and focused tests also run with Python
but no binutils in `PATH`.

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/config_log_path94.py --out <tmp-dir-one>
PYTHONHASHSEED=91 TZ=Pacific/Honolulu python3 tools/config_log_path94.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
```

GNU objdump 2.42 was used only to inspect instructions by eye; neither the
collector nor tests invoke it. For example, from the repository root:

```sh
objdump -d --start-address=0x13ecf10 --stop-address=0x13ed094 artifacts/node/94/hl-node
```

No captured binary or service is executed. Two isolated output generations,
with different hash seeds and time zones, were byte-identical to each other and
to the retained generated files. The manifest covers the README and all
producer outputs, excluding itself.

## Evidence

Addresses are linked ELF virtual addresses without rebasing; the TSV records
also give section-mapped file offsets. Every extent below is half-open: the
start is included and the end is excluded. `functions.tsv` records ten actual
FDE extents and body hashes, not a function census or proof of source-level
boundaries. The closed decoder covers each selected FDE byte, rejects unknown
and truncated forms, and checks that in-range direct branches and selected
LSDA endpoints land on decoded instruction boundaries. The decoder reports
lengths and transfers, not all instruction semantics. Full byte locks and 75
named contracts protect the particular interpretations below.

| Selected extent | Local role inferred from instructions | Bytes |
| --- | --- | ---: |
| `0x13e28c0..0x13e4cd4` | configuration-rooted constructor and local result | 9,236 |
| `0x13ecf10..0x13ed094` | optional-prefix selection and formatting | 388 |
| `0x1444710..0x144473a` | category byte to two string slices | 42 |
| `0x1449050..0x144907f` | severity byte to a length and relative string slice | 47 |
| `0x1456cc0..0x1456cfa` | severity-format adapter | 58 |
| `0x1471480..0x14718dc` | appender result, local tag gate and lock | 1,116 |
| `0x14cad30..0x14caf32` | byte-keyed 24-byte-value insertion/replacement | 514 |
| `0x14cb970..0x14cbb74` | byte-keyed 16-byte-value insertion/replacement | 516 |
| `0x3ccd1b0..0x3ccd2a0` | candidate-mask verification helper | 240 |
| `0x3ccdc50..0x3cce16f` | rolling-pattern and extension gate | 1,311 |

The original `/cham` and `/static_config` entries and the `NvTestnet` slice
are retained as context in `templates.json`, `relocations.tsv` and
`summary.json`; they are prior evidence, not new discriminant-table results.
The constructor loads slot `0x576e928`, whose RELATIVE addend is the lazy
configuration cell `0x577b288`; it tests the cell's state at `+0x50` and
uses the value at `+0x18`. The cell is in file-backed `.data`; a relocation
does not establish its runtime contents. The [prior RE-015 inventory](../constants/README.md)
and [build-mode packet](../RE-001-build-mode-94/README.md) associate that field
with the selected configuration directory. Its actual value is unknown. The present
analysis does not establish that the category bytes below are AWS-name bytes,
or that a particular `NvTestnet` configuration affects this route.

### Candidate paths and category boundaries

At `0x13e2acb` and `0x13e2b63`, the constructor selects two complete compact
templates. The argument setup points to the configuration value at `+0x18`,
a category byte formatted by the function at `0x1444710`, and a saved incoming
32-bit value formatted through a separately owned callback. The argument and
call bytes are in `contracts.tsv`; all selected relative calls and slots are
in `edges.tsv` and `relocations.tsv`.

| Template entry | Bytes after the initial argument placeholder | Conditional rendering under the previously established format-token contract |
| --- | --- | --- |
| `0x1fbef2` | `/data/log/`, argument, `/warn/`, argument, terminator | `<directory>/data/log/<category>/warn/<formatted-value>` |
| `0x1f4eba` | `/data/log/`, argument, `/error/`, argument, terminator | `<directory>/data/log/<category>/error/<formatted-value>` |

The token interpretation uses the [prior compiler-stamped format correction](../RE-015-format-prefix-correction-94/README.md);
the source-level field names and rendered path are inferences, not captured
filesystem observations. The third argument's formatter is an external
boundary; the packet does not claim its rendered value.

The loop starts with index zero and ends before index 13. Its bytes at
`0x217875` and formatter branches are recorded in `categories.tsv`: indices
0–4 and 6–12 contain zero and select the five bytes `infra`; index 5 contains
one and selects the five bytes `trade`. The two category strings are
length-delimited slices, not NUL-terminated strings. If the external callbacks return identical renderings for equal arguments,
the twelve zero entries produce the same candidate spelling. This is a static
formatting deduction; it does not establish which paths are opened or how many
times.

### Selection, prefix and explicit failure

The constructor reads three optional-looking values from its input at offsets
`+0x00`, `+0x18` and `+0x30`; the high-bit-only word is the absent sentinel.
The first two supply the error and warning path candidates, respectively;
`+0x30` determines whether the prefix helper receives a null or non-null
pointer. The flag at `+0x4d` supplies the disable bit. A separate lazy pair
of bytes produces the tested live bit: `((first - 1) mod 256 < 2) AND
(second & 1)`. This is the machine-level condition; the high-level build-mode
names are not recovered here.

For either warning or error, conditional on reaching the corresponding local
selection arm and the external calls returning normally:

| Input path | Live bit | Disable bit | Local outcome before later builders |
| --- | ---: | ---: | --- |
| present | 0 | either | Clone the supplied value; the prefix helper is bypassed. |
| present | 1 | either | Reach the diagnostic helper with `assertion failed: !is_live`. |
| absent | 1 | 0 | Pass the formatted default candidate to the prefix helper. |
| absent | 0 | either | Pass an absent candidate to the prefix helper. |
| absent | 1 | 1 | Pass an absent candidate to the prefix helper. |

Warning uses map key 1; error uses key 0. The two assertion branches join the
same diagnostic literal at `0x217736`, while retaining different local channel
values. A helper call with no prefix moves the candidate's three words to its
result. With a prefix, `0x13ecf10` instead formats the channel through
`0x1456cc0` and `0x1449050`, passes the resulting string through the external
transform slot `0x576e050`, and supplies a fresh three-argument array to the
complete template at `0x1f04e5`. The middle argument is the transformed
severity, not the previously formatted default path. The consumed candidate is
conditionally released after the formatted result is stored. The observed
pre-transform slices are `Error` for key 0 and `Warn` for key 1
(`severity.tsv`). The [prior subaccount packet](../vaults-subaccount-create-94/README.md)
infers that the transform is `str::to_lowercase` from compiler locations and a
sigma comparison. If that separate inference is correct, these two inputs
would become `error` and `warn`; this packet does not establish the transform's
semantics independently. The formatter has no local range guard, so these two
keys are the only claimed domain.

The static `scenarios.tsv` records 160 combinations of the two channels, mode
boundary inputs, disable bit, custom presence and prefix presence. Rows marked
`prefix_helper_absent` mean that an absent candidate is passed to the helper;
they do not assert the helper's final output. These are deductions from fixed
instruction contracts, not executed node tests or a claim about valid runtime
state. `cfg-claims.tsv` checks 32 structural reachability propositions with
conditions over-approximated and calls assumed to return; exceptional edges
and indirect transfers are not modeled as normal successors.

### Rolling-pattern validation

On the non-sentinel path, the constructor formats the complete template at
`0x1f62fa`: an argument followed by the literal `_overflow{}`. It passes the
resulting slice to `0x3ccdc50`, the target of slot `0x576eba8`. The validator
first searches for the adjacent bytes `{}`. Lengths below two reach the
missing-pattern error at `0x5ba856`; length two is compared as one pair,
and lengths 3–16 use the scalar pair loop. Longer inputs use two-byte SIMD
comparisons, with a separate unrolled route beginning at length 66. Missing
patterns return the high-bit-only sentinel and an error payload. The caller's
sentinel branch reaches its unwrap diagnostic. These are static instructions,
not an actual file open.

For a normally rendered suffix, the last two bytes are `{}` and the length is
at least 11. At lengths 11–16 the scalar loop reaches the last pair. At length
17 or more, the final two 16-byte loads begin at `length-17` and `length-16`;
their bytewise masks therefore set bit 15 for that last pair. The helper at
`0x3ccd1b0` verifies the candidate byte or preserves a previous match. Under
the existing format-token contract, valid slice memory and normal helper
returns, the fixed suffix supplies the pair required by this gate. This is a
static local proof, not a claim about other builder errors or file creation.
`rolling-cases.tsv` records finite positive and corrupted-suffix examples across
the 16/17 and 65/66 boundaries; the test also compares all SIMD tail lanes
with an independent byte-search oracle.

After a pair is admitted, an external component reader returns a tag and slice.
If the tag is 9, the selected local code scans for the last dot and sends a
non-leading `.gz` suffix to the separate gzip-feature error at `0x5ba873`. A
component exactly `..`, a leading-only `.gz`,
uppercase `.GZ`, and another tag bypass that local error. The component reader
itself is not analyzed here, so these are conditional slice-level facts; no
claim is made about which runtime path produces a particular tag or slice.
`extension-cases.tsv` records the controls and `diagnostics.json` retains both
complete error literals.

### Appender result and local state transitions

The constructor wraps the rolling-pattern result in local objects and then
calls appender builder `0x1471480`. At `0x147164c`, that function calls the
same component-reader slot on a separately constructed input; the following arithmetic admits exactly
component tags 7, 8 and 9 to a two-call gate. This is an unsigned byte test:
`((tag + 249) mod 256) < 3`. The admitted tag labels and the reader's output
contract are not established. `appender-tag-cases.tsv` lists all 256 possible
byte inputs; it is a deduction from the two locked immediate bytes, not a list
of observed runtime components.

| Local condition | Result before the locked operation |
| --- | --- |
| Tag outside 7–9 | Skip the two-call gate. |
| Tag 7–9, first external call returns zero | Skip the second call. |
| Tag 7–9, first call nonzero, second call zero | Continue to the locked operation. |
| Tag 7–9, first call nonzero, second call nonzero | Store the high-bit-only sentinel and returned word; skip the locked operation. |

Before that second call, the function writes the 32-bit value `0x1ff` and a
one-byte value `1` to a local argument structure. The external helpers are
not named or assigned filesystem semantics here. The other routes reach an
atomic compare-exchange on a local state byte. A contended path calls a
separate slot with the immediate `1,000,000,000`, and both success and error
routes attempt an exchange to release the state, with a separate slow-call
boundary. After the operation at slot `0x576f810`, low return bit 1 stores the
same sentinel and an error word; a zero low bit leads to seven 16-byte result
copies. The contended paths, result stores, cleanup and allocation-failure
transfer are
covered by fixed byte contracts and normal-flow reachability checks. They do
not establish the called helpers' side effects, successful file opening, or
behavior of exceptions.

At `0x13e3436`, the constructor calls this appender builder. It tests the first
result word for the sentinel and routes an error to a distinct unwrap site;
otherwise it continues toward appender-map insertion and the final local
result. This connects the rolling check, appender branch and parent error
handling without claiming installation of the resulting configuration.

### Map changes, result and error boundaries

The path insertion helper compares byte keys, returns the previous 24-byte
value on equality, and bypasses the length increment in that replacement
case. The new-entry route increments the map count and writes the no-old-value
sentinel. The analogous appender insertion helper replaces a 16-byte pair and
returns its previous pair; only the new-entry route increments its count.
Their full selected instruction streams and selected edges include the
equality, allocation and capacity branches; the CFG propositions check the
replacement paths. Nonempty-node split helpers, dynamic destructors and
allocator internals remain external.

The caller tests returned old path values before a deallocation boundary and
checks an old appender pair's dynamic destructor and size before cleanup.
It then writes a 64-byte record and increments the local vector count. The
final builder is called through slot `0x576ebd0`; on a non-6 result tag,
`0x13e4077` through the return copies five 16-byte chunks to the output. On
result tag 6, the other branch reaches the `Result::unwrap` diagnostic at
`0x2177b5`. The intermediate rolling-pattern and appender-builder sentinel error
branches reach the same diagnostic text at separate local sites. Allocation
failure, missing-map, custom-live assertion and these result-error boundaries
are distinct; none is claimed to return or terminate beyond the recorded
control transfers.

Five LSDA tables contain 122 call-site entries. For example, the warning
formatter call is covered by a landing-pad entry at `0x13e45e8`, while the
prefix helper's second format call is covered by `0x13ed041`. The raw ranges,
landing pads and action indices are generated in `lsda-sites.tsv` and checked
against instruction boundaries. Action chains, type matching, unwind helper
semantics and behavior after an external call are not decoded.

### Retained generated evidence

| File | Content |
| --- | --- |
| `functions.tsv` | Selected FDE/CIE/LSDA coordinates, file offsets and body hashes. |
| `instructions.tsv` | Closed-reader instruction lengths and bytes for all ten extents. |
| `transfers.tsv` | All transfers classified by that reader, including unresolved indirect transfers. |
| `contracts.tsv` and `edges.tsv` | Selected exact semantic anchors and checked direct/slot targets. |
| `cfg-claims.tsv` | Explicit normal-flow over-approximation queries. |
| `categories.tsv` and `severity.tsv` | Category bytes and the two admitted pre-transform severity slices. |
| `scenarios.tsv` | Local mode, input-presence and prefix decision deductions. |
| `rolling-cases.tsv` and `extension-cases.tsv` | Static tail-mask and local component-extension boundary cases. |
| `appender-tag-cases.tsv` | The complete byte-domain deduction for the appender component-tag gate. |
| `templates.json` and `diagnostics.json` | Complete selected template and failure-message bytes. |
| `relocations.tsv` | Selected RELATIVE slot/addend bindings. |
| `lsda-headers.tsv` and `lsda-sites.tsv` | Selected LSDA headers and protected ranges. |
| `summary.json` | Digest, machine-readable counts and limitations. |

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo lock, compiler
and linker flags, two-build reproducibility, target behavior comparison,
raw/normalized body matches, masks and complete helper/data/relocation
closure are not yet implemented/measured. The unlicensed reference is a lead,
not source authority. The following compares its `base/log/handle.rs` defaults
with this packet's byte-grounded observations; the source-level association of
its bucket value with the selected machine byte remains an inference.

| Reference lead | Target-bound observation | Comparison |
| --- | --- | --- |
| The default path uses `/data/log/` and warn/error directory fragments. | Both compact entries contain those literal fragments. | The literal fragments agree under the format-token interpretation. |
| Bucket zero renders as `0`. | Category byte zero selects `infra`. | The rendered category differs under the inferred bucket association. |
| Bucket one renders as `1`. | Category byte one selects `trade`. | The rendered category differs under the inferred bucket association. |
| The lead supplies a fixed empty live-path prefix. | The constructor supplies the lazy configuration field at `+0x18` to the formatter. | The target field's runtime value is unknown; equality is not established. |

No upstream source was copied. The default and bucket names in the lead do not
establish the target's full source-level layout or any installation behavior.

The focused tests include corrupt artifact identity, instruction opcodes and
branch targets, malformed/truncated decoder forms, an actual branch redirected
into an instruction, template length/terminator mutations, both severity table
operands, changed or duplicate relocation slots, invalid LSDA headers/ranges,
NOBITS and ambiguous mappings, and an independent exhaustive check of the
live-bit predicate over byte inputs. They also verify the two map replacement
edges, local scenario boundaries, the full appender tag byte domain, result
and lock edges, and corrupted tag and operation constants. These are static
extraction controls, not differential executions.

## Results and limitations

The generated summary reports 10 selected FDEs / 13,468 bytes, 2,760 decoded
instruction records, 619 transfers, 75 fixed contracts, 81 selected edge
contracts, 21 selected RELATIVE relocations, 5 LSDA tables / 122 call-site
records, 13 category entries, 2 severity entries, 160 selection scenarios,
36 rolling-tail cases, 13 component cases, 256 appender tag cases and 32
structural CFG propositions. Those are scoped evidence counts, not a component function denominator. The
focused suite passed 51 tests with no skips. The artifact/signature and
catalogue checks passed. Inventory/literal reproduction
passed against identical pinned inputs in an isolated scratch environment; the
full repository unittest suite was not run under the stated memory constraint.

The decoder establishes selected instruction lengths and control-transfer
forms but does not recover complete dataflow, feasible paths or the semantics
of called helpers. The external transform, formatter, allocator, component
reader, final logger builder, installation and exception actions remain
unresolved. No complete component gate or binary-equivalence claim is
requested; all four `constants` gates remain false. Next, establish the
transform, component-reader and downstream logger-builder contracts, then
connect the returned object to installation without reclaiming
the existing upstream handle-construction packet.
