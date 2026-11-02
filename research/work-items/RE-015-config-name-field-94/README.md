# RE-015: configuration path to the `b_keys` field in node 94

This packet shows that the API-secrets initializer formats the existing global configuration directory with a fixed filename, and that the selected `b_keys` field has a separately represented absent/null boundary that a reconstruction must preserve.

- Component ID: `constants`, task `RE-015` (`global_constants/*`); downstream
  configuration consumers are included only to answer this bounded question.
- Target release and full SHA-256: Linux x86-64 node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository
  `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; unlicensed inferred reference
  `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference supplies hypotheses,
  not implementation or evidence.
- Claim status: digest-bound byte, relocation and unwind observations; the
  names of routines, source-level types and the path interpretation are
  explicitly marked inferences. No component gate is requested.
- Scope included and excluded: the initializer, a two-predicate file/format
  selector, JSON document/object/field handling, two JSON key classifiers,
  a binary-format visitor and its full fixed-form field classifier, its selected
  optional-field reader, and selected unknown-field handling. The existing
  static-configuration initializer, file predicate, formatter and AWS-name map
  reader are external boundaries. The 76 AWS-name table is not reproduced.
  This is not a whole-component CFG, implementation or runtime execution.

## Reproduce

Use the repository root as working directory. The run used Linux x86-64,
Python 3.12.3, the repository's shared `tools/elf_index.py` and
`tools/fde_extents.py`, and the standard library. The producer authenticates
the complete `artifacts/node/94/hl-node` before parsing, rejects NOBITS sections
as byte sources, and invokes no external program. It does not execute the node.

```sh
python3 tools/config_name_field94.py --out research/work-items/RE-015-config-name-field-94
python3 -m unittest tests.test_config_name_field94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
```

For an independent determinism check, substitute two writable repository-root
relative directory names for the placeholders. A PATH containing only Python
is sufficient for both generator invocations and the focused tests.

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/config_name_field94.py --out <tmp-dir-one>
PYTHONHASHSEED=91 TZ=Pacific/Honolulu python3 tools/config_name_field94.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
```

The producer writes the nine evidence files listed below. The two runs and
the retained evidence were compared byte-for-byte; the manifest hashes this
README and each evidence file, excluding the manifest itself. GNU objdump 2.42
was used only for human inspection, and no output from it is parsed by the
producer or tests or retained as generated evidence. No network, captured
service, or file containing actual secrets was accessed; the target binary was
never executed.

## Evidence

All addresses are linked ELF virtual addresses (VAs), with no rebase. File
offsets are section-mapped and appear beside byte windows, calls and branches.
The FDE rows give unwind-described half-open ranges, not a whole-binary
function census. Every selected range is hashed; only the listed windows and
the classifier's admitted fixed instruction patterns were interpreted. In
particular, the 12 FDEs are not claimed to have complete decoded CFGs.

| File | Evidence |
| --- | --- |
| `evidence.json` | Target identity, counts, data/relocation coordinates and derived bounds. |
| `functions.tsv` | Selected FDE start/end, FDE/LSDA coordinates, file offset, size and range hash. |
| `windows.tsv` | Exact selected bytes with VA, file offset and length. |
| `branches.tsv` | Fixed-form relative branches with both fallthrough and taken targets. |
| `calls.tsv` | Direct calls or relocated indirect slots; resolved `memcpy` where applicable. |
| `field-dispatch.tsv` | The 24 JSON tag arms, duplicate diagnostics, colon/error destinations and value-parser calls. |
| `binary-field-paths.tsv` | Every successful symbolic path in the binary classifier, including each equality/inequality predicate. |
| `key-matchers.tsv` | The two independently checked JSON length-six buckets. |
| `json-field-probes.tsv` | Fixed-pattern checks of the 24 binary-derived names and 10 negative strings in each JSON classifier, with branch traces. |

The producer's closed x86 pattern readers fail on unrecognized encodings. The
binary classifier traversal follows only its byte-comparison, conditional
branch and leaf forms; it rejects out-of-range loads and inconsistent path
constraints. It requires every successful leaf to constrain every byte of its
length bucket. There are 24 successful symbolic paths across lengths 6 through
33, 357 feasible fallback path states within those buckets and 1,095 visited
symbolic states. These are traversal counts, not counts of input strings,
functions or executed test cases. Lengths outside the dispatch range take the
classifier's fallback. Success rows agree with the 24 JSON diagnostic tag arms.

For each of the two JSON key classifiers, a separate closed-pattern reader
checks the 24 binary-derived names and 10 negative strings. It models the
recorded register/byte comparisons and validates the resulting branch target
and leaf; it does not execute target instructions. Each classifier has one
33-byte comparison through a relocated `bcmp` symbol, modeled only under its
zero-if-equal contract. The owned classifier's unknown-name result additionally
assumes the external allocation path returns normally. The focused test checks
each position in each known name with one bit changed: 371 changes per
classifier. These finite probes are not an exhaustive proof for every JSON
input; the all-path statement above applies only to the binary classifier.

### Function and edge map

The machine-readable range table is the authoritative list of 12 selected
FDEs. The main direct-call route is:

```text
global initializer 0x13d28e0
  -> selector 0x144b150
     -> JSON document 0x149e710 -> object 0x14baf90 -> visitor 0x14a2870
        -> field classifiers 0x13c71c0 / 0x13c84c0
        -> selected-value boundary 0x1441d10
        -> unknown-field collector 0x14889f0
     -> conditional binary reader 0x13bd490 -> visitor 0x13abf40
        -> field classifier 0x13c75e0
        -> optional-value reader 0x13aa6e0 -> value boundary 0x13bec50
```

The selector's binary branch is mapped as an independently available branch of
the selector. Its reachability from this initializer's fixed `.json` suffix is
not established: the intervening path transformer is an external boundary.
Likewise the output's eventual consumers and storage synchronization are not
closed. The exact direct-call sites and indirect relocation addends are in
`calls.tsv`; a callee being named as a boundary does not claim its body.

At `0x13d28ef`, relocated slot `0x576e928` selects `0x577b288`; the initializer
passes that value plus `0x18` and callback `0x13da090` to the formatter slot
`0x576e040`. The complete template at VA/file offset `0x1dd405` is
`c0 11 2f6170695f736563726574732e6a736f6e 00`. The value at slot `0x577a898`
has RELATIVE addend `0x13d28e0`. Prior packet
`research/work-items/RE-001-build-mode-94/README.md` connects the first global's
`+0x18` field to the directory named `cham_dir` by the static initializer;
`research/work-items/foundation-hlu-validator-keys-94/README.md` documents the
same display callback and formatter convention. Under those independently
reported contracts, the formatted path is `<cham_dir>/api_secrets.json`. The
runtime value of `cham_dir` is unknown. This is a source-level inference from
the raw argument, template and earlier observations, not an executed path.

The selector calls the same relocated predicate (`0x144a710`) at `0x144b16f`
and, after the separate transformer (`0x144a600`), at `0x144b197`. The first
false result returns selector tag 2. The second false result enters an error
builder and returns tag 3; it must not be collapsed with the first. Prior
`research/work-items/RE-001-file-tracker-init-94/README.md` identifies the
predicate's non-error mode test as regular-file shaped. We do not assert why a
particular runtime call returns false. On tag 2 the initializer writes a default
result including a zero qword at output offset `0x20`; tag 3 reaches the error
boundary at `0x13d2b21`. The selector's three extension comparisons fold ASCII
uppercase and compare `r`, `m`, `p` after a final dot; other extensions take the
document-reader path. Read and parse failures converge on selector tag 3.

### Field identifiers and dispatch

The following table is generated from `field-dispatch.tsv` and
`binary-field-paths.tsv`. A binary-classifier success name and tag match each
JSON arm's duplicate diagnostic and tag. The fixed-pattern probes also match
all 24 names and tags in both JSON classifier representations, subject to the
two external-boundary assumptions above. The separate `NvTestnet` slice at
`0x2180ff` is nine bytes long; its RELATIVE
pointer slot is `0x5668488`. It is contextual evidence for the AWS-name domain,
not a 24-field discriminator or a claim that a particular file is present.
Before the 24-arm JSON table, tag `0x2e` branches to `0x14a6013` and tag
`0x2f` to `0x14a600c`; their producers and full cleanup remain unresolved. The
table count excludes those special cases and the unknown-field fallback.

| Tag | Name: binary predicate / JSON diagnostic | JSON arm | JSON value target | Binary success leaf |
| --- | --- | --- | --- | --- |
| `0x16` | `slack_key` | `0x14a2b6c` | `0x1441a40` | `0x13c7cc2` |
| `0x17` | `mainnet_slack_channel` | `0x14a302e` | `0x1441a40` | `0x13c788f` |
| `0x18` | `testnet_slack_channel` | `0x14a2ea0` | `0x1441a40` | `0x13c8253` |
| `0x19` | `sandbox_slack_channel` | `0x14a2f63` | `0x1441a40` | `0x13c817f` |
| `0x1a` | `pager_duty_key` | `0x14a2cf7` | `0x1441a40` | `0x13c7ae5` |
| `0x1b` | `risk_url` | `0x14a314b` | `0x1441a40` | `0x13c7d29` |
| `0x1c` | `risk_key` | `0x14a326f` | `0x1441a40` | `0x13c842b` |
| `0x1d` | `eth_chain_to_rpc_provider_to_keys` | `0x14a2fc7` | `0x14bc3b0` | `0x13c779d` |
| `0x1e` | `chain_to_etherscan_ws_urls` | `0x14a3393` | `0x14bb860` | `0x13c7a39` |
| `0x1f` | `etherscan_keys` | `0x14a2dbf` | `0x14bd3f0` | `0x13c836f` |
| `0x20` | `etherscan_v2_keys` | `0x14a3334` | `0x14bd3f0` | `0x13c7ff3` |
| `0x21` | `ip_endpoint` | `0x14a2c93` | `0x1441a40` | `0x13c7c51` |
| `0x22` | `ip_main_key` | `0x14a2d5b` | `0x1441a40` | `0x13c8413` |
| `0x23` | `ip_backup_keys` | `0x14a3210` | `0x14bd3f0` | `0x13c82e1` |
| `0x24` | `ip_info_main_key` | `0x14a2c2f` | `0x1441a40` | `0x13c7e75` |
| `0x25` | `ip_info_backup_keys` | `0x14a2f04` | `0x14bd3f0` | `0x13c7f3e` |
| `0x26` | `zip_and_upload_skip_cp` | `0x14a2bd0` | `0x14bd3f0` | `0x13c7bcc` |
| `0x27` | `internal_ips` | `0x14a3092` | `0x14ba3f0` | `0x13c791e` |
| `0x28` | `s3_bucket` | `0x14a32d0` | `0x1441a40` | `0x13c83c1` |
| `0x29` | `chain_to_replica_s3_bucket` | `0x14a3447` | `0x1441ba0` | `0x13c8497` |
| `0x2a` | `s3_daily_prefix` | `0x14a30e7` | `0x1441a40` | `0x13c7dca` |
| `0x2b` | `visor_remote` | `0x14a31ac` | `0x1441a40` | `0x13c806d` |
| `0x2c` | `b_keys` | `0x14a33ed` | `0x1441d10` | `0x13c7648` |
| `0x2d` | `cg_key` | `0x14a34a1` | `0x1441a40` | `0x13c80ab` |

For `b_keys`, JSON classifier tags are `0x2c` in both borrowed and owned key
representations. `cg_key` is `0x2d`; each success leaf requires the complete
corresponding six-byte literal. The visitor's `b_keys` arm at `0x14a33ed` tests a
slot initialized to sentinel 2. Repetition takes `0x14a83a0`, which supplies
the six-byte name and the `duplicate field` template at `0x1e0fd5`. After a
colon, `0x14a4035` calls the separately owned optional-map boundary
`0x1441d10`: result tag 2 takes an error route; other results occupy a 32-byte
slot. At completion, an unchanged sentinel selects a default whose first qword
is zero; otherwise the slot is selected. The chosen 32 bytes are copied into
the visitor result at offset `0x20`. Separately supplied, unreviewed research
proposes an AWS-name-to-string parser at this boundary. Its function body and
the exact key type are not independently established in this packet.

The binary visitor independently indexes its table at `0x20faa0` with tag
`0x2c`; slot `0x20faf8` selects `0x13ad678`. Its sentinel, duplicate check and
default selection mirror the observed JSON shape. Its optional reader has a
`0xc0` null-marker route that zeros the first two output qwords and returns
success. Non-null input calls external `0x13bec50`; returned byte tag 9 leads
to an option qword of 1 and a 24-byte payload, while other tags and exhausted
input propagate failure. A second `b_keys` field takes the duplicate arm at
`0x13b1863`. The visitor selects the zero default for sentinel 2 and, on the
checked success path, copies the selected 32 bytes into result offset `0x20`.
The exact type of the 24-byte binary payload and all value-reader behavior
remain external questions. `null` refers to the observed binary marker here;
no actual configuration or secret value was read.

### Selected failure and state transitions

| Condition | Observed transition and boundary |
| --- | --- |
| Initial path predicate false | `0x144b177 -> 0x144b1b8`: selector tag 2; initializer takes its default branch. |
| Predicate after transformation false | `0x144b19f -> 0x144b1e1`: error-building route, selector tag 3, initializer error boundary. |
| Read error or JSON/binary parser tag 2 | Selector assembles an error and returns tag 3; allocator and error-formatting internals are external. |
| JSON document trailing byte | Only byte values 9, 10, 13 and 32 pass the trailing whitespace mask; another byte reaches code `0x16` and drops the prior success value. |
| JSON object/depth | An absent opening brace has its own failure arm; depth zero and decrement-to-zero have distinct branches, the latter carrying code `0x18`; increment overflow is separately checked. |
| Visitor/close errors | A visitor error is retained if closing also fails; a closing error after visitor success drops that success. Error allocation and the close checker are external. |
| Duplicate `b_keys` or missing colon | JSON duplicate branches to `0x14a83a0`; wrong colon and exhausted input take distinct targets in `branches.tsv`. Binary duplicate branches to `0x13b1863`. |
| Selected value or binary marker failure | JSON tag 2 branches to `0x14a75ce`; binary input exhaustion returns outer tag 1 and the visitor routes tag 1 to `0x13b097f`. |
| Unknown JSON field | Fallback arm `0x14a2e1e` stages a key/value record; records advance in 64-byte strides. Collector `0x14889f0` skips record tag `0x16`, visits others, and returns tag 1 on its checked failure path. The visitor returns tag 2 and conditionally drops the already selected map. |
| Binary collector failure | The visitor's external collector result is checked against tag 9 at `0x13adf75`; another tag selects `0x13ae3f0`. Its complete cleanup is not decoded. |

These are selected normal-return control-flow observations, with explicit
external boundaries. They do not enumerate all allocation failures, unwind
edges, malformed object states, or all field-specific parser implementations.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo lockfile,
compiler/linker flags, two-build comparison, normalization masks, helper/data
closure and whole-ELF comparison: **not yet measured**. The Python collector
is an evidence tool, not a recovered node implementation. No reference code
was copied into it.

The inferred reference's `base/api_secrets.rs` constructs a path through a
`code` subdirectory and models `b_keys` as a non-optional string-keyed map.
The machine code instead supplies the global `+0x18` field directly to the
filename formatter and has the recorded absent/null slot behavior. Those are
specific reasons to validate the reference layout and path before adopting
them; they do not determine the unknown runtime directory or prove every
high-level serialization behavior. Other fields' Rust types remain unresolved.

## Results and limitations

The retained dataset covers 12 selected FDE ranges, 24 field-tag arms, the
binary classifier's 24 successful paths and 24 matching key probes in each JSON
classifier; the number of locked windows, selected branches and call sites is
recorded in `evidence.json`. These denominators are
the explicit selection, not function coverage for `constants` or the node.
The focused suite checks the retained bytes, hash identity, out-of-range and
NOBITS sections, duplicate/ambiguous FDEs, path-result separation, branch and
relocation corruption, field-table corruption, marker/default/error paths and
negative identifier strings. It passed 53 tests with no skips. Artifact
verification, the catalogue check and input reproduction passed. Tests are
static evidence controls, not execution of generated input against the target.
An additional `python3 tools/verify_imports.py` attempt failed when the Git LFS
clean filter tried to write read-only Git metadata; the pinned submodule commit
was read successfully. No #115 or visor claim is made.

Ownership was checked against the available repository and supplied PR snapshot.
No live upstream refresh was made because network access was outside this run's
authorized scope.

No full-scope progress gate is requested; the component's four gates remain
false. Next question: close the binary value reader and the JSON map boundary's
caller/consumer wiring, including the actual key-type conversion and error
cleanup, while preserving the distinction between the two discriminator
domains and respecting existing ownership.
