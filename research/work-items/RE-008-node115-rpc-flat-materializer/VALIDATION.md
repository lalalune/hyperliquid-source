# Validation record

This record separates static captured-byte observations, mathematical reference
qualification and actual execution of independently authored Rust. The target
capture was never executed, emulated or evaluated. All native correspondence
claims retain the premises and exclusions in [README.md](README.md).

## Frozen identities and order

Base revision: `05bc2de303c05525b71e7e257426e741bc66a390`.
Target node #115 SHA-256:
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Search body SHA-256:
`e5b85966c252893cf418f813293abf44565a6a1b94e98b6f4ed334cc7d04e857`.
Materializer body SHA-256:
`7bc6c5f903154186863f3a8a0b0a31361496ba2be6789457706baecdba8985b7`.

The independent manual cases were frozen first. The qualified reference,
generator, 115 structural controls, semantic mutation obligations, independent
manual witnesses and
the ten-file corpus were then sealed before source authoring. Two corpus
generation runs were byte-identical. The baseline has no implementation at
`src/node115-rpc-flat-materializer`; the after-state supplies the independently
authored operation. This is a reconstruction advance, not a before/after
production-defect claim.
The exact literal source patches were authored after the baseline source;
they implement the previously frozen fault definitions and manual witnesses.

The actual builds used these four unchanged executable inputs:

| File | SHA-256 |
|---|---|
| Cargo.toml | `c936a44663b7c0289a8dfffba5cd3cb457204d4a54c3457a57c11bcf3542d0ca` |
| Cargo.lock | `e40ce88aad1cd1958b5fbb70728e88cc8ea1bf4f5c6ad2bf741ea61df894881c` |
| src/lib.rs | `8da06fda6977268c7495b3387272aacbaa3eb35bb1ce72026ac317a8db4a4d9f` |
| src/bin/driver.rs | `2b046ee9f26290bd08f10577ae9647a02b4ae4438f663d783dbffa528c06a36f` |

The original build snapshot's README hash is
`bb3936bbb2eecb1ff187cd651c6b4ad28c634701135424bc51b0f022729ba00a`.
Only its historical “not compiled” paragraph was subsequently replaced with
the actual qualification summary. No Rust, manifest or lockfile change followed
qualification. Cargo accepted the manually authored lockfile unchanged.

## Actual execution outcomes

The host was macOS arm64, Python 3.14.3, Rust 1.95.0 and GNU binutils
2.47.20260726. Source-only snapshots, fresh Cargo homes, offline locked builds,
explicit compiler paths and recorded minimal environments avoided inherited
Cargo configuration. Linux x86-64 library compilation succeeded; no Linux
execution is claimed. The two host release binaries had identical SHA-256
`1cba70dce803b52ee6ae36bb09f1db009067b059c7cfed467733a098f4e7c494`.

Both baseline profiles exited zero and matched all 13,957 outputs. Their input
SHA-256 is `90fe14a49375599b6cc026546aeac708f2a542497ff55f07ac6f828380d43c92`;
expected-output SHA-256 is
`7b7a746b61b891e4d3f6cec41ddc049b1a2987fcf3d4e26bf191b22c49c4e295`.
Expected values were not passed into the child process. The comparator checks
IDs/order, literal LF, operation/arity and canonical syntax separately from
value and domain invariants. A syntax-valid out-of-domain number is a semantic
mismatch, not a format failure that can masquerade as a detected source bug.

Every compiled variant below built successfully, exited zero, produced 13,957
valid rows and changed its predeclared manual witness in both profiles:

| Variant | Intended fault | Mismatches per profile |
|---|---|---:|
| M01 | Ignore wrapped seam equality | 597 |
| M02 | Select first ordinary equal key | 1,453 |
| M03 | Swap strict seam routing | 4,396 |
| M04 | Omit second-segment logical offset | 2,102 |
| M05 | Treat hit logical index as physical | 3,115 |
| M06 | Compare only the first 31 bytes | 10,269 |
| M07 | Compare bytes as signed | 4,979 |
| M08 | Compare little-endian integer chunks | 42 |
| M09 | Increment/clamp absent insertion index | 3,397 |
| M10 | Return successful prefix on a miss | 3,266 |
| M11 | Deduplicate materialized values | 1,242 |
| M12 | Sort materialized values | 922 |

The 80 separate transport invocations include exact 16,384/16,385 record and
16,777,216/16,777,217 byte boundaries. Eleven accepted cases returned exact
outputs; all 69 refusals exited two with empty stdout, including an invalid
late row. The exact byte-limit positive is valid input, not garbage padding.
Output I/O failure after writing, OOM and native allocation behavior are excluded.

The actual public reproduction additionally passed both modes. The driver mode
qualified the manual reference, regenerated all ten corpus files twice with
byte-identical results, and matched all 13,957 driver rows. Mutation mode
repeated data qualification and built/executed twelve release variants. Each
changed its named manual witness through a semantic mismatch; all twelve counts
equal the table above. These are additional actual public integration runs,
not a claim that the helper replays the historical debug, Linux, static or
transport checks. Their complete commands and raw streams are archived.

## Retained records, amendments and portability

[validation/RESULTS.json](validation/RESULTS.json) locates original result
records within [validation/logs.json.gz](validation/logs.json.gz). This data
archive retains actual command, environment, source identities, stdout/stderr,
process results and comparisons. Each member gives original and projected
hashes/lengths and replacement counts. Only declared absolute path prefixes
are replaced with `<RESEARCH>`, `<REPO>`, `<CAMPAIGN>` or `<RUST_TOOLCHAIN>`.
Cargo's ancestor-configuration absence paths additionally use `<USER_HOME>`
and `<USER_PARENT>`. The first expanded archive attempt stopped on an unmapped
ancestor path before publishing its replacement archive; these two explicit
masks resolved that packaging refusal without changing any numerical evidence.
Numerical rows are unchanged. Original embedded hashes identify original
streams; projected text is not falsely labelled byte-identical to them.

Before the first static collector execution, review found that the original
draft authenticated source but could then execute a cached `.pyc` through its
loader. The collector was amended to compile/execute the exact authenticated
source buffer. The old unexecuted draft and amendment were preserved. Qualified
collector/verifier code was copied unchanged into the public packet. Its only
scope metadata edits are five portable relative paths. Both full GNU/LLVM
exports remain byte-identical to their originals; the 115 controls perturb
structural evidence, not native runtime behavior.

Public-helper review caught an ID-field mismatch in its witness assertion
before any execution: comparator rows include the ID, but the first assertion
discarded that field. The final assertion compares the complete field list.
The companion loader was also changed before execution to compile the exact
authenticated buffer; no cached-code loader is used. Previous unexecuted
snapshots and hashes are preserved in the authoring receipt. Neither correction
changed the source operation, reference, expected rows or mutation definitions.

The handcase/reference, corpus/reference, Rust/contract and actual raw-output
reviews have different roles. They are not multiple independent native
captures. The independently audited baseline/transport and mutation receipts
check retained results without rerunning Rust or treating a worker status
message as proof. The comparator's synthetic process-error fixtures prove
classification only. All known limitations remain explicit.

`make doctor`, `make verify`, `make catalogue-check`, `make reproduce`, Rust
formatting and staged whitespace checks all passed. Verification checked 32
imported files, unchanged source pins and 559 packet manifests / 7,214 entries
at that validation snapshot. `make catalogue` regenerated the component tables
and inventory counts: one new implementation area and Cargo manifest; work
items 559 to 561 because the base already contained 560. All 92 gates stayed
false. Imported evidence, submodule pins and selected-byte coverage are unchanged.

The first whitespace check reported only extra final blank lines in four
already frozen files. Exact-path attributes preserve those bytes and suppress
only that diagnostic; raw mutation patch context has its own exact-path
whitespace exemption. The successful recheck is retained. Small corpus and log
gzip files have exact-path attributes that store their bytes directly in Git.
Full `make test`, hosted CI, native runtime equivalence and full-scope acceptance
are not claimed.
