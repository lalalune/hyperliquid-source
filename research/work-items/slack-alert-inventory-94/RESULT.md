# Result: strong bounded slack_alert evidence

Target: node #94, `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Task: `slack-alert-inventory-94` / RE-001. Exact path:
`base/src/slack_alert.rs`. No acceptance gate is requested.

## Observations

All counts and factual tables below derive from the regenerated JSON. The
verifier and tests reject stale report blocks.

<!-- BEGIN GENERATED METRICS -->
| Metric | Count |
| --- | ---: |
| constants_bound | 0 |
| constants_unresolved | 2 |
| decoded_instructions | 6272 |
| diagnostics_absent | 3 |
| diagnostics_bound | 5 |
| diagnostics_probed | 12 |
| diagnostics_unresolved | 4 |
| indirect_calls_unresolved | 382 |
| indirect_jumps_unresolved | 17 |
| internal_rel32_calls | 0 |
| internal_rel32_jumps | 331 |
| location_leas | 27 |
| locations | 21 |
| pointer_length_anchors | 15 |
| scoped_fde_bytes | 33622 |
| scoped_fdes | 6 |
| scoped_rel32_calls | 6 |
| scoped_rel32_jumps | 0 |
| unique_line_column | 7 |
| unresolved_external_rel32_calls | 224 |
| unresolved_external_rel32_jumps | 0 |
<!-- END GENERATED METRICS -->

The census preserves every relocation-backed exact-path Location separately,
including duplicate source coordinates. All candidate Location LEAs pass the
FDE-start decoder and internal direct-branch alignment checks. Complete raw
instruction transcripts and CIE/FDE/index records are committed; unwind
extents are not claimed as exclusive source-function boundaries.

The bounded literal candidates and negative results are:

<!-- BEGIN GENERATED LITERALS -->
| Candidate | Status | Bytes | Occurrences | Bindings |
| --- | --- | --- | --- | --- |
| https://slack.com/api/chat.postMessage | bound | 38 | 3 | 3 |
| Authorization | bound | 13 | 12 | 3 |
| content-type | bound | 12 | 15 | 3 |
| application/json | bound | 16 | 2 | 3 |
| slack alert | bound | 11 | 3 | 3 |
| Content-Type | present-but-unbound | 12 | 3 | 0 |
| @@ Alerting if slack configured: | present-but-unbound | 32 | 1 | 0 |
| (not alerting because alerted recently) | present-but-unbound | 39 | 1 | 0 |
| n_logs_swallowed | present-but-unbound | 16 | 1 | 0 |
| reference-error-prefix-1 | absent | 27 | 0 | 0 |
| reference-error-prefix-2 | absent | 17 | 0 | 0 |
| reference-error-prefix-3 | absent | 32 | 0 | 0 |
<!-- END GENERATED LITERALS -->

For example, the URL setup at `0x14495b0` puts its pointer in RDX, initializes
other registers with non-clobbering LEAs, then puts the byte length in ECX and
calls at `0x14495c9`. At `0x14495f6` and `0x14495fd`, the header and media-type
LEAs use distinct pointer/length register pairs in the same bounded setup.
The `slack alert` label at `0x1458618` is stored through R14, followed by an
immediate qword length in the adjacent field. Analogous constructions occur
in the other scoped ranges. These are instruction/data facts; the call's ABI
meaning and effects are not established.

The direct call edges are:

<!-- BEGIN GENERATED EDGES -->
| Caller FDE | Call VA | Raw E8 rel32 | Signed displacement | Callee FDE |
| --- | --- | --- | --- | --- |
| 0x1457070 | 0x14586cf | e83c0dffff | -62148 | 0x1449410 |
| 0x1457070 | 0x145935c | e8af00ffff | -65361 | 0x1449410 |
| 0x1479d30 | 0x147b2e9 | e842e0ffff | -8126 | 0x1479330 |
| 0x1479d30 | 0x147bbb9 | e872d7ffff | -10382 | 0x1479330 |
| 0x14b23d0 | 0x14b3951 | e8ea83ffff | -31766 | 0x14abd40 |
| 0x14b23d0 | 0x14b3c2d | e80e81ffff | -32498 | 0x14abd40 |
<!-- END GENERATED EDGES -->

Each edge records E8 bytes, signed displacement and next-instruction VA; the
computed destination equals an independently parsed, Location-anchored FDE
entry. The larger ranges call the smaller ranges at distinct sites. Interpreting
those sites as initial-send/retry behavior would require CFG and argument
analysis and is deliberately not claimed. The inventory separately retains
all decoded rel32 transfers, including internal jumps and unresolved external
calls, so internal jumps do not inflate the external-call gap.

## Negative results and unresolved constants

The capitalized header spelling occurs in the file but has no accepted scoped
binding; the lowercase spelling has length-bearing bindings. The alert,
throttling and swallowed-log phrases also occur globally but have no matching
scoped LEA. Their proximity in a string pool does not connect them to this
file. The reference error-prefix candidates are absent under exact whole-file
search. Their digests and offsets into the pinned reference preserve the
negative experiment without copying absent reference text. These are finite
probe results, not a census of every possible diagnostic or behavior.

<!-- BEGIN GENERATED CONSTANTS -->
| Candidate | Status | Numeric value established |
| --- | --- | --- |
| retry delay schedule | unresolved | none |
| minimum alert interval | unresolved | none |
<!-- END GENERATED CONSTANTS -->

No fixed retry schedule or minimum alert interval is established. Generic
numeric immediates within an unwind range are not uniquely attributable to
alerting, and literal byte lengths are already part of the anchor evidence,
not additional recovered operational constants. No arbitrary numeric probes
are added to increase the packet's apparent depth.

## Validation and controls

Passed: the requested generator command and packet unittest suite; the
standalone packet verifier (whitelist, manifest, digest, byte-identical JSON
regeneration and derived report tables); `make doctor`;
`make verify test catalogue-check`; and `make reproduce`. Artifact hashes,
signatures and imported/submodule provenance passed in this clone without
an upstream-key workaround. Repository-wide tests and reproduction of the
imported inventories/literal classifications passed. No final validation
failure remains. These are local results, not hosted CI or a container build.

The packet suite exercises producer and verifier with process creation and
network access blocked. The committed decoder and packet tests depend only
on Python standard-library modules; no GNU/LLVM objdump is invoked. No target
execution, network access, installation, GitHub operation, progress/catalogue
mutation or imported-evidence change was performed.

Controls cover wrong target digest before output creation; corrupted Location
fields/path/relocations; missing, malformed and non-executable sections;
malformed FDE/index records; shifted LEAs and operand-embedded opcode bytes;
invalid, unsupported and truncated encodings; internal branches into operands;
wrong literal lengths, pointer registers, field offsets and content; register
clobbers and interrupted setups; mutated call displacements and destinations;
report drift; manifest omissions, extras, symlinks, duplicate/traversal entries
and changed bytes. Lower-level mutation tests intentionally exercise parsers
beneath the production digest gate; production has no skip-digest option.

## Explicit non-claims and remaining gaps

- No target execution, runtime behavior, request transmission, protocol
  semantics, retry/throttle policy, token handling or response handling.
- No source reconstruction, recovered names/types, Rust build, binary
  equivalence, accepted function-coverage denominator or progress gate.
- No exclusive component ownership or CFG reachability. Inline/shared code,
  split bodies and code without FDEs remain gaps.
- No claim for spot_meta, spot_clearinghouse, evm_kvs, nv_stream, HTTP/reqwest
  internals, tokio runtime, abci or other base/foundation helpers.
- No helper closure, indirect-call/callee or vtable closure. Only Location
  relocations are resolved; other data/relocations and whole-ELF comparisons
  remain open. No normalization is applied and no matched-body count exists.
- No parity for node #115 or visor, hosted CI result or container build claim.

Verdict: **strong for this bounded static inventory**, supported by complete
exact-path census, length-bearing anchors, scoped call edges and adversarial
controls. It remains partial research, with constants and semantic claims
unresolved. The next bounded question is CFG and argument provenance for the
retained edge at `0x14586cf`; it can be studied without attributing unrelated
HTTP or runtime helpers.
