# RE-001: HTTP IO shutdown completion and retained payloads

Component: foundation/network-client dependency support. Target: Linux x86-64
node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Baseline: `e5c9b6436876b2a4a39daef813171f9879317699`.

This packet closes a specific static interpretation gap before reconstructing
HTTP shutdown: a zero socket result does not alone determine the driver's final
outcome. The selected completion block also consumes a retained payload. It
separately maps the transport variant, direct socket error, and pending-like
raw result paths. No complete Rust type, first-party endpoint, peer protocol,
full driver behavior, or acceptance gate is claimed.

## Observations

`records.json` records the exact sites, raw instruction bytes, FDEs and relocations.
The driver range is `0x1493170..0x149788c`; repeated source-path references into
`hyper-fork/src/proto/h1/conn.rs` and HTTP diagnostics suggest dependency ownership.
This is an inference from the binary, not imported inferred Rust source.

At `0x1496f1a`, the saved incoming ECX low byte controls whether to call transport
shutdown. Tag 2 at local R15+0xe8 delegates through `0x14c1360`; other tags call
`0x4f7d610` with local R15+0xe8. That wrapper reads the fd at input+0x18 and calls
`shutdown(fd,1)` through the actual dynamic-symbol relocation. Its minus-one arm
loads `__errno_location` and returns the encoded errno with a zero RAX.

The driver distinguishes this call's result from the field at local R15+0xc8.
The common completion block loads and clears that field. Zero selects raw output
tag 0; a nonzero old payload selects tag 2 and preserves the payload. A socket
error instead goes through `0x29c7d90` and returns tag 2 without taking that common
field-clearing block. The wrapper helper allocates 0x18 bytes, initializes an
inner tag 0x0e, and tail-calls another constructor; that constructor is not yet
closed. Do not equate these raw output tags with a recovered Rust enum ABI.

The generic AL-bit branch returns raw output tag 3. It is not reachable through
the selected plain wrapper's normal returns, which set RAX to zero. The delegate
can return a distinct RAX; its downstream helper behavior remains unresolved.
R15 has multiple definitions in this driver. All field offsets are local to the
selected branch, not a claimed complete entry-object layout.

## Reproduction and validation

The extraction uses CPython 3.12.1, Capstone wrapper 5.0.7 / API 5.0 and GNU
objdump 2.47, x86-64 Intel syntax. Both decoders agree on every instruction address and
raw byte pair in all five complete FDEs. Original exports are retained as
`disassembly.json.gz` and `gnu.objdump.txt.gz`; no operand normalization is used.

From repository root (a full authenticated capture is required):

~~~sh
python3 research/work-items/RE-001-http-shutdown-outcome-94/verify.py --check
python3 research/work-items/RE-001-http-shutdown-outcome-94/controls.py
python3 research/work-items/RE-001-http-shutdown-outcome-94/export.py --out work/http-shutdown-outcome-94
make doctor
make verify test catalogue-check
make reproduce
~~~

Each script accepts `--binary /absolute/path/to/hl-node` to reuse the same full
capture outside the checkout. `export.py` accepts an existing `--capstone`
module directory and an explicit `--objdump` executable; it installs nothing.
The standard-library verifier and controls need neither decoder installed.
Native Windows validation uses the operator's bounded Job supervisor; commands,
absolute executable hashes, actual results and cleanup records accompany the PR.

The positive full-capture check and 27 structural corruption controls passed
while developing this packet. Controls reject altered flag/variant/error
branches, fd/how/errno fields, retained-field loads/clears, output tags, call
slots, actual RELATIVE/import records, an FDE length, unanchored body bytes,
whole-input identity and corrupted decoder exports. `controls.json` records
these refusals. They are static proof-integrity checks, not runtime behavioral
cases or an emulator. All five full FDEs (18,718 bytes / 3,311 instructions)
were exported by both decoders and their complete address/byte pairs agree.

The first verifier run used the wrong displacement width for the short JNE at
0x1496f30. Its original failure is retained outside the source. The corrected
observer follows the actual 756d encoding; it changes no capture bytes or test
assertions. Final-head mandatory results and any missing-input/tool failures
are reported with the PR, separately from the focused packet checks.

Gzip uses mtime 0. Original GNU output includes the supplied capture path and
tool formatting; whole archive hashes can differ across paths/tool versions.
The verifier compares the complete original instruction addresses/bytes, with
no operand normalization. `export-report.json` records the actual tools and
archive hashes for this export. No compiled-code comparison is registered.

The capture was never executed or emulated; no network or TLS session was opened.
The standard Linux shutdown/errno contract interprets the imported API only:
https://man7.org/linux/man-pages/man2/shutdown.2.html and
https://man7.org/linux/man-pages/man3/errno.3.html. The captured dependency and
binary bytes retain their upstream rights; new analysis is independently authored.
No can1357 inferred implementation was copied.

## Limits and next question

No Rust reconstruction, whole-driver CFG, asynchronous liveness, indirect-call
closure, system-call execution, deployed behavior, equivalence or progress gate
is claimed. Observed branches are conditional on valid stable memory and normal
returns of opaque helpers and tracing calls. Next, close the delegate/error
constructor calls and map the driver's outer application owner before joining it
to a source-built node.
