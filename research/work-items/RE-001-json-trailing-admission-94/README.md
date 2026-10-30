# RE-001: node94 JSON-related wrapper checks the tail after its delegate

- Component: foundation/serialization boundary; RE-001 actual function and
  caller mapping. Question: does the reference-led wrapper at `0x15ba010`
  pre-trim ASCII whitespace, or check unconsumed input after its first callee?
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. Base/reference pins unchanged at
  `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Actual wrapper FDE: `0x15ba010..0x15ba1c8`, **440 bytes**. Supporting caller
  FDE: `0x1611910..0x1615281`, **14,705 bytes**, with selected direct call at
  `0x1613e08`. Complete native disassembly of both is retained for boundaries;
  the large caller's full state machine is explicitly not recovered here.
- No copied inferred implementation, captured code execution, network request,
  new Rust implementation, completed subsystem or progress gate.

## Reference correction

The unlicensed inferred `base/http_client.rs` labels this address as a
JSON-RPC response parser that removes trailing ASCII whitespace *before*
parsing. The actual bounded wrapper does something materially different:
it keeps the original pointer/length in state, calls `0x15c0d90` first, and
then scans **forward from a returned cursor** with a four-byte mask. The raw
ordering and accepted byte class do not support backwards ASCII pre-trimming.
The response/result names and the initial callee's parser role are contextual
inferences, not a proven concrete generic type or recovered API.

The observed mask `0x100002600` with unsigned upper bound 32 admits only
hex **09, 0a, 0d, 20**, agreeing with the JSON whitespace class in
[RFC 8259 section 2](https://www.rfc-editor.org/rfc/rfc8259#section-2).
Rust's byte ASCII-whitespace class additionally includes form feed **0c**;
see the exact compiler-stamped
[core num contract at lines 1012-1014](https://github.com/rust-lang/rust/blob/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/core/src/num/mod.rs#L1012).
The separately fetched file SHA-256 was
`8289fb308a092aff72689b70238477e5fbbbcfbcf0f60639ff89f9a0159b055d`.
Vertical tab 0b is excluded by both classes; Python `bytes.isspace()` would be
the wrong independent oracle for this comparison.

A form-feed suffix is therefore a **conditional local counterexample** to
substituting ASCII pre-trim for the observed end check: if the initial callee
has returned a non-sentinel result with its cursor at that suffix, the wrapper
routes to its error block rather than consuming the byte as whitespace. This
packet does not claim a particular complete JSON-RPC body is valid for the
unknown concrete response type, or that its hypothetical `{}` test prefix was
accepted by the captured parser. No target parser was executed.

## Instruction and state evidence

The straight-line entry saves original RSI at state offset `+0x18` and original
RDX at `+0x20`, zeroes cursor `+0x28`, and calls `0x15c0d90` at `0x15ba05b`
with RSI pointing at that stack state. No pre-trim loop or shortened input
length precedes this call. RDI is the original output pointer retained in RBX.

After the call, raw output word `0x8000000000000001` skips the tail check.
For other words, the wrapper saves the 104-byte result and loads original
length and cursor. A cursor >= length goes to cleanup/return. For the scoped
valid-state case cursor < length, it visits bytes in increasing order:

- `0x15ba0d7`: load 64-bit mask `0x100002600`;
- `0x15ba0f0`: load byte at original pointer plus current cursor;
- `0x15ba0f5`: unsigned compare with 32, reject if above;
- `0x15ba0fb`: test mask bit for the byte, reject if clear;
- `0x15ba101`: store cursor+1 only for an admitted whitespace byte;
- `0x15ba106..0x15ba114`: advance and repeat until the original length.

The unsigned bound is part of the predicate: x86 BT's register bit index
wraps, so the mask alone must not be generalized to high bytes. At the first
non-whitespace byte, `0x15ba13a` materializes raw local error code **0x16**,
calls `0x15b8e90`, stores its returned pointer at output `+8`, and writes the
sentinel to output `+0`. The error enum name, allocation/position/formatting
and complete cleanup semantics of downstream helpers are not claimed.
The wrapper returns its output pointer in RAX at `0x15ba12c`.

The selected caller's instructions at `0x1613dfd..0x1613e1f` pass output
`rsp+0x70`, input pointer RBP and length R14, call `0x15ba010` directly,
and read the result word. This binds one incoming edge; other callers and the
rest of the caller's 14,705-byte asynchronous state machine remain unknown.
The `DIRECT` records also retain outgoing call destinations without assigning
unproved Rust names or claiming transitive closure.

## Reproduce

From repo root, materialize pinned LFS captures and use native GNU binutils:

```sh
python3 -B tools/json_trailing_static.py --output work/json-trailing-admission-94
python3 -B tests/test_json_trailing_static.py
make doctor verify test catalogue-check
make reproduce
shasum -a 256 -c research/work-items/RE-001-json-trailing-admission-94/SHA256SUMS
```

Host: macOS, Python 3.12.14, GNU readelf/objdump 2.47.20260726. One authenticated
snapshot is used by analysis and by both native tools in a private temporary
file. The generator runs `readelf -wf` and `objdump -d -M intel --insn-width=16
--start-address=... --stop-address=...`; it never launches captured code.
`foundation_millis.decode_export` verifies complete contiguity/bytes/end bounds,
and each selected control/call must be a decoded instruction start. Temporary
paths alone are replaced with `<authenticated-node94>`; no instruction/data
normalization mask is applied.

`frames.txt`, the two `.objdump.txt` files and `records.json` preserve raw native
ranges, original VAs/file offsets, sizes/hashes, field/guard observations,
checked instruction bytes and direct edges. Independent transient Capstone
5.0.6 consumed all bytes in **99/2,525** instructions respectively. That is an
additional decoding check, not independent proof of parser semantics.

Five focused tests pass in 21.492 seconds: real state/mask/edge bindings;
all 256 bytes and all **65,536 two-byte suffixes** against a separately listed
JSON whitespace class; the conditional form-feed/pre-trim distinction and a
wrong-mask control; **23** actual-byte instruction corruptions below the whole
input digest gate; and native regeneration plus wrong-input admission rejection.
The suffix model is not an implementation or execution of the captured parser.
Required suite/reproduction results are recorded in the PR after completion.
SHA256SUMS binds the durable packet and both new files.

## Limits and next question

The mask and call ordering are observed; JSON/response ownership is inferred
from the reference lead and surrounding call context. Initial delegate parsing,
concrete schemas/result types, validity and reachability of every cursor state,
error enum identity, drop/allocation helpers, full caller flow, all callers,
independent Rust builds and runtime equivalence remain unproved. The enclosing
caller bytes do not count as recovered caller semantics. No input/pin/import or
progress gate changes. Next establish the initial delegate's concrete accepted
result shape before constructing full-response fixtures or implementing an API.
