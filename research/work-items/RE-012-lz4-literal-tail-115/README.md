# RE-012: node #115 final literal sequence encoder

Target Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`. Component transport;
maintainer scope: bounded frame/codec research in docs/TASKS.md RE-012.
New code/docs MIT; independently read captured bytes, no inferred source copied.

## Resolved question

What does the shared final-literals helper emit, and can a capacity failure
occur after advancing its sink? Before this packet, the existing decoder
and sender-selection packets leave compressor output generation open.
This packet follows the complete FDE `0x477f750..0x477f8ba` (362 bytes)
and four actual direct calls from the two compressor bodies: `0x477ee72`,
`0x477ef5c`, `0x477f582`, `0x477f66c`. Those are bounded caller observations,
not a whole-ELF caller census. No full compressor implementation is claimed.

## Observations

Entry registers: RDI sink descriptor; RSI input base; RDX input end count;
RCX anchor count. At `0x477f755`, R8=end-anchor uses checked subtraction;
borrow reaches the failure helper through slot `0x64df848`. Sink fields
are pointer +0, capacity +8, current length +16. These are inferred role
names from actual loads/stores, not a recovered native Rust signature.

At `0x477f769`, current length >= capacity fails before writing a token.
Otherwise `0x477f772..0x477f78a` emits
`min(literal_count,15)<<4`, with low nibble zero; it immediately advances
the sink length by one. Counts through 14 skip extension encoding. Counts
15 and above subtract 15 and emit zero or more 255 extension bytes,
followed by a final byte in 0..254, including a zero byte when the excess
is an exact multiple of 255. The scalar loop and terminal extension guard
are at `0x477f830..0x477f85d`; a bounded unrolled four-byte 0xffffffff loop
at `0x477f810` accelerates the repeated-255 part. It preserves the same byte
sequence. The reciprocal constant `0x8080808080808081` supports the unrolled
run bound; exact whole-domain arithmetic equivalence of that optimization
is not independently proved here.

The terminal tail at `0x477f861` advances the source pointer by anchor,
passes the literal count in both RDX and RCX, and tail-jumps to the sink
append helper `0x477e5c0`. That helper's full body was studied in
RE-012-lz4-decode-115; this packet binds the actual tail edge, not new
ownership or equivalence credit for that helper. Allocation, append failure,
copy ABI and full unwinding remain external boundaries.

Capacity checks exist before token, repeated scalar extensions and terminal
extension. The sink length is stored after successful token/extension writes.
Consequently this routine is **not a transactional preflight**: its local
failure edges can follow an already-written token or extension prefix.
No rollback appears in this FDE. This describes writes before the failure
call, not whether the original caller can catch a panic and observe them.
For example, literal count 15 with one spare output byte writes 0xf0,
advances length by one, then fails its required zero-extension-byte check.
This is a static consequence of the ordered guards, not captured execution.

## Evidence, qualification and limits

`records.json` retains full FDE/CIE bytes, body hash, original instruction
anchors, calls/tail branches and actual relocation writers. Complete GNU
and LLVM exports are cross-checked byte-for-byte against Capstone. Native
readelf independently checks the FDE extent. `scope.json` freezes exact
ranges and anchors, including all four selected incoming calls.
`verify.py` regenerates exports, refuses changed retained facts, rejects
wrong/truncated captures and mutates one real byte per anchor with the
whole-image digest check deliberately bypassed for that narrow control.
This does not prove all failure helper implementations or a native ABI.

From repository root, Python 3.14.5 / Capstone 5.0.7, GNU binutils 2.45,
LLVM 23.1.4:

```
python3 -B research/work-items/RE-012-lz4-literal-tail-115/verify.py
make doctor verify catalogue-check reproduce
```

Repository test code and base are identical to the preceding complete
583-file qualification (zero nonzero exits, 25 explicit skips); its result
is reused rather than represented as a fresh full test run. This packet's
new verifier is run separately; validation.json records exact outcomes.
No captured execution/emulation, live network, Rust implementation,
compiled-code match or full-scope gate is claimed. All gates remain false.
Next: recover the literal/match sequence emitters within the compressor loops,
with their sink-helper contracts before implementing a complete encoder.
