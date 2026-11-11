# RE-014: node115 newline request and callback-state protocol in Rust

Component foundation. Initial validation base 8fd8db680ec4bfef40996e5616bce3d5156d0b86.
Current integration base 05bc2de303c05525b71e7e257426e741bc66a390.
Target Linux x86-64 node115105896032B SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Main retains a qualified native newline protocol and frozen abstract traces,
but no active Rust implementation of that115 helper. This adds independently
authored dependency-free no_std write_lines and a synthetic callback recorder
that instantiates the SAME generic function, not a second test-only algorithm.

Primary full FDE0x1686bd0..0x1686e46,630B/173 instructions,
SHA256fc968173616031f08d0a0e77dedca4e6cc4b81ddd1f7cb57e74b10cfae20cb2d.
Full parent0x167d950..0x167dad6,390B/109 instructions is reused context only.
Existing MIT newline-protocol collect.py/bindings and the MIT abstract trace
model in tests/test_node_padadapter_semantic_comparison.py are reused unchanged
and explicitly hash-pinned. They are not new independent peer review. Fresh
Capstone raw instruction partitions agree exactly with retained GNU rows for
both complete bodies. All32 branches,2 freshly loaded V+0x18 callback sites,
8 explicit MOV stores,11 NOP forms, constants/literal, raw frame/CIE records,
parent/table references and four selected unique RELA writers are replayed.
No new GNU/LLVM command success or new recovery credit for this static evidence.

## Conditional request/state behavior

For immutable input, valid nonaliasing storage, protected frames/control state
and normally returning preserving callbacks, split into nonempty first-LF
pieces including LF and at most one nonempty final tail. For each piece:
read the current flag; if nonzero request four spaces. An indent callback's
nonzero AL stops before the owned flag store or payload. Otherwise write
whether this piece ends in LF, then request the exact piece. Nonzero payload
AL stops after the owned store. Every nonzero callback status normalizes to1;
all success returns0. Empty input/terminal empty tail requests nothing.
Callbacks may edit the byte flag and their future behavior. Indent-success
flag edits are overwritten by the owned payload predicate; payload edits may
affect the next indentation decision. Final flag is not assumed unchanged.

The safe generic FnMut API is logical and byte-fed, not the native formatter,
nominal type, original result ABI or physical vtable identity. Its valid flag
reference is required even when input is empty, stricter than native's empty
B mapping requirement. Real renderers/method-pointer identities, arbitrary
aliasing, changed input, unwinding and concurrency remain unqualified. Stateful
scripts exercise changing callback behavior, not a recovered callback callee.
The probe's3 header words and4-word events are a NEW observation ABI: status,
final flag,call count; then kind,input offset-or-four-space word,length,flag
on callback entry. Input offset+length identifies an exact borrowed input
view; indentation bytes are actually read from the freshly authored Rust's
own stack slice. No rendered output or native pointer-identity comparison.
Synthetic probe fixtures are bounded to129 input bytes; its raw callers must
supply nonaliasing valid input,4*script_len bytes and representable output
room for3+8*input_len qwords, all within valid allocation/slice bounds.

3493 deduplicated(data,initial flag,callback script) cases x8 actual unaligned
coordinates =27944 compiled-code comparisons,0 mismatch. All34 existing frozen
cases are included in that deduplicated denominator, not added again. The
matrix covers empty/tail/terminal/repeated LF, scalar/alignment/word boundaries,
high bytes, flags0/1/2/128/255, raw status128/255, errors before/after owned
stores and dynamic flag edits. Existing freeze chronology belongs to the old
project vectors; no new pre-implementation freeze is claimed for our matrix.
Raw expected/actual trace rows are retained under work in deterministic
comparisons.jsonl.gz; the record pins their SHA256 and the regenerated corpus.
The compressed file is not a new LFS input or copied captured instruction log.
Seven real compiled source mutants are rejected; repeated own objects agree.
Six actual native operand/literal changes have operative short-path witnesses
and below-identity binding rejection. Those changed-target equations are
restricted to inputs<=15 bytes; they do not simulate a PC/register machine
or claim the behavior of a mutated wide scanner.

## Source and safety proof

Before each outer iteration0<=start<=n. On entry start<n; the search cursor
starts there and grows only while end<n, so start<=end<=n. A found LF advances
end by1 only when end<n. Thus the emitted end satisfies start<end<=n; subtraction
and the internal borrowed slice are valid. A successful piece strictly advances
start, proving finite progress and at most2 callbacks per input byte. The
input remains immutable during normal callbacks. Four stack-indent writes have
fixed indices0..3. This justifies the internally unchecked slice without
inventing a panic helper. The public safe function does not need a caller
pointer/length ABI; the unsafe synthetic recorder documents its own bounds.

## Reproduce

```sh
python tools/newline_requests115_rust.py --rustc /path/to/rustc --out work/newline-fresh
cargo build --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-newline-requests/Cargo.toml
HYPERLIQUID_NEWLINE_REQUESTS_RUSTC=/path/to/rustc python -m unittest discover -s tests -p test_newline_requests115_rust.py -v
```

Rust1.94.1/Linux target, Python3.12/Capstone5.0.6; fresh output directory.
Exact flags/compiler/source/model/corpus/own-body/raw-comparison hashes are in
rust-validation.json. Only newly compiled own ELF REL enters the unchanged
evaluator; unknown instructions, external calls/data/relocations fail closed.
Captured inputs are refused as object/compiler. No captured process, chain,
network operation, new ISA model or original helper stub is involved.

## Ownership and limits

Merged1370 supplies the115 native protocol and merged1496 the abstract vectors.
Closed1030's retired94 controller/622B helper is not imported or treated as115
validation. New Rust is authored from the qualified115 byte protocol. Open2401
owns a different96B byte arm0x1686b70;2410 owns shim0x168aa10. Those callee
semantics are neither adopted nor implemented. Context/table slots remain
boundaries. Source/provider/archive/compiler identity of the captured node,
full parent/controller, real writer/value callbacks, physical rendering,
whole-runtime integration and nominal ABI remain unresolved. Own412B/107
instructions differs from target630B/173; no byte-window credit or whole-module
denominator is claimed. All component gates stay unchanged.
Next question: bind actual caller/writer capabilities and uphold the protected
memory/normal-return premises before integrating this logical protocol.
