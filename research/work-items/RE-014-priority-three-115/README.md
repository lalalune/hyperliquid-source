# RE-014: node115 defined three-byte normal-path Rust projection

Target Linux x86-64 node115 SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Main contains the merged RE-003 static certificate but no corresponding active
Rust implementation. This contribution reconstructs its established normal
stores and cursor/count transition in a dependency-free no_std Rust library.
All three equivalent entry copies are covered together, not separate tasks.

Complete FDEs: 0x1839480..0x1839913, 0x2fbf570..0x2fbfa03,
0x48117a0..0x4811c33; each1171B/267 instructions. Their first359 bytes are
identical. Complete exports are context, not matched or reconstructed bytes.
The existing MIT priority_prefix_static.py certificate is reused unchanged,
explicitly credited and hash-pinned. It supplies the raw branch, gate and
diagnostic observations; it is neither new independent peer review nor a new
source-version/type attribution. Full FDE/CIE analysis, unique diagnostic
relocation writers and actual Capstone5.0.6 decoding are repeated here.

## Qualified semantics

Exactly three readable u8 values; nonnull cursor p, nonwrapping end=p+3,
count<=u64::MAX-3, valid nonaliasing state/output/stack and ordinary completion.
The first two numeric gates admit every u8; the third converts exactly too.
The selected prefix and epilogue have no calls. Defined native outputs:
qwords+0/+16=0, binary64 payloads+32/+40/+48 represent the three respective
integers exactly, byte+56=0; cursor advances3 and count advances3.
Native+8..15 and+24..31 come from incoming XMM4/XMM0 and remain unspecified.
Other bytes/padding and RAX are not compared or initialized as known native
values. The diagnostic 'struct PriorityRateDelayParams with 6 elements'
does not establish a six-byte requirement or recover a concrete Rust type.

The new safe Projection and Option are logical interfaces, not native ABI.
The probe's nine qwords are qualification/state/controls2/value-bits3/marker,
not the original object layout. Our None on cursor/count domain refusal is
not a native error claim. Cursor is a numeric coordinate, never dereferenced.
Integer exponent/mantissa construction independently produces exact binary64
bits for0..255, without needing floating-point instructions in the own-code
evaluator. All16,777,216 triples follow algebraically from separability;
this is NOT the number executed. Actual9467 unique triples x9 state pairs
=85203 own-code comparisons, zero mismatches. Three cursor coordinates and
counts0/1/MAX-3 exercise unaligned coordinates and the upper boundary.

Seven separately compiled Rust corruptions and six operative native operand
counterexamples are rejected. Native counterexamples are static equations on
patched bytes, not execution or interpretation of captured instructions.
Only newly compiled own ELF REL code enters the unchanged project evaluator;
external calls/data/relocations fail closed. Repeated own objects agree.
No shared ISA change or tooling repair is necessary.

## Reproduce

```sh
python tools/priority_three115_rust.py --rustc /path/to/rustc --out work/priority-fresh
cargo build --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-priority-three/Cargo.toml
HYPERLIQUID_PRIORITY_THREE_RUSTC=/path/to/rustc python -m unittest discover -s tests -p test_priority_three115_rust.py -v
```

Use Rust1.94.1/Linux target and fresh output directory. Actual flags/compiler
hash, own object/body hashes and all control witnesses are in rust-validation.
Captured binaries are inert and rejected as compiler/object inputs.

## Ownership and limits

Live PR2442 owns bin-supply caller tracing; PR2465 owns alternate error-route
and caller reachability research. Neither implements this normal-path Rust
projection. No caller/reachability/protocol/error claims from those PRs are
adopted here. PR2393/2075/2062 fix the existing static parser; that module is
unchanged. No review request/review was present on2442/2465 at scope check.
Source types, whole visitor/decoder, other lengths, suffix/errors/helpers,
original ABI, callers, protocol, ownership and whole-node closure remain open.
No byte identity or window credit; every component gate remains unchanged.
