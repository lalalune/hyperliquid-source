# RE-012: reconstruct node #115 final literal encoding in Rust

Target Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`, component transport,
maintainer task RE-012 frame/codec semantics. New Rust/docs/scripts MIT;
independently authored from target bytes. No unlicensed inferred source copied.

## Gap and result

The earlier static-only PR #2770 recovered the final-literals sequence but
supplied no Rust implementation and explicitly left the grouped-255 arithmetic
proof open. This packet implements that bounded sequence with its real sink
append contract. It does not re-credit the earlier static research as new
first-party matched bytes. Main's RE-012-lz4-decode-115 already contains append
observations; this packet rebinds that existing helper to close the new Rust
implementation's local copy/failure boundary. Complete compression remains open.

The new `src/node115-lz4-literal-encoder` is a real dependency-free Cargo crate,
with lockfile, `no_std` library and a host probe. On the base no such encoder
exists. After this change a caller can append a final literal sequence while
observing the retained output prefix and length after each capacity refusal.

## Observations and implementation choices

`scope.json`, `records.json`, raw GNU/LLVM exports and native unwind output bind
both full FDEs: final-literal emitter `0x477f750..0x477f8ba` (362 bytes,
89 instructions), and append `0x477e5c0..0x477e6d4` (276 bytes, 74 instructions).
Four selected real caller sites are retained as instruction anchors; this is
not a whole-ELF caller census. Every instruction byte is partitioned by
Capstone/GNU/LLVM, without masks. Sixteen real byte anchors are independently
corrupted below the artifact digest guard; all are rejected. Wrong/truncated
capture controls are separately rejected. Full source ABI is not inferred.

The emitter checks `end-anchor` for borrow at `0x477f758`; capacity for its
first byte at `0x477f769`; and stores token plus new length at
`0x477f78a..0x477f792`. The token is `min(count,15)<<4`. For count >=15,
the excess uses repeated 255 bytes followed by one byte 0..254, including
zero for an exact multiple. Each successful output stage advances length;
refusal at a later stage retains those writes. A count of 15 and one spare
byte writes `f0`, advances length once, then refuses its required zero byte.

At `0x477f861..0x477f86f`, both append length arguments equal `end-anchor`.
The full append helper checks checked length addition and whole-copy capacity
at `0x477e5d2..0x477e5e5` before copying any literal, then records the new
length at `0x477e681`. Its call through slot `0x64df508` for long copies is
an external byte-copy boundary. This Rust implementation uses safe disjoint
slice `copy_from_slice`, not the original copy ABI. Native failure-call slots
and original relocation records are retained, but panic payloads, unwinding
and caller catchability are not reconstructed.

The safe API maps captured failure boundaries to explicit stage errors, rather
than preflighting and rolling back the complete operation. It adds an explicit
`Domain` rejection for `end>input.len()` or `used>sink.len()`: the original
unchecked pointer ABI does not supply those checks. Those invalid-descriptor
cases are safe API behavior, never claimed as target equivalence. Valid-domain
`anchor>end` returns `Anchor` before touching output. Lifetimes forbid aliasing.

## Grouped extension arithmetic

A scalar emitter is sufficient for logical output/state, but this requires
checking the native optimization rather than assuming it away. At
`0x477f7b8..0x477f7c5`, C=`0x8080808080808081`, with
`C*255=2^71+127`. For every unsigned 64-bit x,
`x*127 < 2^71`. The reciprocal error is therefore strictly less than `1/255`;
`x/255` has fractional parts in multiples of `1/255`, so
`floor(x*C/2^71)=floor(x/255)`. `qualify.py` checks the integer premises.
For `x=count-270`, this is one less than the number of required 255 bytes.
The native loop bounds its count by remaining sink capacity and rounds down
to a multiple of four, leaving the scalar loop to emit remaining 255 bytes.
All grouped stores are within capacity; its completed-store length and next
capacity refusal match scalar emission. This proves logical sequence and
capacity-failure state, not asynchronous-fault visibility, vector/store
instructions, speed, native ABI, or compiled-byte identity.

## Independent qualification

`oracle.py` first constructs the mathematical token/extension/literal event
sequence, then applies capacity to each event. The production Rust performs
scalar arithmetic directly. Both are independently authored from the static
branches; neither runs a captured instruction interpreter. `freeze.json` was
written while the new Rust directory did not exist. Its immutable generator,
input and full expected-output hashes cover 22,848 cases: all counts 0..1099,
thresholds through 131071, extension/append capacity boundaries, arbitrary
existing sink prefixes, varied source anchors and seeded bytes, and safe API
domain failures. The probe compares every output byte including unchanged
prefix/suffix, as well as returned stage and length. This is not target
execution or a proof for every arbitrary byte slice.

Actual separately compiled Rust opt-level 0 and 3 both match every frozen row.
Six compiled mutants terminate normally and are detected: low token nibble,
missing mandatory zero extension, 255 boundary, wrong extension divisor,
partial literal copy on refusal, and incorrect final length. The initial
qualification reached four mutants then failed compiling the partial-copy
mutant due to overlapping borrow syntax. That negative result is retained in
ignored work; only the mutant's syntax was corrected, without altering the
production code or frozen oracle. The successful final run compiles and kills
all six. `qualification.json` retains first divergent witnesses and hashes.

From repository root with Python 3.14.5, Capstone 5.0.7, GNU 2.45, LLVM 23.1.4,
Rust 1.95.0; source `work/environment/new-three-env.sh`:

```sh
python3 -B research/work-items/RE-012-lz4-literal-encoder-115/verify.py
python3 -B research/work-items/RE-012-lz4-literal-encoder-115/qualify.py --out work/literal-encoder-replay --rustc "$RUSTUP_HOME/toolchains/1.95.0-aarch64-apple-darwin/bin/rustc"
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-lz4-literal-encoder/Cargo.toml
cargo +1.95.0 clippy --all-targets --offline --locked --manifest-path src/node115-lz4-literal-encoder/Cargo.toml -- -D warnings
cargo +1.95.0 fmt --check --manifest-path src/node115-lz4-literal-encoder/Cargo.toml
```

The Linux build emits only an rlib; no captured binary or cross-target executable
is run. Host execution is limited to newly compiled independent Rust. No network
node, complete compressor, whole-program equivalence, or gate completion is
claimed. All component gates and registered byte counts remain unchanged.
Next: recover match-sequence emission and integrate it with the established
probe, literal tail and caller-selected sink contracts.
