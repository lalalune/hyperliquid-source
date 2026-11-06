# RE-005: GossipRpcResponse variant2 outer envelope and scalar-record composition

Target Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`; serialization / RE-005,
with RE-012 gossip context. All addresses ELF VAs, no rebasing or masks.
New material MIT; the existing scalar/reader research code is reused unchanged.
No unlicensed inferred reference source was copied.

## Bounded gap and outcome

The base's RE-005-node115-gossip-response-record reconstructs the inner record
at0x5aabd20 and retains its response parent as **context only**. Its next step
leaves response-container semantics open. This change implements the complete
**variant2 envelope**: u32 variant tag, outer optional marker, and its actual
handoff to that existing record decoder. It exposes logical values and cursor/
charge state, not the parent native ABI or the entire GossipRpcResponse.
Variants0/1 are explicitly unimplemented selection boundaries in the new API;
they are not represented as completed native response decoding. No gate advances.

The parent is the complete FDE0x5aac7c0..0x5aacc22 (1122 bytes). Its initial
call0x5aac7d5→0x5821150 reads the u32 tag. The selected compare at0x5aac7fb
chooses index2; indices0/1 route to other opaque payload decoders, and >2
construct invalid-variant context. The already-qualified u32 reader charges4
in canonical limited mode, independently of encoded length, accepts nonminimal
FB/FC forms and is little-endian at its actual short-helper call. The selected
u32 semantics are copied/credited from the existing MIT Request component;
this contribution does not claim a new primitive.

## Outer marker and error-state ordering

On selected index2,0x5aac804 checks canonical mode1. In limited mode,
0x5aac822 checks charged==u64::MAX before adding; overflow fails without a
count store. Otherwise0x5aac834 stores charged+1 **before** comparing the
old count with the limit at0x5aac838. Refusal preserves the newly stored
count but does not consume a marker. This is equivalent to next>limit only
under the already-observed overflow guard. Unlimited mode preserves count.
Missing marker input is checked after this charge.

0x5aac867/0x5aac86b store the advanced pointer/decremented length before the
marker tests. Marker0 selects outer absence; marker1 calls the actual inner
record at0x5aac886→0x5aabd20; every other marker is consumed before an invalid
outer-option error. The inner record has its **own** optional scalar marker,
which must not be silently read twice or confused with this outer layer.

A normal absent envelope logically charges5 (tag4+outer marker1). A present
record with its inner optional scalar absent normally charges38; when present,
46. These are scalar logical charges, not wire byte counts, aggregate precharge
or recovered field units. Each inner scalar/marker keeps its own failure
ordering through the unchanged qualified record package.

At0x5aaca51, outer absence uses raw first word2 on the normal return path.
The inner record also uses raw word2 for failure, but0x5aac8b3 detects that
before entering the normal-return stores and routes it to parent failure.
Conflating these paths would turn an inner error into an absent response.
The new safe Option<Record>/Error API intentionally avoids pretending to
recover the original flattened enum/niche/padding layout.

## Reuse, expectations and actual builds

The genuine Cargo dependency is node115-gossip-response-record0.1.0 from the
existing main source. Its Reader adapter points to the already-imported,
hash-verified MIT snapshot at commit45e91f8499f1a78460407d235f580c1625f44d1a.
No copied Reader replacement, guessed dependency version, fabricated original
workspace or missing-source shim is introduced. Source/manifest hashes and
exact versions are retained; reused primitive/record credit stays with prior work.

Before the new Rust directory existed, oracle.py authenticated the seven-FDE
context, revalidated the immutable existing35692-row record fixture and froze
**47292 new envelope cases**. cases.tsv and freeze.json preserve the exact
rows/hash and source/scope hashes; the recorded new_rust_exists=false is a
historical observation, not a claim that it stays false during later replay.
The oracle is explicit static branch mathematics plus the existing immutable
record relation, **not** a Reader/Rust implementation run or captured-instruction
interpreter. It remains same-author fallible target interpretation, not an
independent peer review or native dynamic oracle.

The production decoder actually composes the unchanged record library. Real
Cargo debug/release builds each compare every result, total consumed count
and charged count with the frozen rows. Six actually compiled source mutations
cover wrong tag charge, omitted tag-count commit, wrong variant selection,
wrong outer charge, incorrect Some marker and double outer-marker consumption.
Every mutant must return normally and differ on a retained witness. The scalar
record's seven existing unit tests are rerun as regression, not counted as new
record reconstruction.

## Physical evidence and controls

The seven complete contexts total2819bytes/742instructions: parent1122,
u32 wrapper243/short293, record602, u64 wrapper229/short316 and invalid-marker
fields14. Except for newly interpreted parent-envelope semantics, these are
already-qualified/reused context, not new matching or implemented-byte credit.
records.json binds whole hashes, FDE/CIE bytes, all call/branch rows, actual
RELA writers and four signed reader dispatch tables. Other parent branches,
indirect/table behavior outside the selected route, type/action chains and
transitive failure-formatting/unwind behavior remain unclosed.

GNU/LLVM/Capstone complete instruction partitions agree; readelf independently
checks all extents. The verifier replays retained records/exports, rejects two
wrong/truncated captures and mutates one real byte per nine instruction/four
data-table anchor with the full-file digest gate bypassed only for those narrow
controls. It does not execute or emulate original code.

```
python3 -B research/work-items/RE-005-gossip-response-v2-envelope-115/verify.py
python3 -B research/work-items/RE-005-gossip-response-v2-envelope-115/qualify.py work/v2-fresh
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-gossip-response-v2-envelope/Cargo.toml
cargo +1.95.0 clippy --all-targets --offline --locked --manifest-path src/node115-gossip-response-v2-envelope/Cargo.toml -- -D warnings
make doctor verify catalogue-check reproduce
```

Python3.14.5, Capstone5.0.7, GNU binutils2.45, LLVM23.1.4, Rust1.95.0.
Actual result/source/compiler hashes, commands and checks are in qualification.json
and validation.json. The unchanged583-file base suite result is reused explicitly
(zero nonzero exits,25 skips), not represented as a new full-suite run. Additional
catalogue/component and dependency checks cover this change. Linux rlib build
is not Linux execution on the macOS host, and hosted CI is not claimed.

## Limits and next step

No original Rust ABI/inactive data, arbitrary context aliasing/raw modes,
field units, state invariants, signatures, framing, other response payloads,
full original dependency/compiler lock, compiled-byte identity or integrated
node compatibility is established. Only the selected branch is implemented;
OtherVariant is a routing boundary, not a placeholder decoded message. No
captured execution/emulation, chain operation or live endpoint was used.
All92 full-scope gates and byte-comparison totals stay unchanged. Next: recover
one of the separate variant0/1 payload decoders, then compose the real complete
response decoder with this already-qualified variant2 path.
