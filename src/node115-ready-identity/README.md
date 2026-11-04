# RE-001: node115 ready-vector identity scan in Rust

Component foundation; current base8fd8db680ec4bfef40996e5616bce3d5156d0b86.
Target Linux x86-64 node115105896032B SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Main retains a static relation for the299B/80-instruction probe
0x154cd10..0x154ce3b but no active Rust ready-vector scan. This adds an
independently authored no_std generic scan and an adapter that instantiates
the SAME function for actual compiled-code comparison. No duplicate test-only
implementation substitutes for the public safe API.

Two complete caller FDEs 0x14c2a40..0x14c2b4c(268B/73 instructions) and
0x14c2b50..0x14c2c47(247B/67) are retained context only. Their effects are not
implemented or reclaimed as new observations. The existing MIT project
tls_lock_id_static.py and RE-001 packet supply source/relocation observations;
they are reused unchanged, explicitly credited/hash-pinned, not claimed new
independent peer review. All3 complete FDEs/CIEs, Capstone partitions, selected
unique relocation writers, source Locations and dynamic bcmp symbol metadata
are replayed against the authenticated115 capture. No new GNU success claimed.

## Established conditional relation

Input byte+32 unequal1 returns false without this TLS scan. Otherwise assume
TLS readiness1, borrowed counter<2^63-1, finite well-formed nonwrapping56B
records, valid byte regions and no alias with counter/state/output. Each row
compares record+24/key+24u64, record+16/key+16u32, record+8/key+8u64 length.
Only then does import slot0x64df9f8, GLOB_DAT symbol11 bcmp, compare row+0 and
key+0 for the key's length. Under the standard ordinary ABI-preserving bcmp
zero/equality contract, any full match yields true; empty/exhausted yields
false. Both normal scan returns restore the saved counter, rather than
persistently advancing an identity sequence. Input pointers can differ while
their bytes match. Padding+20..23 and other fields are not identity fields.

Original TLS FS:-0x1180 and 56B/field offsets are observed coordinates, not
recovered Rust types. New Key bytes/word/token labels are logical API fields.
Generic ready_contains takes a finite ordered iterator of safe borrowed keys;
it does not implement actual TLS access or counter mutation/borrow ordering.
None is our refusal outside the qualified counter domain, not a native panic
result. The synthetic raw adapter writes qualification/bool/original-counter
as three NEW qwords, not the native AL/object ABI. Adapter safety requires
ALL encoded byte slices valid, nonnull, <=isizeMAX, even on scalar mismatch;
this is stricter than the native deferred bcmp reads. Different memory-read
ordering is not claimed equivalent. Bytewise volatile reads avoid an external
helper in newly compiled own code; they do not reproduce libc implementation.

738 explicit-length/boundary/deterministic vector fixtures x4 counter/enabled
states x8 unaligned raw coordinates =23616 actual comparisons,0 mismatch.
Two own counter refusals are separate, not native error comparisons. Lengths
0/1/7/8/15/16/31/32/63/64/65/127/128, field-only and first/last byte mismatch,
different lengths, duplicates and matches at different positions are included.
The emitted corpus input-stream hash is retained, and the tool regenerates
every row; no pre-implementation freeze or independent chronology is claimed.
All7 separately compiled corruptions and6 operative native operand examples
are rejected. Repeated own objects agree. Native controls use static literal
field equations; no original instruction/register/PC stream is interpreted.

## Reproduce

```sh
python tools/ready_identity115_rust.py --rustc /path/to/rustc --out work/identity-fresh
cargo build --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-ready-identity/Cargo.toml
HYPERLIQUID_READY_IDENTITY_RUSTC=/path/to/rustc python -m unittest discover -s tests -p test_ready_identity115_rust.py -v
```

Rust1.94.1/Linux target, Python3.12/Capstone5.0.6; fresh output directory.
Exact compiler/flags/source/model/body/corpus hashes and all negative witnesses
are in rust-validation.json. Only freshly compiled own ELF REL enters the
unchanged evaluator. Unknown instructions, external data/calls/relocations fail
closed; captured object/compiler paths are refused. No ISA extension needed.

## Ownership and limits

PR2394/2070/2053 change the retained static parser's malformed-input handling;
it is untouched here. PR2434 owns a different destructor/registration route
at0x5ca53f0, not this scan; no TLS lifecycle claim is adopted. No concrete
Rust source type, original ABI, TLS initialization/destruction/borrow failure,
panic/unwind, mutex acquisition/concurrency/ordering, loader interposition or
whole caller/protocol effect is recovered. Standard bcmp normal behavior is
an explicit helper premise, not a reconstructed runtime callee. Own236B/71
instructions differs from target299B/80; no byte-match credit or whole-module
denominator. All component gates and registered byte windows remain unchanged.
Next question: establish the initialized TLS vector's actual producers and
ownership/lifetime before integrating this logical predicate into a runtime.
