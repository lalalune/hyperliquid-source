# RE-005: node #115 complete unsigned64 buffer writer and growth order

Target Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`; serialization / RE-005.
All ranges are half-open ELF VAs, without rebasing or byte masks. New Rust and
research are MIT. The packet verifier is adapted from the author's prior
repository-MIT static packet, head
`8ede1e78eb0b18d0faeb5dea619a566b73d4221c`; raw exports are freshly generated.
No unlicensed inferred code or public serialization implementation was copied.

## Missing result and whole selected scope

The base's varint-size-state reconstruction updates a counter. It does not
write bytes or close a byte-vector's marker/payload allocation order. This
packet reconstructs the complete unsigned64 buffer writer
`0x5822910..0x5822b90` (640 bytes), all four encoding-width branches together,
and its real byte-vector growth helper `0x5963a10..0x5963a9e` (142 bytes).
The raw layout/allocator adapter `0x5963650..0x5963739` (233 bytes) and actual
caller `0x4e09fe0..0x4e0a1f6` (534 bytes) complete the selected static contexts.
The denominator is **four complete FDEs / 1,549 bytes / 423 instructions**.
No compiled-byte equality or whole-program coverage is claimed.

This is one whole u64 writer with 1/3/5/9-byte alternatives. Neighboring
functions are higher-level serializers, not assumed u128/u32 writers from
address proximity. They are not invented into this scope.

## Established value and mutation rules

| Native branch | Value range | Writes |
| --- | --- | --- |
| 0x5822915..0x582293a | value <251 | one raw byte |
| 0x582293a..0x582297b | 251 <= value <65536 | FB then LE16 |
| 0x582297b..0x58229bb | 65536 <= value <2^32 | FC then LE32 |
| 0x58229bb..0x5822a01 | value >=2^32 | FD then LE64 |

The observed vector descriptor fields are capacity+0, pointer+8, length+0x10.
Every prefix byte checks capacity, potentially grows by one element, stores the
byte and commits length. Marked branches then inspect capacity remaining for
the whole 2/4/8-byte payload. A shortage calls the same real growth helper with
additional2/4/8, alignment1 and element size1. No payload byte is stored before
that reserve returns. The payload store and final length update are atomic
logical stages; original WORD/DWORD/QWORD store granularity is not reproduced.
The native normal result writes raw QWORD8. The new `Result<(), Error>` is a
safe projection, not that private native result type.

These observations rule out two plausible but wrong reconstructions: reserving
the whole encoding before writing a marker, or pushing payload bytes one by
one. Both change state at an allocation-refusal boundary. A later failure does
not roll back the already initialized marker.

## Growth and allocator closure

For selected element size1/alignment1, the complete growth helper computes
required=length+additional with a checked addition, then
new_capacity=max(8,2*old_capacity,required). Its generic minimum branches for
other element sizes are retained as context but not exposed by this byte API.
It calls the real raw allocation adapter, storing new pointer and capacity
only on success. It does not change vector length. Failure reaches actual
slot0x64df498; the native path is not assumed to return.

The raw adapter checks size multiplication and the aligned signed-size bound
before calling a backend. With alignment1 and nonzero byte capacity, this is
size<=isize::MAX. Its initial-allocation and existing-allocation routes use
actual RELATIVE slots retained in `allocator-bindings.json`:

| Slot | Linked addend |
| --- | --- |
| 0x64df480 | 0x6355830 |
| 0x64df498 | 0x141e264 |
| 0x64df580 | 0x635a790 |
| 0x64df588 | 0x635a7a0 |
| 0x64df590 | 0x63577f0 |

These actual writers are pinned and freshly checked. Backend implementation,
TLS state, allocator identity, returned addresses, OOM handler payloads and
fatal/unwind behavior remain external boundaries. The new crate genuinely
uses the compiler's `alloc::Vec` and actual allocator; it does not replace
those boundaries with fake vector storage. Rust1.95's actual byte-vector
amortized growth is checked against the native derived capacity rule by the
qualification's real capacities and request counts. No allocator machine-code
identity is asserted.

The safe API maps actual `try_reserve` failure to a logical prefix or payload
boundary and retains the real vector. This makes its snapshot inspectable;
it does not assert that a native allocation failure returns an enum, is
catchable, or can continue. Invalid raw descriptors and unallocated enormous
capacities are outside safe Vec's domain. Arithmetic size-overflow boundaries
are static observations; the qualification does not claim to allocate or
fault-test an isize::MAX-sized buffer.

## Actual caller and scope limit

The complete caller context contains two confirmed direct calls at0x4e0a008
and0x4e0a028. It obtains values from its entry source's +0x90 and +0x10 fields,
and forwards the same byte-vector state at its entry context+0x10. This proves
real higher-level use and sharing of the vector. Application field names,
units, the rest of that caller's schema and its other serializers remain open.
The packet makes no whole-ELF caller census claim: a preliminary byte search
also found unowned candidates; only complete-FDE-confirmed selected calls are
used as evidence.

## Independent expectations and real allocation failure controls

`oracle.py` independently builds value/prefix/payload events and applies the
derived max(8,2cap,required) growth relation and a selected request refusal.
It is branch mathematics, not an instruction evaluator or vector substitute.
**124,192** cases were frozen before the new Rust directory existed. The
original TSV hash is
`1426f81b7758e1dc1fe5e7a9c23bc91131ad184b4488227513630b7224835092`.
`cases.tsv.gz.hex` is lossless gzip(mtime0) hex storage packed before Rust;
`qualify.py` decompresses, authenticates the raw bytes and recomputes the
unchanged independent relation.

Cases cover values0..1099, all width thresholds and neighboring values,
large seeded u64 words, capacities0..32, empty/partial/full prefixes, and first,
second or untriggered-third allocation refusal. Host qualification calls the
**actual newly compiled library on actual alloc::Vec**. The probe's
`GlobalAlloc` forwards successful allocation/reallocation/deallocation to the
real System allocator. It returns null only for a selected request while the
library call is armed. This safely forces real `Vec::try_reserve` failure;
there is no mock Vec, target execution, simulated instruction path, deliberate
resource exhaustion or external effect.

Actual debug and release builds each match all124,192 observations: status,
capacity, initialized length, number of actual alloc/realloc requests and every
initialized byte. Nine compiled production mutants exit normally and mismatch:
three value thresholds, endian, marker, exact-versus-amortized growth, complete
preflight, marker rollback and piecemeal payload. The last three exercise real
allocation refusals and detect different retained byte prefixes, not just
self-reported trace labels. Exact outcomes and source hashes are in
`qualification.json`; original compiler/stdout/stderr remain under ignored
`work/environment/next-ten/varint-buffer-writer/qualification/`.

Static replay checks full target identity, four FDE/CIE records, native
GNU/LLVM/Capstone complete partitions, actual calls/branches/relocations and23
instruction/RELA anchors. It rejects23 real-byte anchor corruptions below the
full-file guard and two wrong identities. Those controls bind evidence, not
captured runtime outcomes.

```
python3 -B research/work-items/RE-005-varint-buffer-writer-115/verify.py
python3 -B research/work-items/RE-005-varint-buffer-writer-115/qualify.py
cargo +1.95.0 fmt --check --manifest-path src/node115-varint-buffer-writer/Cargo.toml
cargo +1.95.0 clippy --all-targets --offline --locked --manifest-path src/node115-varint-buffer-writer/Cargo.toml -- -D warnings
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-varint-buffer-writer/Cargo.toml
```

Only independent host Rust executes. The Linux rlib is built but not executed.
No captured execution/emulation, socket, chain action, original ABI or binary
identity claim exists. All full-scope gates and byte totals stay unchanged.
Next integrate this actual byte writer into one completely recovered enclosing
serializer with its own schema and allocation/error lifecycle evidence.
