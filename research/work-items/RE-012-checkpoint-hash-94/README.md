# RE-012: checkpoint record encoding and hash helper

Target: Linux x86-64 node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The implementation contract is [CONTRACT.md](CONTRACT.md).

## Observed instructions and data

The full caller FDE `0x2209450..0x22095bd` invokes `0x2830a50` at
`0x220948e`. Its returned prefix pointer and length are passed onward in
`rsi` and `rdx`. The caller copies three `0x810`-byte records from state
offsets `0xcb8`, `0x15c0` and `0x1ec8` into contiguous stack storage at
`+0x48`, `+0x858` and `+0x1068`. At `0x2209522` it calls the hash helper
through `0x57739f8 → 0x394b410`, passing that record storage in `rcx`.
These observations establish the call boundary; they do not reconstruct or
validate the canonical-prefix serializer's internals.

The full FDE `0x394b410..0x394b657` initializes a BLAKE3 hasher, updates it
with the supplied state-byte slice, encodes three supplied records, updates it
with that encoding, and returns 32 bytes. Its call at `0x394b42f`, through
`0x57700c0 → 0x14fa220`, selects the CPU implementation. The caller itself
initializes the state: `0x394b435..0x394b4c5` writes zero counters/flags and the
eight-word IV loaded from `0x20c020`. The IV words are `6a09e667 bb67ae85
3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19`.

Both update calls use `0x57700c8 → 0x14f93e0`: the original byte slice at
`0x394b4d0..0x394b4de`, then the encoding buffer at
`0x394b53c..0x394b556`. No separator or length is inserted between them.
Finalization uses `0x57700d0 → 0x14fa010`. That helper calls `0x14f8b80`,
ORs flag `8` at `0x14fa048`, passes a zero counter to the selected compression
implementation, and copies 32 result bytes. The update helper's directly used
Location at `0x566ff18` points to the captured `blake3-1.7.0/src/lib.rs`
path, line 1201, column 24. The retained update and chunk helpers include the
64-byte block / 1024-byte chunk controls and start/end flags.

`0x394b509` stores the DWORD `0x01000400` at serializer offset `+8`.
Its byte at `+0xb` is therefore **1**, selecting named maps in `0x37e2510`
and `0x3815120`. The separately zeroed byte at `+0xc` does not select the
array path. An earlier positional-array interpretation is superseded.

The outer map is `83`, with fixed-string keys `accounts_hash`,
`contracts_hash`, `storage_hash` in that order. Each value is a map `83`
with fixed-string keys `n_elements`, `n_bytes`, `hash`, also in that order.
The native record stores 2048 raw bytes first, then its words at `+0x800`
and `+0x808`. The independent `FixedRecord` stores those as `bytes`, `first`
and `second`; this is a value mapping, not a native layout claim.

The first word is emitted at `0x38151e3`, the second at `0x3815227`, both
through `0x359b320`. Its branches emit positive fixint, `cc`/u8, `cd`/BE16,
`ce`/BE32 or `cf`/BE64 with the shortest unsigned width. The `hash` field
uses `0x35995d0`: `c5 08 00` and exactly 2048 copied bytes. It is neither a
sequence of integers nor text. Encoding length is 6271 plus the six integer
encoding lengths: 6277 through 6325 bytes.

## Retained evidence and verification

[anchors.json](anchors.json) binds selected instruction encodings, all 19
full FDE bodies, 11 data ranges and 21 complete relocation tuples to the
artifact. [native-exports.json](native-exports.json) records exact GNU and
LLVM commands, versions, bounds and output hashes. The 38 complete listings
are in [native/](native/). No large enclosing peer caller is duplicated.

From the repository root:

```sh
python3 research/work-items/RE-012-checkpoint-hash-94/verify.py
python3 tests/test_checkpoint_hash_evidence.py
cargo test --manifest-path src/node94-tcp-frame/Cargo.toml --locked --features checkpoint-hash --test checkpoint_hash
```

The Python verifier reads the captured ELF; it does not execute it. Its
unqualified structural seam is labeled separately from digest-authenticated
analysis. Negative controls alter every selected instruction, each full body,
each data range and each relocation component, plus FDE/export metadata,
dispatch targets and source coordinates. Both native listings must cover all
selected instruction addresses.

The Rust tests compare complete encodings and digests with the independently
frozen MessagePack/BLAKE3 corpus in [fixtures/](fixtures/), and cover integer
width boundaries, all record bytes, record order and prefix sensitivity.
Fixture inputs are synthetic and do not assert a valid checkpoint prefix.

## Inferences and limits

The versioned native path, IV, block/chunk controls, root flag and ordinary
32-byte output support identifying this as unkeyed BLAKE3. `blake3 = 1.7.0`
is a public independent dependency; no original dependency graph or matching
machine code is claimed. Its package license is `CC0-1.0 OR Apache-2.0 OR
Apache-2.0 WITH LLVM-exception`. Its `pure` feature selects Rust implementations:
on x86 these may use SIMD intrinsics; it does not mean scalar-only. This crate
still has a Cargo build script and a `cc` build dependency.

The prefix must already be canonically serialized by the caller. This work
does not implement the enclosing `0x2830a50` / `0x2811e40` state serializer,
validate received snapshots, establish native ABI equivalence, reconstruct
all optimized hash kernels, or prove checkpoint/peer acceptance. No captured
target execution, peer-network activity, node build or Docker success is claimed.
