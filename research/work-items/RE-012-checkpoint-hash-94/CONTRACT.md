# Checkpoint hash-helper contract

RE-012 / state synchronization. Node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base `d31f2bdb4efed900bc77853e10f6d4e086117144`.
All addresses are linked ELF VAs. This contract precedes implementation.

The bounded target is `0x394b410..0x394b657`, called by `0x2209450`.
It initializes an unkeyed BLAKE3 hasher, updates it with the caller-supplied
serialized-state byte slice, serializes three supplied records using the
named MessagePack configuration, updates with those bytes, and returns the
ordinary 32-byte digest. There is no inserted separator or length prefix
between the supplied byte slice and the record encoding. This is not hashing
the received MessagePack snapshot verbatim: the enclosing caller produces a
canonical prefix via `0x2830a50` / `0x2811e40`, which remains separate work.

The second preimage part is a three-entry MessagePack map, in this order:
`accounts_hash`, `contracts_hash`, `storage_hash`. Each value is a map in
this order: `n_elements` (u64), `n_bytes` (u64), `hash` (exactly 2048 bytes).
The outer map and each record start with 0x83. All keys use fixed-string
headers. Integers use shortest unsigned encodings: positive fixint through
127, then cc/u8, cd/BE16, ce/BE32 and cf/BE64. The raw hash uses bin16 header
c5 08 00 followed by exactly 2048 bytes. The complete encoding length is
6271 plus the six integer encoding lengths (6277 through 6325 bytes).

The actual serializer state at `0x394b509` is DWORD 0x01000400 at +8;
therefore the named-map flag at +0xb is 1. The byte stored separately at
`0x394b511` is +0xc, not the named-map flag. The positional-array path in
the generic helpers is not the path used by this caller.

The existing independent `greeting::reply::FixedRecord` expresses these
values as first, second and bytes, respectively, without matching the native
layout. The native layout instead places raw bytes first and the two words
at +0x800/+0x808. Reuse the independent value type and preserve every byte.

Expose encoding and digest functions under an optional checkpoint-hash
feature in the existing component. Pin the public BLAKE3 implementation to
1.7.0, observed in the target's source paths, and generate the real Cargo
lockfile. A pure-Rust backend is a build choice for this independent library,
not a target machine-code match or original dependency-graph claim.

The prefix argument must be documented as already canonically serialized by
the caller. This helper cannot establish that the prefix encodes valid state.
No complete Exchange serializer, state deserializer, quorum/signature policy,
checkpoint installation, network activity or node/Docker acceptance is supplied.
