# RE-002: node #115 rocksdb::Hash2x64 wrappers (unseeded 0x61c3db0 + seeded 0x61c3de0)

This packet reconstructs one bounded node #115 behavior: the two
35-byte `rocksdb::Hash2x64` wrappers that split a 128-bit XXH3 hash
across two `uint64_t` out-pointers. The unseeded wrapper at
`0x61c3db0` calls the 128-bit one-shot at `0x61deab0` with the
default secret and seed 0; the seeded wrapper at `0x61c3de0` calls
`0x61defa0` with the caller seed. Both store high64 through the
first out-pointer and low64 through the second. A whole-`.text`
caller census finds exactly three direct call sites, all in the
unique-ID paths (`GenerateRawUniqueId` and
`GetSstInternalUniqueId`).

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: instruction bytes, the FDE ranges, the body
  hashes, the census confirmations and the caller census are
  observations. The census symbol labels are confirmed by the
  bytes (see Census confirmation below): each census
  `target_body_sha256` matches the 35 bytes hashed from the node
  binary, and each census `source_body_sha256` is reproduced
  exactly by hashing the same bytes with the 4-byte E8 call
  displacement zeroed — the only linked-vs-source difference.
  The wrappers' identity as thin delegating wrappers, the
  argument mapping and the out-pointer split are observations
  from the disassembly. The caller-side meaning of the hashed
  buffers beyond the observed call setup is unknown and stated
  as such.
- Scope included: both wrapper bodies, their call targets, the
  census confirmations, the whole-`.text` caller census with
  each call site's argument setup and immediate post-call use,
  and the layout of the wrapper pair. Excluded: the exact
  RocksDB source lines behind the confirmed identities, the
  hash computation itself (delegated to the already
  reconstructed 128-bit one-shots, cited not re-claimed), any
  indirect caller (the scan sees direct calls only), and the
  contents of the buffers the callers hash.

## Reproduce

From the repository root, with the materialized work binary at
`work/hl-node-115.bin`:

```sh
objdump -d --start-address=0x61c3db0 --stop-address=0x61c3dd3 work/hl-node-115.bin
objdump -d --start-address=0x61c3de0 --stop-address=0x61c3e03 work/hl-node-115.bin
(cd research/work-items/re-002-node115-hash2x64-wrappers-115 && sha256sum -c MANIFEST.sha256)
sha256sum research/work-items/re-002-node115-hash2x64-wrappers-115/hash2x64_115.hex
sha256sum research/work-items/re-002-node115-hash2x64-wrappers-115/hash2x64_seed_115.hex
```

The two `sha256sum` calls reproduce the census
`target_body_sha256` values `cdf83f11…` (unseeded) and
`77d46c5d…` (seeded) directly from the raw body bytes. The node
binary was not executed. No cargo/rustc/git-lfs/Ghidra is
available on this machine, so no native rebuild or Ghidra
cross-check was performed.

## Evidence

### Contract

`Hash2x64(data, len, out1, out2)`: writes the 128-bit hash of
`data[0..len]` as `*out1 = high64`, `*out2 = low64`; no return
value, no data-dependent branch.

`Hash2x64(data, len, seed, out1, out2)`: the same, with the
caller seed folded into the hash.

### Function bodies (observed)

Both wrappers are 35 bytes (`hash2x64_115.hex`,
`hash2x64_115.objdump.txt`, `hash2x64_seed_115.hex`,
`hash2x64_seed_115.objdump.txt`). The objdump excerpts are
whole-function and verbatim; the `<...>` label line on each is
objdump's nearest-symbol annotation on the stripped binary, not
the function identity — identity comes from the census records
below.

Unseeded (`0x61c3db0..0x61c3dd3`, body SHA-256
`cdf83f118dae4ddaabf19ff5fef1f5c12469608c9664d39a3b95b0389165ce3f`):
`endbr64`; save `%rdx` (out1) in `%rbp` and `%rcx` (out2) in
`%rbx`; `sub $0x8, %rsp` for call alignment; `call 0x61deab0`
at `0x61c3dc0`; store `%rdx` (high64) through out1 and `%rax`
(low64) through out2; one `ret` at `0x61c3dd2`.

Seeded (`0x61c3de0..0x61c3e03`, body SHA-256
`77d46c5d98d167a3da48e8471c2ded2361ced5e47565abbdc0c11628ab785b7b`):
the same shape with the argument registers shifted by one:
out1 is `%rcx` (saved in `%rbp`), out2 is `%r8` (saved in
`%rbx`), and the seed in `%rdx` is left untouched so it reaches
the callee as its third argument; `call 0x61defa0` at
`0x61c3df0`; the same high64/low64 stores; one `ret` at
`0x61c3e02`.

Neither wrapper reads `.rodata`, `.data` or `.bss`, takes any
address, or contains a conditional branch. The pair is
separated by 13 bytes of `0xcc` int3 padding
(`0x61c3dd3..0x61c3de0`); a further 13 bytes of `0xcc`
(`0x61c3e03..0x61c3e10`) precede the next FDE,
`rocksdb::BijectiveHash2x64` at `0x61c3e10`.

### Census confirmation

- `node115-vendor-61c3db0` labels `0x61c3db0` librocksdb-sys
  0.11.0+8.1.1 `_ZN7rocksdb8Hash2x64EPKcmPmS2_` with
  `target_body_sha256 cdf83f11…`: confirmed, the hash matches
  the binary bytes. Its `source_body_sha256 cd935345…` is
  reproduced exactly by hashing the binary body with the 4-byte
  E8 rel32 at offset 17..20 zeroed, so the linked body differs
  from the source body only in the call displacement to
  `0x61deab0` (relocation offset 17, kind 4, addend -4).
- `node115-vendor-61c3de0` labels `0x61c3de0` librocksdb-sys
  0.11.0+8.1.1 `_ZN7rocksdb8Hash2x64EPKcmmPmS2_` with
  `target_body_sha256 77d46c5d…`: confirmed the same way; its
  `source_body_sha256 0719e38e…` is the rel32-zeroed hash, and
  the only difference is the call displacement to `0x61defa0`.

### Call targets (observed)

Each wrapper makes exactly one call, and the call is its whole
purpose: the unseeded wrapper calls `ROCKSDB_XXH3_128bits` at
`0x61deab0` (census `node115-vendor-61deab0`, body `065ec95c…`),
the seeded wrapper calls `ROCKSDB_XXH3_128bits_withSeed` at
`0x61defa0` (census `node115-vendor-61defa0`, body `180dccff…`).
Both entry points are reconstructed in the merged XXH3_128bits
packet (lengths 0..128) with their 129..240 and >240 branches in
the merged len_129to240_128b and hashLong_128b packets; the hash
itself is cited there, not re-derived here. The wrappers add no
hashing of their own: no arithmetic, no secret, no branch. The
return convention they rely on — low64 in `%rax`, high64 in
`%rdx`, the `XXH128_hash_t` split — is the one those packets
establish.

### Caller census (observed)

Whole-`.text` scan (`0x1419300..0x63f6a00`, file offset VA −
0x1000) for E8/E9 rel32 transfers targeting either wrapper,
plus a rip-relative lea scan for either address; each candidate
verified by disassembly. Exactly three direct call sites, no
lea references:

- `0x602e9bd` in `rocksdb::GenerateRawUniqueId` (FDE
  `0x602e650..0x602ea44`) calls the unseeded wrapper with
  `rdi = lea 0x30(%rsp)` (a 168-byte stack buffer),
  `rsi = 0xa8` (168, the length), `rdx = %rbp` (out1),
  `rcx = %r12` (out2). The raw unique ID is the 128-bit hash
  of that 168-byte buffer under the default secret and seed 0.
  The buffer contents are not established here. Length 168
  runs through the entry point's 129..240 branch, reconstructed
  in the merged len_129to240_128b packet.
- `0x61b016d` in `rocksdb::GetSstInternalUniqueId` (FDE
  `0x61affe0..0x61b0260`) calls the seeded wrapper with
  `rdi = (%r12)` (data pointer), `rsi = 0x8(%r12)` (length),
  `rdx = 0x20(%rsp)` (seed), `rcx = lea 0x30(%rsp)` (out1),
  `r8 = %r15` (out2). Right after the call the high64 at
  `rsp+0x30` is xored into `%rbp` and stored at +8 of the
  output UniqueIdPtr at `%r13`; the +0 slot was stored just
  before the call from `0x28(%rsp)`. The low64 target `*%r15`
  is not followed here.
- `0x61b01c1`, also in `GetSstInternalUniqueId`, calls the
  unseeded wrapper with `rdi = (%rsi)` (data pointer, `%rsi`
  from `0x8(%rsp)`), `rsi = 0x8(%rsi)` (length),
  `rdx = 0x10(%rsp)` (out1), `rcx = 0x18(%rsp)` (out2). This
  site is in the loop-back block at `0x61b01a8`, reached when
  the byte at `0x40(%rsp)` is nonzero; after the call the flag
  at `0x28(%rsp)` is tested and control returns to `0x61b013f`,
  so the wrapper runs once per loop iteration with the same
  out-pointers. Which iteration's values survive is not
  established here.

## Results and limitations

- Both census labels are confirmed by byte hashes, including
  the exact rel32-zeroed reproduction of both
  `source_body_sha256` values, which pins down the
  `raw_equal: false` census flag to the single linked call
  displacement in each body.
- The caller census is complete for direct calls (3 sites, 0
  lea references); indirect calls through registers cannot be
  seen by the scan and are not ruled out.
- `tools/verify_packets.py` flags only the pre-existing
  mismatch in the unrelated packet `RE-001-adjacent-last-115`
  (present on clean upstream main, untouched by this change).
- Unknown: whether an indirect caller of either wrapper exists;
  the contents of the 168-byte stack buffer hashed at
  `0x602e9bd`; the target of the seeded wrapper's out2 pointer
  `%r15` at `0x61b016d`; which loop iteration's values survive
  at `0x61b01c1`.
- Next question: the `BijectiveHash2x64` family at `0x61c3e10`
  is already reconstructed in the open packet of the same run;
  the next fresh lead is a new RE-002 family or a RE-001/RE-009
  area from `docs/TASKS.md`.
