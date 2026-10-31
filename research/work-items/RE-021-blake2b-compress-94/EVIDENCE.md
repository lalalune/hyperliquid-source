# EVIDENCE — RE-021-blake2b-compress-94

## Binary

- Path: `artifacts/node/94/hl-node`
- sha256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`

## Function extent

- VA range: `0x4e9a8a0 .. 0x4e9b02c` (length 1932)
- Ret at: `0x4e9aeaf`
- Carved sha256: `df9b7ff03af68d61cb6e574cadb5fc0081e4a38a7fd35cefd030fbebea1a8788`

## ABI (from prologue bytes)

| Reg | Role |
|-----|------|
| rdi | rounds (test+je → early finalize when 0) |
| rsi | h `*mut [u64;8]` (written back) |
| rdx | m `*[u64;16]` |
| rcx | t `*[u64;2]` (`IV[4]^=t[0]`, `IV[5]^=t[1]`) |
| r8  | f final flag (`test r8d`; `cmovne` selects `~IV[6]`) |

## IV movabs (pinned)

| VA | Imm |
|----|-----|
| 0x4e9a8c8 | 0x6a09e667f3bcc908 |
| 0x4e9a8b9 | 0xbb67ae8584caa73b |
| 0x4e9a8e1 | 0x3c6ef372fe94f82b |
| 0x4e9a9a8 | 0xa54ff53a5f1d36f1 |
| 0x4e9a8f3 | 0x510e527fade682d1 |
| 0x4e9a904 | 0x9b05688c2b3e6c1f |
| 0x4e9a923 | 0x1f83d9abfb41bd6b |
| 0x4e9a8d7 | 0x5be0cd19137e2179 |
| 0x4e9a919 | 0xe07c265404be4294 (= ~IV[6]) |

## SIGMA

- Lea at `0x4e9a99e` → `0x7c4ad0` (anchor); table base `0x7c4a90` as u64 indices.
- SIGMA[0] = 0..15; SIGMA[1] = 14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3.

## G rotates

Exactly 8× each: `rol imm 0x20`, `0x28`, `0x30`, `1` (= RFC 7693 ror 32/24/16/63).

## Source pin

- VA `0x1e9dcb`, length 102:
  `/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/revm-precompile-16.0.0/src/blake2.rs`

## EIP-152 behavioural proof (Unicorn on carved bytes)

| Vector | rounds | f | output sha256 (of 64-byte h) |
|--------|--------|---|------------------------------|
| 4 | 0 | 1 | (see JSON; output starts `08c9bcf3…`) |
| 5 | 12 | 1 | (output starts `ba80a53f…` = BLAKE2b-512("abc")) |
| 6 | 12 | 0 | (output starts `75ab69d3…`) |
| 7 | 1 | 1 | (output starts `b63a380c…`) |

All four: `byte_identical=true` under Unicorn emulation of the carved bytes.

## HyperEVM precompile 0x09 wiring (statically shown)

### Dispatch table entry

- Precompile object VA `0x574f0b0` (0x30-byte stride alongside neighbouring Address 0x01..0x0a objects).
- `Address(0x09)` at VA `0x574f0c0` = 20 bytes `00…09` (file-backed).
- `.rela.dyn` `R_X86_64_RELATIVE` (`r_info=0x8`): `r_offset=0x574f0b0`, `r_addend=0x4e9d2a0` installs the `run()` wrapper as the object's function pointer (file contents of the slot are zero before reloc).

### `run()` wrapper `0x4e9d2a0 .. 0x4e9d480`

| VA | Bytes | Meaning |
|----|-------|---------|
| 0x4e9d2a0 | `4156534881ec18010000` | prologue |
| 0x4e9d2aa | `48817e10d5000000` | `cmpq $0xd5, 0x10(%rsi)` — EIP-152 input length 213 |
| 0x4e9d2b2 | `7519` | `jne` reject |
| 0x4e9d2b8 | `8b18` | `mov ebx, (%rax)` load rounds |
| 0x4e9d2ba | `0fcb` | `bswap ebx` — big-endian rounds |
| 0x4e9d2bc | `4839da` | `cmp %rbx, %rdx` — require gas ≥ rounds → **1 gas/round** |
| 0x4e9d2f2 | `0fb688d4000000` | `movzbl 0xd4(%rax), %ecx` — load `f` at offset 212 |
| 0x4e9d2f9 | `80f902` | `cmp $2, %cl` |
| 0x4e9d2fc | `0f8356010000` | `jae` reject if `f ≥ 2` |
| 0x4e9d3ba | `4889df` | `mov %rbx, %rdi` — rounds → F |
| 0x4e9d3bd | `ff15659b8d00` | `call qword ptr [0x5776f28]` |

### Compress F GOT slot

- `.rela.dyn` `R_X86_64_RELATIVE`: `r_offset=0x5776f28`, `r_addend=0x4e9a8a0` installs compress F.
- Sole static code reference: the `ff 15` at `0x4e9d3bd` inside the wrapper.

**37** key instructions pinned byte-for-byte (26 compress-F + 11 wiring).
