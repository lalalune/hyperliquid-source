# RE-002 · Reference comparison for root digest SIMD implementations

Target Node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. The three relative-slot targets identified by the root finalizer can be mapped to the BLAKE3 SSE2, SSE4.1 and AVX-512 in-place routines by instruction-byte comparison with independently assembled public source. The prior FDE-gap census provides entry evidence. The selected window begins after the observed four-byte ENDBR64 and ends just after the observed RET. These assembly ranges do not have individual FDEs in the capture.

| Reference | Target window | Raw matching bytes | Qualified PC32 fields |
| --- | --- | ---: | ---: |
| SSE2 | 0x633d0c4 through 0x633d2b3 | 476/496 | 5 |
| SSE4.1 | 0x633fac4 through 0x633fc78 | 425/437 | 3 |
| AVX-512 | 0x6345bc4 through 0x6345d38 | 369/373 | 1 |

Each qualified field is a four-byte R_X86_64_PC32 reference to .rodata in the rebuilt object. Before masking it, the verifier compares the 16 bytes at the two resolved constant addresses. Every byte outside these nine fields matches. A flipped unmasked byte is rejected. The target ENDBR64 prefixes are checked separately. Neither linked binary was executed. The windows establish correspondence to these public implementations but do not establish CPU feature selection, exact runtime bindings, or a unique dependency release.

## Replay

Obtain the files c/blake3_sse2_x86-64_unix.S, c/blake3_sse41_x86-64_unix.S and c/blake3_avx512_x86-64_unix.S from the upstream BLAKE3 repository at df610ddc3b93841ffc59a87e3da659a15910eb46 (1.8.2). Save them in an ignored directory as sse2.S, sse41.S and avx512.S. The corresponding 1.7.0 files at a9e92981a5c15db7f6c3a040ffc764b7a49eb4d4 were byte-identical, so this comparison cannot distinguish these two revisions. Upstream source and notices remain with their original project.

SHA-256 of SSE2 source: 94baa998f4114bf57b99e1791a21e9f0bcdc4bd5803864eb30a2477440b7380c.
SHA-256 of SSE4.1 source: 135048e4a81a6f9e86960b115141874a55954dbfd2cd1e8e9818837b46b498ad.
SHA-256 of AVX-512 source: c641987dd82fabed59d527f1a3413c4a2ff3df919af6d13ff2788c95e4035c0d.

Use Apple clang 21.0.0, build clang-2100.0.123.102, with clang -target x86_64-linux-gnu -c INPUT.S -o OUTPUT.o. Two independent assemblies of each source produced identical object bytes. Run python3 research/work-items/RE-002-node115-root-digest-simd-provenance/compare.py REFERENCE_DIRECTORY READELF from the repository root, supplying the directory of the three named objects and GNU readelf 2.45. The verifier pins the object hashes and reads relocation metadata directly with readelf. This packet does not register a comparison denominator or change a progress gate.

### Root-specific selector handoff

The previously analyzed selector at 0x160bee0 is also called by the root digest initializer at 0x41c52d8. On the selected normal path the intervening stores preserve AL. It writes that byte to RSP+0xfb and passes RSP+0x90 as the context to both update and finalization. This yields offset +0x6b, consistent with the already measured runtime-tag initializer family. Prior cache-readback evidence identifies the raw feature predicates. In combination with the finalizer dispatch and these body comparisons, the stable-cache tag 1 selects SSE2, tags 2 and 3 select SSE4.1, and tag 4 selects AVX-512. The selector internals and finalizer jump table are prior context. This mapping remains conditional on the selected normal path, helper preservation of the selector, and the stated stable-cache assumptions.
