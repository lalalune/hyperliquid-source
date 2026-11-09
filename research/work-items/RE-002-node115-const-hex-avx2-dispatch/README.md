# RE-002: node #115 const-hex AVX2 dispatch

- Component: `foundation`; bounded build-provenance / runtime-feature question.
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit: `0781ce04826eeefd89fe336cb8ea073be0c1de30` (`main`).
- Reference input: the repository's retained #115 vendor census and CPUID
  field-map packets at that commit; no unpinned reference checkout is used.
- Claim status: static observation of the branch and call bytes; symbol and
  feature-field meaning are cross-referenced inferences from those packets.
- Question: Is the `const-hex` AVX2 decode body selected only when the node's
  cached CPU-feature word enables AVX2?
- Claim: yes for this one dependency path; the node tests cached A bit 15 and
  reaches the AVX2 body only on the set-bit branch.
- Excluded: a whole-binary AVX/VEX/EVEX/BMI inventory, exact target Cargo
  package version, execution behavior, and any global CPU requirement.

## Evidence

The retained #115 dependency census identifies these complete FDE extents:

| FDE | Extent | Census identity |
| --- | --- | --- |
| caller | `0x167a9c0..0x167abfb` | `const-hex::decode_to_slice_inner` candidate |
| callee | `0x167ac00..0x167afcf` | `const-hex::arch::x86::decode_avx2` candidate |

The coordinates below are ELF virtual addresses. The caller reads the pointer at `0x64dfa60`, dereferences the cached word at
`0x6500098`, and tests `AX`. If the cache is empty, the code calls through
`0x64dfa68`; its `R_X86_64_RELATIVE` relocation points to refresh helper
`0x5cadd50`. After the refresh, `JNS` at `0x167abc6` returns to the fallback
when bit 15 is clear. When bit 15 is set, `JS` at `0x167aafa` reaches
`0x167abcc`, whose direct call at `0x167abdb` targets the AVX2 FDE at
`0x167ac00`. The callee contains YMM instructions, including the initial
`vpbroadcastw` and a final `vzeroupper`.

The referenced [CPUID field map](../RE-002-node115-cpuid-field-map/README.md)
binds the refresh result's low 64-bit word to A. Its A bit 15 record maps to
CPUID leaf 7, subleaf 0, EBX bit 5 and records the XCR0 bits 1 and 2 gate.
The machine-readable branch and relocation facts are in `records.json`; raw
GNU Binutils exports are retained under `native/`.

The vendor census attributes the compiled body to candidate `const-hex`
versions 1.14.0/1.14.1. The 1.14.0 crate archive from crates.io has SHA-256
`4b0485bab839b018a8f1723fc5391819fea5f8f0f32288ef8a735fd096b6160c`, matching
the retained candidate lockfile. Its source selects `decode_avx2` through
`has_avx2()` and falls back to generic decoding. This corroborates the target
branch; it does not prove which candidate version was built into #115. The
published crate declares `MIT OR Apache-2.0`; no upstream code is copied here.

## Reproduce

After materializing only the pinned node #115 LFS input:

```sh
python3 -B tools/node115_const_hex_avx2_dispatch.py --write
python3 -B tests/test_node115_const_hex_avx2_dispatch.py
```

The commands run from the repository root with Python 3.14.3. The raw exports
were produced by GNU Binutils 2.47.20260726 using `objdump -d --start-address
... --stop-address ...` and `readelf -rW`; exact commands and output identities
are recorded in `VALIDATION.md`. The analyzer checks the target digest, both FDE hashes, the two relative
relocations, the signed-bit branches, the direct call target, the AVX2 opcode
bytes, and the referenced census / field-map records. GNU Binutils 2.47.20260726
produced the retained exports in `native/`. No captured executable was run.

## Result and limits

This resolves one AVX2 dependency path as runtime-gated by A bit 15. It does not
resolve `target_cpu_features` globally: other vector or BMI instructions may
belong to other functions and dispatch paths. No component gate changes.

The crate corroboration is limited to the published `const-hex` 1.14.0 archive
at `https://crates.io/api/v1/crates/const-hex/1.14.0/download`, whose downloaded
archive digest is in `records.json`; the census lists 1.14.0 and 1.14.1 as
candidates, so the target's exact package version remains unknown. No source
code from that archive is copied into this repository.
