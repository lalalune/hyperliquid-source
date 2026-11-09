# RE-002: node #115 libm FMA backend dispatch

- Component: `foundation`; one bounded build-provenance / runtime-feature path.
- Source commit: `0781ce04826eeefd89fe336cb8ea073be0c1de30` (`main`).
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: static byte observations, with labels joined to the retained
  rustc 1.95.0 standard-library census.
- Question: Which CPU-feature bits select the `compiler_builtins` libm FMA
  implementation in this target?

## Result

`full_availability::fma` at `0x63f0210` calls through the function-pointer
slot `0x64ffe00`. Its relocation points to the initializer at `0x63f06a0`,
which fills that slot from a cached feature byte at `0x6728920` and calls
`load_x86_features` at `0x63f0730` when the cache's bit 31 is clear.

The initializer tests feature-byte bit 6 and bit 7. Bit 6 selects the
three-operand `VFMADD213SD` entry at `0x63f0680`; when bit 6 is clear, bit 7
selects the four-operand `VFMADDSD` entry at `0x63f0690`; when both are clear,
it selects the software fallback FDE at `0x63f0230..0x63f0679`. These two
short instruction entries are verified as pointer targets and raw bytes; this
packet does not claim they have FDEs.

The loader derives bit 6 from CPUID leaf 1 ECX bit 12 only on its XSAVE/OSXSAVE
and XCR0 bits 1/2 path. It derives bit 7 from CPUID leaf `0x80000001` ECX bit
16, restricted to `AuthenticAMD` or `HygonGenuine`. The bit-7 write occurs
after the XGETBV branch; this packet records that control flow but does not
assess architectural OS-state safety or runtime consequences.

The selected FDE identities and target-body hashes cross-check the retained
`RE-002-node115-std-census` records. This establishes one concrete FMA dispatch
path; it does not resolve global CPU requirements, assert exact crate features,
or change a component gate. No source code is copied.

## Reproduce

Run from the repository root with GNU Binutils 2.47.20260726 and Python 3.14.3:

```sh
objdump -d --start-address=0x63f0210 --stop-address=0x63f0221 artifacts/node/115/hl-node > research/work-items/RE-002-node115-libm-fma-dispatch/native/gnu-wrapper.objdump
objdump -d --start-address=0x63f0230 --stop-address=0x63f0679 artifacts/node/115/hl-node > research/work-items/RE-002-node115-libm-fma-dispatch/native/gnu-fma-fallback.objdump
objdump -d --start-address=0x63f0680 --stop-address=0x63f06a0 artifacts/node/115/hl-node > research/work-items/RE-002-node115-libm-fma-dispatch/native/gnu-fma-entries.objdump
objdump -d --start-address=0x63f06a0 --stop-address=0x63f0711 artifacts/node/115/hl-node > research/work-items/RE-002-node115-libm-fma-dispatch/native/gnu-fma-initializer.objdump
objdump -d --start-address=0x63f0720 --stop-address=0x63f08d9 artifacts/node/115/hl-node > research/work-items/RE-002-node115-libm-fma-dispatch/native/gnu-feature-loader.objdump
readelf -rW artifacts/node/115/hl-node | rg '00000000064e0fd0|00000000064ffe00' > research/work-items/RE-002-node115-libm-fma-dispatch/native/gnu-relocations.txt
python3 -B tools/node115_libm_fma_dispatch.py --write
python3 -B tests/test_node115_libm_fma_dispatch.py
```

The analyzer authenticates the target and four census FDEs, resolves the two
relative relocations, checks the RIP-relative slot references and selected
addresses, pins the CPUID/XGETBV feature-bit paths, and verifies the two short
FMA instruction entries. Raw exports are retained under `native/`.

## Limits and next question

The FMA4 feature bit is observed outside the loader's XGETBV-gated branch. The
remaining question is whether the platform and instruction-state requirements
make that path valid when XCR0 bits 1/2 are absent. Answering it requires a
separate architecture-level review; no safety conclusion is made here. The
captured executable was never run.
