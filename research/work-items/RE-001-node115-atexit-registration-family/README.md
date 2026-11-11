# RE-001 · Node #115 shared teardown registration

Component: foundation utilities, startup and teardown map. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Repository baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

The [initializer census](../RE-001-node115-init-array-census/README.md) establishes the relocated slots. This packet identifies which of those slots have the same zero-and-register sequence and follows the registration and callback linkage.

## Evidence

- The scan derives all 168 slot targets from their `R_X86_64_RELATIVE` relocations. It compares the first 52 bytes at each target with a fixed instruction sequence. It masks six four-byte displacements for the initial comparison, then resolves all six and checks their target addresses and relationships. The remaining bytes must be identical.
- Each match sets the first 16 bytes and the next eight bytes of a 24-byte region to zero. It sets `rdi` to the shared callback `0x5d36020`, `rsi` to the region's address, and `rdx` to `0x64efa20`. It tail-jumps through `0x63f0f80`, whose jump slot carries an `R_X86_64_JUMP_SLOT` naming `__cxa_atexit`.
- The callback reads the first word and returns when it is zero. Otherwise it passes the first word and the third word minus the first word to the PLT entry for `_ZdlPvm` at `0x63f0d80`. The symbol is the sized delete entry point. This is consistent with cleanup of a contiguous allocation. Element type and object ownership are unverified.
- The [transcript](evidence.txt) records **95 of 168** matching slots, each with a distinct 16-byte-aligned region in `.bss`. The other 73 slots are outside this exact sequence; they may use other registration or cleanup paths. The denominator is relocated initializer slots. No Rust comparison or acceptance gate change is claimed.

## Reproduction

With the pinned binary materialized, run from the repository root. The transcript uses Python 3.12.14, Capstone 5.0.9 and pyelftools 0.33. Addresses are ELF VAs.

```sh
python3 -B research/work-items/RE-001-node115-atexit-registration-family/scan.py
```

The script reads the capture without executing it. It checks the full digest before parsing. Its negative controls flip one byte each in the first opcode, the region address, and the tail-jump displacement of a known positive match. Each edited copy must be rejected.
