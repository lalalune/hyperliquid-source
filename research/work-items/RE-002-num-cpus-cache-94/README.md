# Node94 cgroup quota to logical-CPU cache

Task RE-002, dependency/runtime support for the RE-001 startup thread count.
The earlier thread-pool packet left the producer of `0x57883f8` unclosed.
This packet binds its actual once callback to the complete initializer,
reconstructs the selected quota calculation and final cache publication, and
provides an independently authored Rust value/publication projection.

The result includes two details that a replacement must preserve: input
rounding can make integer ceildiv disagree with the target, and skipping a
write differs from storing zero. See [PROOF.md](PROOF.md) for address-level
derivation, assumptions and explicit gaps.

Target SHA-256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base revision: `e5c9b6436876b2a4a39daef813171f9879317699`.

## Retained evidence

- `evidence/records.json`: actual FDE/CIE records, complete body hashes,
  relocations, import names, RIP references, constants and filenames.
- `evidence/*.objdump.txt` and `*.llvm.txt`: whole-function exports from GNU
  and LLVM with identical bytes and instruction boundaries.
- `preparation/build_oracle.py`, `oracle/FREEZE.json`, `oracle/vectors.json`:
  integer-only expected values frozen before the Rust implementation.
- `rust/`: real standalone Rust 1.94.1 crate with no external dependencies,
  native tests and a vector driver. It is not a node workspace or original ABI.
- `validation.json`: actual native/focused results and their limits.

The small static collector is required to bind the producer's full FDEs,
numeric constants and actual relocation targets together; existing generic
indexes and the previous consumer packet do not establish this producer
relation. It does not alter catalogues or the global byte-window registry.

## Reproduce

From the repository root with captured inputs materialized:

```sh
python3 -B research/work-items/RE-002-num-cpus-cache-94/verify.py
python3 -B tools/cpu_cache_static.py
python3 -B -m unittest discover -s tests -p test_cpu_cache_static.py -v
cargo +1.94.1 test --locked --offline \
  --manifest-path research/work-items/RE-002-num-cpus-cache-94/rust/Cargo.toml \
  --target-dir work/cpu-cache-94/cargo
```

Use GNU objdump for the collector; on macOS add the installed GNU binutils
directory to PATH. Set `LLVM_OBJDUMP` to the native LLVM executable for the
repository's other checks. The focused Python suite builds only the new Rust
crate, offline, in a temporary directory. It skips its native-build test if
Rust 1.94.1 is unavailable; the recorded run had no skips. `verify.py` is
static and does not itself run the Rust vector driver or captured code.

`manifest.json` binds the closed packet inventory and its collector/test.
Regenerating the mathematical oracle is a preparation action and changes the
frozen provenance if the generator changes; it is not part of verification.

## Limits

This closes a selected dependency-backed value/publication relation. It does
not reconstruct the full cgroup parser, filesystem paths, once primitive,
cleanup or source build. No captured node was executed, no network request to
a node was made, and no complete component or source-byte match is asserted.
