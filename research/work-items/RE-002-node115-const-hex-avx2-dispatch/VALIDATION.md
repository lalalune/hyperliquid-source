# Validation record

- Repository revision: `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Host: macOS arm64; analysis is over the Linux x86-64 ELF bytes and does not
  execute the captured node.
- Tools: Python 3.14.3; GNU objdump/readelf 2.47.20260726.

## Static evidence commands

Run from the repository root:

```sh
objdump -d --start-address=0x167a9c0 --stop-address=0x167abfb artifacts/node/115/hl-node > research/work-items/RE-002-node115-const-hex-avx2-dispatch/native/gnu-caller.objdump
objdump -d --start-address=0x167ac00 --stop-address=0x167afcf artifacts/node/115/hl-node > research/work-items/RE-002-node115-const-hex-avx2-dispatch/native/gnu-avx2.objdump
readelf -rW artifacts/node/115/hl-node | rg '00000000064dfa6[08]' > research/work-items/RE-002-node115-const-hex-avx2-dispatch/native/gnu-relocations.txt
python3 -B tools/node115_const_hex_avx2_dispatch.py --write
python3 -B tests/test_node115_const_hex_avx2_dispatch.py
```

The retained export SHA-256 values are:

```text
c44cebd5f7df31e7044f5f477483ca068479ce3a244ff88a524ccae1c8f8fdfe  native/gnu-avx2.objdump
b2dab3cac7b2f53abdeaee2a1127d16e82118ccd83f1ae11eb8aea90f1485861  native/gnu-caller.objdump
a90b02c6a0d7f388122dd838dae78deb0ef782908612d66254d4371f19359194  native/gnu-relocations.txt
```

The focused test command passed 6 tests. They cover census/FDE identities,
branch targets, cache relocations, AVX2 bytes, a wrong target digest, and a
mutated branch opcode. `make reproduce` passed and reproduced both node #115
and visor inventories byte-for-byte.

`make test` was started but interrupted after about seven minutes. Its runner
executes 1,131 test files sequentially; at interruption,
`test_chain_origin_writers_static.py` had consumed over two minutes of CPU.
The repository-wide suite has no final result, and no full-suite pass is
claimed. No failure result was observed before interruption.

## Repository checks

`PATH=/opt/homebrew/opt/binutils/bin:$PATH make doctor` passed with
`analysis_ready: true`; exact rebuild readiness remains false because recovered
Cargo manifests, target build flags/toolchain provenance, and an accepted
comparison harness are not established. `make verify` passed: pinned artifacts
and signatures, 32 imported files and pinned repositories, and all evidence
packet manifests. `make catalogue-check` passed after regenerating the catalogue
for the added packet; the generated count is 2,151 documented work items.
