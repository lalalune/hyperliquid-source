# evm: node #115 Keccak-256 sponge (absorb, pad/squeeze, f1600) and RIPEMD-160 block compression, rebuilt and checked against the captured bytes

With this packet the hashing that sits under the EVM `KECCAK256` opcode and the RIPEMD-160 precompile can be reimplemented from node #115 itself: an executable Python reconstruction of the Keccak-f[1600] permutation (0x5cda380), the sponge write (0x5cda910) and the pad-and-read step (0x5cdad40) that together form Keccak-256 as the node computes it, and of the RIPEMD-160 compression function (0x5c3ce60). The reconstruction agrees with the machine code on 10,015 comparisons, including the exact points where the target's slice checks stop it, and 52 deliberately wrong reconstructions or corrupted bytes are all told apart from it.

- Component ID: `evm`
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked by the tool before anything is parsed).
- Source commit / reference commit: workspace commit `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No reference source was copied; the algorithms are the published Keccak and RIPEMD-160 definitions, written out from their specifications and then checked against the bytes.
- Claim status: addresses, extents, decoded instructions, the round-constant table, the rotate immediates and every comparison result are observations (the interpreter reads bytes and never executes the node). The role names, the field layout of the sponge structure and the mapping to EVM opcodes are inferences.
- Scope included and excluded: four functions and one data table, as listed below. Excluded: who calls them (the callers are indirect), the SHA-256 block functions (0x5d20100 is already byte-matched by an earlier packet; the SHA extension path 0x5c66b90 needs vector instructions the interpreter does not model), the EVM opcode handlers and gas wrappers around the hashes, and every other precompile.

## Reproduce

From the repository root, Python 3.12, standard library plus `tools/elf_index.py` and `tools/fde_extents.py`, with the authenticated artifact at `artifacts/node/115/hl-node`:

```sh
python3 tools/evm_keccak_ripemd_115.py --out research/work-items/evm-keccak-ripemd-hash-115
python3 -m unittest tests.test_evm_keccak_ripemd_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/evm-keccak-ripemd-hash-115 && sha256sum -c MANIFEST.sha256)
```

The generator takes about 3.5 minutes and under 300 MB; the unit tests take about 17 seconds. It runs no external program and no binutils, writes no times, paths or random values, and two runs in different output directories (and with `-R` hash randomisation) are byte-identical. The interpreter section of the tool is the verified shared x86-64 skeleton, copied into this tool; the node is never executed.

## Evidence

Coordinates are virtual addresses of the loaded image; function ends are the unwind (FDE) interval ends, and the decoder consumes each interval exactly (`functions.tsv`).

| function | start | end | bytes | role |
| --- | --- | --- | --- | --- |
| f1600 | 0x5cda380 | 0x5cda902 | 1,410 | Keccak-f[1600] over 25 lanes at `rdi`, 24 rounds |
| absorb | 0x5cda910 | 0x5cdad3a | 1,066 | sponge write `(self, ptr, len)` |
| squeeze | 0x5cdad40 | 0x5cdb03d | 765 | finalize-and-read on a copy of the structure `(self, out, len)` |
| ripemd160_compress | 0x5c3ce60 | 0x5c3e4eb | 5,771 | state of five words at `rdi`, 64-byte block at `rsi` |

- `constants.json`: the 24 round constants read straight from the rodata table at 0x94c518, the rotate immediates found in the two large bodies, and the check that all eight non-zero RIPEMD-160 constants occur as instruction immediates. `decoded-instructions.tsv` lists every decoded instruction of the four functions with its raw bytes (2,582 rows).
- Sponge structure inferred from the offsets the two sponge functions use: bytes 0..199 state (25 little-endian lanes), +0xc8 position, +0xd0 rate, +0xd8 delimiter byte, +0xd9 a flag that is 1 once the structure is in the reading phase; total size 0xe0.
- Indirect calls: f1600 is reached through a pointer slot at 0x64ecb70 (initialised by a relative relocation to 0x5cda380) from both sponge functions; the memory-copy slot at 0x64df508 is used by squeeze; the other slots listed in `summary.json` lead only to bounds-check failure paths and are modelled as a stop. No direct call reaches any of the four entries: absorb and squeeze sit in a pointer table at 0x64e0148/0x64e0150 and the RIPEMD compression in the table at 0x64ec328, both by relative relocation.

## Implementation and comparison

`tools/evm_keccak_ripemd_115.py` contains three pure-Python reconstructions, none of which read the binary: `keccak_f` (theta, rho, pi, chi, iota with the lane offsets written out), `sponge_absorb` and `sponge_squeeze` (the sponge discipline of the structure above, with explicit bounds-check points) and `ripemd_compress` (two lines of 80 steps with the published selector, shift and constant tables). Each is compared with the machine code run on the offline interpreter, one input at a time, results compared immediately and only counts kept.

What the byte comparison fixed that the specification alone does not say:

- absorb with the reading flag set first permutes and resets the position to zero, then writes; with the flag clear it needs `rate >= position`; a block that is exactly full is permuted immediately (`>=`).
- squeeze works on a copy and leaves the caller's structure unchanged; when not yet in the reading phase it xors the delimiter at the position, xors 0x80 at `rate-1` and permutes once; it permutes lazily between output blocks.
- Out-of-range values stop the target only where the slice is actually used: position above 200 stops even for an empty write, but `rate` above 200 is harmless for a short write that stays inside the state. The reconstruction raises at those same points (2,200 absorb and 1,500 squeeze comparisons include the stops).
- Whole-hash flows: the target pieces reproduce the published Keccak-256 and RIPEMD-160 digests (empty, `abc`, the fox sentence, and the standard RIPEMD-160 vectors) and agree with the reconstruction on 152 messages of 0..1000 bytes, written in one piece or split at a message-dependent point.

Controls (`negative-controls.tsv`, 52, all detected; `equivalent-mutants.tsv` is empty): 14 wrong Keccak variants (round count, constants, offsets, theta, pi, chi), 12 wrong RIPEMD-160 variants, 7 wrong sponge variants, 10 single-bit corruptions of rotate immediates in the target's own bytes, 3 corrupted round constants, 3 out-of-range classifications and 3 corrupted copies of the binary digest.

## Results and limitations

`measure.json`: 10,015 comparisons (f1600 2,400; ripemd160_compress 3,600; absorb 2,200; squeeze 1,500; whole-hash flows 315), 52 negative controls, 52 detected, 0 equivalent. The committed `cases.tsv` is a sample of 659 rows; the tool regenerates all comparisons.

Limits: inputs are generated from fixed seeds, not exhaustive; the copy routine and the failure paths are replaced by small models, so only their observable behaviour is claimed; the pad delimiter byte and rate are caller data, so which values the node passes (0x01 and 136 for Keccak-256) is checked only through the published digests, not by finding the caller; the sponge structure name and the EVM role are inferences. This asks for no component gate.

Next question: find the callers of the two table entries at 0x64e0148 and 0x64ec328 to confirm which opcode handler and which precompile glue drive these functions.
