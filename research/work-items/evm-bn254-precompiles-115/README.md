# evm: node 115 alt_bn128 precompile glue (add, mul, pairing) and six gas wrappers

The node #115 reconstruction can now specify, input to output, the three EVM alt_bn128 precompile run bodies (add `0x5c15e20`, mul `0x5c16080`, pairing `0x5c162b0`) and the six fixed-price wrappers that call them (`0x5c09750`, `0x5c097f0`, `0x5c15ba0`, `0x5c15c40`, `0x5c15ce0`, `0x5c15d80`): the order of the gas, overflow, length and allocation checks, how inputs are padded or read in place, which slices reach the crypto provider, and how the 0x28-byte body result is widened into the 0x58-byte frame, each verified against the real machine code on 10,700 cases.

- Component ID: `evm` (HyperEVM precompile execution); this is a bounded extension of the RE-011/RE-021 precompile work, not a row in `docs/TASKS.md`.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`; `references/can1357-hl` was not consulted for this packet, nothing was copied. The #94 report was not used.
- Claim status: observation (ELF bytes, FDE extents, relocation words, instruction forms, machine-code evaluation results); inference (field and function roles, the revm-style naming of the bodies, the meaning of the status words); unresolved (the provider's curve arithmetic behind the vtable, the precompile registry that selects these wrappers, fork activation).
- Scope included and excluded: the nine functions above, their GOT call slots `0x64eaec0/0x64eaec8/0x64eaed0`, the lazy provider static `0x64fe3d8`, allocation, memcpy, once-init and panic call targets as stubbed boundaries. Excluded: the provider methods themselves (bn254 field and pairing arithmetic), the blake2f wrapper `0x5c16650` (already in RE-021-blake2b-lookup-115), registry/dispatch, and every other precompile.

## Reproduce

From the repository root with Python 3.12 and the authenticated node #115 artifact present:

```sh
python3 tools/evm_bn254_precompiles_115.py --out research/work-items/evm-bn254-precompiles-115
python3 -m unittest tests.test_evm_bn254_precompiles_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

For a separate repeatability check, replace `<tmp-dir>` with an existing writable directory:

```sh
PYTHONHASHSEED=0 TZ=UTC python3 tools/evm_bn254_precompiles_115.py --out <tmp-dir>/one
PYTHONHASHSEED=937 TZ=Pacific/Honolulu python3 tools/evm_bn254_precompiles_115.py --out <tmp-dir>/two
diff -r <tmp-dir>/one <tmp-dir>/two
```

The generator verifies the full input SHA-256 first. It uses only the standard library, `tools/elf_index.py`, `tools/fde_extents.py` and the concrete x86-64 evaluator already in `tools/re11_transient_storage115.py` (imported, not copied). It starts no external program and never executes the node: it decodes code bytes read from the file and evaluates them in Python with synthetic memory. SHT_NOBITS sections are never read as file bytes. One generation takes about 60 s and 437 MB peak resident memory; the unit tests take about 8 s. GNU objdump was used only by hand to read instruction windows; no output of it is parsed or stored. Three generations in the default environment were byte-identical; the output contains no time, random value or absolute path, and every table is written in a sorted or fixed order (the two-setting check above could not be run under this session's command policy). `MANIFEST.sha256` covers every other file in this folder.

## Evidence

Coordinates are ELF virtual addresses (VA). FDE ends are exclusive unwind ranges, read with the shared FDE parser.

| Role (inferred) | Start VA | End VA | Bytes |
| --- | --- | --- | --- |
| add body | `0x5c15e20` | `0x5c1607d` | 605 |
| mul body | `0x5c16080` | `0x5c162ad` | 557 |
| pairing body | `0x5c162b0` | `0x5c165a6` | 758 |
| add wrapper, gas 150 / 500 | `0x5c09750` / `0x5c097f0` | `+0x9a` | 154 each |
| mul wrapper, gas 6000 / 40000 | `0x5c15ba0` / `0x5c15c40` | `+0x9a` | 154 each |
| pairing wrapper, 34000 per pair + 45000 / 80000 per pair + 100000 | `0x5c15ce0` / `0x5c15d80` | `+0xa0` | 160 each |

Relocation words (all read from `.rela.dyn`): GOT `0x64eaec8 -> 0x5c15e20` (add), `0x64eaec0 -> 0x5c16080` (mul), `0x64eaed0 -> 0x5c162b0` (pairing); the wrappers' only direct calls are these slots (`call *slot` at `0x5c0976a`, `0x5c0980a`, `0x5c15bba`, `0x5c15c5a`, `0x5c15d00`, `0x5c15da0`). The wrappers load their price from immediates: `0x96`, `0x1f4`, `0x1770`, `0x9c40` (cost) and `0x84d0`/`0xafc8`, `0x13880`/`0x186a0` (per pair / base). The provider is a lazily initialised static: GOT `0x64ec358 -> 0x64fe3d8`, with the data pointer at `+0`, the vtable at `+8` and a once-state dword at `+0x10` (non-zero calls the initialiser `0x5bee2d3` first); the vtable methods used are `+0x30` (add), `+0x38` (mul) and `+0x40` (pairing). Both evidence tables (`constants.json`, `decoded-instructions.tsv`) are produced from file bytes only.

Observed behaviour of the bodies (each statement is one of the compared properties):

- add and mul: compare fixed cost against the limit first (`cost > limit` -> status `0x8000000000000001` in a zero-tagged result, no provider call). Inputs shorter than 128 (add) or 96 (mul) bytes are copied with `memcpy` into a zeroed stack buffer; longer inputs are read in place. add passes two 64-byte slices (`in+0`, `in+64`), mul passes a 64-byte slice and a 32-byte scalar. A provider error is copied through (bytes 8..0x20); a success allocates 0x40 bytes (a null return is a diverging allocation error with arguments `(1, 0x40)`), stores the 64-byte result and returns `{vtable, ptr, 0x40, ptr|1 or ptr, cost}` where the vtable word is `0x64040c0` for an odd allocation and `0x64040e8` for an even one.
- pairing: `n = len / 192` via the reciprocal multiply; `n * per` then `+ base` are checked and diverge into the multiplication / addition overflow panics before any other check; then `cost > limit` -> out-of-gas; then `len != 192 n` -> status `0x800000000000000a`. `len == 0` hands the provider a dangling vector (pointer 8, length 0) without allocating; otherwise `32 n` bytes are allocated (null -> diverging allocation error `(8, 32 n)`) and each pair gets the descriptor `(in+192 i, 64, in+192 i+64, 128)`. The vector is freed after the call (`dealloc(ptr, 32 n, 0)`). An `Ok` provider tag `0x8000000000000024` yields `{0x64c0420, true? 0x4576a0 : 0x457f80, 0x20, 0, cost}` chosen by bit 0 of the provider's bool; any other tag is copied field by field, in the order the stores execute, so one byte at `+0x18` is overwritten by the overlapping store at `+0x11`.
- wrappers: call the body with their price, then either write `{0x8000000000000024, 16 bytes of stale stack, tag, ptr, len/tag-word, cost, 0, ctx}` (ok) or `{status, tmp[0x10..0x20], &static, 1, 0, 0, 0, ctx}` (error; `&static` is `0x64c0190` for add and `0x64c0420` for mul and pairing). In the ok frame bytes `8..0x18` are uninitialised wrapper stack and are modelled as the harness fill value.

Raw files: `cases.tsv` (one row per case: arguments, outcome class, stub-call sequence, result digest, match), `outcome-classes.tsv`, `decoded-instructions.tsv` (every instruction of the nine functions with whether any case executed it), `functions.tsv`, `constants.json`, `negative-controls.tsv`, `equivalent-mutants.tsv`, `summary.json`, `measure.json`.

## Implementation and comparison

`tools/evm_bn254_precompiles_115.py` holds (1) `model_run` / `model_wrapper`, one pure-Python reconstruction of the bodies and wrappers; (2) a rig that places the input, the output frame, the provider static, a 3-entry vtable and allocations in synthetic memory, stubs every external call target (allocator, deallocator, memcpy import, once-init, allocation-error and panic functions, the three vtable methods) with recorded arguments, and runs the real code bytes; (3) a comparison of the return register, the full output frame, the ordered stub-call log (including the bytes the provider would read and the descriptors it would receive), the allocated box contents, callee-saved registers, the stack pointer and the untouched caller stack. No Rust is written in this packet; the model is the executable specification for a later Rust port.

Cases are generated from named deterministic byte streams: 1,300 add-body, 1,300 mul-body, 1,500 pairing-body cases, 1,000 each for the four add/mul wrappers and 1,300 each for the two pairing wrappers (10,700). They cover every status path, both padding branches and their boundaries (`pad-1`, `pad`), once-state zero and non-zero, both allocation parities, allocation failure, provider success and failure, limits at `cost-1`, `cost`, `cost+1`, `0` and `u64::MAX`, empty / partial / multi-pair pairing input, and multiplication and addition overflow with adversarial per-pair prices.

Negative controls (132 made, all counted): 6 deliberately wrong models (`>=` gas compare, pad boundary off by one, mul scalar length 64, rounding-up pair count, wrong bad-length code, swapped bool vtable), 122 single-byte edits of every conditional jump, small immediate and `mov` immediate in the nine functions run on the real code, and 4 input corruptions (flipped `.text` byte, flipped trailing byte, address past `.text`, address that starts no FDE). 127 are detected. 5 byte edits are not observable and are listed with reasons in `equivalent-mutants.tsv` (a length threshold that the multiple-of-192 test makes irrelevant, one dead store, one argument of an unreachable bounds panic, two unwind landing-pad instructions). The generator fails if any undetected edit lacks such an entry.

## Results and limitations

Machine-readable (`measure.json`, `summary.json`): 10,700 cases, 0 mismatches; 132 negative controls, 127 detected, 5 equivalent; 124/124, 118/118 and 146/171 instructions of the add, mul and pairing bodies executed, 39/39 or 40/40 in each wrapper. The 25 unexecuted pairing-body instructions are the slice-bounds panic arms, the vector-grow call and the unwind landing pad, which no valid input reaches.

Limits: the provider's curve and pairing arithmetic, field-element validation errors, and the exact error enum behind the copied bytes remain unresolved; stubs record arguments only. The registry that maps precompile addresses to these wrappers, fork selection and the gas schedule choice per fork are not shown here (the wrapper constants are observed, their fork meaning is inferred from the usual 150/500, 6000/40000 and 34000+45000 / 80000+100000 schedules). The stale-stack bytes in the ok frame are modelled as the harness fill, which states only that the wrapper does not initialise them. No progress gate is requested.

Next question: the registry/dispatch that selects between the two wrapper variants per address and fork, and the provider vtable methods `+0x30/+0x38/+0x40`.
