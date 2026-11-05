# RE-001 · Node #115 startup argument cells and their reader

Component: foundation utilities, startup function map. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Repository baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

The [initializer census](../RE-001-node115-init-array-census/README.md) maps slot zero to `0x5ca55c0`. The [entry packet](../RE-001-node115-entry-start/README.md) maps the initial argument registers into libc and Rust startup. This packet follows the two cells written by the initializer to a second writer and the reader already seen at the boundary of the [chain-origin wrapper](../RE-005-node115-chain-origin-writers/README.md).

## Observations

- The relative relocation at `.init_array[0]` binds VA `0x63f36c8` to the function in FDE `[0x5ca55c0, 0x5ca55d2)`. The function sign-extends `edi` to 64 bits, writes it to `0x6500000`, writes `rsi` unchanged to `0x6500008`, and returns. Both cells are eight-byte slots in `.bss`.
- In the startup function with FDE `[0x5c99970, 0x5c9a045)`, the instructions at `0x5c99e07` and `0x5c99e12` store to the same two cells. The recorded excerpt establishes the destinations. It does not establish dominance or when that path runs.
- The reader at `0x5c9a530` loads and tests the second cell first. Its null branch skips the first-cell load and count arithmetic. The non-null path reads the first cell, computes `count * 24` in registers, and branches on an unsigned comparison to `0x555555555555555`, the largest count whose product by 24 fits in a signed 64-bit positive range.

## Inference and limits

The input widths, startup position and reader use are consistent with process `argc` and `argv` storage. The transcript records three selected windows. It does not exhaust the callers, readers, stores or paths, recover symbol names, or establish the type or ownership of the 24-byte output elements. No implementation comparison or acceptance gate change is claimed.

## Reproduce

From the repository root after materializing the pinned node binary, with Python 3.11+ and the recorded Capstone 5.0.9 and pyelftools 0.33:

```sh
python3 -B research/work-items/RE-001-node115-startup-argument-handoff/inspect_args.py
python3 -B research/work-items/RE-001-node115-startup-argument-handoff/inspect_args.py research/work-items/RE-001-node115-startup-argument-handoff/evidence.txt
```

The first command derives [the transcript](evidence.txt) from the pinned capture. Addresses are ELF VAs except the labeled file offsets. The second command rejects a wrong input at the digest check before attempting to parse it. Neither command executes the captured node.
