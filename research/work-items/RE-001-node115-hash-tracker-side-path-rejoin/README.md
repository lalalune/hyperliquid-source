# RE-001: separate the hash tracker side call from its shared update path

RE-001 · Block execution and state. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Repository baseline: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. Coordinates are link-time ELF VAs.

## Evidence

The hash-signature-tracker caller's zero/nonzero global check gates a side call. Both normal paths reach the same tracker call at `0x5afac82`. The zero case falls through to the call setup. The nonzero case calls indirectly through `0x64df9f0` (resolved FDE start `0x5c87d50`), restores `rdx` from `r15`, and jumps back to the same setup block.

[#3970](https://github.com/lalalune/hyperliquid-source/pull/3970) recorded the fallthrough. Resolving the taken successor shows that the data flow of the core call is shared, rather than gated by this condition. Before the check, the caller updates the qword at `r14+0x80` to the unsigned maximum of its previous value and `r15`. After the shared call it passes an unsigned saturating subtraction of 50,000 from `r15` to a second routine. The branch input is a 32-bit load from `.data` at `0x64f01d8`, whose on-disk word is `0x3`.

[record.json](record.json) retains the decoded instructions and bytes.

## Reproduction

Run from the repository root with the pinned LFS artifact materialized:

```sh
target=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x5afa7f0 --stop-address=0x5afad86 "$target"
readelf -rW "$target" | grep -i 64df9f0
```

Verified the target SHA-256, caller FDE, indirect slot relocation and destination FDE. The decoded zero, one and high-bit-set test cases distinguish optional side-call execution from shared-call reachability after a normal return. The subtraction borrows at 49,999, yields zero at 50,000, and yields one at 50,001 under the recorded unsigned instructions.

Local static checks used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33. The captured binary was read without execution.

## Limits

The side-call label describes its control-flow role. The runtime writer and source-level name of the global, unwind behavior, and the full identities of the two update routines remain open. This packet requests no acceptance gate or byte-coverage change.
