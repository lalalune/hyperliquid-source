# RE-001: identify node #115 RPC location path and line format arguments

RE-001, shared RPC diagnostics. Linux x86-64 node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Baseline `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. Addresses are link-time ELF VAs.

## Evidence

The consumer at `0x1508b00`, reached by the location-copy handoff in [#3951](https://github.com/lalalune/hyperliquid-source/pull/3951), constructs two callback/value pairs. Its first value is the incoming `rsi` pointer and its second is that pointer plus 16. At `0x1508b41` and `0x1508b57` it binds those values to `0x15ebbc0` and `0x15eb990`, respectively.

The first callback dereferences the saved location pointer, loads a 64-bit address and length from offsets 0 and 8, and tail-jumps through `0x64df720` (RELATIVE addend `0x167fa70`). The second callback loads a 32-bit value from the pointer at offset 16 and begins a decimal conversion path (radix 10 setup and unsigned comparison with 1000). Thus the observed formatter consumes the path span and line field. Neither callback prefix reads the location column at offset 20.

The wrapper passes the two pairs in `rcx` and the literal bytes `c0 01 3a c0 00` at `0x434571` in `rdx` before the indirect call at `0x1508b7b`. The colon byte is observable. The exact format encoding and final rendered output remain unresolved. That call resolves through `0x64df6f0` (RELATIVE addend `0x1680500`). The raw instruction sequence and relocation values are in [record.json](record.json).

## Reproduce

Run from the repository root with the pinned LFS artifact materialized.

```sh
target=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
objdump -d -M intel --start-address=0x1508b29 --stop-address=0x1508b81 "$target"
objdump -d -M intel --start-address=0x15ebbc0 --stop-address=0x15ebbd6 "$target"
objdump -d -M intel --start-address=0x15eb990 --stop-address=0x15eb9ae "$target"
objdump -s -j .rodata --start-address=0x434571 --stop-address=0x434576 "$target"
readelf -rW "$target" | grep -Ei '64df(6f0|720)'
```

Local static extraction used Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33. Recompute each RIP-relative target from the signed displacement and next VA. Replacing the second pair's offset 16 with 20 would feed the column field, which contradicts the immediate `10` in the address adjustment at `0x1508b2e`. No captured code execution, implementation comparison or acceptance gate. Next, decode the format stream at the resolved formatting call to verify how the literal and callbacks are interleaved.
