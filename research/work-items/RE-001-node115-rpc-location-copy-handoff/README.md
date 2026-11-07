# RE-001: resolve the shared node #115 RPC source-location copy handoff

RE-001. Components: EVM JSON-RPC and consensus. Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source baseline `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. All coordinates are ELF virtual addresses.

## Evidence

The existing [consensus constructor packet](../RE-001-node115-rpc-store-update-dispatch/README.md) records the two constructor calls. This packet follows their source-location pointers into those callees and compares the handoff against the method-router caller. On all three entry paths, `movups` reads descriptor bytes [0,16) and `mov eax` reads [16,20). The next two stores copy those bytes into consecutive stack locations. Each path takes the stack copy's address in `rsi` before calling through the same RIP-relative slot.

| Source descriptor suffix | Entry VA | Incoming register | Stack offset | Indirect call VA |
| --- | --- | --- | --- | --- |
| evm_rpc/method_router.rs:58 | `0x2502450` | `rsi` | `0x70` | `0x2502486` |
| node/consensus/rpc.rs:101 | `0x5ab20d0` | `rdx` | `0x140` | `0x5ab214a` |
| node/consensus/rpc.rs:102 | `0x5ab1ce0` | `rdx` | `0xf0` | `0x5ab1d1f` |

All three `ff 15 disp32` instructions resolve to `0x64e0b00`. Its symbol-zero `R_X86_64_RELATIVE` relocation has addend `0x1508b00`, which is the start of the actual FDE at `0x104b894` with exclusive end `0x1508dff`. The instruction bytes, descriptor relocation coordinates, source-side direct calls and entry traces are in [record.json](record.json).

The shared handoff accounts for the pointer, length and line bytes of the observed descriptors. The column at offset 20 is outside the copied range. Other uses of the original descriptor, the shared callee's behavior and whole-function identity remain open. No implementation comparison or progress gate is claimed.

## Reproduce

From the repository root with the LFS input materialized:

```sh
target=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
readelf -rW "$target" | grep -i '0*64e0b00 '
readelf --debug-dump=frames "$target"
objdump -d -M intel --start-address=0x2502450 --stop-address=0x250248c "$target"
objdump -d -M intel --start-address=0x5ab20d0 --stop-address=0x5ab2150 "$target"
objdump -d -M intel --start-address=0x5ab1ce0 --stop-address=0x5ab1d25 "$target"
```

Decode from each entry through the indirect call. Add each signed disp32 to its next instruction VA. The three results must equal the same relocation coordinate. Adding one to any disp32 instead yields `0x64e0b01` and fails the equality check. Inspect the two stack stores and the `lea rsi` before the call. Python 3.12.14, Capstone 5.0.7 and pyelftools 0.33 performed the local static checks on Windows. No captured code was executed. Next, track the second argument within the shared callee to establish whether it preserves the line value or only uses the path span.
