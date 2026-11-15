# RE-017: selected replay traversal leaf compaction (#115)

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses are ELF virtual addresses. This packet follows the secondary timed path documented in PR #6624 and the caller evidence in #5157. The latter captured the traversal helper but did not establish its leaf-compaction behavior. This is a partial static finding, not a component completion claim.

## Observations

At `0x51527e9`, the caller decrements a qword and passes a three-word descriptor to `0x4d31c60`. That helper loads the descriptor's node, depth and index; if depth is zero, it passes the same node and index in a new zero-depth descriptor to `0x4d2c060` (`0x4d31e42`–`0x4d31e5d`). Other depth values take a different path.

The callee reads the node's 16-bit count at `+0xe6` and saves the indexed eight-byte field at `node+8+8*i`. It computes `count-i-1`, and calls the function loaded from relocation slot `0x64df568` with destination `node+8+8*i`, source `node+16+8*i`, and byte count `8*(count-i-1)`. It similarly saves the 12-byte field at `node+0x60+12*i`, and calls that same function with byte count `12*(count-i-1)` to shift the subsequent fields left. The ELF relocation identifies that slot as `memmove@GLIBC_2.2.5`. It then stores `count-1` as a 16-bit value and branches on whether the new count exceeds four.

Under the explicit assumptions that `i<count`, both ranges are valid, the dynamic slot resolves to the stated `memmove`, and both calls return normally, this removes the selected entries from the two parallel field arrays and preserves the order of their trailing entries. The selected values are saved on the stack; this packet does not claim their eventual use. The observed low-count continuation is not analyzed here.

## Reproduction and limitations

Run `python3 research/work-items/RE-017-node115-replay-leaf-compaction/verify.py`. It authenticates the target and verifies the selected instruction anchors and two direct calls; one-byte negative controls are applied to each anchor. The raw instruction windows were generated with `/usr/bin/objdump -d --x86-asm-syntax=intel` using their address boundaries, and the relocation with `readelf -rW`. These checks do not execute captured code, validate runtime reachability, prove type names, characterize aliases or low-count rebalancing, or establish a relationship to checkpoint height or a state root. A valid descriptor and normal return are assumptions, not verified runtime observations.
