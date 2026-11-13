# RE-008: shared S decoder fixarray path

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This packet follows the fixarray sequence branch at `0x31c3aac` of the shared S decoder. It does not execute the target.

## Observed sequence branch

Open #6599 identifies the containing decoder and its map-path `s` and `r` fields but explicitly excludes this sequence path. At `0x31c333b..0x31c333f`, the fixarray marker's low nibble is moved to the `edi` argument before jumping to the selected path at `0x31c3aac`; the latter copies its low byte to `ebp`.

- The function reads a 16-bit field from decoder `+0x22`. Zero branches to `0x31c42b1`; otherwise it decrements and stores that field. A resulting zero branches away at `0x31c3ac4`. The meaning of this field and the complete called error handlers are not asserted.
- For a zero low-nibble count, `0x31c3acc` branches to `0x31c3d72`, which clears both `r15d` and `eax`. For a positive count, the first direct helper `0x469a340` is called. On its result tag `9`, the returned qword is copied to `r15`. If count is one, the second qword is set to zero and control reaches the common result construction.
- For count greater than one, `0x421ecc0` is called. After tag `9`, count two loads its qword into `rax` and reaches the same construction; other counts reach `0x31c4081`, which constructs a record containing byte `4` and dword `2`. Helper failures follow separate paths. These observations do not by themselves establish the names or numeric interpretation of the two qwords, or the meaning of the output tags.
- The common block at `0x31c3d77` saves `r15` and `rax`, writes tag byte `9`, and proceeds through an increment guarded against `0xffff` in the same decoder field. Error-path calls and integer reader bodies are outside this packet.

## Reproduction and limits

```sh
python3 research/work-items/RE-008-node115-shared-s-sequence/verify.py
readelf -wf artifacts/node/115/hl-node | rg 'pc=00000000031c32d0'
/usr/bin/objdump -d --x86-asm-syntax=intel --start-address=0x31c32d0 --stop-address=0x31c4390 artifacts/node/115/hl-node
```

The verifier authenticates the target SHA-256, checks nine instruction byte anchors and both selected direct-call targets, and rejects nine single-byte anchor mutations. The retained FDE disassembly is a review aid. These selected checks do not prove full control-flow coverage, integer semantics, runtime reachability, malformed-input behavior, or map/sequence equivalence. No node code is executed and no component gate is advanced. Only the short fixarray arm is claimed; other marker dispatch routes remain outside scope.
