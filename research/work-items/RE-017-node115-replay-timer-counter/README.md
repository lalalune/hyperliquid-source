# RE-017: selected timer counter and common handoff

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This static packet follows the secondary comparison branch left open in #6623, upstream of the replay digest handoff in merged #5157. No captured code is executed.

## Selected branch

- After the second selected three-word comparison, `0x5152495..0x51524a8` loads two pointers through context `+0x28` and `+0x30`, reads one qword through each, and branches to `0x515269d` only if the first is unsigned-below the second. The values' provenance and their meanings are not established here.
- The target block increments the first loaded qword and stores it through the first pointer, then unconditionally jumps to `0x51527e9`. Assuming the values do not change concurrently between the comparison and store, unsigned `first < second` implies that `first + 1` does not wrap and is at most the second value. This is a mathematical implication of that selected branch, not a claim of thread safety or an atomic update.
- The direct path from `0x515269d` to `0x51527e9` does not pass through the digest extraction call at `0x51525bb`. At the common block, the body loads a pointer from the traversal object `+0x08`, decrements the qword through that pointer, forms a three-word local descriptor from selected traversal registers, and calls `0x4d31c60`. It then copies returned words into the saved caller output and traversal descriptor. The helper's full semantics are a boundary here; no deletion or queue behavior is inferred from its address.
- A different path can reach the same common block after the selected digest extraction path; #5157 documents the latter. This packet does not claim that the common block is exclusive to either route, that the secondary branch was reached at runtime, or that a counter increment produces a replay record.

The FDE is `0x51520f0..0x51528fb`; retained windows are linked ELF virtual addresses. Pointer validity, concurrent mutation, helper behavior, ownership, caller authentication, timer units and state-root effects are outside scope. No node completion gate is advanced.

## Reproduce

```sh
python3 research/work-items/RE-017-node115-replay-timer-counter/verify.py
readelf -wf artifacts/node/115/hl-node | rg 'pc=00000000051520f0'
/usr/bin/objdump -d --x86-asm-syntax=intel --start-address=0x5152470 --stop-address=0x51524b7 artifacts/node/115/hl-node
/usr/bin/objdump -d --x86-asm-syntax=intel --start-address=0x515269d --stop-address=0x51526a8 artifacts/node/115/hl-node
/usr/bin/objdump -d --x86-asm-syntax=intel --start-address=0x51527e2 --stop-address=0x515286d artifacts/node/115/hl-node
```

The verifier authenticates the target SHA-256, checks ten selected byte anchors and two direct-call targets, and rejects ten single-byte anchor mutations. It does not prove full CFG, pointer validity, helper semantics, concurrency conditions or dynamic equivalence. #6623 maps the preceding timer comparisons but explicitly excludes the secondary branch's qword meaning; #5157 covers the selected extraction path and leaves timer eligibility open.
