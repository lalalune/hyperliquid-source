# RE-008: node #115 signer candidate lookup

Target: `artifacts/node/115/hl-node`, Linux x86-64, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This static packet follows one question in the vote-admission path: what does the indirect call at `0x537bbed` check before its caller tests the returned byte? It does not execute the target.

## Observed path

- The call at `0x537bbed` loads its destination from `0x64e6ac0`. The target ELF has one relocation for that slot, an `R_X86_64_RELATIVE` entry with addend `0x37141b0`. This is static loader interpretation, not an observed running pointer. The caller tests `al` and branches to `0x537b9d0` on zero. The surrounding caller is studied in open PR #6053; this packet does not depend on that PR's code.
- `readelf -wf` records an FDE interval `0x37141b0..0x371438a`. This is an unwind extent, not a proof of all possible entrypoints or runtime reachability. `body.objdump.txt` retains the decoded interval.
- The body first loads owner `+0x58` and compares against entries in either a tree-shaped path or a wrapped sequence. On the latter path, direct helper `0x4551810` returns a result tested at `0x3714270`; a failed result or out-of-range index goes to the zero-result path. The retrieved outer element has a `0x38` stride.
- In the non-sentinel inner path, `0x37142ac` calls `0x4559a60` with the candidate pointer; the zero/nonzero result is converted to a boolean. Merged #5371 studies this helper's 32-byte ring-key search. In the sentinel path, the body walks nodes and calls the slot `0x64dfb50` with length `0x20`; the ELF identifies that slot as `memcmp`. Equality reaches `mov al, 1`, while exhausting the descent reaches zero.
- Missing outer selection calls `0x36dae30` with an on-stack `0x9b` word before returning zero. This packet does not characterize that helper's side effects.

These observations support a bounded **32-byte candidate membership** interpretation. “Signer”, “epoch”, and membership provenance are inferred from the caller context, not established solely by this function. The full selector construction, collection writers, ordering invariants, alternate entrypoints, helper semantics and the effect on quorum or authenticated state are not established here. No component gate is advanced.

## Reproduction

From repository root:

```sh
python3 research/work-items/RE-008-node115-signer-membership-lookup/verify.py
readelf -wf artifacts/node/115/hl-node | rg 'pc=00000000037141b0'
objdump -R artifacts/node/115/hl-node | rg '64e6ac0|64dfb50'
/usr/bin/objdump -d --x86-asm-syntax=intel --start-address=0x37141b0 --stop-address=0x371438a artifacts/node/115/hl-node
```

The verifier authenticates the target digest, checks nine selected byte anchors, resolves three direct-call displacements, and checks the indirect call's RIP-relative slot and unique relative relocation. It rejects nine single-byte mutations to the selected anchors. These checks do **not** independently prove the whole disassembly, the complete set of callers, FDE extent, dynamic aliasing or full target behavior. The retained raw disassembly is a review aid.

Prior work: merged #2594 identifies `0x371426b` as a caller of the outer wrapped-key search; merged #5371 studies the inner ring-key search `0x4559a60`; open #6053 identifies the vote-admission indirect call but explicitly leaves the slot target outside its scope. This packet connects that call to the selected wrapper and its two inner branches. It claims no new behavior for those previously studied helpers.
