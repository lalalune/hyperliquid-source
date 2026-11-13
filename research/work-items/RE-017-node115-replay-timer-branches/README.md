# RE-017: selected replay tracker timer comparisons

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This packet traces selected comparison branches in FDE `0x51520f0..0x51528fb`, upstream of the digest extraction described in merged #5157. It does not execute captured code.

## Selected observations

- The selected traversal reads a qword key at `0x5152177`, a 12-byte per-entry value at `0x5152191..0x51521a2`, a pointer to a three-dword comparison value from the callback context, and an f64 from a separate context pointer. It passes the f64 to slot `0x64e0f70`, then uses slots `0x64e0f78` and `0x64e0aa0` during the selected threshold construction. The target's relative relocations bind those slots to `0x15ed960`, `0x162a9a0` and `0x16290d0`, respectively. The helper bodies and their full input domains are boundaries here.
- At `0x51522ca..0x5152315`, the selected code compares the three dwords at the context pointer against three constructed or fallback dwords. The first comparison uses signed `setge`; the next two use unsigned `setae`/`jb` conditions. On the selected greater-or-equal route it reaches `0x515259e`, loads the saved key, and calls `0x5377df0`. #5157 documents the subsequent selected digest extraction; this packet does not claim that extraction always succeeds.
- When the first comparison takes its earlier-than branch, the body constructs another threshold using the exact target bytes for f64 `60.0` at `0x459718`, with the same three slots. The comparison at `0x5152474..0x5152493` again selects between proceeding and the traversal continuation. On its selected greater-or-equal route, `0x5152495..0x51524a8` compares qwords loaded through context pointers `+0x28` and `+0x30`; the unsigned-below outcome branches to `0x515269d`. This packet does not infer the owners or meaning of those qwords or claim that the second branch invokes digest extraction.
- Both threshold constructions have fallback routes that load dwords at `0x4679d0`, `0x4679d4` and `0x4679d8` after selected range checks or a zero helper result. The reason for fallback and the complete arithmetic/overflow contract are not established here.

The labels “entry”, “threshold” and “timer” are interpretations of the observed layout, the selected `60.0` constant, and #5157's caller context. The helper semantics, tuple units, timestamp provenance, all other branches, actual callback scheduling and runtime reachability remain open. In particular, a value comparison is not a proof of consensus finality, authentication or state-root correctness. The FDE listing does not establish complete function ownership. No node completion gate is advanced.

## Reproduce

```sh
python3 research/work-items/RE-017-node115-replay-timer-branches/verify.py
readelf -wf artifacts/node/115/hl-node | rg 'pc=00000000051520f0'
readelf -rW artifacts/node/115/hl-node | rg '00000000064e0f70|00000000064e0f78|00000000064e0aa0'
/usr/bin/objdump -d --x86-asm-syntax=intel --start-address=0x51520f0 --stop-address=0x51528fb artifacts/node/115/hl-node
```

The verifier authenticates the target SHA-256, checks fifteen selected byte anchors including the f64 bytes, resolves the direct digest-extraction call and six selected indirect call slots with their three unique relative relocations, and rejects fifteen single-byte anchor mutations. FDE inspection is independent. The verifier does not prove complete control flow, helper semantics, tuple interpretation or runtime behavior. Merged #5157 leaves timer eligibility open; open #6048 studies a related but different `0x51515f0` extraction loop.
