# RE-017: 32-byte projection before candidate ordering

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This static packet follows `0x5b81970`, which open #6615 identifies as the helper called before the selected candidate preparation paths. No target code is executed.

## Observed flow

- Caller `0x53485b0` passes a local copy of its input descriptor to `0x5b81970` at `0x53485fa`. On return, it examines the output word at caller stack `+0x28`; #6615 records its later zero, one, 2–20 and larger-count paths.
- In the selected input representation, descriptor tag `2` uses two pointer spans. Each nonempty step advances the current pointer by `0x68`; on exhausting one span, the body switches to the other. For a different tag, it instead calls `0x51373b0`; the latter helper's layout and behavior are not inferred here.
- For each non-null selected pointer in either path, the helper loads two 16-byte chunks at offsets `+0x00` and `+0x10`. It writes these 32 bytes to an output buffer whose append offset increases by `0x20`. Buffer growth uses `0x5963a10`; this packet does not recover that helper's contract.
- When no element is available initially, the output triple is `{0, 1, 0}`. Otherwise, the returned triple contains the accumulated descriptor and count. These are observed words, not a validated Rust type or ownership guarantee.
- The pinned ELF records FDE interval `0x5b81970..0x5b81cb8`. Its disassembly is retained for review. FDE bounds do not establish complete function ownership, all call paths or runtime reachability.

“Element”, “span”, “projection” and “count” are interpretations of visible pointer arithmetic and register use. This packet does not prove that the first 32 bytes are a signer key, digest, authenticated value or complete identity; it does not establish ordering, uniqueness, failure semantics or predicate correctness. No component gate is advanced.

## Reproduce

```sh
python3 research/work-items/RE-017-node115-candidate-key-extract/verify.py
readelf -wf artifacts/node/115/hl-node | rg 'pc=0000000005b81970'
/usr/bin/objdump -d --x86-asm-syntax=intel --start-address=0x5b81970 --stop-address=0x5b81cb8 artifacts/node/115/hl-node
```

The verifier authenticates the target SHA-256, checks thirteen selected instruction anchors and four direct-call targets, and rejects thirteen single-byte anchor mutations. These selected checks do not establish full CFG, iterator invariants, allocator semantics or dynamic equivalence. #6615 records this helper as an unresolved boundary; #6616 and #6617 address later small- and large-count paths, not this projection.
