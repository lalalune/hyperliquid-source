# RE-015: two key literals at all direct node #115 chain-serializer callers

- Component ID: `constants` (`RE-015`, `#115 literal and data xrefs`).
- Target release and SHA-256: node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source/reference revision: repository `8f8a38d0d44f0c41a94aa156bb4274777f20fd4d`; no inferred source was read or copied.
- Claim status: **observation** — each of 52 direct calls to the three existing chain-name serializer entries has the same verified 49-byte path prefix: write MessagePack marker `0xb0`, check capacity, load and store the 16-byte `hyperliquidChain` literal, update the output cursor, set serializer arguments, then reach the direct call. Each containing FDE also contains a matching load/store-opcode reference to the 16-byte `signatureChainId` literal. **Unresolved** — source function/type ownership, capacity-fallback behavior, runtime use, and protocol meaning.
- Bounded question: do all direct node #115 callers of the three reconstructed chain-name serializer copies write the `hyperliquidChain` key immediately before invoking the serializer?
- Scope: caller FDEs from `RE-015-chain-local-callers-115`; exact raw bytes from each key marker through serializer argument setup, plus two read-only literal references. FDE boundaries are unwind-record containment evidence only, not validated source routine identities.

## Reproduce

From repository root, Python 3.10+:

```sh
python3 tools/re015_chain_key_context_115.py --out research/work-items/RE-015-chain-key-context-115
python3 -m unittest tests.test_re015_chain_key_context_115 -v
python3 research/work-items/RE-015-chain-key-context-115/verify.py
```

## Validation

Observed environment: macOS arm64, Python 3.14.3, GNU Binutils 2.47.20260726.
On repository revision `8f8a38d0d44f0c41a94aa156bb4274777f20fd4d`, the focused
two-test suite, packet verifier, deterministic collector comparison, and
`PATH=/opt/homebrew/opt/binutils/bin:$PATH make catalogue-check` passed. The
repository's `make doctor` passed with that PATH and reported analysis tools
ready; exact rebuild remains unavailable by design because reconstruction
inputs are incomplete. `PATH=/opt/homebrew/opt/binutils/bin:$PATH make verify`
could not complete because this checkout lacks `upstream/node/pub_key.asc`;
the retained artifact hashes and signatures passed. The full local
`make test` run was interrupted at test file 23 of 1,562, so no local
full-suite result is claimed. The hosted PR workflow is the full-suite gate.

The producer authenticates the full artifact digest, reuses the exhaustive direct-call/FDE census, parses the file-backed `.text` and `.rodata` sections, and calculates each RIP-relative destination from the raw signed displacement. It requires one exact load/store-opcode sequence for each literal inside every containing FDE. For `hyperliquidChain`, it additionally verifies 49 exact bytes from the `0xb0` marker through the capacity branch, key write, output-cursor update, and serializer argument setup. The direct-call census verifies the call instruction and destination. No captured code is executed and no network is used. Records use original ELF virtual addresses. The literals are the exact 16-byte spans at `0x455050` and `0x455a90`; no null terminator is assumed.

## Evidence

The pinned target bytes at `.rodata` VA `0x455050` are `7369676e6174757265436861696e4964` (`signatureChainId`); at `0x455a90` they are `68797065726c6971756964436861696e` (`hyperliquidChain`). For every direct call site in the prior exhaustive census, its unique containing FDE has exactly one load/store-opcode sequence referencing each byte span. More specifically, the `hyperliquidChain` literal is at `call_site - 25`; each 49-byte prefix starts with `c6 04 02 b0`, includes the capacity comparison and conditional branch, writes the literal to the output buffer, advances the cursor by 16 bytes, and sets `rdi`/`rdx` for the direct serializer call. The conditional branch destination is retained and verified inside the same FDE. The census denominator is 52 direct call sites: 17 targeting serializer entry `0x2674b80`, 17 targeting `0x467f2d0`, and 18 targeting `0x57c1de0`. All are bound to the same full target SHA-256.

The observation narrows the prior one-caller `hyperliquidChain` context packet to all 52 direct callers and adds the second literal. The capacity branch may bypass this straight-line prefix; its destination is recorded but its fallback path is not analyzed. The evidence does not establish that FDEs correspond to distinct Rust functions or source owners, or that either label has any particular chain/network meaning. It does not establish equality with source code. Indirect calls, tail jumps and FDE-less code are outside this census. No reconstruction gate or runtime behavior is claimed.

No gate is requested. Next question: identify any independently supported caller ownership or upstream source mapping for these serialization contexts without using FDE labels as source names.
