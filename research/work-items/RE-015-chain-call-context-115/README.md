# RE-015: map key at one node #115 chain-codec caller

- Component: `constants`; one bounded caller-context question under RE-015.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source/reference revision: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no inferred reference source was read or copied.
- Claim status: **observation** — target bytes show one direct call to codec entry `0x2674b80`, a RIP-relative 16-byte literal load, and the preceding MessagePack string marker. **Inference / unresolved** — source type, struct owner, the other 16-call sites, and protocol-level meaning.
- Bounded question: what literal key is appended before one direct call to the reconstructed chain-name serializer?
- Scope: caller site `0x24062c7`, the branch and data references in its containing FDE, and the referenced read-only literal. No complete caller census or source attribution.

## Reproduce

From the repository root, with Python 3.10+ and the pinned artifact present:

```sh
python3 tools/re015_chain_call_context_115.py --out research/work-items/RE-015-chain-call-context-115
python3 -m unittest tests.test_re015_chain_call_context_115
python3 research/work-items/RE-015-chain-call-context-115/verify.py
PATH="/opt/homebrew/opt/binutils/bin:$PATH" objdump -d -w --start-address=0x240627b --stop-address=0x24062cc artifacts/node/115/hl-node
```

Observed environment: Python 3.14.3 and GNU objdump 2.47.20260726. The producer authenticates the full target digest before parsing ELF sections, checks every listed instruction encoding, decodes the RIP-relative displacement to the exact `.rodata` address, and verifies one containing FDE. It reads bytes only; no captured code is executed and no network is used. The records are deterministic.

## Evidence and results

All addresses are original ELF virtual addresses. On the path where the byte at `[r14+0x1b]` equals 1, the caller appends `0xb0`, loads 16 bytes from `.rodata` VA `0x455a90`, stores those bytes into the same output vector, and then calls `0x2674b80` at `0x24062c7`. The literal bytes are `68797065726c6971756964436861696e`, ASCII `hyperliquidChain`. `0xb0` is the MessagePack fixstr marker for a 16-byte string. The call site lies in FDE `[0x2406120,0x24064e4)`.

This is one caller-context observation that narrows the earlier chain-codec caller question. It does not establish a Rust struct name, external protocol semantics, or what the serializer means to the owning type. Other direct callers and their key literals remain unresolved. No Rust implementation or component gate is claimed; no progress gate is requested.

Next question: map the remaining chain serializer call sites to their literal keys without treating FDE ranges as source-function names.
