# RE-001: node #115 checked-read32 caller result wrapping

- Component: foundation / serialization boundary; one bounded caller-flow packet.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source/reference revision: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no inferred source was read or copied.
- Claim status: **observation** — call site `0x4e182ed`, its containing FDE, the local output buffer, the tag comparison, and how the caller moves 32-byte windows into its output. **Unresolved** — source names, the caller-of-caller input domain, and whether every copied byte is initialized for every helper result.
- Bounded question: how does one #115 caller wrap the result of the existing checked-read32 leaf?
- Scope: one direct call to `0x5821430` in `[0x4e182e0,0x4e18353)`, plus the local tag test and return-output construction. This is not a complete call graph.

## Reproduce

From repository root with Python 3.10+ and the pinned artifact materialized:

```sh
python3 tools/re001_checked_read32_caller_output_115.py --out research/work-items/RE-001-node115-checked-read32-caller-result
python3 -m unittest tests.test_re001_checked_read32_caller_output_115
python3 research/work-items/RE-001-node115-checked-read32-caller-result/verify.py
PATH="/opt/homebrew/opt/binutils/bin:$PATH" objdump -d -w --start-address=0x4e182e0 --stop-address=0x4e18353 artifacts/node/115/hl-node
```

Observed tools: Python 3.14.3 and GNU objdump 2.47.20260726. The producer authenticates the complete target digest, verifies exact instruction bytes and the direct-call destination, and checks one containing FDE. It reads data only; no captured code is executed and no network is used.

## Evidence and results

The call passes a 40-byte local output area at `rsp+0x28` in `rdi`; `rsi` and `rdx` pass through unchanged. The caller tests its first byte. If that byte is 1, the caller writes outer tag 1 and moves 32 bytes from helper-output offsets `[8,40)` to outer-output offsets `[8,40)`. For any other byte, it writes outer tag 0 and moves helper-output offsets `[1,33)` to outer-output offsets `[1,33)`. The copy instructions and exact branches are retained in the tool's byte whitelist and reproduced by `records.json`.

The existing checked-read32 leaf packet records its own output writes, but this caller packet does not claim that every byte in either copied window is initialized on every return. It also does not identify the caller's source type or input construction. No Rust implementation or component gate is claimed; no progress gate is requested.

Next question: bind the incoming `rsi`/`rdx` state at the nearest caller before assigning a source-level input domain.
