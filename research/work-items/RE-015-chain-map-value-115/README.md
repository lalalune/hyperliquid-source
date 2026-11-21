# RE-015: bind the `hyperliquidChain` output value to a node #115 tag byte

- Component: `constants`; bounded follow-up to the RE-015 chain-name codec and caller-context packets.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source revision: `8f8a38d0d44f0c41a94aa156bb4274777f20fd4d`.
- Question: on one path that emits the MessagePack map key `hyperliquidChain`, what input supplies the serialized chain name, and how do the observed tag bytes map to names?
- Claim status: instruction bytes, FDE bounds, call target, key bytes and tag dispatch are target observations. The MessagePack field interpretation and tag-to-name labels follow the separately verified chain-codec evidence. Struct ownership and runtime meaning remain open.

## Evidence

At VA `0x240627b`, the caller compares byte `[r14+0x1b]` with 1. If equal, it writes fixstr marker `0xb0` and appends the 16 bytes at `.rodata` VA `0x455a90` (`hyperliquidChain`). If unequal, the `jne` at `0x2406280` skips only that key prefix and branches to `0x24062c1`. The key path's capacity branches at `0x240628c` and `0x24062a8` lead to the two retained fallback spans. Both key-present and key-omitted paths then reach serializer `0x2674b80` at `0x24062c7`.

At `0x2406277`, the caller sets `rsi = r15 + 0x30`. On the gate-unequal path, the branch joins serializer setup at `0x24062c1`; the intervening instructions do not overwrite `rsi`. On the key-writing path, the two vector-capacity fallback arms at `0x2406440` and `0x240646d` save `rsi` in `r13`, call the same helper at `0x231e050`, restore `rsi`, and return to the relevant write step. The retained instruction spans bind both save/restore pairs, helper targets and rejoin branches. This supports the pointer flow on the recorded normal-return paths; it does not prove helper failure behavior. The called serializer reads the first byte at `[rsi]` at `0x2674b87` and dispatches its four-entry table. The existing `RE-015-chain-codec-115` packet independently validates the target serializer and reconstructs tag bytes `0..3` as `Local`, `Sandbox`, `Testnet`, and `Mainnet`; this packet runs that target-bound verifier before reusing its mapping.

Therefore, on the gate-equal path, the bytes for `hyperliquidChain` immediately precede serialization of the one-byte selector at `r15+0x30`. The serializer call also occurs on the unequal path, where this key prefix is absent; the later meaning of that output is not established here. The codec maps byte values 0 through 3 to the listed names; inputs outside that range are not claimed. This connects a concrete output key to a concrete value source on one path. It does not prove what owns `r15`, why the gate is set, or whether these names identify current live networks.

## Reproduction

From the repository root with the pinned artifact present:

```sh
python3 tools/re015_chain_map_value_115.py --out research/work-items/RE-015-chain-map-value-115
python3 -m unittest tests.test_re015_chain_map_value_115 -v
python3 research/work-items/RE-015-chain-map-value-115/verify.py
PATH="/opt/homebrew/opt/binutils/bin:$PATH" objdump -d -w --start-address=0x2406120 --stop-address=0x24064e4 artifacts/node/115/hl-node
PATH="/opt/homebrew/opt/binutils/bin:$PATH" objdump -d -w --start-address=0x2674b80 --stop-address=0x2674d80 artifacts/node/115/hl-node
```

The producer authenticates the full file hash, derives file offsets from ELF section headers, verifies exact instruction spans and the unique FDE containing the call, verifies that the unequal branch joins at serializer setup, and checks the target-derived tag mapping against the full chain-codec packet. It only reads the captured binary; it does not execute or emulate it.

Observed locally on Darwin arm64 with Python 3.14.3 and GNU binutils 2.47.20260726: the producer, focused 3-test module, packet verifier, `make catalogue-check`, and `git diff --check` pass. `make doctor` reports `analysis_ready: true`. Repository `make verify` and `make reproduce` stop at artifact verification because this checkout's uninitialized `upstream/node` submodule lacks pinned `pub_key.asc`; other checked artifact digests and signatures pass. The full `make test` suite was not run.

## Results and limitations

- One field path in FDE `[0x2406120,0x24064e4)` is bound from gate, key and value pointer through the serializer call.
- Both the key-present and key-omitted paths reach the value serializer. Two capacity fallback arms preserve the input pointer on their observed normal-return paths.
- Four codec tag values are linked to their exact emitted names using the already validated codec packet.
- The origin and owner of `r15+0x30`, the source-level purpose of `[r14+0x1b]`, other serializer callers, and any relationship to the separate global selector at `0x46f3fc0` remain unproven.
- The capacity fallback facts assume the helper returns normally; its failure behavior is outside scope.
- No component gate or live network behavior is claimed.
