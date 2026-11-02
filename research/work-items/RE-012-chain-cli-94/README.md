# RE-012: node94 chain and selected-command construction

This partial `node-runtime` reconstruction resolves how the parsed CLI state is
turned into a chain byte, an optional owned key, and one of fourteen selected
commands. It binds exact names, field offsets, helper calls and failure order to
two complete function bodies: `[0x4578bd0,0x4578e2a)` and
`[0x4583030,0x4583f52)`, 4,476 bytes / 1,027 instructions.

The first output qword is not a simple fourteen-member command numbering:
`change-validator-profile` stores **0 or 1 according to the presence of
`commission-bps`**. The other successful paths store 2 through 13 or 15;
unmatched names and missing child arguments store 16. The chain wrapper rejects
16 before copying the command result. Its caller copies 152 bytes, including
inactive payload and padding bytes that this packet does not treat as a
deterministic serialized object.

- Target: Linux x86-64 node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Initial qualification base: `e5c9b6436876b2a4a39daef813171f9879317699`.
  Rebased qualification base: `2c75904241b9165693d40dea8b0d0d340f8e22b3`.
  Results for the two bases are separate in `validation.json`. Linked ELF
  virtual addresses, exclusive ends; no guessed runtime load base.
- Primary observations and conditional interpretation: [CONTRACT.md](CONTRACT.md).
  Exact bytes, CIE/FDEs, instructions, options, stores, calls, RIP references and
  relocation writers: [records.json](records.json).
- Eleven complete FDE exports cover 6,458 bytes / 1,566 instructions, including
  caller and adapter context. This is a decoded-evidence denominator, not
  reconstructed code coverage or an attribution of every instruction to private
  first-party source. All 80,300 RELA records are scanned for duplicate writers.
- [scope-review.json](scope-review.json) records the 638-open / 50-recently-merged
  PR snapshot check. [PR #1748](https://github.com/lalalune/hyperliquid-source/pull/1748)
  covered output configuration `[0x4579310,0x457acef)` and its packet is now on
  the rebased main; that body is excluded here.
  Shared lookup helpers are context, not a new ownership claim.

The existing [startup inventory](../hl-node-startup-inventory-94/README.md)
located `hl_node.rs` Locations and selected literals but did not establish this
command map, option ordering, chain tags or output initialization boundary.
The small dedicated extractor is necessary to bind those newly interpreted
instructions and constants; the existing inventory does not extract the
19-entry length table, split name comparisons or output stores. No general
tooling changes, gate changes or generated progress edits are made.

## Reproduce

From the repository root with the authentic artifact, Python 3.14.3,
Capstone 5.0.7, GNU objdump 2.47.20260726 and Apple LLVM 17 objdump:

```sh
export PATH=/opt/homebrew/opt/binutils/bin:$PATH
export LLVM_OBJDUMP=/usr/bin/objdump
python3 -B tools/chain_cli_static.py --check
python3 -B tests/test_chain_cli_static.py -v
python3 -O -B tests/test_chain_cli_static.py -v
python3 -O -B research/work-items/RE-012-chain-cli-94/verify.py
python3 -O -B research/work-items/RE-012-chain-cli-94/verify.py \
  --native-output work/chain-cli-recheck
```

The last command runs installed disassemblers on a private authenticated file
snapshot, **not the captured program**. Both providers' instruction bytes and
boundaries must equal Capstone and all retained exports. The only text
normalization replaces the temporary snapshot path with
`<authenticated-node94>`; no instruction, address, symbol, operand or relocation
is normalized. `native-commands.json` records every export command and hash.

`verify.py` authenticates an exact manifest inventory, regenerates target facts,
checks all 22 native exports, and losslessly decodes/hash-checks the raw stream
archive. The archive retains initial environment failure, recovery and focused
check output. [validation.json](validation.json) gives actual local outcomes and
their scope. No full-suite-on-this-head, hosted CI or Linux runtime pass is
claimed; the parent runs the shared baseline separately.

Historical environment logs contain local paths. Their published copies replace
only home, checkout and temporary-directory paths; each archive row records the
published hash and original hash separately. Original bytes remain in ignored
`work/chain-cli-research/`. The archive is lossless for its published payloads;
it does not pretend the sanitized environment logs are byte-identical originals.
No target instruction/data bytes are altered by that sanitation.

## Evidence status

No original executable or emulator was run. There is no Rust implementation,
new compiler output, native behavioral corpus, byte-equality comparison to
reconstructed code, or whole-node build here. Static decoders independently
check bytes, not high-level semantics. The corruption controls test evidence
bindings, not a substitute for end-to-end CLI behavior.

New analysis and documentation are independently authored MIT work. The target
and its disassembly remain evidence with their existing rights. No inferred
can1357 source was read or copied for this contribution. Embedded
`/home/ubuntu/hl/code_Mainnet/node/src/hl_node.rs` paths are target provenance,
not public source or a grant to claim recovered source ownership. Attribution:
OpenAI / gpt-6-astra / Codex 0.166.0, as supplied by the coordinating session.

The remaining bounded question is the preceding CLI builder/parser's actual
defaults and value-conversion contract; until those are closed, these selected
name/value paths do not define the complete accepted command-line grammar.
