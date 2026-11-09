# RE-012: node115 CLI parser calls from the entry callback

This packet closes one static call-chain gap between the node #115 entry callback and the existing CLI parser evidence. It shows that the callback reaches an executor which calls the CLI builder and config extractor through relocated slots, and that the config extractor calls the selected-command extractor. It does not map a command choice to a service, file write, or persistent effect.

- Component: `node-runtime`; task: `RE-012`.
- Bounded question: does the entry callback's selected executor path statically invoke the already studied CLI parsing helpers?
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: linked ELF virtual addresses before load bias.
- Source/reference revisions: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no external source was used.
- Provider/model/client: OpenAI / GPT-6 / Codex CLI 0.167.0.

## Observations

The unwind-described interval at `0x2cd8370..0x2cd83af` contains a direct call at `0x2cd83a2` to `0x2ae1690`. The interval at `0x2ae1690..0x2ae27b2` contains a direct call at `0x2ae1a47` to `0x2ae41e0`.

Within `0x2ae41e0..0x2ae6d66`, calls at `0x2ae42f5` and `0x2ae437a` use RIP-relative indirect slots `0x64e73c0` and `0x64e73c8`. Their `.rela.dyn` records have type 8 (`R_X86_64_RELATIVE`) and addends `0x564d700` (the CLI builder) and `0x564cce0` (the config extractor), respectively. The config extractor interval `0x564cce0..0x564cf36` calls through slot `0x64ebcb0`; its type-8 relative relocation has addend `0x5654bf0`, the selected-command extractor.

At executor entry, a byte at input offset `0x21a` is loaded and used to index a 16-entry relative jump table at `0x6040e4`; the verifier checks the load, indexed relative read, indirect jump, and every resolved entry. The existing [RE-012 command contract](../RE-012-cli-config-115/CONTRACT.md) assigns tags 2 and 3 to `run-non-validator` and `run-validator`. This packet does **not** establish that those tags are the input byte used by this dispatch table: the dataflow between parser output and that byte remains unresolved. The main callback call site is retained as context in [RE-017](../RE-017-entry-checkpoint-115/transfers.tsv); this packet independently verifies those bytes against the authenticated artifact.

FDE extents are unwind records, not proof of source-function boundaries. These call and relocation observations establish static references only; they do not prove runtime reachability, command-specific service startup, file I/O, or persistence. The captured binary was never executed or emulated.

## Reproduction

From the repository root, run:

```sh
python3 research/work-items/RE-012-node115-cli-execution-dispatch/verify.py
```

The verifier authenticates the pinned artifact, recomputes the five selected FDE extents from `.eh_frame`, checks each direct/indirect call encoding and target, resolves the three relative relocations, validates the 16-entry dispatch table, and asserts a negative control that rejects an incorrect direct-call target.

Validation recorded for this packet:

- `make doctor`
- `make verify`
- `make test`
- `make catalogue-check`
- `python3 research/work-items/RE-012-node115-cli-execution-dispatch/verify.py`

Actual results are reported in the pull request; no hosted CI result is claimed here.

## Inference and remaining work

The entry callback's path reaches code that invokes the CLI builder and config extractor, and the extractor reaches the selected-command parser. The identity of the caller's input structure, the mapping from selected command to executor dispatch byte, downstream effects, and all command-specific startup behavior remain open. This partial result does not advance a component completion gate.
