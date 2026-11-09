# RE-001: node #115 raw-tag-3 selector-to-consumer handoff

- Component ID: `constants` / #3909, bounded selector and consumer dataflow
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: `0781ce04826eeefd89fe336cb8ea073be0c1de30`
- Claim status: observed instruction flow and RELATIVE relocation targets; generic once-helper runtime semantics unresolved
- Scope: distinguish selector raw tag 3's payload from the special raw-tag-3 consumer path and trace their static handoff into the same 20-byte lookup loop

All code/data addresses below are ELF virtual addresses. `records.json` also stores the corresponding file offset for every retained code window. No captured instructions were executed or emulated.

## Result

Merged [#4231](https://github.com/lalalune/hyperliquid-source/pull/4231) traced selector raw tag 1 and noted that consumer raw tag 3 takes a separate special path. This packet resolves that distinction without assigning a chain name or treating the two global cells as interchangeable. The current open #4336 contribution maps the separate static-config name path; this packet does not overlap its functions or evidence.

At selector `0x46f3fc0`, the signed relative jump-table entry at `0x7d92e0` (table base `0x7d92d4`, index 3) targets `0x46f3ff0`. That arm uses state dword `0x64fdb48` and payload slot `0x64fdb30`. The slot's ELF `R_X86_64_RELATIVE` relocation initially targets `0x46e83c0`, the selected tag-3 initializer already bounded as a target in #4231.

The raw-tag-3 special case in consumer `0x3c377b0` does not call the selector through `0x64e5be8`. It uses a separate once-state at `0x64fdba8` and gives the once helper at `0x64df9f0` a pointer to a local cell seeded with the address of payload slot `0x64fdb90`. The initial RELATIVE relocation for `0x64fdb90` targets wrapper `0x46e7ec0`. That wrapper reads the selector-tag-3 state and payload (`0x64fdb48` and `0x64fdb30`), plus the adjacent word at `0x64fdb38`, and passes the payload and adjacent word to `0x391c6a0` before constructing its return object.

After the consumer's lazy-init call, a non-null payload joins at `0x3c37809`. The shared lookup reads the root's height and performs a 20-byte comparison through slot `0x64dfb50`; this is the same comparison boundary used by the already mapped search path. The lookup result remains only a membership-dependent policy input: downstream calls and named-chain meaning are not established here.

The static evidence therefore connects the special consumer path to the selector-tag-3 payload through a separate wrapper and separate once-state. It does not prove generic once-helper scheduling, publication ordering/concurrency, the wrapper's full object contract, or the meaning of the embedded keys. In particular, `0x64fdb90` is not the selector payload slot `0x64fdb30`.

## Reproduce

From the repository root, using an isolated Python environment and Capstone 5.0.7:

```sh
python3 -m venv /tmp/hl115-capstone-venv
/tmp/hl115-capstone-venv/bin/python -m pip install capstone==5.0.7
/tmp/hl115-capstone-venv/bin/python research/work-items/RE-001-node115-tag3-consumer-handoff/verify.py
```

The verifier checks the target digest, five instruction windows (712 bytes, 158 instructions), enclosing FDE extents, the raw tag-3 jump-table word, both RELATIVE targets, and 18 instruction/dataflow facts. Six in-memory semantic corruptions are rejected, including changes to the selector arm, wrapper/state references, comparator width, and either relocation. The corruption checks bypass the global digest/window comparison and exercise the semantic assertions directly.

Observed local checks: `make verify` passed after restoring the six pinned submodules; the artifact verifier confirmed the #115 and visor hashes/signatures and all 32 imported files. The focused packet verifier passed with Capstone 5.0.7. `make doctor` reports `analysis_ready=false` because GNU `objdump` and `readelf` are absent; Apple `objdump` supplied the displayed disassembly, while ELF/FDE/RELA checks use the repository's Python parsers. Repository-wide `make test` was not run because its unfiltered discovery includes a captured-instruction emulator, outside this task's authorization. No repository implementation, catalogue, or acceptance gate is changed.

## Limits and next question

This is a partial RE-001 packet for #3909, not a complete constants or consumer reconstruction. It does not infer any key's domain, prove authorization semantics, assign source-level names, or claim a runtime memory layout beyond the observed offsets and branches. The next bounded question is whether the wrapper result layout at `0x46e7ec0` is consumed exactly as the root/height pair read at `0x3c37809`; that requires tracing the wrapper's selected helper contract and remains open.
