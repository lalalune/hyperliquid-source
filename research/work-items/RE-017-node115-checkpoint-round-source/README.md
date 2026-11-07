# RE-017 · Node #115 checkpoint round source

- Component: ABCI checkpoint restore and initial replay.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. The authenticated ELF is the only binary input.

The selected MessagePack checkpoint map reads `exchange.locus.ctx.round` (alias `consensus_round`) independently of `exchange.locus.ctx.height`. The selected decoder writes the former to result `+0x30` and the latter to `+0x28`. The materializer copies both words into the loaded state at the same offsets. The loader checks the decoded height against the request and copies the decoded round into `+0x20`. There is no conversion from height to round along this path.

## Field writes

- Both round spellings classify as field 4. The relative entry at `0x68ac5c` selects `0x30d22ae`. A seen flag of 1 branches to the duplicate path at `0x30d3ad6`. Otherwise call `0x30d22c5` obtains a result at `rsp+0x50`. Tag 9 stages the returned qword at `rsp+0xd8` and sets the seen flag. A different tag branches away before either write.
- On the selected map completion with height present, `0x30d2ef0` through `0x30d2f00` select that round qword or zero when the round flag is clear. The store at `0x30d31be` writes it to result `+0x30`.
- Field 2 is `height`. Its selected decode at `0x30d2be9` stages the value separately at `rsp+0x198` on tag 9. The completed map writes that qword to result `+0x28` at `0x30d31ba`. The earlier [binary context packet](../RE-009-abci-binary-context-115/README.md) pins the names, selectors, height scalar and missing-field paths.

## Transfer into the loaded state

The copy arithmetic below covers two neighboring qwords on one selected successful map path. Stack offsets are local to each callee. All instruction addresses are linked ELF VAs.

| Boundary | Pair transfer |
| --- | --- |
| Locus reader | Context child result starts at `rsp+0xc70`. Its 16-byte pair at `rsp+0xc98` moves to `+0x480`, `+0x520`, then `+0x3810`. The `0xa10`-byte copy writes it at `+0x1c98`. The `0xba0`-byte return copy starts at `+0x1c70`, retaining the pair at output `+0x28/+0x30`. |
| Exchange reader | The pair at child stack `+0xb60` moves through `+0x1f40` into `+0x4b60`, which is `+0x28` relative to the aggregate at `+0x4b38`. The selected `0xba0` copies preserve its position in the aggregate before the final `0x10e8`-byte output copy. |
| Wrapper and outer decoder | The pair at wrapper `+0x4088` moves to `+0x9820`, relative `+0x28` to `+0x97f8`. The selected `0x27a8`-byte copies carry it to the outer child output and then the allocated result. On the selected return, tag 9 and that pointer reach the reader at `0x422e6af` and `0x422e6b6`. |
| Reader and Location wrapper | The reader returns tag 0 in RAX and the allocated pointer in RDX. Wrapper `0x3c13520` takes the non-1 arm and passes that RDX as RDI to the materializer at `0x3c135c2`. Its relative slot resolves to `0x3c13610`. |
| Materializer | `0x3c13665` calls slot `0x64e9630` with stack output and the decoded input pointer. At `0x3c2f00a`, the resolved callee copies `0xba0` bytes from the input base to the output base. On non-null allocation, `0x3c13689` copies the constructed `0x42c8` bytes into the allocation that `0x3c1369f` returns. This is the selected writer of loaded-state `+0x30`. |
| Loader | Wrapper returns tag 0 and the materialized pointer. Loader `0x3c12800` compares state `+0x28` to the request and rejects a mismatch at `0x3c128d7`. On the accepted arm it reads `+0x30` and copies it to `+0x20`. Its increment is on another qword at `+0x18`. |

This gives the upstream source for the selected replay capture in #3988. The existing [begin-path packet](../RE-017-abci-preflight-result-115/README.md) independently shows that later block processing increments height at `+0x28` and stores an input word into `+0x30`. The static result is that restore uses the serialized round, with zero on the selected missing-round branch. A numerical rule such as round = H or H + 1 cannot be assumed from this restore path. Real fixture values and any protocol constraints on the serialized pair remain outside this packet.

The join assumes the selected normal returns, ordinary `memcpy` binding, valid nonoverlapping buffers and no intervening alias writes. The result identifies the two words at the loader boundary. It does not extend to every checkpoint format, every startup arm, the first queue slot, or state-root equality. No progress gate is requested.

## Reproduce

From the repository root with authenticated inputs, GNU objdump and LLVM objdump available:

```sh
python3 research/work-items/RE-017-node115-checkpoint-round-source/reproduce.py --check
python3 -m unittest tests.test_abci_binary_context115 tests.test_abci_state_read115 tests.test_abci_loader_handoff115
make verify catalogue-check
```

[Selected instruction bytes](instructions.tsv) include linked addresses, file offsets, indexed unwind extents and GNU Intel-syntax decode. The collector checks both decoders against the original bytes, reuses the context key interpreter, and checks the field-table targets and materializer call displacements and relocations. Observed with GNU objdump 2.45 and LLVM objdump 23.1.4. FDE bounds identify unwind extents. No node binary was executed.
