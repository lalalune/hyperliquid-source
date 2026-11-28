# RE-017 #115 loader binds the rolling state to a separate exact-height row

The source of the snapshot payload matters for #115 checkpoint restore. The selected loader decodes the same rolling state path used by the native writer, yet supplies a separately chosen height-keyed row to the materializer. The [state-load chain](../RE-016-state-load-chain-115/README.md) treats both sources as stubs. The [writer-path packet](../RE-008-periodic-state-path-115/README.md) identifies the writer's name. This packet joins them at the selected restore calls and shows which height binds the inputs.

Target Linux x86-64 node #115 with SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Selected input joins

| Input | Observed source and destination |
| --- | --- |
| Requested height | Caller field `+0x18` becomes the third argument of `0x4468c20` through call `0x3c12847`. This helper obtains already discovered 32-byte rows from `0x4468e30`. It selects the first row whose fourth word equals that request and whose first word differs from `0x8000000000000000`; a first word of zero still qualifies. It returns the four selected words. The [discovery packet](../RE-009-node115-latest-checkpoint-markers/README.md) covers the provider's file markers. |
| Rolling state path | Call `0x3c12877` supplies the name record at `0x6476768` to `0x38dbd80`. Its relocation and length name `abci_state`. The helper uses the configured root from slot `0x64e0918` and renders `{root}/hyperliquid_data/abci_state.rmp`. The loader passes the formatted pointer and length through boundary `0x3c13520` into the parser at `0x422e410`. |
| Materializer handoff | On the selected successful return, `0x3c13587..0x3c135c2` preserves the row in a separate stack argument and passes the parser-returned state pointer to the builder. Its `0x3c13665` call forwards those inputs to `0x3c2e860`. The [materializer packet](../RE-016-state-materialize-3c2e860-115/README.md) identifies a copied prefix covering the height at state `+0x28`. The loader later compares that height with the requested height at `0x3c128d4`. |

The selected writer at `0x5485ae0` supplies a second name record for the same 10-byte string to `0x5942870`. Both pathname helpers use the same rooted template and extension-selection layout. The two pairs of display callbacks lead to the same format-write slot after loading identical argument offsets. The verifier masks only their four-byte displacement to that shared slot for each pair. It also authenticates the two root-relative templates, suffix bytes and original selector instructions. Matching an independently captured `periodic_abci_states/.../<H>.rmp` filename to H cannot establish that both native inputs were present. A restore fixture also needs the corresponding row accepted by the native discovery path. This conclusion applies to the selected loader and its normal materializer route. The packet does not establish a successful read from a real archive, complete restore, or state-root equality.

## Reproduce offline

From repository root:

```sh
python3 -B research/work-items/RE-017-node115-restore-input-pair/verify.py
```

The verifier reads pinned ELF bytes, checks relative call bindings and selected call and branch edges, and tests the materializer input pairing with seven synthetic cases. Inputs cover a stale rolling state, a missing exact-height row, a same-height inactive row, a zero-capacity first match, ordered duplicates and literal preservation of the configured root separator. See the [instruction windows](instructions.tsv) and [offline log](offline-log.txt).
