# RE-005: identify the `SendToEvmWithData` d1 callback field

- **Component:** `action-wire`; bounded question under [issue #3912](https://github.com/lalalune/hyperliquid-source/issues/3912).
- **Target:** Linux x86-64 node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- **Source revision:** `ec87b0e812f363a43abaa26e6c9c4c808bf9a285`.
- **Claim status:** the callback-bearing payload field is identified as the `addressEncoding` enum by a crosswalk of target serializer order, field-name bytes, enum serializer, and the existing target-bound EIP-712 schema. The callback implementation and output semantics remain unresolved.
- **Scope:** identify the field at payload `+0x60` shared by the `0xd1` signing-method callback and action-payload serializer. No production digest, signature validation, or callback target is claimed.

## Reproduce

From the repository root, with Python 3.12+ and the pinned node #115 artifact:

```sh
python3 tools/action_wire_d1_address_encoding_115.py --out research/work-items/RE-005-node115-d1-address-encoding-bridge
python3 -m unittest tests.test_action_wire_d1_address_encoding_115 -v
sha256sum -c research/work-items/RE-005-node115-d1-address-encoding-bridge/MANIFEST.sha256
```

The collector hashes the complete ELF before reading it, parses `.eh_frame`, checks exact instruction and `.rodata` bytes, and reads the already verified typed-data schema row. It never executes or emulates the captured binary. The output includes the target digest, FDE ranges, raw byte witnesses, observations, inference, and unresolved items.

## Evidence

Addresses are ELF virtual addresses; `.text` and `.rodata` are read through their ELF section headers. The FDEs are unwind ranges, not source-level function boundaries.

1. The existing target-bound [`arms.tsv`](../RE-010-action-serialize-tag-dispatch-115/arms.tsv) maps `SendToEvmWithData` variant index 75 to payload serializer `0x240eef0`. That serializer processes `destinationRecipient` from payload words `+0x50/+0x58` at `0x240f185`; the target literal at `0x5ed61a` is `destinationRecipientaddressEncoding...`, and the explicit field-name length is 20 bytes.
2. The next field-value call at `0x240f20b` passes `payload+0x60` to `0x24580c0`. The next 15 bytes in the target literal are `addressEncoding`; the enum serializer's observed branch emits the 11-byte variant string `UnvalidatedBridgeEpoch` from `.rodata` `0x5f174d`.
3. The same payload offset `+0x60` is loaded as a function-object pointer by the `0xd1` signing method at `0x442d179`; its first qword is called with `payload+0x78`, `[payload+0x68]`, and `[payload+0x70]`. The method copies 32 returned bytes into its local record at `0x442d194`.
4. The existing target-bound builder record at [`action-wire-typed-data-structs-115/eip712.tsv`](../action-wire-typed-data-structs-115/eip712.tsv) identifies `address_encoding` as a `string` field immediately after `destination_recipient` and before `destination_chain_id`.

### Inference and limits

The serializer call order, contiguous target field-name bytes, enum variant serializer, and EIP-712 field order together identify payload `+0x60` as `addressEncoding` / `address_encoding`. This corrects the earlier unresolved field identity. Because the EIP-712 field type is `string`, a 32-byte string-hash callback is plausible; this packet does not prove that interpretation or a concrete output value.

Still unresolved: the callback/vtable target, the producer of the object at `+0x60`, whether its output equals the EIP-712 string hash of the selected enum variant, runtime values, production digest, signature verification, replay checks, and error ordering. This is a partial finding and does not advance any full-scope gate.

## Checks

- `python3 tools/action_wire_d1_address_encoding_115.py --out research/work-items/RE-005-node115-d1-address-encoding-bridge`: passed; target hash, three FDE ranges, instruction witnesses, literals, and schema crosswalk verified.
- `python3 -m unittest tests.test_action_wire_d1_address_encoding_115 -v`: passed, five tests including target identity and three byte-corruption controls.
- `make doctor`: `analysis_ready=true`; `exact_rebuild_ready=false`. The report identifies missing recovered Cargo manifests/lockfiles, exact build flags and fork provenance, and an accepted implementation/harness; Ghidra and Java are also unavailable in this environment.
- `make verify`: passed, including binary signatures, import checks, and evidence packet manifests.
- `make catalogue-check`: passed.
- `make test`: attempted all 1,670 test files; 34 child test files failed and the command exited 2. The run preceded materializing ignored local index `work/index/node-115-fde.tsv`. After generating it with `make fde-index` and setting `PYTHONDONTWRITEBYTECODE=1`, four selected tests passed: `test_node115_hotstuff_vote_and_qc.py` and the three FDE-index-dependent tests `test_bole_reserve_interest_engine_115.py`, `test_fee_trial_referral_rewards_115.py`, and `test_spot_clearinghouse_accounting_115.py`. The full suite has not been rerun, and those selected passes do not explain the other failures. A separate rerun of `test_foundation_byte_matches_115.py` failed because the installed `rustc` rejected the test's `rustc +1.95.0` invocation with “multiple input filenames”; the underlying cause has not been established. Do not treat the repository-wide suite as green.
- No captured executable run is part of this evidence.

Next question: locate the producer of the callback object at `payload+0x60` and verify whether it hashes the selected `addressEncoding` string.
