# RE-005: identify the `SendToEvmWithData` d1 callback field

- **Component:** `action-wire`; bounded question under [issue #3912](https://github.com/lalalune/hyperliquid-source/issues/3912).
- **Target:** Linux x86-64 node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- **Source revision:** `ec87b0e812f363a43abaa26e6c9c4c808bf9a285`.
- **Claim status:** the callback-bearing payload field is identified as the `addressEncoding` enum by a crosswalk of target serializer order, field-name bytes, enum serializer, and the existing target-bound EIP-712 schema. The returned 32-byte object is copied into the `address_encoding` field slot and later invoked by the typed-data hash helper; its concrete function pointer and output semantics remain unresolved.
- **Scope:** identify the field at payload `+0x60` shared by the `0xd1` signing-method callback and action-payload serializer, then trace that callback object's handoff into typed-data hashing. No production digest, signature validation, or concrete callback target is claimed.

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
3. The same payload offset `+0x60` is loaded by the `0xd1` signing method at `0x442d179`; it calls the first function pointer in that object with `payload+0x78`, `[payload+0x68]`, and `[payload+0x70]`. The method copies the 32-byte return into local `rsp+0x118..0x138` at `0x442d194`.
4. At `0x442d30a`, the method passes a local record based at `rsp+0xb8` into `0x46e6d30`. Therefore the callback's 32-byte return occupies that record's `+0x60` slot.
5. `0x46e6d44` forwards the same record pointer to `0x4433f90`. The wrapper preserves it in `r14` and at `0x44340f2` forwards it unchanged through relocation slot `0x64ea978` to hash helper `0x4428520`.
6. The hash helper preserves its input record base in `r15`; at `0x44289b2..0x44289ca` it loads the object at record `+0x60`, passes neighboring fields at `+0x68/+0x70/+0x78`, and invokes the object's first function pointer. This proves that the 32-byte return is reused as a callable field object by the typed-data hash helper. Its concrete target and emitted value are not identified.
7. The existing target-bound builder record at [`action-wire-typed-data-structs-115/eip712.tsv`](../action-wire-typed-data-structs-115/eip712.tsv) identifies `address_encoding` as a `string` field immediately after `destination_recipient` and before `destination_chain_id`.

### Inference and limits

The serializer call order, contiguous target field-name bytes, enum variant serializer, and EIP-712 field order together identify payload `+0x60` as `addressEncoding` / `address_encoding`. The method-to-wrapper-to-hash-helper chain shows that its 32-byte callback return is the field object consumed by the generic typed-data helper. The bytes are not established as a final string hash; the exact callable and its emitted string/encoding remain unknown.

Still unresolved: the producer of the object at payload `+0x60`, the concrete function pointer returned in the 32-byte field object, its emitted string/encoding, runtime values, a production or public/synthetic digest vector, and signature/replay behavior. This is a partial finding and does not advance any full-scope gate.

## Checks

- `python3 tools/action_wire_d1_address_encoding_115.py --out research/work-items/RE-005-node115-d1-address-encoding-bridge`: passed; target hash, three FDE ranges, instruction witnesses, literals, and schema crosswalk verified.
- `python3 -m unittest tests.test_action_wire_d1_address_encoding_115 -v`: passed, seven tests including target identity and five byte-corruption controls covering serializer input, callback return, record handoff, and hash-helper callback reuse.
- `make doctor`: `analysis_ready=true`; `exact_rebuild_ready=false`. The report identifies missing recovered Cargo manifests/lockfiles, exact build flags and fork provenance, and an accepted implementation/harness; Ghidra and Java are also unavailable in this environment.
- `make verify`: passed, including binary signatures, import checks, and evidence packet manifests.
- `make catalogue-check`: passed.
- `make test`: attempted all 1,670 test files; 34 child test files failed and the command exited 2. The run preceded materializing ignored local index `work/index/node-115-fde.tsv`. After generating it with `make fde-index` and setting `PYTHONDONTWRITEBYTECODE=1`, four selected tests passed: `test_node115_hotstuff_vote_and_qc.py` and the three FDE-index-dependent tests `test_bole_reserve_interest_engine_115.py`, `test_fee_trial_referral_rewards_115.py`, and `test_spot_clearinghouse_accounting_115.py`. The full suite has not been rerun, and those selected passes do not explain the other failures. A separate rerun of `test_foundation_byte_matches_115.py` failed because the installed `rustc` rejected the test's `rustc +1.95.0` invocation with “multiple input filenames”; the underlying cause has not been established. Do not treat the repository-wide suite as green.
- A fresh long-running `make test` session (handle 89182) is also active in the follow-up worktree. Its latest visible output reached `test_bridge_event_json_reader_115.py`; it has not returned a terminal status, so this run is not counted as either a pass or a failure. Because the worktree was edited while the session ran, it is not an exact immutable-revision result.
- No captured executable run is part of this evidence.

Next question: identify the concrete function pointer and producer of the field object at `payload+0x60`, then recover its emitted encoding and a public/synthetic typed-data vector.
