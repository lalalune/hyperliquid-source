# RE-005: identify the `SendToEvmWithData` d1 callback field

- **Component:** `action-wire`; bounded question under [issue #3912](https://github.com/lalalune/hyperliquid-source/issues/3912).
- **Target:** Linux x86-64 node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- **Source revision:** `ec87b0e812f363a43abaa26e6c9c4c808bf9a285`.
- **Claim status:** the d1 method's callback-bearing field at variant-input `+0x60` is inferred to be `addressEncoding` by crosswalking the matching `SendToEvmWithData` variant dispatch, serializer field order/name, and target-bound EIP-712 schema. The returned 32-byte object is copied into the `address_encoding` field slot and later invoked by the typed-data hash helper; its concrete function pointer and output semantics remain unresolved.
- **Scope:** identify the semantic field of the d1 method callback at variant-input `+0x60`, then trace that callback object's handoff into typed-data hashing. The serializer-context `+0x60` is a different base and is not claimed to be the same address. No production digest, signature validation, or concrete callback target is claimed.

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

1. The existing target-bound [`arms.tsv`](../RE-010-action-serialize-tag-dispatch-115/arms.tsv) maps `SendToEvmWithData` variant index 75 to serializer arm `0x2bced39` and payload serializer `0x240eef0`. The arm advances RSI by 8 bytes before calling the serializer. The serializer context supplies the `destinationRecipient` call at `0x240f185` with 20-byte name at `0x5ed61a`; its adjacent bytes continue with `addressEncoding`.
2. The next field-value call at `0x240f20b` passes the serializer-context pointer `context+0x60` to `0x24580c0`. This is a separate context base, not the d1 method's variant-input pointer. The next 15 target bytes spell `addressEncoding`; the enum serializer's observed branch emits `UnvalidatedBridgeEpoch` from `.rodata` `0x5f174d`.
3. Independently, the target-bound method-dispatch table maps the same variant index 75 / tag `0xd1` to method arm `0x36c3696`; it too advances RSI by 8 bytes before calling the method slot. The d1 method at `0x442d179` therefore reads its callback object at variant-input `+0x60`; it calls the first function pointer with variant-input `+0x78`, `[+0x68]`, and `[+0x70]`. It copies the 32-byte return into local `rsp+0x118..0x138` at `0x442d194`.
4. At `0x442d30a`, the method passes a local record based at `rsp+0xb8` into `0x46e6d30`. Therefore the callback's 32-byte return occupies that record's `+0x60` slot.
5. `0x46e6d44` forwards the same record pointer to `0x4433f90`. The wrapper preserves it in `r14` and at `0x44340f2` forwards it unchanged through relocation slot `0x64ea978` to hash helper `0x4428520`.
6. The hash helper preserves its input record base in `r15`; at `0x44289b2..0x44289ca` it loads the object at record `+0x60`, passes neighboring fields at `+0x68/+0x70/+0x78`, and invokes the object's first function pointer. This proves that the 32-byte return is reused as a callable field object by the typed-data hash helper. Its concrete target and emitted value are not identified.
7. The existing target-bound builder record at [`action-wire-typed-data-structs-115/eip712.tsv`](../action-wire-typed-data-structs-115/eip712.tsv) identifies `address_encoding` as a `string` field immediately after `destination_recipient` and before `destination_chain_id`.
8. In the hash helper, the callback result's returned pointer and length are read at `0x44289cc`; negative lengths take an error path. On the nonnegative path, the helper allocates/copies using that pair and calls a method at the callback-result object's `+0x20` at `0x4428a32`. This supports the field-object handoff description but does not identify the method implementation or emitted bytes.

### Inference and limits

The serializer and method dispatch tables both bind variant index 75 to `SendToEvmWithData`, and both arms advance the enum pointer by 8 bytes to the variant input. Serializer field-name/order evidence places `addressEncoding` immediately after `destinationRecipient`; the existing EIP-712 schema places `address_encoding` in the same relative order. Together these support identifying variant-input `+0x60` as the `addressEncoding` / `address_encoding` callback field. This is an explicit crosswalk inference: the serializer-context pointer at its own `+0x60` is not asserted to be the same memory address as the method input. The method-to-wrapper-to-hash-helper chain shows that its 32-byte callback return is the field object consumed by the generic typed-data helper. The bytes are not established as a final string hash; the exact callable and its emitted string/encoding remain unknown.

Still unresolved: the producer of the object at variant-input `+0x60`, the concrete function pointer returned in the 32-byte field object, the returned object's `+0x20` method implementation and emitted string/encoding, runtime values, a production or public/synthetic digest vector, and signature/replay behavior. This is a partial finding and does not advance any full-scope gate.

## Checks

- `python3 tools/action_wire_d1_address_encoding_115.py --out research/work-items/RE-005-node115-d1-address-encoding-bridge`: passed after adding exact hash-helper pointer/length and `+0x20` method-call witnesses; target hash, FDE ranges, instruction bytes, literals, and schema crosswalk verified.
- `python3 -m unittest discover -s tests -p 'test_action_wire_d1_address_encoding_115.py' -v`: passed, ten tests including target identity and eight byte-corruption controls covering serializer context, both enum-pointer adjustments, callback return, record handoff, and hash-helper callback reuse.
- `make doctor`: `analysis_ready=true`; `exact_rebuild_ready=false`. The report identifies missing recovered Cargo manifests/lockfiles, exact build flags and fork provenance, and an accepted implementation/harness; Ghidra and Java are also unavailable in this environment.
- `make verify`: passed after refreshing `records.json`, including binary signatures, 32 imports, and 4,851 evidence-packet manifests / 34,473 entries.
- `make catalogue-check`: passed after refreshing `records.json`.
- `make test`: attempted all 1,670 test files; 34 child test files failed and the command exited 2. The run preceded materializing ignored local index `work/index/node-115-fde.tsv`. After generating it with `make fde-index` and setting `PYTHONDONTWRITEBYTECODE=1`, four selected tests passed: `test_node115_hotstuff_vote_and_qc.py` and the three FDE-index-dependent tests `test_bole_reserve_interest_engine_115.py`, `test_fee_trial_referral_rewards_115.py`, and `test_spot_clearinghouse_accounting_115.py`. The full suite has not been rerun, and those selected passes do not explain the other failures. A separate rerun of `test_foundation_byte_matches_115.py` failed because the installed `rustc` rejected the test's `rustc +1.95.0` invocation with “multiple input filenames”; the underlying cause has not been established. Do not treat the repository-wide suite as green.
- The previously observed full-suite session handle 89182 was no longer present in the process table on 2026-11-28. Its terminal result could not be recovered, so it is not counted as either a pass or a failure; the run was also against a worktree edited while it ran and is not an immutable-revision result.
- No captured executable run is part of this evidence.

Next question: identify the concrete function pointer and producer of the field object at `variant-input+0x60`, then recover its emitted encoding and a public/synthetic typed-data vector.
