# RE-009: EVM storage slot lookup and update path in node 94

This packet establishes how the node's EVM storage overlay obtains a slot's initial 32-byte value, caches it, and records a subsequent change, enabling reconstruction of this path without treating an absent database value as an absent cache entry.

- **Component ID:** storage / RE-009, EVM state storage overlay.
- **Target release and full SHA-256:** Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- **Source commit / reference commit:** repository `d3af75257a396c85d20857f421c370ddb8cb40e5`; inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only as a lead. The binary embeds locations with suffix `revm-19.2.0/src/journaled_state.rs`.
- **Claim status:** observed for the selected instruction bytes, FDE extents, call and branch targets, locations and field moves; inferred for the semantic names account, storage slot, cache and journal; unresolved for durable writes, error payloads, rollback and hash ownership.
- **Scope included and excluded:** two related lookup bodies, their address and slot map helpers, and one update caller; database getter bodies and their wire format are prior work and not reanalysed. No captured execution, chain data or cross-release comparison.

## Reproduce

From the repository root, Python 3.12.3 and the standard library suffice. The generator checks the complete target digest before parsing. It imports the repository's ELF and FDE parsers; it does not invoke a disassembler or run the target.

```sh
python3 tools/artifacts.py verify
python3 tools/evm_slot_cache94.py --out <tmp-dir>/first
python3 tools/evm_slot_cache94.py --out <tmp-dir>/second
diff -r <tmp-dir>/first <tmp-dir>/second
diff <tmp-dir>/first/slot-cache.json research/work-items/RE-009-evm-slot-cache-94/slot-cache.json
python3 -m unittest tests.test_evm_slot_cache94
(cd research/work-items/RE-009-evm-slot-cache-94 && sha256sum -c MANIFEST.sha256)
```

Generation was also run with different hash seeds and time zones and a PATH containing Python but no binutils; the outputs were identical. `slot-cache.json` SHA-256 is `b58d459c4c263168fcb6588a5dd59410148ce95daff0a6ba4903e681b1c3d2a4`. GNU objdump 2.42 was used only for bounded human inspection, not as generator input. The generator records complete raw function bytes, selected instruction windows and decoded branch/call operands. FDEs describe unwind extents, not a whole-function census; these extents were also inspected for control flow.

## Evidence

Addresses are ELF virtual addresses and ends are exclusive. The generator records six FDEs, 11 selected direct calls, 43 selected conditional branches and 14 instruction-aligned windows. The table is a bounded path, not a global call census.

| Role inferred from instruction use | FDE | Bytes |
| --- | --- | ---: |
| lookup A | `0x32ab8f0..0x32abc91` | 929 |
| lookup B | `0x32abca0..0x32ac041` | 929 |
| lookup then update | `0x32ac050..0x32ac2eb` | 667 |
| find or prepare slot entry | `0x379ab70..0x379acea` | 378 |
| find address entry | `0x37a0d20..0x37a0e47` | 295 |
| find existing slot entry | `0x37a0e50..0x37a0f74` | 292 |

The address helper compares 16 bytes and a further 4 bytes; the slot helpers compare two 16-byte blocks. They probe control bytes in 16-byte groups and use entry strides `0xd0` and `0x68`, respectively. Empty maps return null from the lookup helpers; the slot preparation helper can call a growth slot when its available capacity is zero. The lookup caller requires the address lookup to succeed; a null result goes to `0x32abc40`, which calls the relocation slot `0x576e470`. A second no-current-journal branch goes to `0x32abc4d` and calls the same slot. These are failure paths; the callee's behavior is not recovered here.

| Lookup A decision | Target or observation |
| --- | --- |
| slot helper indicates an existing entry | `0x32aba43`: read its 32-byte value, clear its byte at `-0x8`; an initially nonzero byte proceeds to the tag-7 record path, otherwise returns with result byte zero |
| slot helper indicates a missing entry and address-entry flag bit 0 is set | `0x32aba72`: use a zero 32-byte value |
| missing entry, flag bit clear | call account getter `0x37d0fb0`; a zero result selects zero; otherwise call slot getter `0x37d11d0` with a 20-byte address and 32-byte slot |
| slot getter result byte is zero | `0x32aba84`: select zero; otherwise use the returned 32 bytes |
| missing entry after value selection | populate a `0x68`-stride map entry and set its byte at `-0x8` to zero; proceed to tag-7 record path |
| tag-7 record path | reserve if needed, then write tag `7` into a `0x58`-stride record, copy address and slot, and return result byte one |

The function returns 32 value bytes at output `+0x00` and a byte at `+0x20`. The input and value roles are supported by the prior `RE-009-evm-kv-schema-94` binding of the two external getters; this packet does not assert what their errors mean. The address and slot helpers' control bytes, hash inputs, allocation and map representation are only interpreted to the extent shown in the raw windows.

The update caller `0x32ac050` calls lookup B and checks its result byte for `2`; that arm returns early. Otherwise it finds the same address and slot again, with distinct failure branches `0x32ac2c4` and `0x32ac2d1`. It compares the supplied 32 bytes to the lookup value. Equality goes to `0x32ac24d` and bypasses the observed mutation. Inequality requires a nonempty current record collection (`0x32ac152`), appends a `0x58`-stride record with tag `6`, copies the former value into it, then writes the supplied 32 bytes to the slot at `+0x20`. Three 32-byte values are copied to its output, followed by the lookup result byte at `+0x60`. The nonempty check failure goes to `0x32ac2de`. The exact meaning of the early `2` arm and the record consumer is unresolved.

Locations reached by the two lookup failures have line/column pairs `684:52` and `711:18`; the three update failure locations have `734:48`, `737:46` and `753:14`. Their relative relocations point to the same binary string with the suffix shown above. The output records the full string's hash and length, not its build-machine prefix. Location evidence supports a crate and source association, not source-level identity or a claim that the inferred reference is authoritative.

The lookup bodies have 911 equal raw byte positions out of 929. All 893 positions outside nine selected PC-relative displacement fields (36 bytes) are equal. Those fields are instruction operands, not asserted ELF relocation records; this is a structural comparison of two target bodies, not a reconstructed-code match. The direct calls at corresponding sites resolve to the same four targets, and corresponding selected branches have the same conditions and offsets.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Build provenance, target execution, normalized compiled-code comparison, helper closure, relocation and data closure are **not yet measured**. The 7 offline unit tests cover the target digest, extents, selected decisions, result and journal windows, source locations and paired comparison. Negative controls corrupt the input digest, a call opcode, a branch opcode and a Location record, and request invalid and non-file-backed ranges. They test extraction, not target runtime behavior.

## Results and limitations

This is a static, bounded storage-overlay path, not the persisted database schema, a full state-root or snapshot compatibility result. It does not establish the tag consumer, reverse operations, concurrency, durable commit, error propagation, or the complete return domain. The external getters, growth routine and failure callee are not analysed. The generated evidence contains no runtime fixture and does not establish equivalence to independently built Rust. No component acceptance gate is requested.

Next question: trace the tag-6 and tag-7 record consumer through checkpoint rollback and commit, then connect its final slot value to the established `Es` writer without assuming intermediate cache writes are durable.
