# Node #115 DEX map upsert result and ring paths

- Component: `dex-registry` / RE-009, DEX metadata map
- Bounded question: on the compact ring representation, what does the DEX map insertion routine do for a missing key versus an existing key, and what does its return buffer record?
- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source/reference revisions: repository `8f8a38d0d44f0c41a94aa156bb4274777f20fd4d`; no reference source used
- Addresses are ELF virtual addresses. FDE extents: `0x4dd59a0..0x4dd6145` (1,957 bytes), `0x57fc670..0x57fc932` (706 bytes), and `0x57ed5e0..0x57ed70a` (298 bytes), all in `.text`.
- This supplements merged PR #6082, whose RE-009 packet records `0x4dd59a0` as an excluded insert helper and already notes the 32/64 representation thresholds. The new result here is the bounded ring-path hit/miss and return-buffer trace; those thresholds are context only.

## Reproduce

From the repository root:

```sh
python3 tools/fde_extents.py --release 115 --output-dir work/re-009-map-insert-probe
rg '0x4dd59a0|0x57fc670|0x57ed5e0' work/re-009-map-insert-probe/node-115-fde.tsv
python3 research/work-items/RE-009-node115-dex-map-upsert/verify.py > research/work-items/RE-009-node115-dex-map-upsert/verification-output.txt
python3 -m unittest tests.test_re009_node115_dex_map_upsert
```

The verifier authenticates the pinned ELF, recomputes the three selected unwind extents from `.eh_frame` and `.eh_frame_hdr`, and checks that they agree with `fde.tsv`. It also checks raw instruction anchors for the ring search result, low-bit branch, insert helper, replacement writes and result discriminants. Its whole-file digest gate and byte checks are tested separately: a changed target is rejected by the digest gate, and an in-memory mutation of each of the 24 anchors is rejected by the corresponding byte comparison. The observed output is retained in `verification-output.txt`. The target is read as data and is never executed.

## Observations

- The caller in the merged RE-009 packet invokes `0x4dd59a0` for the 24-byte key and 20-byte value in the `Hip3` map at state offset `+0x338`. The current packet's scope starts inside that map routine.
- On the non-sentinel representation, `0x4dd5b84` calls `0x57fc670` with the map and key. The key argument is a 24-byte Rust `String` record; the helper compares its string contents through relocated slot `0x64dfb50`. It returns a status in `AL` and a position in `RDX`. Its empty-ring path returns status 1 and position 0. Its comparator result is reduced to -1/0/1, so the caller's low-bit test at `0x4dd5c57` distinguishes equality (0, existing key) from an insertion position (odd nonzero, absent key).
- `test al, 1` at `0x4dd5c57` branches to the existing-key path when the low bit is clear. When the low bit is set, the routine assembles the 24-byte `String` record and 20-byte incoming value, then calls `0x57ed5e0` at `0x4dd5ca7` with the search position. That helper checks `position <= len`, grows when `len == capacity`, shifts the ring entries, increments the count and copies the 0x30-byte record into the selected slot. The final 4 bytes in this temporary record are not assigned a separate semantic field by this packet.
- The missing-key route sets the result discriminant to zero at `0x4dd6070` and converges on the common result write at `0x4dd5f7b`. The exact machine-code path therefore records `None` after inserting the new key/value record. In `0x57ed5e0`, the position is checked against ring length, capacity equality reaches the growth slot, the length increments, and three 16-byte loads copy the 0x30-byte key/value record into the chosen slot.
- The existing-key route resolves the matched ring entry. At `0x4dd5f61` it loads the old 16-byte value, then copies the remaining 4 bytes at `0x4dd5f5b`; it writes the incoming value's first 16 bytes at `0x4dd5f70` and remaining 4 bytes at `0x4dd5f76`. It sets the result discriminant to one at `0x4dd5f79`/`0x4dd5f7b`, so this path returns `Some(old_value)` while replacing the stored value.
- The 32 and 64 count comparisons, sentinel route, and conversion calls are retained as context from the same body and the already merged RE-009 packet. This packet does not claim to close the tree-side search or transition helpers.

## Interpretation and limits

The ring/tree labels and the map wrapper shape come from prior target-bound packets; names are not recovered source names. The local verifier proves selected bytes in the pinned file, not the helper semantics. It does not establish allocation-failure behavior, comparator behavior beyond the traced status contract, the tree-side hit/miss route, full map invariants or runtime reachability. The tree helpers `0x5b76b30`, `0x51dcf80`, `0x5163150`, and `0x51f2d60` remain outside this packet. The `Option` return is unused by the dispatcher caller, as recorded in #6082. No component gate is claimed complete.

Next step: trace one authorized Main/Hip3 update through this map insertion path and close the relevant nested helper contracts, as requested by the DEX-registry acceptance issue.
