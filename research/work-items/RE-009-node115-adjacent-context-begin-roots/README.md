# RE-009 · Check node #115 Context inputs across adjacent raw roots

Match four Context leaves at checkpoint height H and at H+1 against two independently supplied native `abci_hashes` rows. At H the comparator uses the normalized restored Context. At H+1 it applies the selected native begin projection to the separate admitted replay header, then checks the resulting leaves. Both raw reference exports must first reproduce their own recorded digests.

| Field | Context path | H+1 value |
| --- | --- | --- |
| Height | `[0,0,2]` | H+1, checked against the supplied successor archive height |
| Consensus round | `[0,0,4]` | The admitted header's `round` |
| Current time | `[0,0,5]` | Incoming time when strictly newer, otherwise the restored current time |
| Previous time | `[0,0,6]` | The restored current time after rotation, otherwise the restored previous time |

The references retain each complete ordered reduction tree and are independently pinned by SHA-256. The comparator rebuilds both root preimages with the [same-height root toolkit](https://github.com/lalalune/hyperliquid-source/pull/7404), then compares only the four expected child digests. It reports a separate result for each field and height. A valid H+1 reference with a differing leaf measures disagreement with the begin projection, which may come from a later update. This is a check of selected normal Context changes, not a replay engine or proof of equality for all H+1 state.

The native begin byte window is identical for the compact and expanded paths. It compares packed clocks, rotates them only on a strictly later normalized ordinary clock, increments height and writes the admitted round to `+0x30`. [#7342](https://github.com/lalalune/hyperliquid-source/pull/7342) models clock rotation, [#7402](https://github.com/lalalune/hyperliquid-source/pull/7402) models the selected memory stores, and [#7344](https://github.com/lalalune/hyperliquid-source/pull/7344) identifies Context tree coordinates. [#7370](https://github.com/lalalune/hyperliquid-source/pull/7370) identifies the decoded header's admitted round and clock independently of the archive height. This check joins those boundaries to adjacent raw references. Transaction-index writes, later helper effects, actions and leap-second captures remain outside scope.

### Input manifest

The manifest itself and all four artifacts are SHA-256-pinned. Its paths resolve relative to the manifest. Each entry is `{"path":"filename","sha256":"64 lowercase hex digits"}`.

| Role | Contents |
| --- | --- |
| `restored_context` | Normalized H JSON with `height`, `round`, `time` and `prev_time`. The output from [#7368](https://github.com/lalalune/hyperliquid-source/pull/7368) supplies these fields for selected named checkpoints. |
| `successor_header` | Selected decoded header JSON with explicit archive `height`, admitted `round` and `time`. The decoded parent round is a separate coordinate. |
| `reference_h` | Native raw export row at H, including its complete `exchange_abci_hash` tree |
| `reference_h_plus_one` | Native raw export row at H+1, including its complete `exchange_abci_hash` tree |

Clock values are objects with `unix_seconds` and `subsec_nanos`. Artifact checks establish exact local bytes, leaving producer identity and chain provenance to the supplied captures. The full verification fixture uses synthetic pins and raw trees. No actual H/H+1 roots were available.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

From repository root:

```sh
packet=research/work-items/RE-009-node115-adjacent-context-begin-roots
python3 -B "$packet/verify.py"
python3 -B "$packet/verify.py" --root-packet PATH_TO_7404_PACKET
```

The second command requires Rust 1.95 and the [#7404 packet at its published head](https://github.com/0xQueenQ/hyperliquid-source/tree/e398ce425ef2b446aaa96bf48608bc3a7fd314a2/research/work-items/RE-009-node115-context-root-isolation). It compiles that packet's local BLAKE3 helper. To compare supplied files, use its documented build command and run:

```sh
python3 -B "$packet/transition.py" PATH_TO_7404_PACKET/isolate.py HASH_TREE_HELPER \
  MANIFEST.json MANIFEST_SHA256
```

Exit 0 means all eight field comparisons match, 1 means a valid reference disagrees on a selected field, and 2 means an invalid input or inconsistent reference. [Measured offline output](offline-log.txt).
