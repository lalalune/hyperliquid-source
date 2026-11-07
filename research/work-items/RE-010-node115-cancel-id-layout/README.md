# RE-010 · Node #115 cancel batch bounds and identifier layout

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The existing cancel-routing packet covers a classifier, grouping, and selected routing branches. This packet binds the shared batch-size rejection and two different in-memory row widths to the named action types in the selected execute dispatcher. A replay implementation needs to preserve these distinctions before sending rows to the appropriate identifier-specific helper.

The outer decoder uses the same relocated field names `cancels` and `f` for both variants, but the successful internal tags and downstream execution are distinct.

| Wire action | Decoder call and success tag | Execute call and wrapper | Row width | Preparation | Downstream after checks |
| --- | --- | --- | ---: | --- | --- |
| `cancel` | `0x4d40cbf → 0x56f1f20`, `0x89` | `0x54a34b1 → 0x5513df0` | 16 | `0x5514285 → 0x50f9480` | `0x5514347 → 0x5208370` |
| `cancelByCloid` | `0x4d40850 → 0x56e01b0`, `0x8a` | `0x54a339a → 0x5539010` | 20 | `0x55394a6 → 0x50fb250` | `0x5539568 → 0x5133120` |

Both wrappers read the row count at payload `+0x10` and compare it unsigned against 10001. At or above 10001 the branch stages result word `0x158` and skips preparation. Below the cutoff the pointer at payload `+0x08` becomes the beginning of the range. `cancel` forms its end using a left shift of four. `cancelByCloid` forms it with two scaled adds, first multiplying by five and then by four. Thus zero produces an empty range, 10000 reaches preparation with the appropriate stride, and 10001 takes the limit error. This describes admission to preparation, not success of the action.

Preparation and both subsequent checks must each return `0x1a2` before the final action-specific call. The selected error branches preserve their nonmatching result and return outer byte `0x0f`. The table names the reached processing boundary. Row member types, lookup effects and wire response serialization remain open.

Run `python3 research/work-items/RE-010-node115-cancel-id-layout/verify.py` from the repository root. The verifier authenticates the target and checks the selected cells, field relocations, relative calls, size comparison, range arithmetic and check branches. It rejects a modified threshold and a changed range scale on copies of the target bytes. No captured code is executed.
