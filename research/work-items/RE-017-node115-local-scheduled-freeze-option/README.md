# RE-017 #115 local scheduled freeze height through startup

Component `abci`. The selected local MessagePack Exchange map uses field 13 for the optional `scheduled_freeze_height`. When the requested checkpoint fixture supplies an unsigned height, its tag and payload reach the local hardfork guard at state +0x10e8/+0x10f0. Missing and MessagePack nil both return tag zero, so startup bypasses that guard's height comparison.

| Boundary | Static observation |
| --- | --- |
| Field identity | The local table at `0x4ac778` sends index 13 to `0x1851f82`. Its already-seen edge names the exact 23-byte literal `scheduled_freeze_height`. |
| Option decode | The unseen stack tag at +0x160 starts at 2. On the selected value arm, marker `c0` sets the tag to 0. A value from unsigned reader slot `0x64e2580` with success tag 9 sets the option tag to 1 and stores the height at +0x258. The same field encountered again enters the duplicate path even after nil. |
| Local Exchange completion | The selected map completion translates unseen tag 2 to output tag 0. It writes the tag and staged payload at inner result +0x10e8/+0x10f0. Only the payload under tag 1 carries a height claim. |
| Preserve offsets | The outer Exchange's tail copy starts +0x28 relative to the child result and the assembled destination. The subsequent 0x27a8-byte returns and allocation preserve both offsets on the [local reader route](../RE-017-node115-local-hardfork-materialization/README.md). The selected materializer explicitly loads this 16-byte lane at `0x3c2eb57` and stores it into the constructed state at `0x3c2f05f`. |
| Startup | `0x2cc1aa6` gates the compare at `0x2cc1ab7` on the low dword of tag being 1. [The startup rewrite packet](../RE-017-node115-local-replay-hardfork-rewrite/README.md) establishes the three height relations and what the equality case writes. |

The selected local MessagePack result constrains fixture construction for the rewrite and bypass branches. This pass establishes no other format, actual checkpoint value, first queue slot, or state-root result. Normal returns and the ordinary copy binding are assumed.

## Reproduce offline

From the repo root:

```sh
python3 -B research/work-items/RE-017-node115-local-scheduled-freeze-option/verify.py
```

See the [raw run](offline-log.txt) and [instruction windows](windows.txt). The verifier reads the pinned artifact as data and checks table entries, instruction bytes, control targets, literal bytes and field offsets.
