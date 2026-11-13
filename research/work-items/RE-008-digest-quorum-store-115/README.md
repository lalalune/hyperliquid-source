# RE-008: node #115 digest quorum store: fill, retain pass and 1000-entry cap (61st stage)

- Component ID: abci. Question: #6046 found that the step wrappers' 0x68-byte quorum entries come from `0x5afa1f0` over the store at box `+0x3d98` (layout B `+0x4908`), with a "threshold" `max(0, store+0x78 - 1000)`. It left open what the fill helper `0x4de1d80` moves, what an insert records, what `store+0x78` is, and what `esi` 0..3 selects in `0x54cae80`.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). Continues open PRs #6042 and #6046. It imports only the merged `tools/freeze_snapshot_115.py` helpers.
- Claim status: instruction bytes, offsets, constants, jump-table arms, call targets and call censuses are observations. "Map length", "B-tree", "retain", "extract", "deadline", "now", "consensus time" and "initial height" are inferred labels from the access shapes and from #6004's field names. The binary was not executed.
- Scope excluded: the vector-form retain `0x57f14a0`, the entry builder `0x53779c0`, the source `0x5374b70`, `0x5376540`, the arms for `esi` 0 and 1, the second store's fill `0x5afa3b0`, the dispatcher's other case bodies (no action names are given), and the caller-side value passed as "now". No gate changes.

## Reproduce

```
python3 tools/digest_quorum_store_115.py --check
python3 -m unittest tests.test_digest_quorum_store_115
```

The tool reads the ELF only. The five `*.objdump.txt` files were made with GNU objdump 2.42 for review only.

## Evidence 1: the take and its cap

`0x5afa1f0` builds a 7-word closure: the caller's `rdx`, the store, `&store+0x48`, `&store+0x88`, the caller's `rcx`, `&counter` (starts at 0) and `&threshold`, with `threshold = max(0, store+0x78 - 1000)` (`0x5afa208..0x5afa214`). It runs `0x4de1d80` on the map at `store+0x60`, then takes the Vec at `store+0x48` (leaving `{0, 8, 0}`) and keeps the 0x68-byte entries whose qword `+0x20` is non-zero (`0x5afa2b0`).

`0x4de1d80` treats the map as a B-tree when its first word is `0x8000000000000000`, with root `+0x68`, height `+0x70` and length `+0x78` (`0x4de1e3f..0x4de1e49`). It runs the extract loop `0x51515f0` (its only direct call, `0x4de1fc6`) and rebuilds the small form when the length falls below `0x20`. So `store+0x78` is the map length, and the "threshold" from #6046 is the number of entries above 1000, not a height.

## Evidence 2: the extract predicate

Per B-tree entry (key a u64, value a 12-byte time at node `+0x60 + 12*i`):

| Test | Action |
|---|---|
| now `>=` time + f64 `[closure+0x18]` s (that is `store+0x88`) | remove, build a 0x68-byte entry, push it to `store+0x48` (`0x5151a9e..0x5151ce5`) |
| otherwise, now `>=` time + 60.0 s (`0x459718`) and counter `<` threshold | counter += 1, remove, no push (`0x51519a5`, `0x5151b9d` -> `0x5151ce9`) |
| otherwise | keep |

An addition that leaves the date range uses the far-future tuple `0x4679d0` (#5861). "now" is `[closure+0x0]`, the take caller's `rdx`. Inference: entries older than `store+0x88` seconds become quorum entries; entries older than 60 s are dropped silently while the map holds more than 1000.

## Evidence 3: the insert

`0x5afa5d0` walks 0x68-byte entries from `0x5374b70(store)`. For each: `store+0x80 = max(store+0x80, height)`; `map[height] = ctx+0x60` through `0x4dbe1e0` (vtable `0x64bc830`); `store+0x90 = 1` (word) when the height equals `ctx+0x10`; then `0x5376540` with `height - 50000`, saturating at 0. `ctx` is the box (`rsi` from `0x54cae80`); #6004 binds box `+0x60` as `consensus_time` and `+0x10` as `initial_height`.

## Evidence 4: the selector

`0x54cae80` dispatches on byte `esi` through table `0x926a70`: arms `0x54caec4`, `0x54cb082`, `0x54cb042` (`0x5afa5d0` on box `+0x3d98`) and `0x54cb062` (`0x5afa3b0` on box `+0x3e50`). The layout-A dispatcher `0x538cd30` calls it four times in a row with `esi` 0, 1, 2, 3 (`0x5392009..0x5392032`). So each pass services all four stores; `esi` is not per action.

## Results and limitations

- Corrects #6046: the 1000 bounds the map's entry count, not the height.
- Limits: the vector-form retain, the entry builder `0x53779c0` (it returns `0x8000000000000001` to skip the push), the source of the inserted entries, `0x5376540`, the arms for `esi` 0 and 1, the twin fill `0x5afa3b0`, the value of `store+0x88`, and the caller's "now".
- Next lead: `0x53779c0`, which builds each quorum entry from the removed key.
