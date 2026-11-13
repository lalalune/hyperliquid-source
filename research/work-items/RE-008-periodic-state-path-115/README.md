# RE-008: node #115 periodic abci state paths and the blocking wrapper (33rd stage)

- Component ID: abci. Question: the 32nd stage (open PR #5999) found that the linked abci state step `0x5485f80` builds two paths with `0x38d8240`, an abci_state path with `0x5942870`, and calls `0x4e45a30` with `edx = 1`. It left open the exact path pieces, what selects the `rmp` or `json` extension, and what the `edx` flag does.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues #5970 and open PR #5999. The tool imports helpers from the merged `tools/freeze_snapshot_115.py`.
- Claim status: instruction bytes, constants, string bytes, relocations, Location records, FDE starts and call censuses are observations. "Date", "height", "root", "Display", "chrono format", "tokio runtime context" and "blocking" are inferred labels from the strings, the Locations and the call shapes. Format templates are read as Rust format pieces: `c0 NN` is one argument followed by an `NN`-byte literal. The binary was not executed.
- Scope included: `0x38d8240`, `0x38d8100`, `0x5942870` in full; the date formatter head `0x150ce90`; the flag test and both call paths of `0x4e45a30`. Scope excluded: the body of `0x4e363c0` and the work it runs (`0x4e4b3f0`), `0x5aa1020`, the date conversion `0x1629fb0`, the file operations that use these paths, and the names passed by the two other callers of `0x5942870`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/periodic_state_path_115.py --check
python3 -m unittest tests.test_periodic_state_path_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: the two periodic paths

`0x38d8240` (slot `0x64e4f30`, 4 calls) takes the height in `rsi`.

1. It reads the current time (slot `0x64e0990` → `0x1629690`) and converts it with slot `0x64e0ab8` → `0x1629fb0`, `edx = 0`. A zero result jumps to `0x38d838e`, which panics with the 43-byte message `Local time out of range for \`NaiveDateTime\`` and Location `chrono/src/datetime/mod.rs:579:14` (`0x63fc160`).
2. It calls `0x38d8100` (slot `0x64e9568`, its only reference) with the height and the date. That function formats `{root}/data/periodic_abci_states` (template `0x448b77`, name `0x646e9f0`), then template `0x432d1a` = `{}/{}/{}.rmp` with that directory, the date and the height.
3. It formats `{root}/data/periodic_abci_state_statuses` (name `0x646ea00`), then template `0x440e47` = `{}/{}/{}` with that directory, the date and the height.
4. It returns the first String at `+0x0` and the second at `+0x18`.

The date argument is displayed by `0x150ce90` (slot `0x64e0b68`). That function passes the 6-byte format `%Y%m%d` (`0x465bc9`) to the formatter. The height is displayed by `0x1689420` (slot `0x64e0a98`).

So a periodic snapshot at height H on 2026-11-09 uses `{root}/data/periodic_abci_states/20261109/H.rmp` and `{root}/data/periodic_abci_state_statuses/20261109/H`.

## Evidence 2: rmp or json

`0x5942870` takes a name (`&str`):

- If the length is 10 and the bytes are `abci_state` (`movabs` of `abci_sta` plus `xor` with `te`), the extension is `rmp` (`0x9382b9`, 3 bytes).
- Any other name gives `json` (`0x459f60`, 4 bytes).
- The file is `{name}.{ext}` (`0x43d024`) and the path is `{root}/hyperliquid_data/{file}` (`0x44f615`).

The step passes `&"abci_state"` (`0x64aa220`), so it uses `{root}/hyperliquid_data/abci_state.rmp`. `0x5942870` has four direct callers; two of them (`0x5485ae0`, `0x5486000`) pass `0x64aa220`.

## Evidence 3: the `edx` flag of `0x4e45a30`

- `edx == 0`: jump to `0x4e45abe` and call `0x4e363c0` directly.
- `edx != 0`: call `0x5aa1020` with Location `base/src/u.rs:531:9`. Then read and change thread-local bytes, call `0x4e363c0`, and restore them. The two panic paths use Locations in the vendored `tokio/src/runtime/context/runtime_mt.rs` (28:9 and 17:17).

Inference: with `edx = 1`, the work runs after leaving the async runtime context (the shape of a blocking call inside a Tokio worker). The step's only call passes `edx = 1` (`0x5486046`). `0x4e363c0` has two direct calls, both inside `0x4e45a30`.

## Implementation and comparison

The tool pins 25 instruction byte runs, 17 RIP-relative references, 13 relocations, 14 strings and 4 Location records, then recomputes the call census and evaluates the extension rule on four sample names. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: emulating the formatter (not allowed here); reading the work behind `0x4e363c0` (bounded out).

## Results and limitations

- Result: the periodic paths are `periodic_abci_states/{%Y%m%d}/{height}.rmp` and `periodic_abci_state_statuses/{%Y%m%d}/{height}` under `{root}/data`; the current state file is `hyperliquid_data/abci_state.rmp`; the step runs its work through the `edx = 1` path of `0x4e45a30`.
- Limits: what `0x4e363c0` / `0x4e4b3f0` writes and what the 0x38-byte result holds; whether the date is UTC or local (only the chrono message names `NaiveDateTime`); what `0x5aa1020` checks; the names the other two callers of `0x5942870` pass; and the file operations that use these paths.
- Next lead: the names passed by `0x5942b57` and `0x5a396d3` to `0x5942870`, which select the `json` state files.
