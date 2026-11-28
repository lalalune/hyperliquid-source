# RE-017: Continue an offline bootstrap range after a drained chunk

The existing `node115-bootstrap-range` entry point determines the first
inclusive chunk from the selected input bounds. This change adds the
different continuation needed after an exhausted response cursor. It
advances from the previous inclusive end, uses the same 100-coordinate
chunk width, and stops requesting more after the saved target is passed.
At that point it compares the caller's refreshed receive baseline with
the saved target.

The [native continuation](https://github.com/lalalune/hyperliquid-source/pull/7295)
pins the successor and bound compare to `0x5a82ff3..0x5a83026` and later
compares the observed native receive word at `0x5a88433`. The original
[inclusive range packet](../RE-014-bootstrap-range-rust-115/README.md)
owns the first query and original span guard. The new steady-state
adapter takes trusted previously selected endpoints. It does not model
queue polling, fetch anything, or use a state digest as a round number.

The exact-boundary test requests a singleton before completing. Tests also
cover an additional full chunk, a partial final chunk and a mismatching
terminal baseline. The existing 12 frozen first-entry controls are also
replayed. No captured instructions execute.

```sh
python3 -B research/work-items/RE-017-node115-bootstrap-following-chunk/verify.py
rustc --edition=2021 --test -D warnings src/node115-bootstrap-range/lib.rs -o /tmp/node115-bootstrap-range-tests
/tmp/node115-bootstrap-range-tests
```

[Raw offline output](offline-log.txt)
