# RE-009: Read canonical #115 checkpoint clock text

The existing checkpoint fixture can render clock words, but cannot get the
logical values back from the canonical text carried by JSON and MessagePack.
For those inputs, this change provides a local reader for the calendar year,
ordinal day, seconds since midnight, and nanosecond word. A textual second
60 projects to second 59 and adds one billion to the nanosecond word.

Target Linux x86-64 node #115. The raw log records the SHA-256, interpreter
and compiler. Reused ELF witnesses bind the JSON and MessagePack adapters to
the same 18 format-item records at `0x6405668..0x6405818` and the calendar
constructor at `0x1627e60`. The independently derived calendar table in the
linked packet verifies the ordinal projection over a full Gregorian cycle.
The earlier [clock word projection](https://github.com/lalalune/hyperliquid-source/pull/7238)
establishes how the constructor handles the seconds and fractional words.

The Rust adapter checks the supported logical values and compares the spelling
with the existing date and time renderers. This implements the formatter's
canonical output only. It discards packed calendar flags. The native reader's
additional accepted spellings and full checkpoint restoration stay outside
this adapter. No captured instructions run.

From the repository root run:

```sh
python3 -B research/work-items/RE-009-node115-canonical-checkpoint-clock-reader/verify.py
cargo test --locked --offline --manifest-path src/node115-checkpoint-clock-text/Cargo.toml
```

[Raw offline output](offline-log.txt)
