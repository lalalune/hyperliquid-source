# RE-009 #115 render checkpoint clock words

The checkpoint clock adapter renders the selected checkpoint string directly from its three 32-bit clock words. The [calendar packet](../RE-009-node115-clock-calendar-pack/README.md) supplies the year and ordinal projection. The [named clock serializer](../RE-009-node115-context-clock-string-writer/README.md) supplies the literal `T` between the same date and time formatter targets.

`render_checkpoint_clock` extracts the signed year with an arithmetic shift by 13 and the ordinal from bits 4–12. It uses the existing logical constructors and formatter for both components. Low calendar flags are ignored by this logical projection, and inputs outside the crate's supported date or time domain return `None`. The adapter returns only string contents. MessagePack headers belong to the caller.

The verifier checks four date words against the pinned ELF tables and checks the formatter bindings and `0x54` separator. The Rust tests render ordinary time, February 29, a fractional second, a leap-second representation and a negative year. They also cover logical constructor rejections. A control that changes only the checkpoint separator back to a space fails the checkpoint test.

## Reproduce

From the repository root:

```sh
python3 -B research/work-items/RE-009-node115-render-checkpoint-clock/verify.py
cargo test --locked --offline --manifest-path src/node115-checkpoint-clock-text/Cargo.toml
```

This implementation supports the selected normal formatting boundary. It does not expose the native packed ABI, parse an entire checkpoint or establish a state-root match.

[Offline output](offline-log.txt) | [Instruction windows](windows.txt)
