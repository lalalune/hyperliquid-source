# node94 packed-date addition

Independent `no_std` Rust numeric reconstruction of node #94
`[0x151f870,0x151fa9c)`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The complete 556-byte helper adds signed day offsets to a packed
Gregorian year/ordinal/flag representation. This closes the converter body
explicitly left unknown by `foundation-days-to-date-94`.

`add_days(packed: u32, delta: i32) -> Result<u32, InvalidPackedDate>` validates
the exact input representation documented in `lib.rs`. Every i32 delta is
admitted. `Ok(0)` preserves the target's normal rejection of an out-of-range
result; other `Ok` values preserve its packed EAX result. The original writes
EAX, zero-extending into RAX. `Err` is a new refusal to specify the target's
behavior for an invalid representation; it does not model original panics.

The implementation uses a global serial-day formula and binary search over
the admitted years. It has no third-party dependencies, build scripts, unsafe
code or root Cargo workspace. It is a standalone component, not a node build.
The proof covers the original i32 overflow checks, negative-year division,
400-year leap/flag tables and all five unreachable panic calls on valid inputs.
The outer checked wrapper, neighboring calendar helper, original ABI and panic
implementations are excluded.

From the repository root, using installed rustc **1.94.1**:

```sh
python3 -O research/work-items/RE-004-node94-packed-date-add-rust/validate.py
python3 -O research/work-items/RE-004-node94-packed-date-add-rust/verify_recorded.py
```

The validator explicitly pins compiler commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`. It builds this library and the
input-only synthetic client at opt0 and opt3 twice, compares against a frozen
pre-Rust cycle-partition oracle and compiles 14 wrong variants. It executes
only new Rust native binaries, never the captured node or an emulator.
See the [evidence packet](../../research/work-items/RE-004-node94-packed-date-add-rust/README.md)
and [domain proof](../../research/work-items/RE-004-node94-packed-date-add-rust/PROOF.md).
New implementation and documentation are MIT; imported bytes/disassembly keep
the target artifact's upstream rights.
