# RE-001: node #115 staking arms in the action-error display

- Component: staking. No acceptance gate is requested.
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Question: which display arms name staking, delegation, jailing or commission
  failures, and which constant is embedded in the manual-unjail arm?

The body is one FDE, `0x46ef710..0x46f312f` (14,879 bytes, 3,478 instructions).
Its prologue loads a `u16` from `[rdi]`, indexes 418 relative `i32` slots at
`.rodata` `0x7d8c1c`, and jumps. Those 418 targets are distinct instruction
boundaries inside this FDE. The next slot lands at `0x46f3150`, which is not an
instruction boundary. The prologue contains no range compare. There is no
direct `e8`/`e9` to the entry. One `R_X86_64_RELATIVE` slot, GOT `0x64e28a0`,
points at the entry; 19 RIP-relative call, tail, or load sites use that slot.
The other 403 arms are outside this selection. This is not stake accounting,
a jailing transition, or a source-file attribution: `c_staking/jailing.rs` is a
different pair of bodies.

## Selected arms

Selection is a case-insensitive substring match of static text, or of format
literals, against `jail`, `delegat`, `stake`, `unjail`, `commission`, `staker`,
and `undelegate`.

| u16 | Arm | Text |
| ---: | --- | --- |
| 51 | `0x46f20bf` | Delegate amount cannot be zero. |
| 159 | `0x46efdd0` | Can only manually unjail once every {arg} seconds |
| 160 | `0x46f1816` | Jailed until {arg} |
| 184 | `0x46efcae` | Insufficient delegatable balance for priority order |
| 267 | `0x46f1476` | Insufficient balance to delegate |
| 268 | `0x46f0374` | Validator has delegations disabled |
| 269 | `0x46f0e2f` | Insufficient balance to undelegate |
| 270 | `0x46f03c7` | Cannot undelegate during lockup period after delegating or voting. |
| 273 | `0x46f1a00` | Insufficient delegations to propose |
| 278 | `0x46f0dd8` | Insufficient delegations to vote |
| 282 | `0x46f0ea3` | Insufficient stake |
| 306 | `0x46f1e0b` | Validator commission must be between 0 and 100%. If commission increases, it cannot exceed 1%. |
| 324 | `0x46f0954` | Cannot unregister validator with delegations |
| 325 | `0x46f1598` | Self delegation insufficient |
| 358 | `0x46f1c06` | Invalid staker |

Static arms put the bytes in `rsi`, the length in `edx`, and tail-jump through
`[[rsi+8]+0x18]`. Discriminant 159's template is the bytes at `0x43e392`. Its
only argument is the immediate `movabs rax, 0x4072c00000000000`, which is
binary64 300.0, passed to the formatter at `0x1688740`. That formatter loads
the qword with `movsd` and tests formatter flag `0x10000000`. The decimal
spelling it prints is not recovered. Discriminant 160's template is at
`0x44f7f3`. The arm does `add rdi, 4` and passes that address to
`0x3d526f0`. The helper's value format is not recovered, so this does not
establish a timestamp width or unit.

The thirteen static strings, both templates, and the 300.0 bit pattern are
also exposed by `src/node115-staking-error-text`. That crate does not format
through the native printer.

## Reproduce

```sh
python3 research/work-items/RE-001-node115-staking-error-display/collect.py --output work/staking-error-display --check
python3 -m unittest tests/test_staking_error_display_115.py -v
cargo test --locked --offline --manifest-path src/node115-staking-error-text/Cargo.toml
```

Ubuntu, Python 3, GNU binutils 2.42. The collector checks the digest before
objdump, rejects a private one-byte change of the prologue, table, float
formatter head, and the delegate-balance string, and checks the Rust source
still contains the native literals. No captured instruction is executed.

No component gate, whole-ELF comparison, root Cargo workspace, or network
action is claimed. Next: find which of the 19 indirect sites construct
discriminants 159 and 160, and close the comparison against the embedded
300.0 interval.
