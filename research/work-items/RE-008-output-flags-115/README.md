# RE-008: node #115 output command-line flags and the setter's struct bytes (eleventh stage)

- Component ID: abci. Question: the tenth stage (open PR #5878) found that the setter `0x51cf360` sets the global extra-flush byte `0x64ffe50` when its argument byte `+0x20` is set, and panics when bytes `+0x21` and `+0x22` are both set. It named `+0x20` `disable-output-file-buffering` by inference only.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5876 and #5878. It does not depend on their files.
- Claim status: instruction bytes, offsets, lengths, string bytes, relocations and call censuses are observations. "Flag lookup", "byte result", "string result", "subcommand", "output struct" and "the setter's struct is a different type" are inferred labels from the call shapes, strings and layout. The binary was not executed.
- Scope included: the flag reader `0x564d390` (all lookups and the struct writes); its two callers; the `replica-cmds-style` value match; the setter's byte reads, its global-byte store, its pair panic and seven writer-name gates. Scope excluded: the bodies of `0x4e4c8e0` and `0x4e4ca30`; the code that turns the reader's struct into the setter's argument; setter bytes `+0x18` and `+0x23`; the argument definitions in `0x5656bf0`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/output_flags_115.py --check
python3 -m unittest tests.test_output_flags_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The three `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the flag reader and its two callers

`0x564d390` is reached through slot `0x64ebcb8` (`R_X86_64_RELATIVE`) from two calls in `0x5654bf0`:

| Call | Tag stored after it | Subcommand name compared before it |
|---|---|---|
| `0x56550de` | `mov qword [rbx], 2` (`0x56550e4`) | `run-non-validator` (16 bytes at `0x454460` plus `r` at `0x453cb0`, `pcmpeqb`) |
| `0x56551e9` | `mov qword [rbx], 3` (`0x56551ef`) | `run-validator` (`movabs` `run-vali` and `alidator` at `0x5654e03`/`0x5654e10`) |

Both write the reader's output at `rbx+0x8`.

## Evidence 2: one lookup per long name, one struct offset per result

The reader loads each name with `lea rsi, [rip+...]` and `mov edx, <length>`, then calls `0x4e4c8e0` (byte result in `al`) or `0x4e4ca30` (string result). Byte results are saved to a stack slot or register, then written by the block `0x564d5ad .. 0x564d628`:

| Long name | Length | Saved to | Output offset |
|---|---|---|---|
| `write-trades` | 12 | `[rsp+0xe]` | `+0x18` |
| `write-fills` | 11 | `[rsp+0xd]` | `+0x19` |
| `write-raw-book-diffs` | 20 | `[rsp+0xc]` | `+0x1a` |
| `write-order-statuses` | 20 | `[rsp+0xb]` | `+0x1b` |
| `write-misc-events` | 17 | `[rsp+0xa]` | `+0x1c` |
| `write-hip3-oracle-updates` | 25 | `[rsp+0x9]` | `+0x1d` |
| `write-user-clearinghouse-states` | 31 | string | `+0x0 .. +0x18` (`0x8000000000000000` when absent) |
| `write-system-and-core-writer-actions` | 36 | `[rsp+0x8]` | `+0x1e` |
| `disable-output-file-buffering` | 29 | `[rsp+0x7]` | `+0x1f` |
| `batch-by-block` | 14 | `[rsp+0x6]` | `+0x20` |
| `stream-with-block-info` | 22 | `r15d` | `+0x21` |
| `serve-evm-rpc` | 13 | `ebp` | `+0x22` |
| `serve-info` | 10 | `r13d` | `+0x23` |
| `replica-cmds-style` | 18 | string, matched | `+0x24` |

The first eight bytes go out as one qword at `+0x18` (`movd` of the four `[rsp+0xe..0xb]` bytes, `pinsrw` of `[rsp+0xa]`/`[rsp+0x9]` as word 2 and `[rsp+0x8]`/`[rsp+0x7]` as word 3); the rest are single byte stores (`0x564d616 .. 0x564d625`). `replica-cmds-style` is matched to `actions` -> 0, `actions-and-responses` -> 1 (`pcmpeqb` against `0x450640` and `0x454130`), `recent-actions` -> 2; any other value panics.

## Evidence 3: the setter's bytes follow the same order, one byte later

The setter reads qwords `+0x0`, `+0x8`, `+0x10` and bytes `+0x18 .. +0x23` (`0x51cf383 .. 0x51cf3d5`). For seven bytes a `test`/`cmp` is followed by `je` whose fall-through is a `lea rax` of a writer name:

| Setter byte | Gate | Writer name | Reader flag at one byte lower |
|---|---|---|---|
| `+0x19` | `0x51cf40b` | `node_trades` | `write-trades` |
| `+0x1a` | `0x51cf4cf` | `node_fills` | `write-fills` |
| `+0x1b` | `0x51cf742` | `node_raw_book_diffs` | `write-raw-book-diffs` |
| `+0x1c` | `0x51cfe07` | `node_order_statuses` | `write-order-statuses` |
| `+0x1d` | `0x51cfc14` | `misc_events` | `write-misc-events` |
| `+0x1e` | `0x51d0031` | `hip3_oracle_updates` | `write-hip3-oracle-updates` |
| `+0x1f` | `0x51d0262` | `system_and_core_writer_actions` | `write-system-and-core-writer-actions` |
| `+0x20` | `0x51cf3da` sets the global byte | — | `disable-output-file-buffering` |
| `+0x21`, `+0x22` | pair panic `0x51d0aba` "cannot set both batch_by_block and stream_with_block_info" | — | `batch-by-block`, `stream-with-block-info` |

Inference: the setter's argument is a different struct from the reader's output, with one extra byte at `+0x18` and the flags moved up by one. Under that reading `+0x20` is `disable-output-file-buffering`, which supports the tenth stage's label. The code that builds the setter's argument from the reader's output is not found here.

## Implementation and comparison

The tool pins 14 name references, lengths and lookup calls, 12 result stores, the struct-write block, the style match, the setter's read block, its global-slot load and panic message, seven gates and two subcommand tags, then recomputes the reader's call census. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: tracing the async future that carries the argument to the setter (`r13 = rbx+0xae8` before `0x2aec025`; bounded out), and emulation (not allowed for this repository).

## Results and limitations

- Result: the reader's byte for `disable-output-file-buffering` is `+0x1f`, and the setter's flag order matches the reader's order one byte later; the global extra-flush byte follows the `disable-output-file-buffering` flag under that alignment.
- Limits: the conversion between the two structs is not mapped, so the one-byte shift is an inference from the order of seven writer names and the panic text. Setter byte `+0x18` (read at `0x51d0856`) and `+0x23` (tested near the `evm_block_and_receipts` writer) are not named. The bodies of `0x4e4c8e0` and `0x4e4ca30` are not mapped.
- Next lead: find where the setter's argument is built from the `run-non-validator` / `run-validator` payload, and name setter bytes `+0x18` and `+0x23`.
