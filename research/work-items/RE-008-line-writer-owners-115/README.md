# RE-008: node #115 line writers (eighth stage): who owns the 32 daily writers

- Component ID: abci. Question: the seventh stage (open PR #5872) found the daily writer constructor `0x1546700` (slot `0x64e0f98`, 32 calls) and the hourly constructor `0x1546000` (slot `0x64e0fa0`, 27 calls), and mapped where writers go in two of the four functions that also build observers. It left open the name each daily call passes, how the hourly calls relate to the daily ones, and the two other mixed functions `0x2af45f0` and `0x2cc1120`.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5861 and #5872. It does not depend on their files.
- Claim status: instruction bytes, offsets, string bytes, relocations and call censuses are observations. "Daily", "hourly", "writer", "name", "flush byte", "first qword" and "tail" are inferred labels from the call shapes, sizes and the sixth and seventh stages. The binary was not executed.
- Scope included: the argument setup just before each of the 32 daily calls and just after it; the first 0x4d bytes of the hourly constructor; the writer move in `0x2af45f0` and `0x2cc1120`. Scope excluded: where the 21 register names are built, where writers go after the call in the other sites, and the consumer `0x5a81ed0`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/line_writer_owners_115.py --check
python3 -m unittest tests.test_line_writer_owners_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The three `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: names

The tool decodes up to four instructions that end at each daily call (`lea rsi, [rip+x]`, `mov edx, n`, `lea rdi, [rsp+d]`, `mov rdi, rbx`, `mov rsi, reg`, `mov rdx, [rsp+d]`, `lea reg, [rsp+d]`).

- 11 calls pass a static string and its length:

| Call | Name | String |
|---|---|---|
| `0x2af59e6` | `mempool_txs` | `0x606289` |
| `0x2cc2703` | `mempool_txs` | `0x60f4b5` |
| `0x47809ae` | `tcp_traffic` | `0x7e1be8` |
| `0x47833db` | `tcp_lz4_stats` | `0x7e1c86` |
| `0x51d06f8` | `evm_block_and_receipts` | `0x91fd49` |
| `0x51d0918` | `dex_user_clearinghouse_states` | `0x91c33c` |
| `0x5a3965d` | `visor_abci_states` | `0x93b0d0` |
| `0x5a6c42c` | `abci_digest_quorum` | `0x93a6d8` |
| `0x5a6c45c` | `abci_hashes` | `0x93a6ea` |
| `0x5a72050` | `validator_latency_ema` | `0x93b1d7` |
| `0x5b57a6a` | `evm_block_and_receipts` | `0x93ed59` |

- 21 calls pass the name pointer in a register (`mov rsi, reg`) with the length from the stack. In several of them (for example `0x3d4ca13`, `0x478419e`, `0x4da6b1c`, `0x51c9e3e`, `0x57c5b23`) a format call through slot `0x64df6e8` comes shortly before, so the name is built at run time there (inference). The per-call list is in `evidence.json`.

## Evidence 2: the hourly constructor takes a daily writer

- `0x1546011` `mov rbx, rsi`; `0x154603f` `mov [rbx+0x98], r15d` (date); `0x1546046` `mov byte [rbx+0xa8], 1` (hourly byte). The hourly constructor writes into the writer passed as its second argument.
- Each of the 27 hourly calls comes directly after a daily call, and its `rsi` is that daily call's output buffer (the tool checks every pair). 5 daily calls have no hourly call: `0x2e1caf1`, `0x4771e53`, `0x47833db` (`tcp_lz4_stats`), `0x51c9e3e`, `0x5a72050` (`validator_latency_ema`).
- In 12 of the 27 pairs, the next instruction is `mov byte [rsp+d+0xaa], 1`, where `rsp+d` is the hourly output. Per the seventh stage, `+0xaa` is the writer's flush byte.

## Evidence 3: the two remaining mixed functions

`0x2af45f0` and `0x2cc1120` have the same shape. Each builds a daily `mempool_txs` writer, converts it with the hourly constructor, and sets the flush byte. It then moves the writer in two parts into a stack struct:

| | `0x2af45f0` | `0x2cc1120` |
|---|---|---|
| hourly writer | `rsp+0x150` | `rsp+0x16b0` |
| flush byte = 1 | `0x2af5a02` (`rsp+0x1fa`) | `0x2cc271f` (`rsp+0x175a`) |
| first qword to `r15` | `0x2af5a0a` | `0x2cc2727` |
| 0xa8-byte tail to temp | `0x2af5a22` → `rsp+0x920` | `0x2cc273f` → `rsp+0x1440` |
| first qword stored | `0x2af5aa0` → `rsp+0x658` | `0x2cc27c3` → `rsp+0x7e8` |
| tail copied | `0x2af5ab8` → `rsp+0x660` | `0x2cc27db` → `rsp+0x7f0` |
| struct passed in `rdi` | `rsp+0x640` (`0x2af5aee`) | `rsp+0x7d0` (`0x2cc280a`) |
| call | `0x2af5b03` | `0x2cc281f` |

The writer lands at `+0x18` of the struct. Both calls go through slot `0x64e74d8` (relocated to `0x5a81ed0`). In both functions the observer is copied separately with `mov edx, 0x260`. This is the 0xa8 copy seen at `0x2af5a22` in the seventh stage: it moves the writer's tail, not a writer into an observer.

## Implementation and comparison

The tool pins 23 instruction byte runs, 6 RIP-relative call targets and 3 relocations, decodes the argument setup of all 32 daily calls, and checks that every hourly call is paired with a daily call. Tests mutate one byte at a time in a copy of the image and expect rejection (6 mutation tests). Alternatives considered: tracing each register name back to its format template (bounded out); emulation (not allowed for this repository).

## Results and limitations

- Result: of the 32 daily writers, 27 are converted to hourly writers, and 12 of those have the flush byte set right after. In all four mixed functions, writers are kept outside the observers.
- Limits: the decoder covers only the instruction shapes listed in Evidence 1, and nothing after the hourly call except the flush byte. The register names, where writers go in the 28 non-mixed sites, the consumer `0x5a81ed0`, and the struct fields other than `+0x18` are not mapped.
- Next lead: map `0x5a81ed0` and what it does with the struct and its writer at `+0x18`.
