# RE-008: node #115 position field M (115th stage): the decoder rejects 0 and the writer skips 20

- Component ID: abci. Question: open PR #6453 found that the position decoder `0x1bb6b90` gives a missing M the default 0x14 (20), and that its end-of-map code also turns an M of 0 into 20. Open PR #6224 mapped the position writer `0x448ae20`. Can M change when a position is written and read again? For example, is a stored M of 0 written as 0 and read back as 20?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6453 and #6224. It does not depend on their files.
- Claim status: instruction bytes, jump-table entries, branch and call targets, relocation values and strings are observations. "Not seen", "default", "error" and the names of the MessagePack markers are inferred labels. The binary was not executed.
- Scope included: the M arm of the position decoder, the M value decoder `0x2d15d00` down to the integer read `0x34861d0` and its error code, the expected text, and the two M sites in the writer `0x448ae20`. Scope excluded: the value encoder `0x4648d30`, the non-integer marker arms, and the other position fields. No gate changes.

## Result

| Case | Decoder | Writer | Round trip |
|---|---|---|---|
| M missing | default 0x14 (20) | — | reads as 20 |
| M = 20 | accepted | leaves out key and value | reads back as 20 |
| M = other value 1..0xffffffff | accepted | writes key `M` and the u32 at `+0x38` | same value is read back, if the value encoder `0x4648d30` writes it unchanged (not read here) |
| M = 0 in the input | rejected: `invalid value: ..., expected a nonzero u32` | — | — |

So no mismatch is found. The decoder never gives 0 to the position, so the end-of-map step "0 becomes 20" in #6453 only fills a missing M. The value 0 is the "not seen" mark, not a value that can be decoded. The writer leaves out exactly the default value 20, and a missing M reads back as 20.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/position_m_zero_115.py --check
python3 -m unittest tests.test_position_m_zero_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The eight `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: decoder M arm

- The M arm `0x1bb6f07` starts with `cmp dword [rsp+0x48],0; jne duplicate`. So 0 at `rsp+0x48` means "M not seen".
- It calls `0x2d15d00` (`0x1bb6f18`). On tag 9 (success) it copies the 4-byte result to `rsp+0x48` (`0x1bb6f29`).
- At the end of the map (`0x1bb7b4c`), `mov r14d,[rsp+0x48]; test r14d,r14d; cmove r14d,ecx` with `ecx = 0x14`. A field that is still 0 gets 20.

## Evidence 2: the M value decoder rejects 0

- `0x2d15d00` loads the 13-byte name `MarginTableId` (`0x616a3f`) and jumps to `0x17e4bb0`.
- `0x17e4bb0` calls through slot `0x64e25d8` (`0x17e4cdd`). The slot has an `R_X86_64_RELATIVE` relocation to `0x34861d0`. On tag 9 it returns the 4-byte value.
- `0x34861d0` uses the jump table `0x78db10` for markers `0xc0` to `0xe0`. Each integer marker arm tests the value:

| Marker | Arm | Test | A failing value goes to |
|---|---|---|---|
| positive fixint (kind 0) | `0x3486230` | `test cl,cl; jne ok; jmp` | `0x34864c8` |
| `0xcc` u8 | `0x34862bc` | `test ecx,ecx; je` | `0x34864c8` |
| `0xcd` u16 | `0x3486334` | `test dx,dx; je` | `0x34864c8` |
| `0xce` u32 | `0x3486286` | `test edx,edx; je` | `0x34864c8` |
| `0xcf` u64 | `0x34863fe` | range 1..0xffffffff (`movabs rcx,0xffffffff00000000; lea; inc; cmp; jb`) | `0x34864e3` |
| `0xd0` i8 | `0x348638b` | `test rcx,rcx; jle` | `0x348654c` |
| `0xd1` i16 | `0x3486301` | `test dx,dx; jg ok; ...; jmp` | `0x34864d7` |
| `0xd2` i32 | `0x3486254` | `test edx,edx; jg ok; ...; jmp` | `0x34864d7` |
| `0xd3` i64 | `0x34863bf` | range 1..0xffffffff (`jae ok; jmp`) | `0x34864d7` |
| negative fixint (`0xe0`) | `0x34862ee` | `test cl,cl; jle` | `0x34864d3` |

- All error entries set an "unexpected" value (tag 1 unsigned, with 0 at `0x34864c8`; tag 2 signed) and meet at `0x34864ed`. That code passes the template `0x446a6b` (`invalid value: `, `, expected `) and an expected value whose vtable entry `0x646c068` is relocated to `0x38dbaa0`. `0x38dbaa0` writes the 13-byte text `a nonzero u32` (`0x9451ad`). Then it calls `0x3046740`.

## Evidence 3: the writer skips 20

- The writer reads M at `+0x38` (`0x448ae5d`) and keeps it at `rsp+0x24` (`0x448ae7d`).
- The field count adds 1 for M only when `M != 0x14` (`cmp r8d,0x14; setne bpl`, `0x448ae82`).
- At the M site (`0x448aff4`), `cmp dword [rsp+0x24],0x14; je 0x448b054` skips M. Otherwise it loads `rcx = rbx+0x38`, the 1-byte key `M` (`0x7d13c1`) and calls `0x4648d30`.

## Implementation and comparison

The tool pins 19 instruction byte runs (each with its meaning). It also checks: the jump-table entry of each integer marker, each zero test and the target of its branch, the two relocations, five call and branch targets, four string loads and the template pieces. Tests change bytes in a copy of the image and expect rejection. Where a change sits inside a pin, the test removes that pin, so a derived check must catch the change. Alternatives considered: decoding a sample position with M = 0 by running the code (not allowed for this repository).

## Results and limitations

- Result: M is a nonzero u32 with default 20. The decoder rejects 0. The writer leaves out 20. A missing M reads as 20. No case is found where a written M reads back as a different value.
- Limits: the value encoder `0x4648d30` is not read. The arms for non-integer markers (nil, bool, float and others) are not mapped; this packet does not claim what they do. The marker names come from the MessagePack format and are labels, not observations.
