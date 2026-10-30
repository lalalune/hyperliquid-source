# foundation-reserve-grow-94: what does the append window at 0x1520ce0 compute?

- Component: `foundation`, a bounded part of its first time/quantity mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference pin: can1357/hl `999556f6e0a474b8312db96ec3149e1c44e97c23` was a
  search lead only. No inferred implementation was copied, and no reference
  label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call
  edges; its source-level name and types remain inferences.
- Included: the 97-byte FDE window, its fifteen int3 padding bytes, the
  capacity gate, the memcpy fast path, the unnamed grow call and its
  retry jump, and the memcpy slot relocation record.
- Excluded: the grow callee body at `0x1564e60`, the caller of this window,
  other append/copy helpers, all #115 addresses, target execution, Rust
  reconstruction, and complete caller behavior.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library
code from private helpers. A reference label or a matching string cannot
establish that mapping. This packet connects one complete, independently
disassembled FDE window to a named platform binding (memcpy, through its
relocation record) and to an unnamed grow routine whose call-and-retry
shape is visible in the bytes. It establishes a concrete small entrypoint
for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or
test in the tree mentions `0x1520ce0`, and no open pull request title
mentions it or a reserve/grow helper. (One title grep hit, a dex-registry
inventory of "reserved names", is unrelated.) Its bytes overlap nothing in
the hour packet (`0x14509f0`), the days packet (`0x1450810`), the secs-f64
packet (`0x1450a60`), the twin-widen packet (`0x151f0a0`/`0x151f100`), or
the millis packet's calendar helper (`0x151f6f0`–`0x151f86a`).

A correction to the scouting note that proposed this window: the GOT-slot
call is **not** a grow routine. Its relocation record names
`memcpy@GLIBC_2.14`; the grow step is the direct call at `0x1564e60`,
followed by a jump back into the fast path. The packet below follows the
bytes, not the scout's summary.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python
3.12.3, GNU objdump 2.42 (Binutils for Ubuntu), GnuPG 2.4.4. The checker and
tests use Python's standard library only. No llvm-objdump, Ghidra, or Java
was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in
CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_reserve_grow.py --check research/work-items/foundation-reserve-grow-94/evidence.json
python3 -m unittest tests.test_foundation_reserve_grow -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured
service, networked node, chain operation, or model-backed program was
executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x1520ce0 --stop-address=0x1520d50 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `reserve.objdump.txt` file retains complete disassembly of the window
including its padding and the start of the next window. The
`reserve.frames.txt` file retains the FDE record at `.eh_frame` section
offset `0x153f4` (this window). The checker locks this raw FDE record and
its shared CIE, and reads their PC/range fields. It does not add a second
general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra
rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`;
the retained `.eh_frame` has equal file offsets and VAs. The tools resolve
sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x153f4` describes `[0x1520ce0, 0x1520d41)`, 97 bytes. GNU's
  independent frame dump agrees. Complete linear decoding from that start
  gives the instruction sequence below, ending exactly at the FDE endpoint.
- Fifteen `int3` bytes (`0xcc`) pad the window after the FDE end, up to
  the next window start at `0x1520d50`. The checker locks the 97-byte body
  and the padding separately.
- A `R_X86_64_GLOB_DAT` relocation maps slot `0x576dfe0` to symbol index 6,
  addend 0, named `memcpy@GLIBC_2.14`. The stored file bytes at the slot
  are zero, as expected before dynamic relocation.

### Body behavior: one capacity gate, one memcpy, one grow call and retry

Decoded from the FDE start, the window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x1520ce0` | `push r15; push r14; push rbx` | Callee-saved registers |
| `0x1520ce5` | `mov rbx,rdi` | Object pointer |
| `0x1520ce8` | `mov rax,(rdi)` | Capacity field |
| `0x1520ceb` | `mov r14,0x10(rdi)` | Length field |
| `0x1520cef` | `sub rax,r14` | Remaining = capacity - length (unsigned) |
| `0x1520cf2` | `cmp rax,rdx` | Requested amount against remaining |
| `0x1520cf5` | `ja 0x1520d19` | Requested > remaining goes to the slow arm |
| `0x1520cf7` | `mov rdi,0x8(rbx)` | Base pointer |
| `0x1520cfb` | `add rdi,r14` | Destination = base + length |
| `0x1520cfe` | `mov r15,rdx` | Requested amount saved |
| `0x1520d01` | `call *slot 0x576dfe0` | memcpy(destination, entry rsi, requested) |
| `0x1520d07` | `add r14,r15` | New length |
| `0x1520d0a` | `mov 0x10(rbx),r14` | Length field updated |
| `0x1520d0e` | `xor eax,eax` | Return 0 |
| `0x1520d10` | `mov rdx,r15` | Requested amount restored to rdx |
| `0x1520d13` | `pop rbx; pop r14; pop r15; ret` | Epilogue |
| `0x1520d19` | slow arm (see below) | Grow call, then retry |

The fast path passes the entry values of `rsi` and `rdx` to memcpy
unchanged: the second memcpy argument is the window's own entry `rsi`,
and the byte count is the requested amount `rdx`, with no scaling. The
three fields are read as capacity at `0(rdi)`, base pointer at `8(rdi)`,
and length at `0x10(rdi)`; whether capacity and length count bytes or
elements is not proven beyond the unscaled memcpy count, and the packet
does not claim it.

The gate is exact over the unsigned 64-bit domain. The `ja` branch is
taken exactly when the requested amount is strictly greater than the
remaining capacity:

| Capacity / length / requested | Remaining | Static path |
| --- | --- | --- |
| `10 / 4 / 5` | `6` | Fast path (memcpy, length becomes 9) |
| `10 / 4 / 6` | `6` | Fast path (memcpy, length becomes 10) |
| `10 / 4 / 7` | `6` | Slow arm |
| `0 / 0 / 0` | `0` | Fast path (zero-byte memcpy, length unchanged) |
| `0 / 0 / 1` | `0` | Slow arm |

The boundary is inclusive on the fast side: a request exactly equal to
the remaining capacity does not take the slow arm. The subtraction is
unsigned 64-bit arithmetic; what happens when length exceeds capacity
(wrap-around) is not observed and not claimed.

### The slow arm: grow call, then retry without re-checking

The slow arm loads `ecx = 1` and `r8d = 1`, then calls `0x1564e60`
(direct `e8` call) with `rdi` = object, `rsi` = old length, `rdx` =
requested amount, saving entry `rsi` in `r15` and entry `rdx` in `r14`
across the call. After the call it restores `rsi` and `rdx`, reloads the
length field from `0x10(rbx)`, and jumps back to `0x1520cf7` — directly
into the memcpy path, **without re-checking capacity**. The callee has
its own FDE, `[0x1564e60, 0x1564eee)`, 142 bytes, which the checker locks
for extent only; its body is not decoded here.

## Inferences and unknowns

- **Inferred:** this is an append-style helper for a byte buffer with a
  capacity/length/base layout, with a grow step on the slow path. The
  memcpy binding, the unscaled count, the exact inclusive gate, and the
  call-and-retry shape support that label. The binary has no recovered
  symbol name here. Neither the source-level function name, the owning
  type, nor the buffer's element type is proven.
- The slow-arm callee reads naturally as "grow the buffer to fit the
  request", because the retry jumps straight into the memcpy path — but
  that reading is an inference from the retry shape, not a decoded body:
  the callee could also fail, shrink, or replace the buffer, and its
  effect on the capacity field is not observed.
- The caller of this window, its other arguments, and whether other
  callers exist are not closed. No call-site census is claimed.
- The `ecx = 1` / `r8d = 1` constants in the slow arm are retained but
  unexplained: they may be flags, counts, or mode selectors, and the
  packet does not assign them a meaning.

## Implementation, controls and results

No independent Rust implementation/build, lockfile, code equivalence
comparison, normalization mask, behavioral execution, or whole-ELF match is
claimed. All are **not yet implemented/measured**. The raw instruction bytes
in the checker are static evidence locks, not executable reconstruction or
transplanted code. New checker/test/documentation code is independently
authored; imported bytes and disassembly retain the artifact's original
rights.

The repository's required verification, catalogue, and test recipes are run
for this change below. After the change, the new checker and the new unit
test pass. The added controls use the authenticated
real target (explicitly skip if LFS is absent), not fabricated behavior
fixtures. They reject:

- wrong identity and truncation;
- changed capacity/length/base field offsets, gate opcode, or branch target;
- changed memcpy call slot, grow call target, or retry jump target;
- changed slow-arm immediates, argument shuffles, or restores;
- changed FDE extent, CIE bytes, callee FDE extent, or relocation record;
- changed padding bytes.

Structural mutations deliberately bypass only the digest gate in the test
helper, so they exercise downstream checks instead of all failing at
SHA-256. The command-line tool always authenticates the complete target
first.

**No progress gate requested.** Foundation's four gates and generated
progress files stay unchanged. The denominator here is one bounded window,
not all buffer helpers. Next question: decode the grow callee body at
`0x1564e60` far enough to confirm or reject the grow reading, before
reconstructing Rust.
