# foundation-twin-once-flag-94: what do the two flag state-machine windows compute?

- Component: `foundation`, a bounded part of its first time/quantity mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference pin: can1357/hl `999556f6e0a474b8312db96ec3149e1c44e97c23` was a
  search lead only. No inferred implementation was copied, and no reference
  label is treated as established fact below.
- Claim: observations about two target instruction windows and their
  data/call edges; their source-level names and types remain inferences.
- Included: the 91-byte and 82-byte FDE windows, their int3 padding, the
  entry branches, the shared global-slot check, the shared TLS-zero-test
  callee, the atomic swap, and the syscall-slot tail jump with its
  immediates.
- Excluded: the meaning of the global cell, the thread-local cell, and the
  syscall immediates; the callers of these windows; other flag helpers;
  all #115 addresses, target execution, Rust reconstruction, and complete
  caller behavior.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library
code from private helpers. A reference label or a matching string cannot
establish that mapping. This packet connects two complete, independently
disassembled FDE windows that share all three of their call/data edges to
a single observed state machine, and it separates what the bytes prove
from what they do not. It establishes a concrete small entrypoint for
further reconstruction without declaring the component mapped.

This window pair was checked for overlap before building: no work-item,
tool, or test in the tree mentions `0x15080c0` or `0x15081b0`, and no open
pull request title mentions either address or a once-flag helper. Its
bytes overlap nothing in the hour packet (`0x14509f0`), the days packet
(`0x1450810`), the secs-f64 packet (`0x1450a60`), the twin-widen packet
(`0x151f0a0`/`0x151f100`), the reserve-grow packet (`0x1520ce0`), or the
millis packet's calendar helper (`0x151f6f0`–`0x151f86a`).

Two corrections to the scouting note that proposed this pair. First, the
low-bit and nonzero entry paths do **not** take a separate error arm:
they skip the global-slot check and join the atomic-swap path directly.
Second, the old-value-2 path is **not** a panic call: it is a tail jump
through the imported `syscall` slot, and no panic message or source
location record is loaded anywhere in either window. The packet below
follows the bytes, not the scout's summary.

A warning about the disassembly labels: GNU objdump annotates all three
windows here with the same nearest preceding symbol name, at implausibly
large negative offsets. Those labels are objdump's closest-symbol
artifact, not recovered function names, and nothing in this packet relies
on them.

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
python3 tools/foundation_twin_once_flag.py --check research/work-items/foundation-twin-once-flag-94/evidence.json
python3 -m unittest tests.test_foundation_twin_once_flag -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured
service, networked node, chain operation, or model-backed program was
executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x15080c0 --stop-address=0x1508120 artifacts/node/94/hl-node
objdump -d --start-address=0x15081b0 --stop-address=0x1508210 artifacts/node/94/hl-node
objdump -d --start-address=0x4eef080 --stop-address=0x4eef090 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `twin1.objdump.txt` file retains complete disassembly of the first
window including its padding. The `twin2.objdump.txt` file retains
complete disassembly of the second window including its padding. The
`callee.objdump.txt` file retains complete disassembly of the shared
callee. The `twins.frames.txt` file retains excerpts selecting the FDEs
at `.eh_frame` section offsets `0x13600` (first window), `0x13624`
(second window), and `0x280d50` (callee). The checker locks these raw FDE
records and their shared CIE, and reads their PC/range fields. It does
not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra
rebase. The ELF section table maps `.text` with file offset = VA - `0x1000`;
the retained `.eh_frame` has equal file offsets and VAs. The tools resolve
sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x13600` describes `[0x15080c0, 0x150811b)`, 91 bytes. GNU's
  independent frame dump agrees. Complete linear decoding from that start
  gives the instruction sequence below, ending exactly at the FDE endpoint.
- Five `int3` bytes (`0xcc`) pad the first window after the FDE end, up to
  the next window start at `0x1508120`. The checker locks the 91-byte body
  and the padding separately.
- `.eh_frame+0x13624` describes `[0x15081b0, 0x1508202)`, 82 bytes. GNU's
  independent frame dump agrees.
- Fourteen `int3` bytes pad the second window after the FDE end, up to the
  next window start at `0x1508210`. The checker locks the 82-byte body and
  the padding separately.

### First window body: flag from the incoming byte

Decoded from the FDE start, the first window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x15080c0` | `push rbx` | Callee-saved register |
| `0x15080c1` | `cmp $0x2,%sil` | Flag equals 2? |
| `0x15080c5` | `je 0x15080e8` | Flag 2 returns immediately |
| `0x15080c7` | `test $0x1,%sil` | Flag low bit? |
| `0x15080cb` | `jne 0x15080df` | Odd flag skips to the swap |
| `0x15080cd` | `mov slot 0x576e720(%rip),%rax` | Global slot load |
| `0x15080d4` | `mov (%rax),%rax` | Global cell value |
| `0x15080d7` | `shl $1,%rax` | Value shifted left by 1 |
| `0x15080da` | `test %rax,%rax` | Shifted value zero? |
| `0x15080dd` | `jne 0x1508105` | Nonzero goes to the call arm |
| `0x15080df` | `xor %eax,%eax; xchg %eax,(%rdi)` | Atomic swap of 0 into the flag |
| `0x15080e3` | `cmp $0x2,%eax` | Old value equals 2? |
| `0x15080e6` | `je 0x15080ea` | Old 2 takes the syscall arm |
| `0x15080e8` | `pop rbx; ret` | Return |
| `0x15080ea` | syscall arm (see below) | Tail jump, no return |
| `0x1508105` | call arm (see below) | TLS test, then swap |

### Second window body: flag from the object

Decoded from the FDE start, the second window is:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x15081b0` | `push rbx` | Callee-saved register |
| `0x15081b1` | `mov (%rdi),%rbx` | Flag object pointer |
| `0x15081b4` | `cmpb $0x0,0x8(%rdi)` | Flag byte zero? |
| `0x15081b8` | `jne 0x15081cc` | Nonzero flag skips to the swap |
| `0x15081ba` | `mov slot 0x576e720(%rip),%rax` | Same global slot load |
| `0x15081c1` | `mov (%rax),%rax` | Global cell value |
| `0x15081c4` | `shl $1,%rax` | Value shifted left by 1 |
| `0x15081c7` | `test %rax,%rax` | Shifted value zero? |
| `0x15081ca` | `jne 0x15081f2` | Nonzero goes to the call arm |
| `0x15081cc` | `xor %eax,%eax; xchg %eax,(%rbx)` | Atomic swap of 0 into the flag |
| `0x15081d0` | `cmp $0x2,%eax` | Old value equals 2? |
| `0x15081d3` | `je 0x15081d7` | Old 2 takes the syscall arm |
| `0x15081d5` | `pop rbx; ret` | Return |
| `0x15081d7` | syscall arm (see below) | Tail jump, no return |
| `0x15081f2` | call arm (see below) | TLS test, then swap |

### Shared call arm: one tiny callee, one conditional byte set

Both call arms call through the same slot `0x576eb98`, whose
`R_X86_64_RELATIVE` relocation points at `0x4eef080`, FDE
`[0x4eef080, 0x4eef08e)`, 14 bytes, fully decoded:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x4eef080` | `cmpq $0x0,%fs:-0x428` | Thread-local cell zero? |
| `0x4eef08a` | `sete %al` | Return 1 exactly when the cell is zero |
| `0x4eef08d` | `ret` | Return |

The first window's call arm saves `rdi` into `rbx` before the call and
restores it after; the second window already holds its pointer in `rbx`
and needs no save. After the call, both test `%al`: nonzero skips to the
swap, zero stores `1` into byte 4 of the flag object (`0x4(%rdi)` in the
first window, `0x4(%rbx)` in the second) and then jumps to the swap.

### Shared syscall arm: immediates and an import slot, not a panic

Both syscall arms load the same four immediates and tail-jump through the
same slot `0x576ea40`. The first passes the flag object in `rsi` from
`rdi`; the second passes it from `rbx`. Argument order differs only
because the pointer already lives in a different register:

| Item | First window | Second window |
| --- | --- | --- |
| `edi` | `0xca` (202) | `0xca` (202) |
| `rsi` | `rdi` (flag object) | `rbx` (flag object) |
| `edx` | `0x81` (129) | `0x81` (129) |
| `ecx` | `0x1` | `0x1` |
| `eax` | `0` | `0` |
| Control | `jmp *slot 0x576ea40` | `jmp *slot 0x576ea40` |

The slot's `R_X86_64_GLOB_DAT` relocation names dynamic symbol index 19,
`syscall`, addend 0. The stored file bytes at all three shared slots are
zero, as expected before dynamic relocation. No panic message, no source
location record, and no expect helper is loaded anywhere in either
window, so the old-value-2 path is recorded as a syscall-slot tail jump,
not as a panic.

### Shared global slot

The global slot `0x576e720` has an `R_X86_64_RELATIVE` relocation whose
target is `0x5788598`, a cell in `.bss`. Both windows load the qword at
that cell, shift it left by 1, and branch on whether the result is zero.
What the cell holds is not decoded here.

### Observed transitions

As a table over the inputs each window actually reads. Swap outcomes are
stated separately because the old flag value is only known at swap time:

| Window | Input | Path |
| --- | --- | --- |
| First | flag `2` | Return, no swap, no call |
| First | flag odd | Swap directly |
| First | flag even, not 2, global shifted value zero | Swap directly |
| First | flag even, not 2, global shifted value nonzero, TLS cell zero | Call arm returns 1, swap directly |
| First | flag even, not 2, global shifted value nonzero, TLS cell nonzero | Call arm returns 0, byte 4 set to 1, swap |
| Second | flag byte nonzero | Swap directly |
| Second | flag byte zero, global shifted value zero | Swap directly |
| Second | flag byte zero, global shifted value nonzero, TLS cell zero | Call arm returns 1, swap directly |
| Second | flag byte zero, global shifted value nonzero, TLS cell nonzero | Call arm returns 0, byte 4 set to 1, swap |
| Either | swap old value `2` | Syscall-slot tail jump |
| Either | swap old value anything else | Return |

The differences between the twins are exactly four: the flag source
(incoming byte vs byte at `8(rdi)`), the early flag-2 return (first
window only), the swap target register (`(rdi)` vs `(rbx)`), and the
call-arm register save (first window only). The global slot, the call
slot, the syscall slot, and all four syscall immediates are shared.

## Inferences and unknowns

- **Inferred:** these are two near-identical flag state machines, likely
  two entry shapes of one mechanism, given the shared edges and the
  four-point difference list. The binary has no recovered symbol name
  here. Neither the source-level function name, the flag's owning type,
  nor the mechanism's identity is proven.
- The `syscall` import name comes from the relocation record, the same
  kind of edge evidence the reserve-grow packet used for `memcpy`. It
  names the tail-jump slot's import, not the windows themselves, and the
  meaning of the immediates (202, 129, 1) is not decoded in this packet.
- The global cell's contents, the thread-local cell's owner, and the
  meaning of byte 4 of the flag object are not closed. The byte-4 set
  happens only on the call-arm zero path; why that path sets it is
  unknown.
- The callers of both windows, and whether other windows share these
  three slots, are not closed. The byte-pattern scope here is the two
  windows and their three slots only.

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
- changed entry branches, global-slot displacement, or call/syscall slot
  displacements;
- changed swap opcodes, old-2 branch targets, or syscall immediates;
- changed callee bytes, FDE extents, or padding bytes;
- changed relocation records or the syscall symbol name.

Structural mutations deliberately bypass only the digest gate in the test
helper, so they exercise downstream checks instead of all failing at
SHA-256. The command-line tool always authenticates the complete target
first.

**No progress gate requested.** Foundation's four gates and generated
progress files stay unchanged. The denominator here is two bounded windows
sharing three edges, not all flag helpers. Next question: find the
callers of these two windows and check whether other windows share the
global slot, the call slot, or the syscall slot.
