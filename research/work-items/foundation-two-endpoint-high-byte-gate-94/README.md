# foundation-two-endpoint-high-byte-gate-94: what does the 48-byte window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 48-byte FDE window, its zero padding bytes, the two-endpoint gate rule, the signed-byte subtlety shared by both gates, the single confirmed caller and its argument setup, the no-naming-relocation scan, and the one-direct-caller scan.
- Excluded: the meaning of the base pointer, the indices, the limit, and the rejected byte range; the caller's behavior beyond its argument setup; other gate helpers; all #115 addresses; target execution; Rust reconstruction; and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: twenty instructions, no calls inside, unsigned index/limit compares, two signed byte gates that reject exactly the same set through different immediates, and a rule fully determined by those compares. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x3cd2460`, no open pull request title mentions it or two-endpoint-high-byte-gate, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, or later foundation packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_two_endpoint_high_byte_gate.py --check research/work-items/foundation-two-endpoint-high-byte-gate-94/evidence.json
python3 -m unittest tests.test_foundation_two_endpoint_high_byte_gate -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x3cd2460 --stop-address=0x3cd2490 artifacts/node/94/hl-node
objdump -d --start-address=0x3cd2490 --stop-address=0x3cd2d53 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window. The `caller.objdump.txt` file retains complete disassembly of the single confirmed caller FDE. The `frames.txt` file retains excerpts selecting the window FDE at `.eh_frame` section offset `0x1cdd08`, the caller FDE at `0x50f1bc` (whose PC is exactly the window end), and the shared CIE at offset `0x0`. The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000` (segment VA base `0x1343c80`, file offset base `0x1342c80`); the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x1cdd08` describes `[0x3cd2460, 0x3cd2490)`, 48 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x3cd248f` is inside the FDE).
- There are **0 int3 padding bytes**: the next FDE starts exactly at `0x3cd2490`, which is also the caller FDE. The checker locks that record (section offset `0x50f1bc`, PC/range `[0x3cd2490, 0x3cd2d53)`), not the physically adjacent record in `.eh_frame` order (offset `0x1cdd1c`, PC `0x3cd3860`), which is not the next function in address order.
- The window opens directly with the base move — no `endbr64` (an observation, not a scout deviation).

### Body behavior: unsigned span/limit compares, two signed byte gates, no calls

Decoded from the FDE start, the window takes `(rdi, rsi, rdx, rcx)`:

| VA | Instruction | Role |
| --- | --- | --- |
| `0x3cd2460` | `mov %rdx,%rax` | Save the base pointer as the eventual return base |
| `0x3cd2463` | `mov %rsi,%rdx` | Copy the end index for the span subtract |
| `0x3cd2466` | `sub %rdi,%rdx` | `rdx = rsi - rdi` (flags for the unsigned span test) |
| `0x3cd2469` | `jae 0x3cd246e` | Unsigned `rsi >= rdi` continues; else falls to the zero path |
| `0x3cd246b` | `xor %eax,%eax` | Fail path return value 0 |
| `0x3cd246d` | `ret` | Shared by all fail paths |
| `0x3cd246e` | `cmp %rcx,%rdi` | Compare start index against the limit |
| `0x3cd2471` | `jae 0x3cd247b` | Unsigned `rdi >= rcx` skips the start byte check |
| `0x3cd2473` | `cmpb $0xc0,(%rax,%rdi,1)` | Signed-byte compare of `[base+rdi]` against 0xc0 |
| `0x3cd2477` | `jl 0x3cd246b` | Signed byte < -64 fails (see below) |
| `0x3cd2479` | `jmp 0x3cd247d` | Start byte passed, continue to the end gate |
| `0x3cd247b` | `jne 0x3cd246b` | Reached only when `rdi >= rcx`: `rdi > rcx` fails, `rdi == rcx` falls through (check skipped) |
| `0x3cd247d` | `cmp %rcx,%rsi` | Compare end index against the limit |
| `0x3cd2480` | `jae 0x3cd248a` | Unsigned `rsi >= rcx` skips the end byte check |
| `0x3cd2482` | `cmpb $0xbf,(%rax,%rsi,1)` | Signed-byte compare of `[base+rsi]` against 0xbf |
| `0x3cd2486` | `jle 0x3cd246b` | Signed byte <= -65 fails (see below) |
| `0x3cd2488` | `jmp 0x3cd248c` | End byte passed, continue to the return |
| `0x3cd248a` | `jne 0x3cd246b` | Reached only when `rsi >= rcx`: `rsi > rcx` fails, `rsi == rcx` falls through (check skipped) |
| `0x3cd248c` | `add %rdi,%rax` | `rax = base + rdi` |
| `0x3cd248f` | `ret` | |

Rule, with `signed` the signed 8-bit reading of a byte:

- `rsi < rdi` (unsigned) → 0.
- `rdi > rcx` (unsigned) → 0; `rdi == rcx` skips the start byte check.
- `rdi < rcx` and `signed([base+rdi]) <= -65` → 0.
- `rsi > rcx` (unsigned) → 0; `rsi == rcx` skips the end byte check.
- `rsi < rcx` and `signed([base+rsi]) <= -65` → 0.
- Otherwise return `base + rdi`.

### The signed-byte subtlety, stated exactly

The two gates look different but reject exactly the same byte set. The start gate compares against `0xc0` (signed -64) and jumps on `jl`: it fails iff `signed(byte) < -64`, i.e. `signed(byte) <= -65`. The end gate compares against `0xbf` (signed -65) and jumps on `jle`: it fails iff `signed(byte) <= -65`. In unsigned bytes, both reject exactly `0x80..0xbf` and pass everything else — including `0x00..0x7f`, which a "high-byte" reading might wrongly expect to fail. The overflow case proves the point: byte `0x7f` (signed 127) minus -64 is 191, which overflows the signed byte range to -65 with SF == OF, so `jl` (SF != OF) is not taken and the byte passes. The checker locks both immediates, both branch opcodes, and the full accept/reject edge table.

### Scout correction, stated prominently

The round-10 scout note described the byte gates as "byte not in 0xc0..0xff → 0". That is wrong. As shown above, the gates reject only `0x80..0xbf`; bytes `0x00..0x7f` and `0xc0..0xff` pass. The verified rejected set `0x80..0xbf` replaces the scout's set everywhere in this packet. All other scouted elements verified exactly: FDE range, 48-byte body, 0 padding bytes, one caller, no naming relocation.

### Incoming calls: one direct caller, boundary-confirmed

The `.text` byte-pattern scan (70,370,352 bytes) finds exactly one direct `e8` site — `0x3cd2aa2` (bytes `e8 b9 f9 ff ff`), confirmed as an instruction start by linear disassembly from its caller FDE start (`0x3cd2490..0x3cd2d53`). This is explicitly not a complete xref census. The caller's setup immediately before the call is `mov 0x48(%rsp),%rdi; mov 0x28(%rsp),%rsi; mov 0x10(%rsp),%rdx; mov 0x18(%rsp),%rcx`. Caller purpose beyond that setup is not claimed.

### Data edge: no naming relocation

No relocation record of any type in any `.rela.*` section names this window as addend (full-section scan of `.rela.dyn` and `.rela.plt`, counts locked in the checker). The absence of a naming relocation does not identify the window's provenance.

### Symbol hint, explicitly disclaimed

objdump annotates the address with a nearest `ctype` `do_widen` symbol at annotation offset `0x12d59a0`; at that distance it proves nothing, and no stdlib or private provenance is claimed either way.

### Nearest claimed window

Cursor walk loop `0x3c1d690` (packet #46), `0xb4dd0` away; nothing in `0x3cd24xx` claimed.

## Inferences

- The "two-endpoint high-byte gate" label is an inference from the observed rule (two endpoint indices, one limit, byte gates at both ends, pointer return). It is kept separate from the rule itself.
- The rejected range `0x80..0xbf` coincides with the UTF-8 continuation-byte range. That coincidence is an observation only; no encoding, text, or string meaning is claimed for the base, the indices, or the limit.

## Unknowns

- What the base pointer points to, what the indices and limit delimit, what the caller does with the returned pointer or the 0 result, and why exactly `0x80..0xbf` is the rejected set.

## Limits

- No stdlib type, source-level function, field meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
