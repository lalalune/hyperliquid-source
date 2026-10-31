# foundation-tag-dispatched-store-94: what does the 61-byte window compute?

- Component: `foundation`, a bounded part of its first time-conversion mapping task.
- Target: node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository baseline: main `1f8c67c` (Merge PR #34).
- Reference pin: can1357/hl was a search lead only. No inferred implementation was copied, and no reference label is treated as established fact below.
- Claim: observations about one target instruction window and its data/call edges; its source-level name and types remain inferences.
- Included: the 61-byte FDE window, its three int3 padding bytes, the four-way tag dispatch rule, the global-pointer data edge, and the zero-direct-caller scan.
- Excluded: the meaning of the destination, the source value/pointer, and the global pointer's contents, the caller's behavior (there is no direct caller), other tag-dispatched or store helpers, all #115 addresses, target execution, Rust reconstruction, and any family census.

## Why this packet

The component map asks to map time/quantity helpers and distinguish library code from private helpers. A reference label or a matching string cannot establish that mapping. This packet binds one small, previously unclaimed window whose behavior reads directly from its own bytes: zero calls, forward branches only, and a rule fully determined by three tag compares and one rip-relative lea. It establishes a concrete small entrypoint for further reconstruction without declaring the component mapped.

This window was checked for overlap before building: no work-item, tool, or test in the tree mentions `0x5057700`, no open pull request title mentions it or tag-dispatched-store, and its bytes overlap nothing in the hour, millis, duration-guards, days-to-date, secs-f64, twin-widen, reserve-grow, twin-once-flag, set-once, days-seconds, unwrap-guard, twin-take, dealloc-size, dealloc-size-generic, drop-thunk, or later foundation packets.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12.3, GNU objdump 2.42 (Binutils for Ubuntu). The checker and tests use Python's standard library only. No llvm-objdump, Ghidra, or Java was used; GNU `--dwarf=frames` output supplies the retained frame records.

Materialize the pinned submodules and LFS objects as described in CONTRIBUTING, then run:

```sh
make doctor
make verify test catalogue-check
python3 tools/foundation_tag_dispatched_store.py --check research/work-items/foundation-tag-dispatched-store-94/evidence.json
python3 -m unittest tests.test_foundation_tag_dispatched_store -v
```

`make doctor` reported `analysis_ready: true`. No target binary, captured service, networked node, chain operation, or model-backed program was executed. All analysis below is static byte and relocation evidence.

Raw exports were generated with:

```sh
objdump -d --start-address=0x5057700 --stop-address=0x5057740 artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

The `window.objdump.txt` file retains complete disassembly of the window including its padding. There is no caller file: the incoming scan finds zero direct calls, so there is no caller FDE to retain. The `frames.txt` file retains excerpts selecting the CIE at `.eh_frame` section offset `0x0`, the window FDE at `0x2930a8`, and the next FDE at `0x2930bc`. The checker locks these raw FDE records and their shared CIE, and reads their PC/range fields. It does not add a second general FDE decoder or replace RE-001.
`MANIFEST.sha256` covers packet files, including their exact raw output hashes.

## Observations

All addresses below are **ELF VAs**, without a guessed loader or Ghidra rebase. The ELF section table maps `.text` with file offset = VA - `0x1000` (segment VA base `0x1343c80`, file offset base `0x1342c80`); the retained `.eh_frame` has equal file offsets and VAs. The tools resolve sections rather than assuming one global VA/file-offset relationship.

### Entry, FDE extent, and padding

- `.eh_frame+0x2930a8` describes `[0x5057700, 0x505773d)`, 61 bytes. GNU's independent frame dump agrees. Complete linear decoding from that start gives the instruction sequence below, ending exactly at the FDE endpoint (the `ret` at `0x505773c` is inside the FDE).
- The unwind index stride to the next entry is 64 bytes, ending at `0x5057740`, only because three `int3` bytes (`0xcc`) pad the window after the FDE end. The stride is **not** the FDE extent; any description of this window as "64-byte FDE-bounded" would overstate the frame by those three padding bytes, and the checker locks the 61-byte body and the padding separately.
- The next FDE starts exactly at `0x5057740` (`[0x5057740, 0x505774e)`, 14 bytes); the checker decodes and locks its PC/range, and its full record is retained in `frames.txt`.

### Body behavior: three tag compares, one global lea, zero calls

Decoded from the FDE start, the window takes a destination pointer in `rdi`, a source value or pointer in `rsi`, and a tag in `edx` (only the low 32 bits are compared):

| VA | Instruction | Role |
| --- | --- | --- |
| `0x5057700` | `endbr64` | Landing-pad marker |
| `0x5057704` | `test %edx,%edx` | Tag == 0 test |
| `0x5057706` | `je 0x5057730` | Tag 0 → global path |
| `0x5057708` | `cmp $0x1,%edx` | Tag == 1 test |
| `0x505770b` | `jne 0x5057718` | Not 1 → tag-2 test |
| `0x505770d` | `mov %rsi,(%rdi)` | Tag 1: store rsi |
| `0x5057710` | `xor %eax,%eax` | Shared return-zero |
| `0x5057712` | `ret` | Shared return |
| `0x5057713` | `nopl 0x0(%rax,%rax,1)` | 5-byte alignment nop (unreached) |
| `0x5057718` | `cmp $0x2,%edx` | Tag == 2 test |
| `0x505771b` | `jne 0x5057710` | Not 2 → shared return, no store |
| `0x505771d` | `movdqu (%rsi),%xmm0` | Tag 2: load 16 bytes |
| `0x5057721` | `movups %xmm0,(%rdi)` | Tag 2: store 16 bytes |
| `0x5057724` | `jmp 0x5057710` | Tag 2 → shared return |
| `0x5057726` | `cs nopw 0x0(%rax,%rax,1)` | 10-byte alignment nop (unreached) |
| `0x5057730` | `lea 0x701b69(%rip),%rax` | Tag 0: global pointer 0x57592a0 |
| `0x5057737` | `mov %rax,(%rdi)` | Tag 0: store global pointer |
| `0x505773a` | `xor %eax,%eax` | Tag-0 return-zero |
| `0x505773c` | `ret` | Tag-0 return |

The rule is therefore: `edx == 0` stores the 8-byte global pointer `0x57592a0` to `[rdi]`; `edx == 1` stores `rsi` to `[rdi]`; `edx == 2` copies 16 bytes from `[rsi]` to `[rdi]`; any other tag stores nothing; every path returns 0. The two `xor %eax,%eax; ret` sites are distinct: the shared site at `0x5057710` serves tags 1, 2, and the fall-through, while the global path has its own at `0x505773a`. Both alignment nops inside the body are unreachable on every path (each is preceded by a `ret` or a `jmp` and targeted by no branch) and are locked as body bytes, not as executed instructions. The window opens with `endbr64` (an observation, not a scout deviation).

### Data edge: global pointer in .data.rel.ro, no naming relocation

The rip-relative lea at `0x5057730` targets `0x57592a0`, which lies in `.data.rel.ro`. Its contents are not decoded or claimed: the value stored on the tag-0 path is described only as "the global pointer 0x57592a0". The objdump nearest-symbol annotation for that address is not a name and is not used as evidence anywhere in this packet.

The full `.rela.*` scan (80,022 `.rela.dyn` + 278 `.rela.plt` entries) finds no record of any type naming this window as addend. The absence of a naming relocation does not identify the window's provenance.

### Call edge: zero direct callers

The exact `.text` byte-pattern scan covers 70,370,352 bytes and finds zero direct `e8` calls to this window. Register-indirect references and data sections are not a complete xref census, so indirect reachability is neither claimed nor excluded.

### Symbol hint, explicitly disclaimed

GNU objdump annotates the window's address with the nearest preceding symbol, a `ctype` `do_widen` label `0xaf900` bytes below. A nearest-symbol annotation at that distance proves nothing about provenance: no stdlib or private origin is claimed either way, and the label is not used as evidence anywhere in this packet.

### Scout notes

One scout correction, stated prominently: the round-10 note described the nop at `0x5057726` as 3 bytes; the retained bytes show a 10-byte `cs nopw` (`66 2e 0f 1f 84 00 00 00 00 00`) spanning `0x5057726..0x5057730`, and the checker locks all ten bytes. The 5-byte nop at `0x5057713` verified exactly as scouted. Every other scouted element verified exactly (FDE range, 61-byte body, three padding bytes, the three tag paths, the global lea target, zero direct callers, no naming relocation).

### Nearest claimed window

The nearest previously claimed window is the field-inequality gate at `0x5035a70` (packet #41), `0x21c90` away; nothing in `0x50577xx` is claimed.

## Inferences

- The "tag-dispatched store" label is an inference from the tag-compare dispatch shape; it is not a source-level name.
- The three store effects are described only as the bytes compute them; what the destination, the source, and the global pointer mean to any reader is unknown.
- The two alignment nops are described as padding only because no branch targets them and each follows a transfer out of the body segment; that is a control-flow observation, not a claim about the compiler's intent.

## Unknowns

- The meaning of the destination, the source value/pointer, and the global pointer's contents.
- The meaning of the tag values 0, 1, and 2.
- Whether any caller reaches this window indirectly (the byte-pattern scan is not a complete xref census).
- The source-level function, type, or component this window belongs to beyond the foundation task framing.

## Limits

- No stdlib type, source-level function, field meaning, value meaning, tag meaning, or caller purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the absence of a naming relocation does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation was copied, and every claim is grounded in target bytes for node #94 (SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
