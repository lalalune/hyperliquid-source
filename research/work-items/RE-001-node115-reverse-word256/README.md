# RE-001: reverse a 32-byte input into a bounded slot

- Component: serialization / foundation lead; original ownership unknown.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/reference revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; no external source used.
- Bounded question: what does the complete leaf at `0x4332f70` write and return, including its capacity boundary?
- Answer: Given valid, nonoverlapping state, source and destination memory, if the unsigned qword at state `+0x30` is at most 1023, the function writes the 32 bytes at the pointer in state `+0x118` in reverse order to the slot at the pointer in state `+0x28` plus 32 times that count, increments the count, advances the source pointer by 32 and returns RAX 0. If the count is greater than 1023, it writes nothing and sets AL to `0x2d`; the upper 56 RAX bits retain the count's upper bits. These are register and memory observations, not a recovered type or error name.

## Evidence and scope

All addresses are original ELF virtual addresses; byte offsets are file offsets. The complete unwind-described window is `0x4332f70..0x4332fd2` (98 bytes), file offset `0x4331f70`, body SHA-256 `2284a6038d49dc3add1dc92b244708a1728b9d88418338a7c63c4ea82f675045`. FDE VA `0xe9cae4` at file offset `0xe9cae4` references CIE VA `0xca6ed8` at file offset `0xca6ed8`, with no LSDA. The raw records and parsed CIE are in records.json. The preceding 15 and following 14 bytes are all `cc` padding; this and the two returns support, but do not by themselves prove, a source-level function boundary. The disassembly below covers the entire FDE, including both branches; every opcode and operand is checked by the closed Python decoder.

| VA | Bytes | Decoded instruction |
| --- | --- | --- |
| `0x4332f70` | `488b4730` | `mov rax,[rdi+0x30]` |
| `0x4332f74` | `483dff030000` | `cmp rax,0x3ff` |
| `0x4332f7a` | `7753` | `ja 0x4332fcf` |
| `0x4332f7c` | `488b8f18010000` | `mov rcx,[rdi+0x118]` |
| `0x4332f83` | `488d5001` | `lea rdx,[rax+1]` |
| `0x4332f87` | `488b7728` | `mov rsi,[rdi+0x28]` |
| `0x4332f8b` | `48c1e005` | `shl rax,5` |
| `0x4332f8f` | `48895730` | `mov [rdi+0x30],rdx` |
| `0x4332f93` | `488b5118` | `mov rdx,[rcx+0x18]` |
| `0x4332f97` | `480fca` | `bswap rdx` |
| `0x4332f9a` | `48891406` | `mov [rsi+rax],rdx` |
| `0x4332f9e` | `488b5110` | `mov rdx,[rcx+0x10]` |
| `0x4332fa2` | `480fca` | `bswap rdx` |
| `0x4332fa5` | `4889540608` | `mov [rsi+rax+0x8],rdx` |
| `0x4332faa` | `488b5108` | `mov rdx,[rcx+0x8]` |
| `0x4332fae` | `480fca` | `bswap rdx` |
| `0x4332fb1` | `4889540610` | `mov [rsi+rax+0x10],rdx` |
| `0x4332fb6` | `488b11` | `mov rdx,[rcx]` |
| `0x4332fb9` | `480fca` | `bswap rdx` |
| `0x4332fbc` | `4889540618` | `mov [rsi+rax+0x18],rdx` |
| `0x4332fc1` | `4883c120` | `add rcx,0x20` |
| `0x4332fc5` | `48898f18010000` | `mov [rdi+0x118],rcx` |
| `0x4332fcc` | `31c0` | `xor eax,eax` |
| `0x4332fce` | `c3` | `ret` |
| `0x4332fcf` | `b02d` | `mov al,0x2d` |
| `0x4332fd1` | `c3` | `ret` |

The `ja` uses unsigned comparison. On the success path each little-endian qword load is byte-swapped before its little-endian store; the four chunks are read in order +24, +16, +8, +0 and written at +0, +8, +16, +24. Hence the destination is the full reversal of the 32 source bytes. The count store occurs before the first input load; the cursor store occurs after all destination writes. The stated simple rule assumes state, source and destination do not overlap, readable and writable ranges are valid, and pointer arithmetic does not wrap. The failure branch touches no pointer or destination beyond the initial count read. No external or indirect call or tail call occurs in the body: **0 callees**. The complete bytewise `.text` scan for E8/E9 rel32 to this entry found **0 direct-call/jump candidates**; the scan tests every byte, including non-instruction bytes. Thus it establishes no direct rel32 caller here, but cannot find indirect calls, alternate entrypoints or code outside `.text`. The `.rela.dyn` scan found **2 relative relocations** whose addend is this entry: destination slots `0x64862f0` and `0x6487058` in `.data.rel.ro`. Their presence supplies a lead for indirect references; it does not establish that either slot is called or identify an owner.

## Novelty

Before selection, both commands below produced no matches; no callee behavior is bound by this packet:

```sh
rg -i '4332f70' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '70463344' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

The search covers the available local research and PR-title lists at the base revision, not unlisted remote work.

## Reproduce and controls

From the repository root on Linux x86-64 with Python 3.10+ (local validation used 3.13.5), materialize the authenticated capture, then run. The producer uses the repository’s `elf_index` and `fde_extents` parsers, which use the Python standard library only:

```sh
python3 tools/node115_reverse_word256.py --out research/work-items/RE-001-node115-reverse-word256/
python3 -m unittest tests.test_node115_reverse_word256 -v
python3 research/work-items/RE-001-node115-reverse-word256/verify.py
```

The producer hashes the complete input before parsing, checks exact FDE, padding, all instruction operands and the full `.text` scan, then deterministically regenerates records, this README and the manifest. Tests cover boundary values, byte order, digest, mutated instructions, changed FDE, scan target and manifest corruption. No captured executable is run, and no network or side effects outside the selected output files occur.

## Limitations and next step

Before: no local packet bound this entry's rule. After: one complete 98-byte FDE and 26 decoded instructions are bound to the capture. There is no source build, Rust reconstruction, byte comparison or normalization mask. The original type, protocol role, input length validation, callers via function pointers, aliasing effects, invalid memory, exceptions and whole-node behavior remain unproved; no component gate or node equivalence is claimed. Next, identify the data relocation or function-pointer table that references this entry, then validate its dispatch and input bounds before attributing it to a codec.
