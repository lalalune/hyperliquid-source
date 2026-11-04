# Evidence — RE-001-node115-lu-grow-build

## Claim

FDE `0x5155ec0..0x5156053` in node #115 is the grow callee: it
converts a hybrid table past length 63 into a B-tree by draining
the table's ring buffer, sorting the entries, and bulk-building
the tree with FDE `0x4cbd730..0x4cbdcb0` fed through the peeking
iterator `0x4d58320..0x4d5845a`. The build is a right-append bulk
load (11-key nodes, 232-byte leaves, 328-byte internals) with a
rightmost-path redistribute fixup, not a rehash and not a balanced
split.

## Method

Static disassembly only (`objdump -d -M intel`, `readelf -r` /
`readelf --debug-dump=frames-interp`). The node binary was never
executed. FDE bounds come from `.eh_frame` (readelf frames-interp:
grow `FDE cie=0039672c pc=0x5155ec0..0x5156053`; build `FDE
cie=0039672c pc=0x4cbd730..0x4cbdcb0`; iterator `FDE cie=00000000
pc=0x4d58320..0x4d5845a`; drain `FDE cie=0039672c
pc=0x5b9f6f0..0x5b9f898`; small sort `FDE cie=00000000
pc=0x53ef680..0x53ef73c`; large-sort wrapper `FDE cie=0039672c
pc=0x4f3fd80..0x4f3fe90`). Body/tail splits follow the single
`ret` for grow (`0x5155fdd`), build (`0x4cbdbe0`), and drain
(`0x5b9f83f`); the iterator has two `ret`s (`0x4d5842e` end path,
`0x4d58459` normal path) and no tail. All counts below were
recomputed by the verifier (`tools/node115_lu_grow_build.py`), not
copied from this file.

## Observations

### Grow `0x5155ec0` (403 bytes, 94 instructions, 0 nops)

| Site | Bytes / instruction | Reading |
| --- | --- | --- |
| `0x5155ece` | `movups xmm0,[rsi]` / `movups xmm1,[rsi+0x10]` | 32-byte table copy to stack |
| `0x5155ee9` | `call 0x5b9f6f0` | drain helper |
| `0x5155eee` | `mov r15,[rsp+0x28]` | copied count |
| `0x5155ef6` | `je 0x5155fa1` | count 0 → empty path |
| `0x5155efc` | `mov r14,[rsp+0x20]` | entries buffer |
| `0x5155f06` | `mov [rsp+0x40],rax` (`rax = rsp+0xf`) | range-struct scratch slot (overwritten before use) |
| `0x5155f0b` | `cmp r15,0x1; jne 0x5155fde` | count 1 skips sort |
| `0x5155fde` | `cmp r15,0x15; jae 0x5156010` | len >= 21 → large sort |
| `0x5155ff4` | `call 0x53ef680` (rdx = 1) | small insertion sort |
| `0x515601b` | `call [0x64ebae0]` (→ `0x4f3fd80`) | large-sort wrapper |
| `0x5155f15` | `mov r12,[rsp+0x18]` | drain length, into range `+0x10` |
| `0x5155f1a` | `mov edi,0xe8` | leaf alloc, 232 bytes |
| `0x5155f1f` | `call [0x64df480]` (→ `0x6355830`) | TLS fast allocator |
| `0x5155f2e` | `mov [rax+0xb0],0` | new leaf parent = 0 |
| `0x5155f39` | `mov [rax+0xe6],0` | new leaf count = 0 |
| `0x5155f42` / `0x5155f4b` / `0x5155f50` | `[rsp+0x38] = 0; [rsp+0x30] = rax; [rsp+0x10] = 0` | tree out init {node, height 0, count 0} |
| `0x5155f61` / `0x5155f66` / `0x5155f6b` / `0x5155f70` / `0x5155f75` | range struct writes | begin, cursor = begin, length, end, flag byte 3 |
| `0x5155f89` | `call 0x4cbd730` | bulk builder |
| `0x5155f98` / `0x5155f9b` | `[rbx] = [rsp+0x30] (16B); [rbx+0x10] = [rsp+0x10]` | tree out = root+height, count |
| `0x5155fa1` / `0x5155fa8` | `[rbx] = 0; [rbx+0x10] = 0` | empty path: root and count zeroed, height untouched |
| `0x5155fb0` / `0x5155fc9` | free if `[rsp+0x18] != 0`, size `* 24` | drained-buffer free on empty path |
| `0x5155ffe` | `mov edi,0x8; mov esi,0xe8` then `ud2` | alloc-failure handler (align 8, size 232) |

### Drain `0x5b9f6f0` (424 bytes, 121 instructions, 1 nop)

| Site | Bytes / instruction | Reading |
| --- | --- | --- |
| `0x5b9f6fe` | `mov rbp,[rsi+0x18]` | table length |
| `0x5b9f70a` | `lea r14,[rax+rax*2]` (`rax = length * 8`) | alloc size = length * 24 |
| `0x5b9f739` | `call [0x64df480]` | new buffer alloc |
| `0x5b9f7b0` | copy loop (16B movups + 8B qword) | first ring chunk, verbatim 24-byte entries |
| `0x5b9f7f0` | copy loop (16B movups + 8B qword) | wraparound chunk, verbatim 24-byte entries |
| `0x5b9f823` / `0x5b9f826` / `0x5b9f82a` | `[rbx] = length; [rbx+0x8] = buffer; [rbx+0x10] = count` | drain out-struct |
| `0x5b9f840` | `mov r15d,0x8; xor r13d,r13d` | empty case: buffer field 8, length 0 |
| `0x5b9f813` | free old table buffer (`capacity * 24`) | old buffer freed when capacity nonzero |

### Sorts

Small sort `0x53ef680` (188 bytes, 50 instructions, 1 nop):
insertion sort over 24-byte entries (16-byte + 8-byte moves).
Guard at `0x53ef680` (start index `rdx = 1`; `len <= 0` →
`ud2`); early `ret` at `0x53ef692` (len == 1). Outer compare at
`0x53ef6d7` / `0x53ef6da` and inner compare at `0x53ef71e` /
`0x53ef726` both `bswap` the key dword at entry `+0` before
comparing, ascending. The flag-helper walk compares keys the same
way (`0x4dcd206` / `0x4dcd209` `bswap`), so sort order and walk
order agree.

Large-sort wrapper `0x4f3fd80` (272 bytes, 74 instructions, 0
nops): temp count `r12 = min(len, 333333 (0x51615), ceil(len/2))`
at `0x4f3fd9f`–`0x4f3fdb3`; stack buffer (sub `rsp,0x1000`) when
`r12 <= 170 (0xaa)`, heap buffer via the alloc wrapper otherwise
(`0x4f3fdf9`); inner sort call at `0x4f3fe21` (`0x4f6d1e0`,
args ptr, len, temp buffer, count, small-flag = 1 iff `len < 65
(0x41)`); temp buffer freed at `0x4f3fe3c` when heap. The inner
`0x4f6d1e0` (1694 bytes, FDE `0x4f6d1e0..0x4f6d87e`) is not
decoded.

### Iterator `0x4d58320` (314 bytes, 93 instructions, 1 nop)

| Site | Bytes / instruction | Reading |
| --- | --- | --- |
| `0x4d58333` / `0x4d58337` | `r11 = [rsi+0x8]; r10 = [rsi+0x18]` | cursor, end |
| `0x4d5833b` / `0x4d58342` | `dl = [rsi+0x30]; cmp dl,0x3` | state byte: 3 = cursor mode |
| `0x4d58350` | `cmp r11,r10; je 0x4d58422` | cursor == end → end signal |
| `0x4d58359` / `0x4d5835d` | `r14 = r11 + 0x18; [rsi+0x8] = r14` | cursor advances one entry |
| `0x4d58361` / `0x4d5836c` / `0x4d58364` / `0x4d58375` | key `[r11]`, value `[r11+0x4]`, dword `[r11+0xc]`, flag `[r11+0x10]` | current entry fields |
| `0x4d58384` / `0x4d58387` | `cmp dl,0x2; jne` / `jmp 0x4d58422` | current flag 2 → end |
| `0x4d583cc` / `0x4d583e9` / `0x4d583f9` / `0x4d583fd` | peek next entry, stash 16 bytes + tail dwords | next entry copied to state `+0x20..+0x38` |
| `0x4d58400` / `0x4d58403` | `cmp bl,0x2; je 0x4d5841c` | next flag 2 → state 2, output current |
| `0x4d58405` | `cmp ecx,[rdi]` | current key vs next key |
| `0x4d58409` / `0x4d5840c` | equal keys → loop, `edx = next flag` | duplicate dropped; mode B if flag != 3, else cursor mode |
| `0x4d5841c` | `mov [rsi+0x30],0x2` | state = done |
| `0x4d58422` | `mov [rsi+0x30],0x3; mov [rax+0x10],0x2` | end signal: out flag 2 |
| `0x4d5842f` | `mov [rsi+0x30],bl` | state = next flag |
| `0x4d58432`–`0x4d58452` | out triple assembly | key, value, dword, flag, tail dwords to out |

### Build `0x4cbd730` (1408 bytes, 292 instructions, 5 nops)

| Site | Bytes / instruction | Reading |
| --- | --- | --- |
| `0x4cbd744` / `0x4cbd747` | `r15 = [rdi]; rcx = [rdi+0x8]` | root, height |
| `0x4cbd74e` | `je 0x4cbd81f` | height 0 → prologue skipped (grow path) |
| `0x4cbd770` / `0x4cbd7a0` | last-child descent loops | mod-8 steps + unrolled-8 loop via `children[count]` |
| `0x4cbd81f`–`0x4cbd83d` | 48-byte range copy + `[rsi+0x30]` | iterator state local copy |
| `0x4cbd88b` | `call 0x4d58320` | iterator next |
| `0x4cbd890` / `0x4cbd896` | `r14b = [rsp+0x60]; cmp r14b,0x2` | out flag; 2 → end |
| `0x4cbd8a0` / `0x4cbd8a4` | `edx = [rsp+0x50]; r13 = [rsp+0x58]` | key, value |
| `0x4cbd8a9` / `0x4cbd8b1` | `eax = [r15+0xe6]; cmp rax,0xb` | current count; < 11 → append |
| `0x4cbd860`–`0x4cbd87a` | count + 1, key, value, flag stores | append at index count |
| `0x4cbd87f` | `inc [r12]` | inserted count |
| `0x4cbd8b7`–`0x4cbd8d8` | walk up while ancestors full | `rbx` counts visited ancestors |
| `0x4cbd8e0`–`0x4cbd93e` | new 328-byte root | first child = old root, height + 1 |
| `0x4cbd942`–`0x4cbd9c5` | spine build | 232-byte deepest node, 328-byte rest, first-child links |
| `0x4cbd9c7` / `0x4cbd9d3` | `eax = [r15+0xe6]; cmp rax,0xb; jae panic` | ancestor still full → defensive panic |
| `0x4cbd9d9`–`0x4cbd9ff` | separator insert + new last child | key/value/flag at old count, `children[old+1] = spine`, parent + index set |
| `0x4cbda40` / `0x4cbda70` | last-child descent, `rbx` levels | land on new leaf |
| `0x4cbdb27`–`0x4cbdb40` | free drained buffer (`length * 24`) | end-of-stream cleanup |
| `0x4cbdb46` | `r14 = [rbp+0x8]; je done` | post-pass height gate |
| `0x4cbdb68` / `0x4cbdb7c` / `0x4cbdb84` | count 0 → panic; left sibling; last child | rightmost-path walk |
| `0x4cbdbb2` | `cmp last count,0x5; jae descend` | >= 5 → descend, < 5 → redistribute |
| `0x4cbdbc0` / `0x4cbdbcb` | `esi = 5 - count; call 0x4c93c20` | left redistribute, borrow argument |

## Panics (all `node.rs`, file string at `0x4344f8`, length 91)

| Site | Location | Message | Reading |
| --- | --- | --- | --- |
| `0x4cbdc05` | `node.rs:367:9` (struct `0x649a468`) | "assertion failed: len > 0" (25 bytes at `0x913338`) | rightmost-path node with count 0 |
| `0x4cbdc30` | `node.rs:698:9` (struct `0x649a4e0`) | "assertion failed: idx < CAPACITY" (32 bytes at `0x4585c0`) | ancestor still full at insert (defensive) |
| `0x4cbdc5d` | `node.rs:240:77` (struct `0x649a4f8`, location-only) | — | new-root height wraparound guard (practically dead) |

Location structs resolve their file pointer through
`R_X86_64_RELATIVE` relocations (`0x649a468`, `0x649a4e0`,
`0x649a4f8` all → `0x4344f8`); line is the low 32 bits and column
the high 32 bits of the `+0x10` field; file length 91 sits at
`+0x8`.

## Implementation and comparison

Not yet implemented/measured. No Rust reconstruction of these
FDEs is claimed. The packet is static evidence only.

## Results and limitations

Machine-readable metrics: grow 403 bytes / 94 instructions;
build 1408 bytes / 292 instructions; iterator 314 bytes / 93
instructions; drain 424 bytes / 121 instructions; small sort 188
bytes / 50 instructions; large-sort wrapper 272 bytes / 74
instructions. Census denominators: grow 1 direct caller / 0 GOT
sites; build 2 direct callers / 0 GOT sites; iterator 1 direct
caller / 0 GOT sites; drain 1 direct caller / 0 GOT sites; small
sort 3 direct callers / 0 GOT sites; large-sort wrapper 0 direct
callers / 1 GOT site. What remains unknown: the large-sort inner
algorithm, the merge/redistribute internals, the drain length-vs-
count edge behavior, the flag-3 meaning, and the second build
caller. The requested progress gate is not a full-scope gate; no
gate is claimed. Next question: the merge helper `0x4ca2500` and
redistribute helpers `0x4c93c20` / `0x4c9b3b0` internals — how
does the merge move the separator and children, and how does
redistribute choose its borrow count beyond the post-pass's
`5 - count` argument?
