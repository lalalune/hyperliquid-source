# RE-001-node115-lu-classsearch: bounded question

- Component ID: lu class-search helper, FDE `0x63d9340..0x63d945b`
- Target release and full SHA-256: node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes)
- Source commit / reference commit: upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis)
- Claim status: observation for all byte claims below; inference
  flagged where the layout reading goes beyond the bytes; the
  bitmap-clear premise of #229/#227 is refuted (observation: no
  store to the bitmap exists in the FDE)
- Scope included: the class-search FDE only, its one internal call,
  its tail jump, its two census callers by address. Scope
  excluded: the size helper's internals (#227), the consumer
  `0x63b9690`'s internals, the callers' purposes, the bitmap's
  writer, the fallback pointer's identity.

## Reproduce

Working directory: a fresh worktree of upstream main `8fd8db6`
(`git worktree add hl-wt-calls230-115 -b codex/re-004-calls230-115
origin/main`), submodules initialised
(`git submodule update --init --recursive --force` + `git lfs pull`;
git-lfs 3.4.1 restored to /usr/local/bin first, as it was missing
at session start). Static analysis only: `objdump -d` over
`artifacts/node/115/hl-node`, byte scans in Python, no execution
of the node binary at any point. Coordinate system: `.text` file
offset = VA - 0x1000; `.rela.dyn` addends for GOT census (60,723
entries). Tool versions: system `objdump`, Python 3, `make` suite
as shipped in the worktree.

## Evidence

Function bounds from `.eh_frame`: FDE `0x63d9340..0x63d945b`
(283 bytes); `int3` padding at `0x63d945b..0x63d945f`; next
function starts `0x63d9460` (`endbr64`). Single `ret` site
`0x63d9418` (`c3`). One internal `call` (`e8` at `0x63d934b`,
rel32 to `0x63e8c80`, packet #227's size representative helper).
One tail jump (`e9` at `0x63d940a`, rel32 to `0x63b9690`, the
consumer, cited by address only). All other jump targets fall
inside the FDE (`jb 0x63d9420`, `jne 0x63d93e4`,
`je 0x63d9410`, `je 0x63d93c7`, `jne 0x63d944b`,
`jmp 0x63d93fe`, `jmp 0x63d93d0` loop).

Key instruction bytes (verified by the static verifier):

- Entry: `f3 0f 1e fa` (`endbr64`) at `0x63d9340`;
  `push %rbx`; `mov %rdi, %rbx`; `mov %rsi, %rdi`.
- `e8 30 f9 00 00` (`call 0x63e8c80`) at `0x63d934b`.
- Huge threshold: `48 b8 00 00 00 00 00 00 00 70`
  (`movabs $0x7000000000000000, %rax`) at `0x63d9353`;
  `cmp %rdx, %rax`; `jb 0x63d9420` — huge path iff
  `v > 0x7000000000000000`.
- Index idiom at `0x63d9366..0x63d93a2`: `lea -0x1(%rdx),
  %rsi`; `bsr %rdx, %rdi`; `mov $0xe, %ecx`;
  `mov $0xc, %r8d`; `and %rsi, %rdx`;
  `lea 0x400(%rbx), %r9` (bitmap base); `cmp $0x1, %rdx`;
  `sbb $-1, %edi`; `cmp %ecx, %edi`; `cmovb %ecx, %edi`;
  `lea -0x3(%rdi), %ecx`; `sub $0xe, %edi`;
  `cmove %r8d, %ecx`; `shr %cl, %rsi`;
  `and $0x3, %esi`; `lea (%rsi, %rdi, 4), %edi` (= index).
- Bitmap test at `0x63d93a2..0x63d93bc`: `mov $0x1, %esi`;
  `mov %rdi, %rcx`; `shr $0x6, %rdi` (word index);
  `shl %cl, %rsi` (bit mask); `neg %rsi` (bits >= bit);
  `and 0x400(%rbx, %rdi, 8), %rsi` — AT&T operand order makes
  this `rsi = mask & bitmap[word]`, a register test, not a
  memory store. No instruction in the FDE stores to the bitmap:
  the only memory writes are `push %rbx` / `pop %rbx`.
- Found path at `0x63d93e4..0x63d940f`: `tzcnt %rsi, %r8`;
  `add %rcx, %rdi` (= class `c`); `cmp $0x40, %edi`;
  `je 0x63d9410` (class 64 → fallback);
  `mov %r11d, %eax`; `shl $0x4, %rax`;
  `lea (%rbx, %rax, 1), %rdi` (= `record + c * 16`);
  `pop %rbx`; `jmp 0x63b9690`.
- Fallback at `0x63d9410`: `mov 0x1080(%rbx), %rax`;
  `pop %rbx`; `ret`.
- Scan loop at `0x63d93be..0x63d93e2`: `lea 0x1(%rdi),
  %r11`; `test %rdi, %rdi`; `je 0x63d9410` (word 0 miss →
  fallback, no further scan); `mov (%r9, %r11, 8), %rdx`;
  `test %rdx, %rdx`; `jne 0x63d944b` (found in a later word);
  loop increments `r11` and reloads until a nonzero word. No
  upper bound is present in this FDE.
- Later-word found path at `0x63d944b`: `shl $0x6, %r11`;
  `tzcnt %rdx, %rax`; `add %eax, %r11d`; `jmp 0x63d93fe`
  (tail call, no class-64 check on this path).
- Huge path at `0x63d9420..0x63d944b`:
  `mov 0x418(%rbx), %r10` (bitmap word 3);
  `lea 0x400(%rbx), %r9`;
  `mov $0x4, %r11d`; `and $0xffffffffffffff80, %r10`
  (keeps bits 199..255); `je 0x63d93c7` (zero → scan words
  4, 5, ...); `tzcnt %r10, %r11`; `add $0xc0, %r11d`
  (= 192 + bit); `jmp 0x63d93fe` (tail call).

Census (whole-`.text` byte scan with rel32-target filter, each
site confirmed by per-site objdump as `call 63d9340`;
`.rela.dyn` addends for GOT): 2 direct E8 — `0x63b827f` (FDE
`0x63b8160..0x63b81ab`) and `0x63b8918` (FDE
`0x63b8820..0x63b8d85`); 0 E9; 0 LEA; 0 GOT. Caller 1 passes
(r12, r13) and tests the return for `NULL`; caller 2 passes
(rbx + 0x140, r13), tests for `NULL`, then passes the return
onward as an argument. Caller purposes are cited by address
only.

Layout observation (arithmetic, not layout proof):
`record + 64 * 16 = record + 0x400`, the bitmap base — exactly
the class this function refuses to dispatch. Consistent with
16-byte entries occupying `record + 0x00..record + 0x3ff`, but
the mapping for classes 65+ is not established by these bytes.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is claimed
for this helper in this packet; the packet is evidence only
(static verifier + unit tests, no node execution).

## Results and limitations

Machine-readable metrics: 5 exhibits, 188 bytes, 49 strict
mnemonics; FDE 283 bytes; 1 internal call; 1 tail jump;
1 ret site; census 2 E8 / 0 E9 / 0 LEA / 0 GOT over 60,723
`.rela.dyn` entries; MANIFEST 15/15; verifier exit 0; unit
tests 10/10; `make verify` exit 0; `make catalogue-check`
exit 0; `make test` 77 files, 1 pre-existing catalogue Errno 18
failure only.

What remains unknown: the fallback pointer's identity; the
reason for the class-64 special case; the entry layout for
classes 65+; the callers' purposes; the consumer's behavior and
return; the bitmap's writer; why the upward scan has no bound
in this FDE.

Next question: decode the consumer `0x63b9690` end to end —
what it does with the slot entry `record + found * 16`, how it
merges and relinks the chain it reads there, and what it
returns.
