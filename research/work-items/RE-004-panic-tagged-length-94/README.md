# RE-004 panic tagged length — node #94

## Claim status

**Claimed.** #179's first Next question — what does the
`0x576e098`/`0x57706e0` chain do with the (pointer,
length) pair, i.e. why do the arithmetic helpers'
recorded lengths span packed messages? — is answered:
the second word is not a byte length at all. It is a
tagged word: odd means a static string whose true byte
length is the word shifted right by one; even means a
pointer to a structured message. The arithmetic
"lengths" (57, 67, ...) are the tagged form, so read
as raw byte lengths they overshoot into neighboring
packed literals; decoded, they are exactly the standard
messages.

- **Nine thunks, one tagged arithmetic.** A contiguous
  family of nine 25-byte thunks (`0x157b440..0x157b559`,
  0x20 stride) each loads one message pointer and one
  immediate second word, then calls through GOT
  `0x576e098`. Every second word is odd, and
  `(word - 1) / 2` equals the true message length in
  all nine cases (25, 57, 28, 33, 31, 35, 36, 33, 35).
- **The tag transform is explicit in code.** The
  unwrap helper passes raw length 43 to adapter
  `0x157b7f0`, which executes `lea rsi,[rsi*2+1]`
  (43 → 87) before joining the common path — the
  encoder, in instructions, not inferred from data.
- **The decoder branches on the low bit.** At
  `0x4eef390`, the runtime loads the pair's second
  word, tests `al,1`, and on the odd path executes
  `shr rax,1` to recover the true length before
  calling on. The even path builds a sentinel-prefixed
  struct (`0x8000000000000000`) and calls the same
  next hop with a different table — the pointer side
  of the same two-representation argument.
- **The full chain resolves through three GOT hops.**
  Site → thunk/helper → `[0x576e098]` →
  `0x157b810` → `[0x57706e0]` → `0x4ecdcf0` →
  `[0x57770e8]` → `0x4ee9ae0` → `0x4eef390` →
  `[0x5777558]` → `0x4eef596` (not traced past the
  decoder's call). Every hop's relocation is verified
  by `.rela.dyn` entry index.

**Not claimed.** No defect, exploitability, or security
severity is claimed. The std-internal names of the
runtime functions are not identified (only their
instruction shapes and the tag branch are reported).
The even-path (pointer) message representation is not
traced beyond its branch shape. The flag bytes'
semantic names are not determined (only their values).

## Scope

Included:

- The nine message thunks (`thunks.tsv`): thunk
  address, message address, raw word, true length,
  message text, GOT slot, relocation index.
- The three #179 helpers (unwrap, bounds-check, pair)
  and their routes into the chain.
- The adapter chain (`chain.tsv`): panic adapter
  `0x157b810`, tag adapter `0x157b7f0`, copy adapter
  `0x4ecdcf0`, thunk `0x4ee9ae0`, decoder
  `0x4eef390`, second caller `0x157b690`.
- The routing of #179's 35 sites (`routes.tsv`):
  9/9/1/2/1/13 across six GOT slots.
- 28 byte segments in `segments.txt` (28 claim, 1184
  bytes: 828 code + 356 message; 0 anchors — no prior
  packet claims any of these bytes).

Excluded:

- The #179 Location records and citation sites
  themselves (cited only as the route source); the
  decoder's callee `0x4eef596` and everything past
  the decoder's call; the even-path message structure;
  the 3860 binary-wide callers of `[0x576e098]`
  (shared entry, not censused here); the #157–#179
  subjects; #1543's fixed-eight topic; #176's
  header-0 / decoder-out+8 question (not touched).

## Observations

### The thunk family

| thunk | message | raw | true | GOT slot |
|---|---|---|---|---|
| `0x157b440` | attempt to divide by zero | 51 | 25 | `0x576e1b8` |
| `0x157b460` | attempt to calculate the remainder with a divisor of zero | 115 | 57 | `0x576e528` |
| `0x157b480` | attempt to add with overflow | 57 | 28 | `0x576e118` |
| `0x157b4a0` | attempt to multiply with overflow | 67 | 33 | `0x576e1b0` |
| `0x157b4c0` | attempt to negate with overflow | 63 | 31 | `0x576eb38` |
| `0x157b4e0` | attempt to shift left with overflow | 71 | 35 | `0x576e478` |
| `0x157b500` | attempt to shift right with overflow | 73 | 36 | `0x576f128` |
| `0x157b520` | attempt to subtract with overflow | 67 | 33 | `0x576e150` |
| `0x157b540` | `async fn` resumed after completion | 71 | 35 | `0x576f040` |

Each thunk is 25 bytes: `push rbp; mov rbp,rsp;
mov rdx,rdi; lea rdi,[msg]; mov esi,raw;
call [0x576e098]` (7 `int3` pad bytes follow, outside
the FDE). Each thunk has exactly one GOT slot in
`.rela.dyn`. Three thunks (add, mul, sub) are reached
from #179's sites; the other six are family members
with the same shape and their own GOT slots.

### The chain

| hop | from | via | to |
|---|---|---|---|
| thunk/helper → panic | thunks, bounds, pair | GOT `0x576e098` (idx 72894) | `0x157b810` (44 B) |
| unwrap → tag | `0x157a9f0` | GOT `0x576e108` (idx 72907) | `0x157b7f0` (18 B) |
| tag → panic | `0x157b7f0` | GOT `0x576e098` (idx 72894) | `0x157b810` |
| panic → copy | `0x157b810` | GOT `0x57706e0` (idx 74070) | `0x4ecdcf0` (29 B) |
| caller2 → copy | `0x157b690` | GOT `0x57706e0` (idx 74070) | `0x4ecdcf0` |
| copy → thunk2 | `0x4ecdcf0` | GOT `0x57770e8` (idx 77399) | `0x4ee9ae0` (9 B) |
| thunk2 → decoder | `0x4ee9ae0` | direct E8 | `0x4eef390` (173 B) |
| decoder → next | `0x4eef390` | GOT `0x5777558` (idx 77450) | `0x4eef596` (not traced) |

GOT-slot caller counts: `0x576e098` is the shared
binary-wide panic entry (3860 indirect call sites —
not exclusive to this chain). `0x57770e8` has exactly
one caller (`0x4ecdcf0`). `0x57706e0` has exactly two
callers (`0x157b810` and `0x157b690`).

### The adapters

- `0x157b810` (44 B) builds a stack struct:
  `[rbp-0x10] = msg ptr`, `[rbp-0x8] = second word`,
  `[rbp-0x28] = &pair`, `[rbp-0x20] = location`,
  `WORD [rbp-0x18] = 1`, then calls `[0x57706e0]`
  with the struct address.
- `0x157b7f0` (18 B) is the tag adapter: it leaves
  `rdi`/`rdx` alone, replaces `rsi` with `rsi*2+1`,
  then calls `[0x576e098]`. The unwrap helper is its
  only #179-route user (raw 43 → tagged 87).
- `0x4ecdcf0` (29 B) copies the struct's first 16
  bytes (`&pair`, location) to its own stack and
  passes a pointer to the copy onward. The trailing
  flag bytes are not copied — but they are not lost:
  `0x4ecdcf0` stores its own input `rdi` immediately
  after the copy, so the decoder reads the flags at
  copy `+0x10` (the original struct pointer).
- `0x157b690` (53 B) is the second caller of the copy
  adapter: same 16-byte prefix shape, but trailing
  flags `BYTE 0` + `dl` instead of `WORD 1`.
- The bounds-check helper (`0x157a6f0`, 200 B) and
  the pair helper (`0x157a9b0`, 52 B) pass a stack
  struct pointer as the second word (even, aligned) —
  the pointer side of the representation, not a
  length at all.

### The decoder branch

At `0x4eef390`:

```
mov rcx,[rdi]            ; &pair
mov rax,[rcx+0x8]        ; second word
test al,0x1
jne decode               ; odd -> static string
... even path: sentinel 0x8000000000000000, table 0x57528b0 ...
decode:
mov rcx,[rcx]            ; msg ptr
shr rax,1                ; true byte length
mov [rbp-0x28],rcx
mov [rbp-0x20],rax
mov rdx,[rdi+0x8]        ; location
mov rax,[rdi+0x10]       ; original struct pointer
movzx ecx,BYTE [rax+0x10] ; flag byte 1
movzx r8d,BYTE [rax+0x11] ; flag byte 2
lea rsi,[0x5752878]      ; odd-path table
call [0x5777558]
```

For the panic-adapter path the flag bytes are
(1, 0); for the second caller they are (0, `dl`).
Both paths call the same next hop
(`[0x5777558]` → `0x4eef596`) with different tables.

### Routes of #179's 35 sites

| GOT slot | helper | sites |
|---|---|---|
| `0x576e118` | thunk-add | 9 (entries 2, 19x3, 21x3, 23, 25) |
| `0x576e150` | thunk-sub | 9 (entries 11, 18, 20x3, 22x4) |
| `0x576e1b0` | thunk-mul | 1 (entry 1) |
| `0x576e2e0` | helper-bounds | 2 (entries 3, 24) |
| `0x576e468` | helper-pair | 1 (entry 0) |
| `0x576e470` | helper-unwrap | 13 (continuation, entries 4–17) |

## Inferences (separated from observations)

- The second word's low bit is a representation tag,
  not part of the length: odd selects the static-string
  form (length = word >> 1), even selects a pointer
  form (the word is an aligned address). This single
  rule explains all nine thunk words, the unwrap
  transform, and both decoder paths.
- The "recorded lengths span packed messages" reading
  in #179 was an artifact of reading tagged words as
  byte lengths: 57 bytes from "attempt to add with
  overflow" runs 29 bytes into the next packed literal
  only if 57 is taken as a length; as a tag it is
  exactly 28.
- The adapter chain's 16-byte forwarding boundary
  plus the saved-pointer flag read is consistent with
  a message argument of (pair, location, flags) where
  only (pair, location) is forwarded by value and the
  flags are read in place downstream.

## Prior work and overlap

Segment-claim overlap with #157–#179 is zero bytes
(verified programmatically: format-aware check over
all available prior `segments.txt` files, 82 intervals
across #166/#168–#179, plus an address grep over the
#157–#165/#167 packet directories — only incidental
substrings in base repo files, no claimed bytes).
No anchors: no prior claim is re-cited. The candidate
directory name is absent from live upstream main
(trees API recursive, not truncated). No competing
open PR matched the searches (panic+tagged,
panic+length, tagged+length, panic+chain — all 0 hits).

## Verification

- Target: node #94 only (91,774,280 bytes, SHA-256
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
  Static analysis only; the node binary was never executed.
- Generator (tools/panic_tagged_length.py) verifies the node
  digest and size first, checks every recorded instruction byte
  against the binary (code address A at file offset A - 0x1000;
  `.rodata` address A at file offset A), checks every message
  byte and the tagged arithmetic (raw odd, (raw-1)//2 == true),
  checks the tag transform bytes, the decoder branch bytes
  (`test al,1` at +0x10, `shr rax,1` at +0x4d), and all 17
  chain relocations by `.rela.dyn` entry index (entries are
  24 bytes at file offset `0x6bc0`), then writes only
  to --out. Regeneration in two directories with
  different PYTHONHASHSEED/TZ is byte-identical and matches the
  packet files (README/MANIFEST excluded).
- MANIFEST.sha256: 6/6 OK. Unit tests: 6/6 pass
  (tests/test_panic_tagged_length.py). make doctor:
  analysis_ready true. make verify: exit 0. make
  catalogue-check: exit 0. make test: Ran 448 tests, OK (442
  baseline + 6 new, 0 regressions).
- Reproduce: objdump -d -M intel --start-address=<thunk>
  artifacts/node/94/hl-node for any thunk in thunks.tsv;
  readelf -r -W artifacts/node/94/hl-node | grep -E "576e098|57706e0|57770e8"
  for the chain relocations; code address A maps to file offset
  A - 0x1000; `.rodata` uses offset == VA; `.rela.dyn`
  entries are 24 bytes at file offset `0x6bc0`.

## Limitations

- The generator verifies recorded instruction bytes but
  does not disassemble; the site census rests on #179's
  full `.text` objdump census plus this packet's FDE and
  relocation checks.
- The even-path (pointer) message representation is
  characterized by branch shape only; its structure
  and the two tables (`0x5752878`/`0x57528b0`) are not
  analyzed, and nothing past the decoder's call to
  `[0x5777558]` is traced.
- The flag bytes' semantic names are not determined;
  only their values ((1, 0) panic path, (0, `dl`)
  second caller) and their read site are reported.
- Static analysis only; no node execution, so no runtime
  values beyond the statically forced relocation values
  and file bytes are claimed.

## Next question

- Which FDEs contain #179's 35 sites? (Computed, not
  packetized here: 11 FDEs; all 13 continuation sites
  plus the continuation itself sit in FDE
  `0x4e79b00..0x4e7a541` — one caller function, not a
  cross-function fragment. The continuation code bytes
  are unclaimed.)
- What are the `0x574c1a8` object (`0, 1, 1`) and the
  `0x574c1c0` object (reloc to dispatcher `0x4e7c780`,
  `0`, 100) that follow the location run — the next
  record's header, or unrelated data? Leads: the
  post-run region is a long table (lea sites past
  `0x574c400`, be20 sibling slots `0x574c2b0`/
  `0x574c2b8` → `0x1510490`/`0x15103f0`), and a 5-arg
  call at `0x4e7c0d2` passes `0x574c1a8` and
  `0x574c270` via GOT `0x576e048` → `0x157aa10`
  (unresolved).
- What does decoder `0x4e84500` write to out+8 on the
  tag==5 path (corrected framing — not a caller stack
  argument; #176's label remains uncorrected by any
  packet)?
- What is the even-path message representation, and
  what do the decoder's two tables contain?

## Files

- `README.md` — this file (counts cross-checked against the files below)
- `evidence.json` — node binding, thunk table, chain hops, routes, decode, counts
- `thunks.tsv` — 9 rows, one per message thunk
- `chain.tsv` — 9 rows, one per chain hop
- `routes.tsv` — 6 rows, routing #179's 35 sites
- `segments.txt` — 28 rows: 28 claim segments (1184 bytes),
  each with start..end, length == end − start, file offset,
  and SHA-256
- `MANIFEST.sha256` — digests of the 6 files above
