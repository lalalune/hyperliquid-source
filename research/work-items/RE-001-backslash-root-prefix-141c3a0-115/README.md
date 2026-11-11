# RE-001: node #115 backslash-root prefix test 0x141c3a0

## Bounded question

What boolean does routine `0x141c3a0` (FDE `0x141c3a0..0x141c3d3`,
51 bytes) compute over the byte buffer it is handed, which bytes
does it read, and what does it leave unread?

## Answer, pinned to the target

The routine takes a byte buffer as a pointer/length pair --
`rdi` is the pointer, `rsi` is the length -- makes no calls,
writes nothing, and returns one boolean byte in `al`. The
decision, in order, read from the whole-function excerpt
(`main.txt`):

1. If the length is 0 (`test %rsi,%rsi; je`), return 0. The
   pointer is never dereferenced on this path.
2. If `byte[0]` is `0x5c` (`\`), return 1 (`cmpb $0x5c,(%rdi);
   je`). The length and the remaining bytes are not read on this
   path.
3. If the length is 1 (`cmp $0x1,%rsi; je`), return 0.
4. If `byte[1]` is a UTF-8 continuation byte, return 0. The test
   is `cmpb $0xc0,0x1(%rdi); jl`: a signed-byte compare taken
   exactly when `(int8)byte[1] < -64`, i.e. for `byte[1]` in
   `0x80..0xbf`. This is the standard `is_char_boundary` guard --
   `byte[1]` must begin a character.
5. If the length is 2 (`cmp $0x3,%rsi`, with neither `ja` nor
   `je` taken, falling through to `xor %eax,%eax`), return 0.
6. If the length is greater than 3 and `byte[3]` is a UTF-8
   continuation byte, return 0 (`cmpb $0xc0,0x3(%rdi); jl`). For
   length exactly 3, `byte[3]` is never read.
7. Otherwise return `byte[1] == 0x3a (':')` **and** `byte[2] ==
   0x5c ('\')` (`cmpw $0x5c3a,0x1(%rdi); sete %al`).

In words: the routine returns 1 exactly when the buffer begins
with a **backslash separator root** -- a leading `\`, or `?:\`
where the first character is any single-byte character, `byte[1]`
is `:` and `byte[2]` is `\`, with `byte[3]` (when present)
starting a new character. The two `cmpb $0xc0 .. jl` guards are
UTF-8 char-boundary checks, so the routine treats the buffer as
`str` text.

Fields read, and nothing else:

| index | width | role |
| ----- | ----- | ---- |
| `byte[0]` | 1 | leading-backslash fast path: 1 when it is `0x5c` |
| `byte[1]` | 1 | must begin a character (not `0x80..0xbf`) before the drive-style test |
| `byte[1]` | 2 (word) | the drive-style true case needs `== 0x5c3a` (`byte[1]=':'`, `byte[2]='\'`) |
| `byte[3]` | 1 | read only when length > 3; must begin a character |

The routine never reads a buffer byte at index 4 or beyond, never
reads `byte[1]`/`byte[3]` after an earlier length check has
already decided the result, writes nothing, and makes no calls.
All five of its direct jumps land inside its own FDE range.

## Semantic inference (not claimed)

The strong resemblance to a Windows backslash-root / drive-letter
prefix check (`\...` or `?:\...`) is reinforced by the sole
caller, `0x141c3d3..0x141c571`, which just before the first call
site inlines the **forward-slash twin** of this test -- `cmpb
$0x2f,(%r15)` (`/`) and `cmpw $0x2f3a,0x1(%r15)` (`:/`) -- and at
`0x141c459..0x141c468` selects the path separator with `cmovne`
between `0x2f` (`/`) and `0x5c` (`\`) from this routine's result
before comparing it against the buffer's last byte. That reads as
a cross-platform path-join choosing `/` vs `\`. This packet claims
only the bytes this routine reads and the boolean it returns; the
path-join interpretation is recorded as context, not asserted.

## Consumers (site-only)

The exhaustive executable-segment E8/E9 census finds exactly two
direct call sites, no tail jumps, and the routine's address is
never stored as a qword and never appears as a RELATIVE addend:

- `0x141c422`, inside caller `0x141c3d3..0x141c571`. `rdi` is the
  caller's second argument pointer (`r15`) and `rsi` its length
  (`rbx`), set at `0x141c41c..0x141c41f`.
- `0x141c449`, inside the same caller. `rdi` is field `+0x8`
  (`r13`) and `rsi` field `+0x10` (`r12`) of the first argument
  object, loaded at `0x141c43b..0x141c446`.

## NOT claimed

What the buffers denote; what the caller ultimately produces;
behaviour on a dangling pointer or a length that exceeds the real
allocation (the model raises on a non-bytes argument, its own
guard, stated openly); the meaning of the neighbouring routines
`0x141c267..0x141c3a0` and the caller `0x141c3d3..0x141c571`
beyond the two call sites and argument setup cited above.

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json), materialised locally as
  `work/hl-node-115.bin` with the same hash.
- `main.txt`: the whole routine, verbatim, produced by
  `objdump -d --start-address=0x141c3a0 --stop-address=0x141c3d3 work/hl-node-115.bin`.
  The excerpt is the only instruction-level artifact; `records.json`
  holds semantic records only.
- `frames.txt`: the routine's FDE and its sole caller's FDE from
  `readelf --debug-dump=frames`. `callers.tsv`: the two direct call
  sites with the smallest enclosing caller FDE range.
  `relocations.txt` is empty: no relocation record mentions this
  routine.
- Census method: the external call census uses the exhaustive
  executable-segment E8/E9 scan with per-candidate objdump
  confirmation (`census.py`); both sites were confirmed as real
  `call 0x141c3a0` instructions. The routine's own control
  transfers are classified from one linear disassembly of the whole
  routine range (true instruction starts only).
- `verify.py` re-checks the digest, the manifest, excerpt
  regeneration byte-for-byte against a fresh objdump run, every
  excerpt instruction byte-for-byte against the raw binary, three
  spot instructions, the FDE ranges, the empty relocation set, the
  census, the records, the model tests, and the independent oracle
  (below). `census.py` reproduces the census; `export_excerpts.py`
  regenerates `main.txt`.
- Model: `tools/backslash_root_prefix_141c3a0_115.py`, tested by
  `tests/test_backslash_root_prefix_141c3a0_115.py` (31 checks).

### Independent byte-level oracle

The model is a reading of the disassembly, so it is cross-checked
against an execution of the bytes. `interp_141c3a0.py` maps the
virtual address `0x141c3a0` to a file offset through the ELF
program headers, reads the 51 raw instruction bytes, decodes only
the opcodes this routine contains (`test`, `cmpb`/`cmpw`/`cmp`
with honest signed/unsigned flag semantics, `je`/`jl`/`ja`,
`mov $imm8,%al`, `xor`, `sete`, `ret`; any other opcode raises),
and interprets them over a synthetic buffer, returning `al`. It
never imports the model.

`oracle_compare.py` confronts the two. Over **13146** buffers --
every buffer of length 0..4 (11111) drawn from the class-covering
alphabet `00 2f 3a 41 5c 7f 80 bf c0 ff`, plus deterministic
length 5..6 samples -- the interpreter's `al` equals the model's
boolean on **100%** (0 mismatches). The interpreter also records
which indices it reads: the **maximum index read is 3**, no buffer
reads index >= 4, and no buffer reads index 3 when its length is
<= 3 -- a direct, execution-grounded proof of the read claims.

Four one-byte **corruption controls** patch a copy of the routine
and confirm each patched interpreter diverges from the model while
the unpatched one matches 100% (counts over the 11111-buffer
length-0..4 pool, full witnesses in `oracle_results.txt`):

| patch | byte | divergences | sample witness |
| ----- | ---- | ----------- | -------------- |
| `cmpb $0x5c -> $0x2f` (0x141c3a7) | `[9]:=0x2f` | 2204 | `5c` -> interp 0, model 1 |
| `cmpw $0x5c3a -> $0x2f3a` (0x141c3c9) | `[46]:=0x2f` | 162 | `003a5c` -> interp 0, model 1 |
| `jl (7c) -> jge (7d)` (0x141c3b6) | `[22]:=0x7d` | 81 | `003a5c` -> interp 0, model 1 |
| `ja (77) -> jae (73)` (0x141c3bc) | `[28]:=0x73` | 720 | `000000` (len 3) -> patched reads OOB index 3 |

The last control is the sharpest form of the bounds claim: turning
the length-`>3` test into length-`>=3` makes the routine read
`byte[3]` at length 3, which the real routine and the model never
do.

## Reproduce

Working directory: the repository root. Tools, all from this run:

- GNU objdump (GNU Binutils for Ubuntu) 2.42, invoked as
  `objdump -d --start-address=0x141c3a0 --stop-address=0x141c3d3 work/hl-node-115.bin`
- GNU readelf (GNU Binutils for Ubuntu) 2.42, invoked as
  `readelf --debug-dump=frames work/hl-node-115.bin` and
  `readelf -r work/hl-node-115.bin`
- Python 3 for `census.py`, `verify.py`, `export_excerpts.py`,
  `interp_141c3a0.py`, `oracle_compare.py`, and the model tests. The
  interpreter statically reads 51 bytes out of the ELF and runs them
  over synthetic in-memory buffers; it never executes the target.
  Regenerate the oracle report deterministically with
  `python3 research/work-items/RE-001-backslash-root-prefix-141c3a0-115/oracle_compare.py --write`.
- Input: `work/hl-node-115.bin`, SHA-256 as above; no execution of
  the target binary, no network, no side effects beyond writing the
  packet files listed in MANIFEST.sha256.

## Duplicate check

Before claiming this routine: `grep -rn` for `141c3a0`/`0x141c3a0`
across `research/` and `docs/` returns nothing; `gh search prs`
and `gh pr list --search` on `141c3a0` against the repository
return nothing. The address is absent from `docs/PROGRESS.md`,
`research/byte-windows.json` and the vendor census.

## Verification scope and next step

This packet's own checker (`verify.py`), the model tests, and the
byte-level oracle (`tests/test_oracle_141c3a0_115.py`, which skips
cleanly when the binary is absent) print ALL CHECKS PASSED and
their check counts before submission.
Repository-wide gates (`make verify`, `make test`,
`make catalogue-check`) cover the whole tree; their baseline on
this VM is affected by missing LFS material and the absence of
cargo/rustc, pre-existing environment limits, not results of this
change. The next question is what the caller `0x141c3d3` produces
end-to-end, and whether a standalone forward-slash twin of this
routine (currently only inlined in that caller) exists elsewhere.
