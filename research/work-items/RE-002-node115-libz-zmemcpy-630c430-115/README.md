# RE-002 — node #115 libz `zmemcpy` at 0x630c430

Bounded reconstruction of one vendor routine inside the pinned node artifact.

| field | value |
|---|---|
| artifact | `artifacts/node/115/hl-node` |
| artifact SHA-256 | `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` |
| symbol | `zmemcpy` |
| member | `f0389296f42960e9-zutil.o` |
| rlib | `liblibz_sys-a9c65f05df14367b.rlib` |
| crate / versions | `libz-sys` / `1.1.22` |
| window | `0x630c430..0x630c558` (296 bytes, 90 instructions) |
| FDE | `pc=000000000630c430..000000000630c558` |
| body key | `target_body_sha256 == source_body_sha256` (`194f2a48…df`), `raw_equal`, 0 relocations, 1 source object |
| form | leaf: no calls, no relocations |

The vendor census records a version note for this window: node #115 embeds
`ZLIB_VERSION "1.3.1"`, but these bodies are identical in the zlib 1.3.2
bundled by libz-sys 1.1.31, **so this window does not pin the zlib release**.
The packet therefore cites the member and the body digest rather than a zlib
version.

## Question

What bytes does the 296-byte leaf routine at `0x630c430` write for a
destination, a source and a length, and which path does its own guard select?

## Answer

```
void zmemcpy(dest, source, len)      # no return value: the contract is memory

len == 0                              -> nothing is read or written
len <= 7                              -> byte loop
1 <= dest-source <= 15                -> byte loop      (the guard)
otherwise                             -> 16-byte chunks, then a byte tail
```

Both paths copy forward and both produce the same bytes for non-overlapping
regions, which is why the interesting content of this window is the third line.

### The guard, and why the window is not just "memcpy"

`semantics.tsv` anchors every claim to the instruction that carries it
(19 rows: claim, address, size, bytes, decoded instruction, note); `verify.py`
and the tests re-read every anchor's bytes from the digest-verified artifact and
re-decode them with Capstone.

* **The overlap probe compares against `source + 1`, unsigned.**
  `lea 0x1(%rsi),%rsi` / `mov %rdi,%rcx` / `sub %rsi,%rcx` / `cmp $0xe,%rcx` /
  `ja 0x630c478` (`0x630c445..0x630c453`) take the chunk path only when
  `dest-(source+1) > 14`, i.e. the byte loop is kept exactly for
  `1 <= dest-source <= 15`. Because the subtraction is unsigned, every case with
  `dest <= source` — including `dest < source`, where the difference wraps to a
  huge value — falls through to the chunk path, which is safe because the chunk
  loop also copies forward.
* **The chunk path snapshots 16 bytes before storing them.** `movdqu` loads the
  chunk (`0x630c490`) and `movups` stores it (`0x630c496`), so a store cannot
  feed the next load *within a chunk*. On overlapping regions that produces
  different bytes than the one-byte loop (`movzbl`/`mov` at
  `0x630c460`/`0x630c465`, which stores one byte and then reads the next). The
  committed ledger records **96 rows where the chunk result differs from the
  byte result**, and one test asserts the difference explicitly: for `len = 18`
  with `dest = source + 1` the byte loop yields eighteen copies of the first
  byte, while the chunk path yields the first 16 bytes unchanged and then
  `[16, 18]`, because its tail reads a byte the first chunk already overwrote.
  That is what the guard prevents.
* **Short copies never reach the chunk path.** `lea -0x1(%rdx),%edx` with
  `cmp $0x6` and `jbe 0x630c455` (`0x630c43d..0x630c443`) test `len-1 <= 6`, so
  the byte loop handles `len <= 7`; after the guard, `cmp $0xe,%edx` with
  `jbe 0x630c548` (`0x630c478/0x630c47b`) skips the chunk loop for `len <= 15`
  and goes straight to the byte-at-a-time tail. Both tests are on `len-1`, not
  on `len`.

## Caller census

44 direct calls, 0 tail jumps, in the caller FDEs listed in `records.json`, each
validated at the instruction boundary with Capstone and attributed to the
`.eh_frame` FDE that encloses it (`callers.tsv`).

The routine is **void**, so this packet does not present a returned-value
contract: `caller_use.tsv` records what each caller does with `rax` *after* the
call, which here is the caller's own reuse of the register — 42 sites write
`rax` before reading it and 2 never read it again. `records.json` states that
explicitly in `caller_census.contract` and a test asserts it, so a reader cannot
mistake the column for evidence about a return value. The evidence for the
caller contract is the recorded continuation of each site, not a value it
receives.

## Evidence in this directory

| file | what it holds |
|---|---|
| `main.txt` | the raw `objdump -d` excerpt for the window (91 lines, 90 instructions) |
| `frames.txt` | the `.eh_frame` FDE `0x630c430..0x630c558` |
| `relocations.txt` | no relocations; the raw-equal body digests |
| `callers.tsv` | the 44 call sites with their enclosing FDE bounds |
| `caller_use.tsv` | per-site post-call `rax` activity and the following instructions |
| `functions.tsv` | empty: this routine calls nothing |
| `semantics.tsv` | 19 claim anchors (claim → address → bytes → decoded instruction) |
| `cases.tsv` | 300 reviewable cases with a `path` column and a `vector_only_differs` column |
| `records.json` | observations vs inferences, the derived census, the unknowns |
| `census.py` | regenerates `callers.tsv`, `caller_use.tsv`, `frames.txt`, `relocations.txt` |
| `semantics.py` | regenerates `semantics.tsv` from the artifact |
| `export_excerpts.py` | regenerates `main.txt` from the artifact |
| `verify.py` | re-checks the manifest, the anchors, the census and the model |
| `MANIFEST.sha256` | every file here, plus the model and its tests |

## Validation

* `python3 research/work-items/RE-002-node115-libz-zmemcpy-630c430-115/verify.py`
  → re-checks the manifest, the excerpt, the 19 anchors, the 44-call census and
  the model against the artifact.
* `python3 -m unittest discover -s tests -p test_zmemcpy_630c430_115.py`
  → 31 tests, `OK`.
* The model in `tools/zmemcpy_630c430_115.py` is a path law plus a replay of the
  selected path over an explicit buffer, **plus** an emulator that executes the
  routine's own decoded bytes (including `movdqu`/`movups`) on a small machine
  model that raises on any instruction it does not implement. The two agree on
  the whole 2,400-case sweep, on every committed ledger row, and on 600 random
  cases. Modelling the buffer explicitly matters here: host `memcpy` semantics
  are undefined for overlapping regions, so the model has to reproduce what this
  compiled body does rather than what a host would do.
* The excerpt's concatenated bytes are asserted equal to the binary's own bytes
  for the window, in both `verify.py` and the tests, and the guard's operands are
  asserted through the Capstone decoder rather than through objdump's text.
* The ledger is stratified so each family selects one path: `empty` (len = 0),
  `small` (len 1..7), `overlap` (len ≥ 8 with `1 <= dest-source <= 15`) and
  `vector` (len ≥ 16 with no overlap).

## Limits

* Static only: the artifact is never executed, and no source build is claimed.
  The emulator is deliberately narrow: it implements the instructions this
  routine uses and raises on anything else.
* For overlapping inputs the C-level result is undefined by the C standard; the
  packet reports what **this** compiled body computes, which is precisely the
  point of reconstructing it. Whether any caller actually passes overlapping
  regions is not characterized here.
* Reading the three arguments as destination, source and byte count is an
  **inference** from the symbol name and the loops' strides; the packet does not
  prove the C types.
* This window cannot pin the zlib release (see the version note above), and
  `identical_source_count` is 1, so there is a single source object.

## Provenance

`libz-sys` / zlib is public (zlib licence). Nothing inferred is copied from
unlicensed sources, and the files added here are MIT under the root license. No
private keys, tokens or live datasets are included.
