# RE-001-node115-lu-write-surface: control-tree write surface and gate

- Component ID: RE-001-node115-lu-write-surface
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`,
  105,896,032 bytes,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main
  `05bc2de303c05525b71e7e257426e741bc66a390` (fetch-confirmed before
  analysis; main clone HEAD untouched at `2993e46`)
- Claim status: observation for all exhibited windows and censuses;
  inference for the flag state names (idle / in-progress / requested)
  and the handler argument convention (context, oldp, oldlenp, newp,
  newlen); unresolved for the ~199 undecoded leaves, the predicate's
  slow-path setup calls, the completion tail-call, and the TLS-byte
  slow path (see README scope section)
- Scope included and excluded: gate flag + predicate + request-init +
  thunk; epoch/tcache-flush/peak-reset/prof-reset/prof-dump handlers;
  init entry; formatter entry; full tree census. Excluded: full bodies
  of the 2085B predicate, 957B request-init, and 633B epoch FDEs
  (key windows only, characterized otherwise); per-leaf read/write
  classification beyond the five decoded handlers and the cited sweep

## Reproduce

Working directory: a worktree of the upstream tree at the commit above.
Static analysis only; the binary was never executed. Tools: `objdump`
(GNU), `readelf`, Python 3 (byte scans, `.rela.dyn` walk). Coordinate
system: `.text` file offset = VA − 0x1000 (verified against program
headers: PT_LOAD file offset `0x1418300` ↔ vaddr `0x1419300`, delta
`0x1000`, and against objdump bytes at two entry points);
`.data.rel.ro`/`.got` file offset = VA − 0x2000; `.rodata` VA as-is.
RELATIVE `.got`/`.data.rel.ro` slots are zero-filled in the file, so
runtime values were read through `.rela.dyn` addends. FDE bounds from
`readelf --debug-dump=frames-interp` (PC-relative sdata4 encoding,
CIE augmentation zR, encoding byte `0x1b`).

Commands used (representative):

- `objdump -d --start-address=<va> --stop-address=<va> hl-node`
  per exhibit window; instruction counts are strict mnemonic lines
  (address + bytes field + tab + mnemonic; objdump byte-continuation
  lines excluded).
- Full-`.text` flag census: `objdump -d --section=.text hl-node |
  grep 64ffab4`, every line classified by mnemonic (3 movl writes,
  12 mov reads, 1 lea read whose next instruction dereferences it).
- Direct-call census: raw E8/E9 scan over the `.text` file range
  (`0x1418300`, size `0x4fd7700`), target = site VA + 5 + rel32; every
  reported site re-verified with objdump to be a genuine call/jmp
  (no embedded-immediate false positives survived).
- Tree walk: `readelf -r` RELATIVE map (59,534 entries) + node
  struct `[flag, name, count, children, handler]` (40 bytes,
  `.data.rel.ro`); flag-0 nodes treated as dynamic (not static
  arrays) and not recursed into; 246 nodes, 204 leaves, 7 dynamic.

## Evidence

Original addresses (VA), all in `.text` unless noted:

- Predicate `0x634f0b0..0x634f8d5` (2085B): mutex `0x6509660`,
  owner slot `0x6509690`, contended byte `0x6509688`, flag
  `0x64ffab4`, neighbour byte `0x64ffab0`, init context pointer
  `0x6712130`.
- Request-init `0x634ece0..0x634f09d` (957B): owner write at
  `0x634ed32` (`pthread_self` → `0x6509690`), flag = 2 at
  `0x634ef6a`.
- Thunk `0x635f320..0x635f334` (20B, full FDE): flag read at
  `0x635f324`, return-0 at `0x635f32e`, tail-jump at `0x635f32f`.
- Epoch `0x63a7fc0..0x63a8239` (633B): init mutex `0x67121a0`,
  newp/newlen check at `0x63a800f..0x63a8021`, advance call
  `0x63a77d0` at `0x63a802b`, read fast path at `0x63a8030..0x63a8052`,
  copy tail from `0x63a8088`.
- Action handlers (full FDEs): tcache flush `0x636de20..0x636de56`
  (flush call `0x63ec600`); peak reset `0x636e210..0x636e236`
  (reset call `0x63c2cf0`); prof reset `0x636d870..0x636d8d1`
  (enabled byte `0x6713606`, global value `0x6712438`, reset call
  `0x63cf9d0`, clamp 63); prof dump `0x6377850..0x63778a1`
  (dump call `0x63c3700`, result mapped with `and $0xe`).
- Init `0x63a8240..0x63a84ea` (714B): mutex `0x67121a0`, init flag
  `0x6712140` (set at `0x63a8398`), table pointer `0x6712130`,
  count `0x6712138`, `0x1000`/`0x1001` entry indices.
- Formatter `0x63de320..0x63de5bd` (669B): state at `(%rdi)`,
  flag bytes `+0x1c`/`+0x1d`, count at `+0x18`, formatter
  `0x63dbd80`, format strings `0x4451e9`, `0x433058`,
  `0x43e7c4`, `0x43b529`, `0x449912`, `0x44ecd8`, empty string
  `0x4376fd`.
- Gate callers (E8): `0x6354368`, `0x6356483`, `0x6358979`,
  `0x635b3c1` (four large allocator FDEs), `0x635df45`,
  `0x635dfe5`, `0x635e098` (three gated helpers); E9: `0x635f32f`
  (thunk).
- Init callers (E8, one each): `0x63a88df` (invoke), `0x63a89b3`
  (wrapper), `0x63a8a26` (walk-invoke), `0x63a8d2a` (sibling),
  `0x63a9056` (dispatcher); E9: none.
- Formatter callers (E8, 18 sites): `0x63e119c`, `0x63e2dee`,
  `0x63e452e`, `0x63e4ab0`, `0x63e5b0d`, `0x63e5c17`, `0x63e6b6b`,
  `0x63e6f2a`, `0x63e7399`, `0x63e80c4`, `0x63e8207`, `0x63e82e2`,
  `0x63e841e`, `0x63e8491`, `0x63e865d`, `0x63e86ce`, `0x63e8765`,
  `0x63e8a0e`; E9: none.
- Direct entries to decoded leaf handlers: none (E8 0, E9 0 for
  epoch, tcache flush, peak reset, prof reset, prof dump). Wrapper:
  E8 0, E9 1 (`0x635dfd3`); invoke: E8 0, E9 1 (`0x635df37`).

Analysis was complete for the censuses and the exhibited windows,
and limited to key windows plus structural characterization for the
three large FDEs (predicate, request-init, epoch). The `.bss`
contents are runtime-filled and not in the file; no `.bss` value is
claimed from the file. Error codes are reported as raw numbers.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is included in
this packet; the verifier is a static byte/census checker, not a
behavioral reimplementation. No two-build comparison applies.

## Results and limitations

Metrics with denominators: 12 exhibited windows, 851 bytes, 210
strict lines; flag census 16/16 references classified (3 writes, 12
reads, 1 lea-read); gate callers 8/8 verified; init callers 5/5;
formatter callers 18/18; handler direct entries 0 for five handlers;
tree walk 246 nodes / 204 leaves / 7 dynamic nodes, leaf set matched
by the verifier. Disjointness: 847 merged-tree ranges, 0 overlaps;
862 extended with #255/#256 worktrees, 0 overlaps.

What remains unknown is listed in the README scope section. No
progress gate is requested by this packet. Next question: complete
the per-leaf read/write classification for the remaining ~199
leaves (starting with `arenas.create`, `tcache.create/destroy`,
`experimental.hooks.install/remove`, `prof.log_start/log_stop`,
`thread.prof.active`); decode the TLS-byte slow path (`0x63ef8e0`)
and the predicate's completion tail-call (`0x6368e40`); find the
writers of the prof-gating byte `0x6713606`.
