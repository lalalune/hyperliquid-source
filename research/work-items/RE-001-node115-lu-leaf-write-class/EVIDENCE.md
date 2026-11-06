# RE-001-node115-lu-leaf-write-class: per-leaf write classification, TLS slow path, completion wrapper, prof-byte writers

- Component ID: lu (control-tree leaf dispatcher family), node #115
- Target release and full SHA-256: artifacts/node/115/hl-node, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `05bc2de303c05525b71e7e257426e741bc66a390`
- Claim status: observation (disassembly + byte census); inference where marked
  (helper identities, state-machine labels); unresolved where listed below
- Scope included and excluded: included — 8 leaf handlers, TLS slow path
  `0x63ef8e0..0x63efba2`, completion wrapper `0x6368e40..0x6368ebb`, prof-byte
  `0x6713606` census. Excluded — ~190 remaining leaves; internals of
  `0x63ef640`, `0x63eec10`, `0x63ed870`; the option-parser FDE beyond the two
  store windows; the shared-tail target `0x63ef8d7` beyond its observed bytes.

## Reproduce

Worktree `~/workspace/hl-wt-calls258-115` (branch `codex/re-004-calls258-115`,
from upstream main). Static analysis only; the binary was never executed.
Coordinate system: `.text` file offset = VA − `0x1000` (program-header
verified: R-E LOAD spans file `0x1418300..0x63f6ba0`, VA = offset + `0x1000`);
`.data.rel.ro`/`.got` = VA − `0x2000`; `.rodata` = VA as-is. FDE bounds from
`readelf --debug-dump=frames-interp` `pc=…` lines (PC-relative sdata4
encoding, CIE `zR`, byte `0x1b` — naive absolute parsing returns garbage).
Instruction counts are strict mnemonic lines (address + bytes + tab +
mnemonic; byte-continuation lines excluded). Verifier:
`python3 tools/node115_leaf_write_class.py`; tests:
`python3 -m unittest tests.test_node115_leaf_write_class -v` (or the test
file directly). Full `make test` was NOT attempted (584 test files on the
new base; hours-long, VM-restart risk).

## Evidence

### Leaf table source

Packet #257's `records.json`, `census.tree.leaves`: 246 nodes, 204 leaves,
7 flag-0 dynamic nodes. Leaf entries are `[path, node_hex, {va, flag, name,
count, children, handler}]`. The eight leaves decoded here, with node,
handler FDE, and `.rela.dyn` slot (slot − node = `0x20` in all cases):

| Leaf | Node | Handler FDE | Rela slot |
|---|---|---|---|
| arenas.create | `0x64dde78` | `0x63a5950..0x63a5bef` | `0x64dde98` |
| tcache.create | `0x64de260` | `0x6377950..0x6377b5d` | `0x64de280` |
| tcache.destroy | `0x64de2b0` | `0x63778b0..0x63778f6` | `0x64de2d0` |
| experimental.hooks.install | `0x64da9c0` | `0x636d5f0..0x636d863` | `0x64da9e0` |
| experimental.hooks.remove | `0x64da9e8` | `0x6376d50..0x6376d9e` | `0x64daa08` |
| prof.log_start | `0x64ddaa0` | `0x63777f0..0x6377841` | `0x64ddac0` |
| prof.log_stop | `0x64ddac8` | `0x63777c0..0x63777ee` | `0x64ddae8` |
| thread.prof.active | `0x64df0a8` | `0x636de60..0x636df5e` | `0x64df0c8` |

Handler argument convention (from #257, consistent here): `%rdi` = context,
`%rcx` = oldp, `%r8` = oldlenp, `%r9` = newp, stack = newlen.

### Leaf decodes (raw disassembly in the `.objdump.txt` exhibits)

- **arenas.create** (`0x63a5950..0x63a5bef`): mutex-guarded on init mutex
  `0x67121a0` (trylock; contention → #251 wait helper `0x63bf680`, record
  base `0x67121a0−0x40`, contended byte `0x67121c8`; counters `0x6712198` /
  `0x6712188`, last-ctx slot `0x6712190`). Entry gates: oldp and oldlenp
  both present and `*oldlenp == 4`, else `*oldlenp := 0` (through oldlenp,
  unconditionally dereferenced on that path) and return 22. Copies a 16-byte
  template from `0x64da4b0` to the stack; if newp present, newlen must be 8
  (else 22) and `*newp` overwrites the template's first qword. Calls
  arena-create routine `0x63a5550` (ctx, template); result −1 → 11; success
  → `*oldp` = new arena index (4 bytes), 0. The FDE also carries a generic
  bounded-copy readback (`min(*oldlenp,4)` bytes); on the entry-enforced
  `*oldlenp == 4` path the direct 4-byte store runs. Exhibit
  `arenas_create_head` ends after the result save at `0x63a5a01`; the
  contention path at `0x63a5a60` is characterised, not exhibited.
- **tcache.create** (`0x6377950..0x6377b5d`): pure-action gate — newp or
  newlen nonzero → 1. oldp/oldlenp missing or `*oldlenp != 4` → `*oldlenp :=
  0`, 22. Calls `0x636b0a0` (context fetch, cited from #257's slow-path
  list) then create routine `0x63ee0a0` (ctx, context-result, out-slot);
  boolean failure → 14; success → `*oldlenp == 4` gives `*oldp` = created
  id, 0; otherwise bounded copy, `*oldlenp := min`, 22 (copy exit at
  `0x6377b50` jumps to `0x6377997`, the `mov $0x16` return-22 path). Exhibit
  ends after the `*oldp` store at `0x6377a00`.
- **tcache.destroy** (`0x63778b0..0x63778f6`, full FDE): oldp\|oldlenp
  nonzero → 1; newp zero → 22; newlen must be 4 (else 22); calls destroy
  routine `0x63ee2a0` (ctx, `*newp` as `%esi`); 0. Pure write.
- **experimental.hooks.install** (`0x636d5f0..0x636d863`): validation
  requires newp nonzero, newlen == `0x20` (32 bytes = 4 pointers), oldlenp
  nonzero, oldp nonzero — any failure → 22. Copies the 32-byte template to
  the stack, calls install routine `0x63b6ee0` (ctx, template); result 0 →
  11; else `*oldlenp == 8` gives `*oldp` = returned pointer, 0; otherwise
  bounded copy, `*oldlenp := min`, 22. Exhibit ends after `xor %eax` at
  `0x636d672`.
- **experimental.hooks.remove** (`0x6376d50..0x6376d9e`, full FDE):
  oldp\|oldlenp nonzero → 1; newp zero → 22; newlen must be 8 (else 22);
  `*newp` nonzero (else 22); calls `0x63b70b0` (ctx, value); 0. Pure write.
- **prof.log_start** (`0x63777f0..0x6377841`, full FDE): prof byte
  `0x6713606` zero → 2; oldp\|oldlenp nonzero → 1; newp optional — if
  present newlen must be 8 (else 22), value = `*newp`, else value = 0; calls
  `0x63d4ad8` (ctx, value); boolean result maps to 0 or 14 (neg/sbb/and
  `$0xe` pattern, same as #257's prof.dump).
- **prof.log_stop** (`0x63777c0..0x63777ee`, full FDE): prof byte zero → 2;
  otherwise calls `0x63d4bbe` (ctx) and maps boolean to 0 or 14. Ignores all
  value arguments entirely.
- **thread.prof.active** (`0x636de60..0x636df5e`): snapshot rule — prof byte
  zero → snapshot 0; prof byte nonzero → snapshot = low byte of `0x63c3d70`
  (ctx) return. Write path (newp present): prof byte zero → 2; newlen must
  be 1 (else 22); calls `0x63c3e20` (ctx, value byte); nonzero result → 11;
  zero → falls through to the read path. Read path: oldp+oldlenp present
  and `*oldlenp == 1` → `*oldp` = snapshot byte, 0; `*oldlenp != 1` → copies
  1 byte (if `*oldlenp != 0`), sets `*oldlenp := 1`, returns 22
  (jemalloc-style length semantics); oldp/oldlenp missing → 0. It READS
  `0x6713606` (lea + movzbl/cmpb) but does not write it — the state change
  goes through `0x63c3e20`. Exhibit ends after `jne 0x636ded0` at
  `0x636df04`.

### TLS slow path `0x63ef8e0..0x63efba2` (674B)

State byte at ctx + `0x330`; flag byte in `%sil`. Dispatch: other values
(0, 1, 5, 7+) and value 3 with flag nonzero → return ctx unchanged
(`0x63ef90d`). Value 4 → install path `0x63efa50`: `0x63ef640` (ctx, 5);
TLS slot = `%fs:0x0 − 0x10a8`; if ctx is not already that slot, `rep movsq`
`0x149` qwords (2,632 bytes) from ctx to the slot; `pthread_setspecific`
(key from `0x672891c`, value = TLS slot); on failure → error-report call
`0x63be670`, then if byte `0x651174d` is 0 continue to init, else jump to
shared tail at `0x63ef8d7` (bytes there are `call abort@plt`; the preceding
instruction at `0x63ef8d6` is `ret` — the failure path is described as
"reports the error and jumps to a shared tail" without over-specifying).
On success: init ctx + `0x1b0` via `0x63d9880`; self-pointer ctx + `0x70` =
ctx; word ctx + `0x0` = `0x100`; call `0x63ef230`; call `0x63b6e70`; return
ctx. Value 6 with flag nonzero → `0x63efb98`: second arg 3, then jump into
the value-4 path at `0x63efa55`. Value 6 without flag: `0x63ef640` (ctx,
0), then the value-2-style loop, then copy to TLS slot + setspecific; on
success → shared init sequence at `0x63efb65` (`0x63d9880`, self-pointer,
`0x63ef230`, `0x63b6e70`, then call `0x63ed870`), return ctx; on
setspecific failure → error path, then `0x63efb65` if `0x651174d` is 0,
else the shared tail. Value 3 without flag → `0x63efb00`: `0x63ef640`
(ctx, 0); decrement ctx + 1 (`subb $0x1,0x1(%rbx)`); value-2-style loop;
`0x63eec10` + init sequence + `0x63ed870`, return ctx. Value 2 → xchg spin
loop (`0x63ef92e` / `0x63ef918`): `xchg` candidate into the state byte; if
the old value was 2, re-check gates — re-read byte must be ≤ 2,
gate-neighbour byte `0x64ffab0` (the byte #257's predicate completion
writes) must be 0, ctx + 0 nonzero, ctx + 1 ≤ 0 — then candidate =
(`0x6728880 != 0`) and loop; if old value was not 2 → call `0x63eec10`,
return ctx. So `0x63ef640`'s second argument is a mode: 5 for state 4, 3
for state 6 with flag, 0 for states 6/3 without flag. What `0x63ef640`
itself does, and what `0x63eec10` / `0x63ed870` do, are NOT decoded.

### Completion wrapper `0x6368e40..0x6368ebb` (123B, full FDE)

Mutex `0x6711b00`; on trylock failure calls #251 wait helper `0x63bf680`
with record base `0x6711ac0` (mutex − `0x40`), sets contended byte
`0x6711b28` = 1, retries. On lock: counter `0x6711af8` += 1; if incoming ctx
(`%rdi`, saved in `%rbx`) differs from last-ctx slot `0x6711af0`, counter
`0x6711ae8` += 1 and slot := ctx. Calls work function `0x6367b20` (ctx,
second arg in `%esi`, saved in `%ebp`); clears contended byte; unlocks;
returns the work function's result. It does NOT write the gate flag
`0x64ffab4` itself (#257's predicate writes flag = 0 before tail-calling
here). Its own writes are bookkeeping (counters, slot, contended byte).

### Direct-entry census (raw E8/E9 scan + objdump mnemonic cross-check)

Method: raw scan of the code segment file range `0x1418300..0x63f6ba0`
(VA = file offset + `0x1000`): every `0xE8`/`0xE9` byte whose rel32 target
equals a handler address; cross-checked by counting `call <addr>` / `jmp
<addr>` mnemonic lines in a full `.text` objdump (that 1.2GB dump was deleted
after extraction). Raw-scan false positives from immediates would only add
sites, so a 0 count is a strong zero. Results: all 8 leaf handlers 0 E8 +
0 E9; TLS slow path 145 E8 + 1 E9 (E9 site `0x63efc17`, in the following
FDE); completion 5 E8 (`0x634ec72`, `0x6353526`, `0x6353596`, `0x6378d95`,
`0x6379085`) + 1 E9 (`0x634f751`, inside the predicate — consistent with
#257's "completion path tail-calls `0x6368e40`"). Address-taken scan
(RIP-relative comments and `movabs` immediates): 0 hits for all 8 handlers.

### Prof-byte writer census (`0x6713606`)

Full-`.text` objdump grep for `# 6713606`: 76 sites. Final classification:
73 reads + 3 writes (66 READ-via-reg, 7 READ-direct, 2 WRITE-via-reg, 1
WRITE-direct). Writers: `0x634c035` `movb $0x0,(%r8)` (CLEAR) and
`0x634d08c` `movb $0x1,(%rbx)` (SET), both in FDE `0x6349be0..0x634eb7c`,
each preceded by a lea of the byte and a `cmpb $0,0x651174b` flag test,
branching after the store; `0x63c41a0` `movb $0x1,0x6713606` (SET, direct)
in latch FDE `0x63c4140..0x63c41b1` (also writes neighbour `0x6713605` =
0 at `0x63c41a7`, and `0x6713603` = 1 at `0x63c415f` on another path).
The option-parser function also writes `0x6713602` = 0 nearby (`0x634d0e6`,
after a `strncpy`-family call) — a neighbouring state byte, not the
target. No `.rela.dyn` addend equals `0x6713606` (0 hits). Classifier
self-correction: the first pass checked only the first deref after each
lea and produced 6 false-positive writes from register reuse (`0x635a874`,
`0x635c781`, `0x636c884`, `0x636c8c4`, `0x63737e2`, `0x63bda35`); the fixed
classifier uses a 256-byte linear window, classifies ALL derefs, tracks
register overwrites, and drops caller-saved registers on `call`. Limitation:
a store through a spilled/reloaded register or beyond the window would be
missed; all three writers sit within 8 bytes of their lea. Read sites of
note (confirm #257): prof_reset's lea at `0x636d874` and prof_dump's lea at
`0x6377854`, plus log_start (`0x63777f4`), log_stop (`0x63777c4`), and
prof_active (`0x636de7e`) reads.

### Disjointness

Recursive range+fde collector over the merged tree plus prior worktree
records (11,586 files scanned in session; deduplicated by real path;
census/cited-only subtrees excluded); all 14 exhibit ranges clear, 0
overlaps. The verifier recomputes this and prints its own scanned-range
count. Neighbour leaves noted, not claimed: `experimental/arenas_create_ext`
(`0x63a56b0..0x63a594f`), `thread/tcache/enabled` (`0x636e240..0x636e32e`,
resolver trap stub `0x636e32e..0x636e338` follows, resolver starts
`0x636e340`), `thread/prof/name` (`0x636df60..0x636e202`).

## Implementation and comparison

Not yet implemented/measured. This packet is evidence only; no Rust
reconstruction, build, or byte-equivalence comparison is claimed.

## Results and limitations

- Exhibits: 14 windows, 1361 bytes, 365 strict instructions; verifier exit
  0; unit tests 10/10; `make verify` exit 0 (tally recorded in the PR body);
  `make catalogue-check` exit 2, pre-existing `Stale catalogue: README.md`
  on a pristine checkout — not a packet regression.
- Unresolved: per-leaf classification for ~190 leaves; `0x63ef640` modes
  and internals; `0x63eec10` / `0x63ed870` roles; option-parser option names
  behind the prof-byte set/clear; the shared-tail jump target `0x63ef8d7`
  beyond its observed bytes; the bounded-copy tails' reachability where
  entry gates already enforce exact lengths.
- No progress gate is requested by this packet alone.
- Next question: continue per-leaf classification for the remaining ~190
  leaves (next candidates: `experimental/arenas_create_ext`,
  `thread/tcache/enabled`, `thread/prof/name`, the `experimental/hooks`
  siblings, `prof.active`, `prof.gdump`, `prof.interval`); decode `0x63ef640`
  (modes 0/3/5) and `0x63eec10`/`0x63ed870`; decode the option-parser FDE
  `0x6349be0..0x634eb7c` (which option names set vs clear the prof byte).
