# RE-001-node115-lu-park-queue: full decode of the park-queue move-or-wake function

- Component ID: RE-001 (`base/src/lu.rs` conversion context, park queue).
- Target release and full SHA-256: node #115, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`
  (upstream main, node-115-only migration).
- Claim status: observation for the signature, slot check, flag protocol,
  list surgery, requeue/wake outcomes, futex constants, deadline arithmetic,
  and call census; inference for the "park queue" / "Instant + Duration"
  labels (the panic message supports the latter); unresolved for the
  entry-word encoding, the item flag bit meanings, the wake-site `rdx`
  setup, and any table-indirect slot-`+0x8` call site.
- Scope included and excluded: included — park body `0x5bb42e0..0x5bb4663`
  in full (899 bytes, 257 instructions), lookup/cleanup/timer as context,
  GOT resolutions, the three GOT call sites. Excluded — the lookup's
  table-resize path, the cleanup's list shape, the wait/notify helpers'
  internals, all other queue users. Prior packets #183–#187 are cited,
  not re-claimed; #187's 643-byte figure is corrected to 899 (see README).

## Reproduce

```sh
cd <worktree at 8fd8db6>
objdump -d -M intel --start-address=0x5bb42e0 --stop-address=0x5bb4663 \
  artifacts/node/115/hl-node > park.objdump.txt
python3 tools/node115_lu_park_queue.py   # exit 0
python3 -m unittest tests.test_node115_lu_park_queue -v
```

Tool versions: system GNU objdump 2.42 (`-M intel`), Python 3.12,
`readelf` for FDE/GOT records. No execution of the node binary, no
network, no disassembler database: all claims are static byte reads.
Working directory is the repository root; the verifier resolves it
from its own path.

## Evidence

Original addresses are ELF virtual addresses (PIE); `.text` file offset
= VA − 0x1000, `.data.rel.ro`/`.got` = VA − 0x2000, `.rodata` = VA.
Validated boundaries: park FDE `0x5bb42e0..0x5bb4663` (readelf
`.eh_frame`, CIE `0x00000000`, single `ret` at `0x5bb45d5`), lookup
`0x5bb4d00..0x5bb4f78`, cleanup `0x5bb66b0..0x5bb678b`, timer
`0x5c842e0..0x5c843a9`. Raw disassembly is retained beside this record
(`park.objdump.txt`, `lookup.objdump.txt`, `cleanup.objdump.txt`) and
the park body bytes in `park.hex`; `records.json` pins every address,
constant, and census result. Callers: 0 direct `E8`, 3 GOT-indirect
(`0x5cf4e8e`, `0x5cf521b`, `0x5cfd965`). Indirect calls: park calls
lookup (direct `E8`), the timer (direct `E8`), cleanup via GOT
`0x64ec150`, and `syscall` via GOT `0x64e06b8`. ABI: SysV
(`rdi` slot, `rsi` item, `rdx` destination queue, `u8` return in `al`).
Overflow: `inc rax; jo` to the `std/src/time.rs:429:33` panic
(`overflow when adding duration to instant`, 40 bytes) — signed
overflow of the seconds increment only. Analysis was complete over
the full FDE range; nothing timed out.

## Implementation and comparison

Not yet implemented/measured: no independent Rust reconstruction is
claimed, no Cargo build, no raw/normalized comparison window. The
verifier checks pinned bytes and constants only; it does not execute
or emulate the function. Corruption controls: the unit tests flip one
pinned byte at a time (park body, futex constant, xorshift shift,
records field) and require the verifier to fail.

## Results and limitations

Metrics with explicit denominators: park 899/899 FDE bytes pinned,
257/257 instructions accounted for (255 code + 2 nop paddings),
census 0 direct + 3 indirect sites over all of `.text` (83,690,752
bytes scanned), GOT resolutions 4/4. Passed: verifier exit 0, unit
tests, MANIFEST digests (see below), `make doctor` / `make verify` /
`make catalogue-check` / `make test` (with the one known pre-existing
catalogue failure, unrelated to this packet). Remaining unknowns: the
entry-word lifecycle, item flag bit meanings, wake-site `rdx` setup,
table-indirect slot-`+0x8` attribution. No gate is requested; the next
question is the entry-word lifecycle or the wake-site `rdx` setup.
