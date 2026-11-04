# RE-001-node115-lu-entryprobe: the size-class entry probe

## Question

Packet #239's next question: what `0x63b9680` checks in the size-class
entry it receives from the handoff's size path, what a nonzero return
means (it gates the bitmap bit at `first-arg+0x400` in #238), and
whether it reads the chains the class insert builds.

## Answer

It checks exactly one thing: whether the entry's head pointer is null.
It returns `1` in `%al` if `[entry] == 0` and `0` otherwise. It reads
nothing else — not the count word at `[entry+8]`, not any node the head
points to, and no chain the class insert builds. A nonzero return
therefore means "this size class is currently empty", and in the
handoff that empty verdict is what sets the class bitmap bit before
the block is inserted.

## The function

Single FDE `0x63b9680..0x63b968c` (12 bytes, `.eh_frame`-confirmed),
`endbr64` entry, single `ret` at `0x63b968b`, zero `call`
instructions, zero branches:

| Address | Bytes | Instruction |
|---|---|---|
| `0x63b9680` | `f3 0f 1e fa` | `endbr64` |
| `0x63b9684` | `48 83 3f 00` | `cmpq $0x0,(%rdi)` |
| `0x63b9688` | `0f 94 c0` | `sete %al` |
| `0x63b968b` | `c3` | `ret` |

Entry contract: `rdi` = 16-byte size-class entry (`[entry]` = head
pointer, `[entry+8]` = count word — the same entries #238's size path
computes as `first-arg + 16*index` and #239's class insert receives).

Return contract, stated exactly: the result is a boolean in `%al`
only. This FDE never zeroes `eax` before `sete`, so it establishes
nothing about `rax`'s upper bytes — and it does not need to, because
both known callers test `%al` only (`test %al,%al` immediately after
each call site). Any claim about full-`rax` values would go beyond
these bytes and is not made here.

## What it does not do

- It does not read `[entry+8]`. The count word's value — incremented
  on insert-after-head, reset on min-displacement, untouched on
  empty-head insert (#239) — is invisible to this probe.
- It does not dereference the head pointer. A nonempty entry returns
  `0` regardless of what the head node contains.
- It does not walk the `+0x30` spine, the `+0x38` side links, or any
  other chain. Whether the chains are sorted, heap-ordered, or
  broken is unknowable from this FDE.

## The two callers, and the opposite bitmap uses

Census: 2 direct `E8` call sites, 0 `E9`, 0 `LEA`, 0 GOT (60,723
`.rela.dyn` entries, no addend hit). Both call sites are cited, not
claimed here; both test `%al` only.

1. **Handoff size path, site `0x63d8874` (#238).** Entry in `rdi`.
   After the call, `test %al,%al; je` skips the bitmap write on
   zero. On nonzero (empty entry), the handoff sets one bitmap bit
   (`or 1<<bit` at `first-arg+0x400`, bit `index mod 64` of qword
   `index / 64`), then tail-jumps to the class insert (#239)
   regardless. So for a block entering an empty class, the sequence
   is: probe says empty → bit set → class insert takes its
   empty-head path (`[entry] := block`, count untouched).
2. **Neighbour FDE `0x63d8630..0x63d8790`, site `0x63d8717`
   (unclaimed, cited only).** This caller first calls `0x63b9d10`
   (entry, block — cited only), then probes the same entry. On
   nonzero (empty entry), it **clears** the same bitmap bit
   (`and` with the rotated `~1` mask at `first-arg+0x400`), then
   returns.

The mirror image is the finding's second half: the same probe, the
same bitmap, opposite writes. The handoff sets the bit when it finds
an empty class it is about to fill; the neighbour clears the bit
when it finds an empty class after its own call. The closest
reading — stated as inference, not bytes — is that the bit tracks
class nonemptiness: set on first insert into a class, cleared when
a class becomes empty. What `0x63b9d10` does (the call that
precedes the clear) is not decoded here; it is #241's question.

## Neighbours

- Previous FDE `0x63b9660..0x63b9674` (a small zeroing helper, cited
  only), then 12 bytes of `int3` padding `0x63b9674..0x63b9680`.
- This FDE, then 4 bytes of `int3` padding `0x63b968c..0x63b9690`.
- Next FDE `0x63b9690..0x63b99c8` is the #231 consumer (cited only).

## Evidence

- Target: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
  SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  upstream main `05bc2de30` (confirmed before analysis).
- FDE bounds confirmed by `.eh_frame`
  (`pc=0x63b9680..0x63b968c`). Static analysis only; the binary
  was never executed.
- 1 exhibit, 12 bytes, 4 strict instructions (strict = mnemonic-line
  count: address + bytes field + tab + mnemonic; objdump
  byte-continuation lines excluded):

| Exhibit | Range | Bytes | Strict | Shows |
|---|---|---|---|---|
| `pb_probe` | `0x63b9680..0x63b968c` | 12 | 4 | Whole FDE: endbr64, cmp, sete, ret |

- Census: direct `E8` call sites to `0x63b9680`: 2. Direct `E9` jump
  sites: 0. Rip-relative `LEA` sites: 0.
  `.rela.dyn` addends equal to `0x63b9680`: 0 of 60,723 entries.
  E8: `0x63d8717` (neighbour FDE `0x63d8630..0x63d8790`; probe
  then bitmap clear on nonzero), `0x63d8874` (handoff FDE, #238;
  probe then bitmap set on nonzero, then tail jump to #239).
  Internal calls within the FDE: 0. Internal jump targets: none
  (no branches). Single `ret` at `0x63b968b`.
- Disjointness: this FDE overlaps no claimed exhibit range from
  packets #183–#239 (96 exhibit ranges in the merged tree's
  `records.json` files, plus the #235–#239 worktree records, all
  checked) and no other contributor's topic, addresses, or tables.
  The handoff, the register, the gate, the driver, the class
  insert, the allocator thunk, and the neighbour FDE are cited by
  address, not claimed here.

## Corrections to earlier packets

- **#239 confirmed and completed.** Its unresolved entry probe is
  this FDE: it reads only the entry head pointer, never the
  chains the class insert builds, and its nonzero return means
  the class is empty.
- **#238 confirmed and completed.** The handoff's bitmap bit is
  set exactly when this probe reports an empty entry; the probe
  result is tested in `%al` only, and the tail jump to the class
  insert happens on both outcomes.
- **#237 confirmed.** The register's size-class entries are the
  entries probed here; the register never calls this function
  directly.
- **#236 confirmed.** A consume-stamped block (`[block+0x68] == 0`)
  never reaches this function — the handoff queues it instead.
- **#235 confirmed.** The gate's paths reach this function only
  indirectly, through the register and the handoff.
- **#234 confirmed.** The driver's gate-block path runs gate,
  then register, then handoff, then (for size-classified blocks)
  probe, then class insert.
- **#233 confirmed.** The loop caller is not involved with this
  function.
- **#232 confirmed.** The single-shot caller reaches this
  function only through the register and the handoff, never
  directly.
- **#216 confirmed.** The allocator thunk `0x636b370` is the
  gate's allocator; this function never calls it.

## Unresolved

- What `0x63b9d10` does with the (entry, block) pair it receives
  from the neighbour caller before the probe — the call that
  precedes the bitmap clear. This is #241's question.
- What the neighbour caller FDE `0x63d8630..0x63d8790` is in
  domain terms, and why it shares the handoff's size-class entry
  computation.
- The domain meaning of the `first-arg+0x400` bitmap bit beyond
  the set-on-empty-before-insert / clear-on-empty-after-call
  pattern: the nonemptiness reading is inference, not bytes.
- Whether any caller anywhere tests more than `%al` of this
  function's return; both known callers test `%al` only.
- `.bss` contents are runtime-filled and not readable from the
  file; nothing here depends on them.

## Next question (#241)

Decode `0x63b9d10` end to end: what it does with the (entry,
block) pair it receives from the neighbour caller, and whether it
removes, unlinks, or otherwise empties a size-class entry — this
decides what makes a class empty before the probe clears its
bitmap bit.

## Verification

- `tools/node115_lu_entryprobe.py` static verifier: exit 0
  ("all checks passed") — SHA/size, exhibit bytes, strict counts,
  FDE bounds, single `ret`, zero calls, key bytes, caller-site
  rel32s and `%al` tests, full census, neighbour disjointness,
  MANIFEST coverage (7 entries).
- `tests/test_node115_lu_entryprobe.py`: 10/10 pass.
- `make verify`: exit 0 (559 manifests, 7161 entries).
- `make catalogue-check`: fails on the new base with
  `Stale catalogue: README.md` — identically on a pristine
  `05bc2de30` checkout, so this is pre-existing upstream
  staleness from the merge wave, not a packet regression.
- Full `make test`: not attempted on the new base (584 files;
  a full run takes hours and was already shown in #234 to be
  liable to VM-restart termination). This packet's own file
  passes 10/10 standalone.
