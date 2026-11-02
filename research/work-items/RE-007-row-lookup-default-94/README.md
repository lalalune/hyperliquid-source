# RE-007: row selection, shared default and the row+0x20 contract

This closes the normal row-selection edge at `0x36f57f0` used by the reserve
path. It establishes the exact key comparison, entry/value offsets, missing-row
selection and the initializer call that remains possible even on a hit. A
conditional constructor/callback path proves the default's `+0x20` word zero
without inventing values for its uninitialized/padding bytes.

- Component/task: clearinghouses and risk, bounded RE-007 static follow-on.
- Target: Linux x86-64 node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`, revalidated live.
- Reference pin: `999556f6e0a474b8312db96ec3149e1c44e97c23`; no inferred
  implementation was read or copied for this contract.
- Observations: bytes, FDE/CIE/LSDA-pointer records, branches, calls,
  relocations, offsets and constructor-defined byte ranges.
- Limits: external hash and generic Once/dispatch behavior, concurrency,
  lifetime/alias guarantees, initialization failures and caller mutation remain
  unresolved. No economic unit, full type, Rust reconstruction, compiled
  comparison, safety conclusion or progress gate is claimed.
- No captured binary or instruction emulator was run.

## Native scope and prior work

All addresses are ELF virtual addresses; `evidence.json` gives file offsets,
whole-body hashes, FDE/CIE records, branch/call operands and data/relocations.

| Role | Half-open FDE range | Bytes | Instructions |
| --- | --- | ---: | ---: |
| Row lookup | `0x36f57f0..0x36f5948` | 344 | 87 |
| Callback A | `0x37618b0..0x376191f` | 111 | 29 |
| Callback B | `0x37608e0..0x376094f` | 111 | 29 |
| Existing default constructor, rebound dependency | `0x3790fc0..0x3791074` | 180 | 40 |

Prior risk/fees packets leave the lookup body external. The constructor has
already been studied by `RE-001-lock-descriptor-94` and
`fees-open-order-cap-94`; its general construction and scalar helper are not
claimed as new. The new connection is its defined flag-word bytes through the
lookup's actual default/callback descriptors. Adjacent open PR #1425 uses this
lookup only as its next-FDE boundary. `intake.json` records the live overlap
review. FDEs remain unwind-described ranges, rather than complete source-level
ownership proofs or a whole-program xref census.

## Exact normal selection contract

At entry, `rdi` is the map view and `rsi` addresses at least 20 key bytes.
A zero count at map `+0x18` skips hash, control and key reads. Otherwise call
`0x36f580f` supplies map `+0x20` and the key to external hash `0x399c7a0`.
Given returned hash `H`, the fingerprint is unsigned `H >> 57`; control pointer
and mask come from map `+0` and `+8`.

The loop reads a 16-byte group, visits all matching fingerprint lanes in
ascending order (`tzcnt` plus clear-lowest-set-bit), and compares exactly 20
key bytes as 16 plus 4. Entry bytes `+20..+23` are not compared. A matching
lane uses index `(group_position+lane)&mask`. Empty byte `0xff` terminates
only after all fingerprint candidates in that group have been tested.
Thus an earlier empty lane does not hide a matching key later in the group.
Without a match or empty byte, the step grows by 16 and advances the masked
position by that step. The model assumes valid backing/control mirroring,
normal table termination and stable storage; malformed states are not modeled.

For control address `C` and matched index `i`, instructions at
`0x36f5869`, `0x36f58ce` and `0x36f58d4` select:

```text
entry = C - (i+1)*120
row = entry + 24              # 96-byte value extent
```

A missing key or empty map selects shared row `G = 0x57862a0`. The retained
lookup has no map-insert/write instruction or selected-row copy; its return is
an address into existing storage. Borrow lifetime, alias validity and external
helper effects are not recovered.

Both hits and misses test state word `0x5786300`, exactly `G+96`. A nonzero
word calls generic Once through slot `0x576e8b8` at `0x36f5940`; a hit does
not bypass that call. If it returns normally under the native calling
convention, the same saved selection is returned. No complete generic Once
state machine or initializer-success guarantee is inferred from that return.

## Conditional default byte contract and caller flag

The ELF file image has 96 zero bytes followed by state word 3. Its RELATIVE
relocation at `G+0` installs constructor `0x3790fc0`; those file zeros are
therefore not proof of a constructed runtime row. The 40-byte descriptor at
`0x56f2288` has size/alignment words 8/8 and relocation-backed callback slots
`0x56f22a0`/`0x56f22a8`, naming the two retained callbacks.

Their first 92 bytes are identical. On the normal callback path, a captured
pointer is consumed, a state byte is checked, `[selected_cell]` is called with
a 96-byte temporary output, then all six 16-byte blocks are copied into that
cell. The two register-indirect calls are recorded as conditional targets:
only when the cell is the observed `G` and retains its constructor pointer do
they name `0x3790fc0`. Actual generic dispatch and failure/cleanup semantics
remain external.

On constructor success (`eax != 0` from external `0x151f6f0`, argument
`0xaf93b`), its native stores define zero bytes in ranges `[0,16)`, `[24,48)`,
`[56,80)` and `[84,92)`, plus the returned `u32` at `[80,84)`. Bytes `[16,24)`,
`[48,56)` and `[92,96)` are not proved initialized and are explicitly unknown
in the model. In particular, `row+0x20..+0x27` is defined zero. This is a
conditional postcondition of constructor completion and callback copying,
rather than a claim that the entire 96-byte default is zero.

Caller `0x3708c09..0x3708c10` passes context `+0xf8` to this lookup. Later
`0x3708dd0..0x3708dd5` tests the selected row's `+0x20` word and emits its
nonzero predicate. Both windows are rebound. Intervening aggregate/hash/
recorder calls are outside this packet, so absence of mutation between lookup
and that later read is not assumed. The flag's business meaning stays unknown.

## Reproduce and controls

```sh
python3 research/work-items/RE-007-row-lookup-default-94/verify.py --out work/row-review
python3 -m unittest discover -s tests -p test_row_lookup_default94.py -v
python3 research/work-items/RE-007-row-lookup-default-94/check_decoders.py \
  --llvm /path/to/installed/llvm-objdump \
  --binary artifacts/node/94/hl-node --out work/row-decoders
```

GNU 2.44 and LLVM 19.1.7 agree on all 185 instruction boundaries/bytes. Raw
outputs and commands are retained; nearest-symbol labels are not recovered
names. The verifier uses only standard-library code and existing ELF/FDE/
RELATIVE parsers, with a separately hash-bound frozen decode.

Nine focused tests pass. Independent table fixtures cover empty count,
hit/miss with ready/pending default state, fingerprint collision, tail-byte
disagreement, padding independence, group-before-empty ordering, a later
group and masked wrap. Constructor controls retain unknown bytes. Native
controls change every recorded branch encoding, layout/caller bytes, raw
default/descriptor data, FDE/CIE records and every recorded RELATIVE target.
Whole-body hashes reject most code mutations; these tests establish byte
admission and model distinctions, not independent semantic CFG equivalence.

`VALIDATION.md` records checks and deterministic regeneration. No full-suite
or hosted-CI result is claimed by this lane. Next: close generic initialization
dispatch and intervening mutation before making a stronger final-flag claim.
