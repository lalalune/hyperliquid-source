# RE-001: one Wei constructor's used carrier byte (node #94)

## Question and outcome

The accepted packet `RE-004-weipriv-sign-guard-94` leaves open whether its
constructors can produce the byte value 9 tested by their callers. This packet
examines **one** of those chains: producer `0x1704700`, constructor
`0x26bb3c0`, and caller `0x16ca240`. It adds the producer's actual stores and
links its output pointer to the byte consumed by this caller.

The producer explicitly stores byte **6** at output offset 0. The constructor
passes its original output pointer to that producer; the selected caller passes
its own stack buffer, reloads that buffer's first byte, compares it with **9**,
and forwards it on the unequal continuation. This is a used data/control
observation, rather than an inference from a register name or an unused constant.

**Whether the final returned carrier can be 9 remains qualified/unknown.**
A conditional opaque helper call follows the store of 6. Its alias/clobber
effects are not closed here. Normal call return, ABI/frame preservation, and
the input/output buffer assumptions below are not observed guarantees.
No `Result`/`Ok` type, enum layout, unreachable branch, or business meaning is
assigned to either numeric byte. A different route in this same caller visibly
stores 9; this packet does not claim that 9 is impossible or dead.

## Provenance and exact scope

- Requirement: RE-001 static binary evidence supporting independent reconstruction;
  follow-up to the explicit unresolved producer question in
  `research/work-items/RE-004-weipriv-sign-guard-94/README.md`.
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Target: `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Native code read: three exact FDE ranges, **512 bytes total**:

  | Role | Half-open virtual range | Bytes | FDE | CIE | LSDA |
  | --- | --- | ---: | --- | --- | --- |
  | Producer | `0x1704700..0x17047a8` | 168 | `0x1006298` | `0xfbdc2c` | `0x94f808` |
  | Constructor | `0x26bb3c0..0x26bb405` | 69 | `0xd7e7e8` | `0xce1518` | none recorded |
  | Consumer | `0x16ca240..0x16ca353` | 275 | `0xd07378` | `0xce1518` | none recorded |

- Metadata read: ELF section mapping; those FDE/CIE records; eight selected
  relocation/symbol bindings; one 6-byte resume PLT stub; the producer's
  14-byte decoded LSDA prefix. Opaque helper bodies are **not** decoded.
- No reference implementation was copied or used as the implementation source.
  The earlier packet supplies the diagnostic/call-chain lead only. No captured
  image, chain action, signing operation, or binary runtime was executed.

The denominator is these three ranges, not all constructors, all callers, all
Wei behavior, or whole-node reconstruction. Their native census is 157
instructions, 10 calls, 15 branches, 7 returns, and one `ud2` instruction.

## Observations

### Producer writes and remaining effects

Entry output pointer `RDI` is retained in `R15` at `0x1704726`. Input word at
offset 16 is retained in `R12`. The signed-word and helper-return branches
select `R13` from a helper return or the constant 1. After the call bound by
the dynamic symbol `memcpy`, the explicit output-pointer stores are:

| Store | Output offset | Width | Observed source |
| --- | ---: | ---: | --- |
| `0x1704753` | 8 | 8 | input word at offset 16 |
| `0x1704757` | 16 | 8 | selected helper-return word or constant 1 |
| `0x170475b` | 24 | 8 | input word at offset 16 |
| `0x170475f` | 0 | 1 | constant 6 |

There is no explicit store through this retained output pointer to bytes 1..7.
That does not establish their initialization, type, or status as padding, and
does not exclude writes through aliases. The conditional call at `0x1704770`
uses the relocation slot `0x576e010` after the byte store. Its effects on the
output and private frames are unresolved. The visible normal return puts the
retained pointer in `RAX` at `0x1704776` and returns at `0x1704782`.

Removing `0x170475f` from the **intraprocedural normal-return CFG** disconnects
entry from that return. This is a local dominance observation, with calls
treated as normally returning edges; it is not an unconditional final-value or
runtime reachability theorem. Exceptional transfers are recorded separately.

### Constructor transfer and actual consumer

The constructor retains entry `RDI` in `RBX` at `0x26bb3c7`. An opaque formatter
call is passed a local descriptor pointer. At `0x26bb3f2` and `0x26bb3f5`, the
constructor passes the original output pointer and that descriptor to the
direct call `0x26bb3f8 -> 0x1704700`. There is no later call or output write in
this 69-byte range, only frame restoration and return.

The caller's signed-input route prepares `RDI = RSP+16` at `0x16ca300` and calls
the constructor at `0x16ca30a`. It then:

1. Loads byte `[RSP+16]` into `EAX` at `0x16ca30f`.
2. Compares `AL` with 9 at `0x16ca314`, then branches on inequality at
   `0x16ca316` to `0x16ca325`.
3. Copies other opaque bytes/words and writes the loaded `AL` to the outer
   output pointer at `0x16ca344` on that continuation.

The distinct route `0x16ca2a4` directly stores byte 9. Neither that route nor
the comparison's equality continuation is classified as dead.

### Relocations and exception metadata

`records.json` and `relocations.txt` retain eight actual RELA rows:
`0x576dfb8`, `0x576dfd8`, `0x576dfe0`, `0x576e010`, `0x576e040`, `0x576e9d0`,
`0x577a668`, `0x5778db0`. GNU `readelf` independently cross-checks their
relocation identities and targets/names. `memcpy` and `_Unwind_Resume` are
dynamic symbol bindings, not proofs about a particular runtime implementation.
All unnamed relative targets and the personality remain opaque.

The producer's CIE is `zPLR`; the other two CIE bindings are `zR`. The producer
LSDA prefix `ffff010a1b098a01002484010000` describes these rows:

| Half-open range | Landing pad | Action |
| --- | --- | ---: |
| `0x170471b..0x1704724` | `0x170478a` | 0 |
| `0x1704724..0x17047a8` | none | 0 |

The call at `0x170471e` returns to `0x1704724`; a **return-PC-minus-one** lookup
therefore associates it with the first row, not the second. All six producer
calls retain their lookup PCs and row indices. This is static association,
not a proof of exception feasibility, personality behavior, type semantics,
or `nounwind` status for either range without an LSDA.

## Reproduce and validate

From the repository root, Python 3 standard library and GNU `objdump`/`readelf`
are required. Recorded native exports used GNU binutils 2.44 on Linux x86-64.
The collector makes one private, non-hardlinked, read-only snapshot (~92 MB)
and authenticates it before and after native reads, so native tools never
reopen the caller's mutable input pathname. It deletes that snapshot on exit.
Only the snapshot pathname in native headers is normalized to
`<authenticated-node94>`; instruction bytes, operands and metadata are retained.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/wei_constructor_carrier_static.py \
  --output /tmp/wei-carrier-new
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest tests.test_wei_constructor_carrier_static -v
(cd research/work-items/RE-001-wei-constructor-carrier-94 && sha256sum -c MANIFEST.sha256)
make doctor verify test catalogue-check
make reproduce
```

Use a new output directory; an existing one is rejected before collection.
Two exports on the same toolchain must match byte for byte. Tests also compare
normalized semantic records against this packet, allowing only the recorded
GNU version strings to differ. This does not assert that raw native text is
identical across different binutils versions. `MANIFEST.sha256` authenticates
all checked-in packet files, including the stated-version raw native exports.

Negative controls mutate actual target bytes in private copy-on-write mappings
below the global identity guard: output value/offset/source, pointer transfer,
consumer load/comparison/branch/forwarding, the independent store of 9, both
direct call bridges, every selected relocation addend, CFI extent/profile/
personality binding, and LSDA encoding/ranges. Separate controls require wrong
target identity rejection and prove that replacing a supplied input pathname
after snapshot acquisition does not redirect native readers. No altered target
is accepted as Node94 or executed.

## Assumptions, exclusions, and next question

Conditional propagation of the visible stored 6 to the caller requires:

- The shown calls return normally and honor native ABI callee-saved register
  and stack-frame preservation.
- The input/output regions are valid and the selected frame buffers remain live
  and distinct.
- Opaque helpers do not alias/clobber the carrier or its saved pointer,
  particularly the post-store call at `0x1704770`.

These are assumptions, not established guarantees. This packet closes only the
missing direct-store/used-byte observation for one constructor chain. It does
not close the earlier packet's general returned-value question. A useful next
question is the alias/effect contract of the post-store helper and any escaped
input buffers. No reconstruction component, success gate, coverage percentage,
private result representation, or whole-program equivalence is claimed.
