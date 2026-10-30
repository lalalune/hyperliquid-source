# RE-001: hourly-liner candidate aggregate output ABI

- Component: `foundation`, one bounded calling-convention/layout question; no gate.
- Target: node94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, 91,774,280 bytes.
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference pin: can1357/hl `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  `base/daily_liner.rs` supplies the `0x14019b0` lead but is inferred,
  unlicensed reference, not authoritative source or code copied here.
- Question: does the captured entry have the simple in-place/unit-return shape
  suggested by the reference's `force_hourly_rotation(&mut self)` entry?
- Status: exact instructions, data and relocations; source-level method names,
  precise Rust signature/ownership and full helper behavior remain inferences.

## Reproduce

Materialize pinned LFS inputs and submodules. From repository root:

```sh
python3 -B tools/hourly_rotation_static.py --output work/hourly-rotation-94
python3 -B tests/test_hourly_rotation_static.py
cmp work/hourly-rotation-94/records.json research/work-items/RE-001-hourly-rotation-abi-94/records.json
make doctor verify test catalogue-check
make reproduce
shasum -a 256 -c research/work-items/RE-001-hourly-rotation-abi-94/MANIFEST.sha256
```

Python3.12.14, macOS26.4arm64 and GNU objdump/readelf2.47.20260726. The tool uses
standard library plus existing repository ELF/FDE parsers. It checks one byte
snapshot against the pinned target digest and supplies the same snapshot to
both native decoders. Two FDEs and all control instruction starts are checked.
A separate observed Capstone5.0.6 cross-check decoded all902bytes/188instructions
in the candidate and all387bytes/95instructions in the selected caller.
Capstone is not required by the reproducer. No captured code executes.

## Observations

All reported addresses are linked ELF VAs, with actual source-file offsets and
raw body hashes in records.json. No guessed runtime/provider base is added.
Denominator: two FDE-described extents, 1,289 original bytes, one verified
incoming call; not a complete function, call-site or source-component census.

The candidate occupies `[0x14019b0,0x1401d36)`. Entry instructions save RSI as
RBX and preserve RDI at `[rsp+0xb8]`. The normal path later recovers that saved
RDI into R14, calls the actual dynamic symbol `memcpy` with RDI=R14, RSI=RBX,
EDX=`0xb0`, and returns R14 in RAX. The dynamic binding at slot `0x576dfe0` is
checked through its `R_X86_64_GLOB_DAT` entry and `.dynsym/.dynstr` name; it is
not guessed to be memcpy just because the calling pattern resembles a copy.

The selected caller `[0x14016d0,0x1401853)` sets RDI to a separate stack output
at `rsp+0xc0` and RSI to an input object at `rsp+0x10`, then calls through GOT
slot `0x576ef78` at `0x140178e`. The slot's `R_X86_64_RELATIVE` addend is the
candidate entry. Afterward it copies 176 bytes from that output into another
aggregate field. Together these are concrete evidence of an aggregate-output
entry and result consumption, rather than just a unit-return mutator at this
address. This does not establish the exact Rust signature or prove a particular
source-level move/borrow declaration; the inferred reference remains untouched.

Other checked relationships explain why the address is an hourly-liner lead:

| Object-relative location | Observed store/replacement |
| --- | --- |
| `+0x98` | 32-bit value loaded from clock-result storage |
| `+0xa8` | byte `1` |
| `+0xa9` | low byte of the multiply/shift quotient in R15 |
| `+0x48..+0x98` | five 16-byte writes from staged member storage |

The initial clock call uses slot `0x576e8a0` (relative addend `0x151cba0`).
Two unsigned guards compare a returned field with `0xe1000` and `0x15f90`;
the following multiply uses `0x91a2b3c5` and shift43. The code records these
operands without assuming the helper's complete date/time layout or declaring
that every possible input is a valid UTC time.

Two compact format descriptors at `0x1e938e` / `0x1e9393` contain `/` and
`/hourly/` separators. Their exact bytes and referencing instructions are
retained; the format interpreter and final filenames are not recovered here.
A member-construction call uses slot `0x576eac0` (relative addend `0x13d1720`).
The old region's first word is compared with `0x8000000000000000`, skipping
call `0x1406b80` on equality, before the five staged writes install 80 bytes.
This is a niche/sentinel observation, not proof of an Option<particular type>.

A later cleanup-shaped block repeats those 80-byte writes and ultimately
leads to `_Unwind_Resume` in the retained disassembly. The actual LSDA dispatch,
which operation can throw, and error reachability were not decoded or executed.
Other filesystem-related calls remain raw evidence, not an assurance about
file creation, flushing, deletion, atomicity or operational safety.

## Controls and limits

Five tests cover actual symbol/field bindings, deterministic native regeneration,
12 independent in-memory instruction/descriptor changes, changed memcpy
relocation type, changed incoming GOT displacement, and wrong input admission.
Corruption checks run below the target-digest gate to exercise ABI reasoning
rather than merely report a SHA mismatch. Source captures and earlier packets
are unchanged. Native exports start at confirmed FDE starts; an initial
exploratory slice starting mid-instruction was rejected and is not included
as instruction evidence.

No inferred source is reimplemented or relicensed; no Rust build or behavioral
comparison exists. This packet corrects the evidence available for future
reconstruction, leaving every component gate false. The next concrete question
is the 80-byte member constructor at `0x13d1720` and its connection to the
existing liner-initialization research, including its error and ownership ABI.
