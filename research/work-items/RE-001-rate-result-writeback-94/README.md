# RE-001: the used writeback of 0x4959020, node #94

- Component: `transport`, through its already observed caller; the helper's
  original source ownership, Rust name and type are not recovered.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Independent source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
  Reference pin: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  No unlicensed inferred implementation was consulted or copied.
- Status: observed instructions/metadata; conditional def-use inference;
  opaque helper, validity, alias, runtime and private-type contracts remain open.

[PR #982](https://github.com/lalalune/hyperliquid-source/pull/982) leaves the
postcondition of `0x4959020` open: its caller computes an address from the output
words at offsets 0 and 16. This packet establishes the four visible final
stores and connects one path's consumed words to an actual earlier call argument.
It is independently based on main; no code from the unmerged PR is required.

If the **zero input+0x20 path reaches its last call bound to `memcpy`**, that
call is supplied destination `R12 + 608*RBP`, with the unsigned index then below
11. The final stores put those two registers at output offsets 0 and 16. Under
the stated ABI/frame preservation conditions, the earlier caller recomputes
that same address. This does not establish that a copy occurs safely, that the
result is a valid pointer, or what private object it describes. The nonzero
path delegates value selection and has no locally established index bound.

## Reproduce

Linux x86-64, Python 3.12.14, GNU objdump 2.44; authenticated project artifacts
and unchanged pinned references. From repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/rate_result_writeback_static.py --output work/rate-result-writeback-94
diff -ru research/work-items/RE-001-rate-result-writeback-94/observed work/rate-result-writeback-94
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p test_rate_result_writeback_static.py -v
sha256sum -c research/work-items/RE-001-rate-result-writeback-94/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

Use a new output directory. The producer authenticates the complete byte
vector, derives metadata from those same bytes, and gives GNU only an owned
510-byte raw slice in a mode-0700 temporary directory. The file is mode 0600,
non-executable and byte/identity checked before and after decoding. Native
tools never reopen the caller's source pathname. The source identity and full
SHA-256 are checked again before exclusive output creation; incidental source
ctime/hard-link-count changes are excluded. Only the owned slice is cleaned up.

The exact native command is retained in `observed/records.json`:

```sh
objdump -D -b binary -m i386:x86-64 -M intel --show-raw-insn --insn-width=16 --adjust-vma=0x4959020 slice.bin
```

Every native row must match the admitted bytes and tile the entire selected
range. `LC_ALL=C`, UTF-8 and LF are explicit. Raw output is retained without
instruction/data normalization. Records include tool identity, original file
coordinates and raw CFI/LSDA/RELA. The maintained Python readers plus direct
field checks establish the selected ELF metadata; this packet does not claim
a separate native readelf or independent disassembler result. Tool text may
vary across GNU releases; tests omit only the recorded tool-version string
when comparing semantic records. No target or emulator runs.

## Exact scope and boundary evidence

| Item | Half-open linked ELF VA range | File offset | Bytes |
| --- | --- | --- | ---: |
| Newly decoded helper FDE | `0x4959020..0x495921e` | `0x4958020` | 510 |
| Revisited caller bridge | `0x4956e63..0x4956e88` | `0x4955e63` | 37 |
| Separate resume-binding PLT stub | `0x5660110..0x5660116` | Recorded by ELF mapping | 6 |

The helper FDE is at `0x12aad24`, CIE `0xfbdc2c` (`zPLR`), LSDA `0xb87d34`.
Its 510 bytes have SHA-256
`232579edc4097019206623ae6693dbcbf23086e2104e6c6df676034c9c95a3b7`.
The native census is 119 rows, 12 calls, eight branches, one RET and one UD2.
The separate 37 revisited bytes and six binding bytes are not additional
recovered functions. None of these counts is a reconstruction denominator,
matched body or completion percentage. FDEs alone do not prove original
source-function boundaries or all incoming entry contracts.

## Final stores and the zero-field path

Entry RDI is retained in R14; RSI in RBX; RDX in R15. All paths from the selected
entry to the visible normal RET at `0x495919a` pass this final store sequence:

| Instruction VA | Entry-output-relative offset | Width | Value at that instruction |
| --- | ---: | ---: | --- |
| `0x495917a` | 0 | 8 | R12 |
| `0x495917d` | 8 | 8 | RAX |
| `0x4959181` | 16 | 8 | RBP |
| `0x4959185` | 24 | 8 | RCX |

No call or memory store follows this sequence before that RET. This is the
last explicit output-pointer writeback, not the function's complete write set:
earlier helpers and other pointer-relative stores may have aliasing effects.
Immediately before it, the code increments `[R13+16]` and reloads RCX from
`[RBX+24]`; no independent net-state/count invariant is inferred from that pair.

When `[input+0x20]` is zero, the call at `0x49590a7` is supplied EDI=`0x1b38`.
A zero return reaches an opaque error call and UD2 if that call returns
normally. A nonzero returned word is retained in R12. The body performs other
stores and a call bound to `memcpy`, then loads a **u16** into EBP at
`0x4959105` and compares RBP with 11. The unsigned JAE at `0x4959112` goes to
`0x49591ad`; under ordinary call-return edges, that route reaches UD2 and
cannot rejoin the visible normal RET. The bound branch dominates the last
imported call at `0x495916a` in this local graph.

Consequently, **at that last call's argument calculation**, RBP is 0..10:
the IMUL/ADD supplies RDI=`R12+608*RBP` modulo 2^64, RSI=entry RDX retained in
R15, and EDX=608. After that call, `xor eax,eax` precedes the common stores.
With the callee-saved-register assumption, output+0/output+16 preserve the same
base/index, and output+8 is zero. The observed earlier caller multiplies
`[output+16]` by 608 and adds `[output]`. The result is the earlier destination
argument's bit pattern; valid allocation, object type, pointer range, imported
copy semantics and runtime effects remain unproved.

## Delegated path and a concrete alias

For nonzero `[input+0x20]`, `0x4959081` calls opaque `0x4258c00`. Afterwards,
R12, RAX and RBP are loaded from local stack offsets `0x18`, `0x20`, `0x28`.
This packet does not establish what wrote those words, their domains, or a
bound analogous to 0..10. That route joins the final stores directly.

The helper call receives R9=`input+0x38`. In the revisited caller, the actual
LEAs supply output=`outer_rsp+0x58` and input=`outer_rsp+0x20`. Thus the forwarded
R9 **equals the outer output pointer**. This observed alias is retained; the
packet makes no blanket assumption that all arguments are disjoint. Earlier
helper writes and the selected input/output objects' complete contracts remain
open even though the final four direct stores can be identified.

## Calls and exception metadata

The raw RELA rows bind eight selected slots, including imported `memcpy`, the
resume PLT's `_Unwind_Resume` slot and the CIE personality slot. Unnamed targets
remain numeric. A symbol binding is not a verified runtime implementation.

The LSDA has six retained call-site rows, encoded type-table base metadata and
a signed first action `(-1,0)`. The type table and negative-filter meaning are
not interpreted. Each of the 12 calls retains return-PC-minus-one ownership;
the call at `0x49591a5` returns exactly at its row's exclusive end, so that
subtraction matters. The cleanup call at `0x49591eb` is outside the retained
call-site rows and is recorded with no owner, without a nounwind inference.

The local graph treats calls as normally returning. It verifies final-store
dominance and the index-bound error route, but records fallthrough after the
last call at `0x4959218` as leaving the FDE. It does not invent a noreturn
contract, full function closure, exception feasibility or personality behavior.

## Validation, limits and next question

Nine focused methods cover the actual fields and metadata, unsigned u16 bound,
caller alias, pointer/store/call corruption, all selected relocation retargets,
CFI/LSDA changes, complete native byte binding, an actual branch-to-instruction-
interior corruption, exact repeats and existing-output preservation. A real
private source-path replacement test verifies that GNU stays on the admitted
510-byte slice and the changed source is rejected before publication. Wrong
identity and owned-slice mutation controls are also included. In-memory
mutations use private copy-on-write pages; original artifacts are not changed.
See `validation.txt` and `focused-tests.txt` for actual run boundaries/results.

No independently authored Rust component/build, target execution, behavioral
differential, normalization mask, source/type recovery, allocation lifetime,
policy or accepted component gate is claimed. All component gates remain false.
The next question is opaque `0x4258c00`'s effects and the provenance of its
three loaded words, including the forwarded output alias. The scalar
helper-return/storage contracts on the zero-field route also remain open.
