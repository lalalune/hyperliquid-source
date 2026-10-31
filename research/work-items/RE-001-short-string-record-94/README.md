# RE-001: one compact-carrier consumer's record and cleanup contract

- Component: **foundation**; one bounded static RE-001 question, no gate requested.
- Target: Linux x86-64 node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Pinned reference: `999556f6e0a474b8312db96ec3149e1c44e97c23`. Its inferred,
  unlicensed implementation is not copied or used as a behavioral oracle.
- Question: how does caller `0x13c6430` place the compact constructor's returned
  carrier and another helper's payload into records, and where is its index
  committed on normal and metadata-described cleanup paths?

The existing [compact-string packet](../RE-001-short-string-94/README.md) retains
this caller's raw context but leaves consumer contracts unresolved. This packet
adds its explicit record stores, source record, local branches and call-site
cleanup associations. The denominator is **one 439-byte unwind-described body,
10 decoded calls, six LSDA call-site rows and one signed action pair**. These
are local observations, not a whole-target function denominator or a recovered
Rust component.

## Reproduce

The collector is independently authored Python using the existing MIT ELF/FDE
readers, plus GNU `objdump` and `readelf`. It never launches the captured image.
It authenticates node #94, reads its own FDE/RELA/LSDA bytes, verifies complete
bounded native disassembly byte coverage and the exact call/branch/return set,
checks one native FDE record and retains selected native relocation rows. GNU
tools receive only an owned mode-0600 snapshot of the authenticated bytes in
a mode-0700 temporary directory, never the mutable source pathname. The collector
checks that snapshot's identity and complete SHA-256 before and after collection,
then rechecks the original input's identity and complete SHA-256 before publishing
to a **new** output directory. Only the owned temporary snapshot is cleaned up.

From the repository root, using a fresh output directory:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/short_string_record_static.py \
  --output work/short-string-record-94
diff -ru research/work-items/RE-001-short-string-record-94/observed \
  work/short-string-record-94
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest \
  tests.test_short_string_record_static -v
make doctor verify test catalogue-check reproduce
cd research/work-items/RE-001-short-string-record-94
sha256sum -c MANIFEST.sha256
```

`INPUTS-AND-TOOLS.json` records exact collector/test hashes, Python 3.12.14,
Linux x86-64 and GNU binutils 2.44. Repeated complete exports, including the
owned-snapshot collector, reproduced all four observed files byte for byte on
those tools. Different native-tool versions
can render disassembly/CFI text differently; preserve that raw difference and
compare the target-bound records and bytes independently. Only the local input
pathname in the objdump header is replaced with `<authenticated-node94>`; no
instruction bytes or operands are masked.

## Boundaries and source attribution

All code addresses below are ELF virtual addresses, not runtime addresses.
The body `0x13c6430..0x13c65e7` maps to file offset `0x13c5430` and hashes to
`8b998c0b8617fecd669e8ea2c722e988b30a992c30575cc2c9b75bfa9cce81bd`.
Its FDE is `0xfc5ad8`, CIE `0xfbdc2c` (`zPLR`) and LSDA `0x91ee14`.
The Python reader and GNU readelf agree on this exact extent. This is an
unwind-described range with internally consistent decoded control flow; an
original Rust signature is not established.

The error branch addresses record `0x5666cd0`. Its RELATIVE relocation points
to the exact embedded path `/home/ubuntu/hl/code_Mainnet/base/src/cid.rs` at
`0x1e4c4a`; the record contains path length 44, line **28**, column **73**.
The adjacent literal at `0x216f9d` is the 43-byte
``called `Result::unwrap()` on an `Err` value``. Its presence supports a
failure-path attribution, not execution or a recovered error type.

## Observed record construction

On entry, 72 bytes from the first argument are copied to stack state. From the
second argument, the body saves its first word, loads an index-like word at
`+8` into `r14`, and loads a base word at `+16`. It computes the visible output
cursor as `base +48*index +16`. These are observed accesses, not a declaration
of an original struct or valid-state/capacity invariant.

The helper at `0x14ce550` writes a stack result. A zero first word branches to
the index-commit/drain route. Otherwise another result word is scaled by 16;
the selected pointer/length pair is passed to constructor slot `0x576e798` at
`0x13c64cb`. Its authenticated RELATIVE addend is `0x1449a80`, the constructor
studied in the existing compact-string packet. Returned `rax`/`rdx` halves are
saved. Two other selected words are passed to the opaque helper bound through
slot `0x576e840` to `0x1444a00`.

At `0x13c64e8`, result byte 1 branches to the failure path. The other visible
route reads 16+4 bytes beginning one byte after that status byte and performs:

| Store VA | Offset from `cursor-16` | Width | Observed source |
| --- | ---: | ---: | --- |
| `0x13c6507` | 0 | 8 | Saved constructor low half |
| `0x13c6503` | 8 | 8 | Saved constructor high half |
| `0x13c6510` | 16 | 16 | Opaque helper payload first 16 bytes |
| `0x13c6517` | 32 | 4 | Opaque helper payload final 4 bytes |

The high half is explicitly stored before the low half. The body then increments
`r14`, advances the cursor by 48 and repeats. The append block has explicit
stores covering offsets 0..35; offsets 36..47 are not explicitly written there.
Whether those bytes are padding, previously initialized state, or affected by
opaque helper aliasing is unresolved. The 20 copied bytes are kept opaque;
they are not assigned an address, `Cid`, tag or other original type.

When the source helper's first result word is zero, the current index is stored
through the saved first output-state word at `0x13c652a`. A drain loop calls
the same source helper until its first word is zero, then reaches the only
decoded return at `0x13c6564`.

## Failure and cleanup associations

The result-byte-1 branch goes to `0x13c6565`, preparing the failure payload,
literal, opaque formatting record and source record before an indirect helper
call at `0x13c658e`. `ud2` follows at `0x13c6594`. The helper's implementation
and dynamic exception behavior remain unclosed.

The LSDA uses omitted LPStart (the body start), type encoding `0x9b`, and ULEB128
call-site fields. Its six observed half-open intervals are:

| Interval | Landing pad | Action |
| --- | --- | ---: |
| `0x13c6490..0x13c64e8` | `0x13c6596` | 0 |
| `0x13c64e8..0x13c656f` | none | 0 |
| `0x13c656f..0x13c6594` | `0x13c659b` | 0 |
| `0x13c65a6..0x13c65a8` | `0x13c65e1` | 1 |
| `0x13c65c0..0x13c65cb` | `0x13c65db` | 1 |
| `0x13c65cb..0x13c65e7` | none | 0 |

Action 1 is the signed pair `filter=-1, next=0` (`7f00`). The collector decodes
41 bytes through that pair; it does not interpret the type table, filter meaning
or personality implementation. CIE personality-slot metadata is retained.

All 10 decoded calls associate with one row using **return-PC minus one**.
The opaque payload helper returns to `0x13c64e8`, exactly the first interval's
exclusive end. Using the return address itself would select the next no-pad
row. The constructor and payload helper both associate with `0x13c6596`.
That pad saves the exception and joins the second index store at `0x13c65ac`,
followed by a drain loop and a direct call at `0x13c65d6`.

The second pad at `0x13c659b` additionally calls through an opaque first-word
pointer before joining the same commit/drain route. The direct resume call
resolves through PLT `0x5660110` and JUMP_SLOT `0x5778db0` to the actual dynamic
symbol `_Unwind_Resume`. The other two pad calls share RELATIVE-bound target
`0x157b63b`; its behavior is not named or analyzed. These are static metadata
and instruction associations, not runtime replay or proof of valid exceptions.

## Related work and remaining closure

- Open [#266](https://github.com/lalalune/hyperliquid-source/pull/266) maps the
  **callee constructor's** `0x1449a80..0x144a009` LSDA and ownership. This packet
  derives the distinct **caller's** metadata. It neither duplicates that body
  nor transfers its claims into an accepted helper implementation.
- Open [#163](https://github.com/lalalune/hyperliquid-source/pull/163) maps CID
  lookup `0x1405240..0x1405508` and source record `cid.rs:69:17`. The relationship
  between these 48-byte records and that lookup's 20-byte values is unresolved.
- Input-state/source-helper semantics, conversion/error/formatter/drop helpers,
  output capacity, aliasing, original Rust types and caller ownership remain
  unknown. There is no whole alias algorithm, serializer, build or equivalence
  claim, and no transfer to node #115 or visor.

## Validation and next question

Thirteen focused tests pass. Below the global identity check, copied real-target
bytes are changed in **12 instruction controls, seven relocation/type controls,
three source/literal controls and four LSDA controls**; all 26 subcases are
rejected by their local obligations. Separate whole-input mutation/truncation
controls reject wrong identity. Native regeneration independently covers all
439 bytes, the exact six branches/10 calls/one return, and the FDE and selected
relocations. Three private-file controls additionally exercise a metadata-only
hard-link change, a source-path replacement after admission, and mutation of the
owned snapshot. Unrelated source ctime changes do not reject unchanged bytes;
source identity or byte changes and snapshot changes still reject publication.
No control mutates a shared capture. No captured executable, emulator, chain,
signer or networked node is run.

The earlier candidate `51b463deca8f7643f2ff93c1f404de76bb563501` passed doctor
and input verification but failed one of 441 tests: its original-input ctime
guard rejected a concurrent hard-link creation during shared-worktree setup.
The before/after audits retained the same input identities, modes and bytes.
That failed run is preserved; the private-snapshot correction requires a fresh
full validation run rather than treating the earlier aggregate as passing.

Repository check outcomes and the exact final tested commit are recorded in
the PR validation receipt; the required commands are listed above. Original
artifacts, signatures, submodule pins and progress records stay intact. Every
component gate remains false.

Next: establish the caller and capacity contract for this record-building body
and the actual result type/side effects of `0x1444a00`, before selecting an
independently authored Rust representation or connecting it to CID lookup.
