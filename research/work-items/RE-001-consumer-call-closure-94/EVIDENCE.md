# RE-001: what calls node #94 0x1455c00, and what does it reach?

- Component ID: none (binary-wide function-map input; no component ownership)
- Target release and full SHA-256: node #94
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: hyperliquid-source
  `1f8c67c63ca4794c9689235471c60297f8a5c985`; can1357-hl
  `999556f6e0a474b8312db96ec3149e1c44e97c23` (not consulted for this record)
- Claim status: observation; the callee's high-level name and Rust implementation
  remain unresolved
- Scope included: the FDE extent of `0x1455c00`, its body digest, byte-pattern
  direct callers, RELATIVE pointer slots to it, RIP-relative `.got` operands and
  their relocations, one `Location` record, one separator store and one overflow
  branch. Scope excluded: decoded caller census beyond `E8 rel32`, indirect call
  or vtable callers, callee semantics, Rust code, runtime execution, gates.

## Reproduce

Platform: Windows 11, Python 3.12.10, UTF-8 I/O forced. Static only; the capture
is never executed. Repository root:

```text
python tools/consumer_call_closure.py --check research/work-items/RE-001-consumer-call-closure-94/records.json
python -m unittest discover -s tests -p test_consumer_call_closure.py -v
python research/work-items/RE-001-consumer-call-closure-94/verify_native.py
```

The stdlib tool prints canonical JSON (sorted keys, one-space indent, trailing
newline) and writes bytes, so its output is host-newline independent.
`records.json` SHA-256 is
`5cbc9201e95866e46d605ad3dfc4a5a9730b3510c5f416ba797ba5cab4b3f3c8`.

`verify_native.py` is optional and needs Capstone 5.0.6 on `PYTHONPATH`; it only
decodes bytes. Its recorded result: 218 instructions covering all 909 bytes
contiguously, seven decoded `call` targets, six decoded caller sites, and two
raw `E8` bytes at `0x1455d61` and `0x1455e2d` that are not instructions. The
218-line listing is `capstone-5.0.6.txt` (SHA-256
`fe806c27c19e86d0f4e3df629560097e8143e2718755a183bb6431c620932f10`).

## Evidence

Coordinates are linked VAs; `site_offset` is relative to the `.text` address
`0x1343c80`. The extent is unwind-described, not a validated boundary.

- **Extent and body.** `0x1455c00..0x1455f8d` (909 bytes), file offset
  `0x1454c00`, body SHA-256
  `4d0392cf3414fcf32f08b1338642341ba9c36ad2368c65f2d00fe0467fa0c3fa`.
- **Direct callers.** Six byte-pattern `E8 rel32` sites reach `0x1455c00`:

  | Site | Containing FDE |
  | --- | --- |
  | `0x1404e53` | `0x1404d90..0x1404ee7` |
  | `0x144a916` | `0x144a890..0x144accc` |
  | `0x144c036` | `0x144bfd0..0x144c180` |
  | `0x144cbab` | `0x144ca50..0x144cca0` |
  | `0x144d004` | `0x144cf90..0x144d0c9` |
  | `0x37e3207` | `0x37e2960..0x37e3a6b` |

  The second row is the consumer function bound in
  `RE-001-periodic-slice-consumer-94` (`0x144a890`), at `+0x86`; that packet
  stopped at an opaque `0x1455c00` call. Branches copying an indirect callee
  address into a register are not counted by this scan.
- **No pointer slot.** No `R_X86_64_RELATIVE` relocation in `.rela.dyn` names
  `0x1455c00`, so no function-pointer/GOT slot references it in this image.
- **Indirect operands.** Eleven RIP-relative operands resolve to `.got` slots.
  Six slots are RELATIVE-bound inside `.text`; two `call` sites are GLOB_DAT
  `memcpy` at `0x576dfe0` (`0x1455e10`, `0x1455e79`). The others: `0x576e010`
  (`free`-shaped single-pointer call under the jemalloc allocator, addend
  `0x54c8cb0`, five sites), `0x576dfb8` (addend `0x1346068`), `0x576dfd8`
  (addend `0x54c06b0`), `0x576e0c8` (addend `0x13460a0`), `0x576e118`
  (addend `0x157b480`). The addend labels are relocation targets, not proven
  API names.
- **Location.** `lea rdi` at `0x1455f31` reaches `.data.rel.ro` slot
  `0x566ad18`, whose RELATIVE addend is the 85-byte path
  `/rustc/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/core/src/iter/traits/accum.rs`
  with line 204, column 1. The overflow branch at `0x1455d13` (`jb`) targets
  that `lea`. This ties the body's unsigned length sum to the core accumulator
  overflow panic; it does not prove the whole function is `Sum`.
- **Separator store.** `0x1455e47` writes the immediate `0x20` between the two
  `memcpy` ranges; it is the only such store in the extent. This is byte
  evidence for a single-space delimiter, not proof of the caller's data model.

Raw `E8` scanning over the body yields nine sites (see Reproduction); two are
immediate/data bytes. That is why this packet keeps byte-pattern caller rows
separate from the decoded listing and does not publish a caller count as a
decoded census.

## Implementation and comparison

No Rust path is implemented and no Cargo build is claimed. The record is
derived only from pinned artifact bytes and the projection is:
`scan(mutated bytes with expected_sha256 replaced)`. Thirteen tests cover the
complete record, the committed bytes, digest rejection, caller retarget, an
injected `E8` inside the body, indirect-operand retarget, RELATIVE and GLOB_DAT
retarget, Location path mutation, separator immediate mutation and overflow
branch retarget, plus hash-seed determinism. The caller retarget test drops one
row instead of erroring because the byte scan by definition reports what it
finds; the decoded listing is the control that rejects non-instructions.

## Results and limitations

- Six callers, eleven indirect operands, one Location, one separator store and
  one overflow branch reproduce byte-for-byte; `--check` passes.
- Native replay is byte-identical and covers the extent contiguously.
- No decoded indirect-call, vtable or callback census exists; `E8` byte
  scanning can both miss branch-loaded calls and over-report non-instructions.
- FDE extents are not function boundaries; no component gate, Rust
  reconstruction, runtime reachability or equivalence is claimed.
- Full-suite result on this host is recorded in the pull request, not here.

Next question: decode `0x54c8cb0`, `0x1346068`, `0x54c06b0`, `0x13460a0` and
`0x157b480` as functions and test whether the six callers pass the same
record layout before any high-level name is assigned.
