# RE-001: node #94 singleton-like registry lifecycle

- Component: `foundation`; one bounded RE-001 static boundary/xref question,
  with no task prerequisites. All component gates remain false.
- Target: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
  91,774,280 bytes. No #115 or visor claim.
- Original analysis base: `6fb86319763b30860f92b9da746cbe4f9b637573`.
- Resubmission base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
  This supersedes closed PR #26 at the owner's explicit request: validation
  records now omit contributor home paths and process-local environment values.
  The static analysis, collector and tests are unchanged; current main checks
  are rerun separately from the retained historical results.
- Reference revision: `999556f6e0a474b8312db96ec3149e1c44e97c23`;
  `base/singleton_set.rs` is an unlicensed lead, not copied implementation.
- Question: how are the two constructor-like paths related to the stored
  fields and cleanup-like operation, and does the alternate path retry until
  it obtains a unique registration?

The observed paths share a registry address and key-format descriptor. A
strict-like path sends a nonzero operation result to a diagnostic failure;
the alternate-like path makes **one** fallback formatting/registration attempt,
then also fails on a nonzero result. A cleanup-like body rebuilds the same
descriptor operands from the constructor's stored fields, calls a second
operation on the same table, and fails on a zero result. This supports a
registration/cleanup lifecycle, rather than a type-only immortal singleton or
an unbounded rerandomization loop. These role names are inferences; the packet
does not establish a complete API, automatic Rust destruction or concurrency
guarantee.

## Reproduce

Use Linux, Python 3.10+, GNU binutils (`readelf`, `objdump`), and the normal
authenticated artifacts and unchanged pinned references from the reviewed
setup instructions. This Python-only packet needs no Rust toolchain install,
REA/Ghidra/npm, captured executable launch, emulator or node/chain traffic.

```sh
make doctor
make verify test catalogue-check reproduce
python3 tools/singleton_lifecycle.py --output work/singleton-lifecycle-94
diff -ru research/work-items/RE-001-singleton-lifecycle-94/observed work/singleton-lifecycle-94
python3 -m unittest discover -s tests -p test_singleton_lifecycle.py -v
```

Recorded environment: Ubuntu 24.04/WSL2, Python 3.12.3, GNU binutils 2.42.
`objdump -d` uses its default AT&T syntax, with linked ELF virtual addresses,
not rebased analysis addresses. The producer authenticates the entire input,
checks relevant bytes/RELA bindings, independently decodes readelf FDE extents,
and streams complete `.text` disassembly for selected references. The nine
exports retain raw bounded disassembly, FDE/relocation rows and machine records.
Only the local binary pathname in objdump's header is replaced. There are no
normalization masks or body-equivalence claims. Text rendering may differ
across binutils versions; raw bytes and hashes are also recorded.

## Exact ranges and source attribution

| Inferred role | ELF VA, half-open | File offset | Bytes |
| --- | --- | --- | ---: |
| Alternate-like constructor | `0x14396c0..0x1439a3f` | `0x14386c0` | 895 |
| Strict-like constructor | `0x1439a40..0x1439bf9` | `0x1438a40` | 441 |
| Cleanup-like operation | `0x1445950..0x1445aab` | `0x1444950` | 347 |
| Table add-like path | `0x14cc320..0x14cc597` | `0x14cb320` | 631 |
| Table remove-like path | `0x14cc7c0..0x14cc997` | `0x14cb7c0` | 471 |
| Release path | `0x143f6d0..0x143f6e3` | `0x143e6d0` | 19 |

All are exact readelf FDE extents, not next-index estimates. There are 121,299
FDE records in the input. This packet inspects **three primary regions plus
three helper regions**, not a whole-target function census or six fully
recovered Rust functions. Their lower callees remain incompletely closed.

The embedded `/home/ubuntu/hl/code_Mainnet/base/src/singleton_set.rs` path is
at VA/file offset `0x1f8990`. RELA slots `0x566a168`, `0x566a180` and
`0x566a198` point to it and are referenced by the cleanup, alternate-failure
and strict-failure paths respectively. GOT slots `0x576efa0`, `0x576f4e0`
and `0x576f008` resolve to the three primary bodies. This binds the native
observations to the source-path lead without trusting inferred source code.

## Shared operands and numeric result branches

All three primary bodies use byte storage `0x5788318` in atomic `cmpxchg`
instructions and pass table address `0x5788320` to the observed operations.
Acquisition/release helpers are linked in the records; fairness, scheduling,
all exceptional paths and a complete thread-safety contract are not established.

The primary key-format descriptor at VA/file offset `0x1f05cd` is exactly
`c0 02 3a 3a c0 00`. The printable `::` occurs inside this compact descriptor,
not a proven standalone C/Rust format string. Both constructor-like bodies
prepare two pointer/length pairs in the same order, use callback `0x14ddab0`
for each, and call formatter slot `0x576e040` (addend `0x1344760`). The exact
fully formatted key requires closing that formatter; this packet proves the
descriptor and operand relation instead.

At entry to the strict-like body, pair A is `rsi/rdx`, pair B is `rcx/r8`.
The formatted object is passed to `0x14cc320` with the shared table. At
`0x1439adc`, zero `al` enters the success route; nonzero enters the failure
route, releasing the shared byte through `0x143f6d0` before calling the
diagnostic path associated with printable `Singleton already created: `.

The observed successful field flow is:

| Output offsets | Observed source |
| --- | --- |
| `+0x18`, `+0x20` | Original pair A, preserved directly |
| `+0`, `+8`, `+0x10` | Length/copy-pointer/length triple derived from pair B |
| `+0x28` | Byte zero |

These offsets do not by themselves establish a full Rust type, field names,
ownership ABI or serialized layout. Allocation/copy helpers remain opaque.

The table add-like body contains a string-comparison search. Its equal-key
route at `0x14cc3fb` sets result 1; its insertion route increments table
offset `+0x10` at `0x14cc522` and returns zero. **This does not establish that
every result 1 means a duplicate**: an owned-string sentinel/overflow path also
exists. The constructor's numeric branching is observed; the full table and
input-validity contract remains unresolved.

## Exactly one fallback attempt

The alternate-like body first submits the same descriptor/pair construction
to the same add-like operation. A zero result bypasses fallback and stores
the ordinary pair-B-derived triple with flag byte `+0x28 = 0`.

On a nonzero first result, it:

1. Calls slot `0x576e9d8`, addend `0x13cc380`, and stores the returned word.
   This is an **opaque word provider** here. Randomness/distribution is not
   independently established by a reference name.
2. Passes the original pair B and that word to another formatting invocation.
   Its descriptor at `0x1e84e2` starts `c0 01 5f c0 00`, with a printable
   underscore, and uses a separate word-format callback slot. Neither the word's
   decimal/hex representation nor the complete resulting string is claimed.
3. Rebuilds the primary descriptor using pair A and the derived owned pair,
   then calls the same table add-like operation again.
4. A zero second result stores the derived owned triple, original pair A and
   flag byte `+0x28 = 1`. A nonzero second result reaches the descriptor with
   printable `SingletonSet could not register ` at `0x1de8e0` and a failure
   call; there is no branch back to the word-generation site.

Thus the observed policy is a single fallback attempt, not an unlimited
retry-until-unique loop. Successful registration, termination of opaque
helpers, allocation success or quality of a generated name are not proven.

## Cleanup relation

The cleanup-like body loads pointer/length pairs from input offsets `+8/+0x10`
and `+0x18/+0x20`. It puts the latter first and the former second in the
**same** primary descriptor with the **same** pair callbacks/formatter. This
matches the constructor output-field flow above, including the alternate
path's stored derived name pair. It then passes the formatted object and
shared table address to `0x14cc7c0`.

The remove-like helper searches with `memcmp` slot `0x576e488`
(`memcmp@GLIBC_2.2.5` in the retained readelf row), calls a lower tree primitive
on a found path, decrements table offset `+0x10` at `0x14cc8d7`, and has a
result-1 return route; absent-tree/search routes return zero. The lower erase,
allocation and sentinel paths are not fully closed. Cleanup saves the result
in `cl` and, after the atomic release attempt, zero `cl` reaches the descriptor
with printable `Singleton never created: ` at `0x2019cd`. Nonzero follows its
normal cleanup-return route.

The compact diagnostic descriptor bytes are retained in machine records,
including their nonprintable prefixes/suffixes. They are not treated as plain
strings or a recovered formatter schema. No automatic Rust `Drop` invocation
or full lifetime guarantee is inferred solely from the cleanup-like body.

## References, controls and limits

The complete `.text` decode records 74 direct/RIP-relative references to the
three primary addresses/slots and 53 direct/RIP-relative outgoing references
inside their extents. These are selected-reference counts, **not** 74 validated
callers, a closed call graph, or evidence that every cleanup is automatic.
Register-indirect/vtable/data references and other caller semantics are outside
this packet. Relevant GOT bindings, shared-byte/table operands, descriptor
bytes, source attribution and field-flow instructions are checked explicitly.

Six focused tests cover the real input and parser rejection. Twenty-four real
instruction corruptions, six descriptor/path corruptions and six actual RELA
retargets are rejected below the global digest gate; three actual call-byte
sequences independently resolve to the expected operations/slot. These are
evidence-collector controls, not a simulation or execution of the captured node.

See `validation.txt` for actual commands/results. No inferred source was copied
into MIT implementation; there is no Rust workspace/component, captured target
execution, runtime comparison, chain networking, hosted CI or progress-gate
claim. The next step before implementation is closing the format, word-provider,
table and ownership/caller contracts; passing static tooling is not a complete
singleton implementation or concurrency proof.
