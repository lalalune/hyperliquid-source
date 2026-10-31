# RE-013: visor large-request classification and conditional zero return

- Component: visor supervisor; every component gate remains false.
- Target: captured visor, 8,305,392 bytes, SHA-256
  `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Status: byte-bound static observations and a conditional arithmetic/return
  proof; no captured execution or original allocator/Rust ABI implementation.
- Scope: 251 bytes / 56 instructions in five disjoint linked-ELF-VA fragments
  of the 7,611-byte unwind-described extent `[0x70a170,0x70bf2b)`.
  The remaining 7,360 bytes are not decoded or claimed by this packet.

PR #1045 (head `26547ee4720895cfc2233e1ac5fbadaae7a7fb5d`) establishes a
194-byte cache helper whose large-request transfer preserves RDI, but records
this slow target as metadata only. This packet closes one useful part of that
explicit gap: after the actual entry flag sample is zero, it derives the
request-only large-class formula without assuming runtime class-map contents.
It also binds the oversized branch's opaque call, numeric store and conditional
zero return. It does not discharge successful allocation/freshness premises.

## Observations and proof

[PROOF.md](PROOF.md) supplies the algebra and physical frame/return premises.
[observed/record.json](observed/record.json) binds the whole target digest,
section mappings, actual FDE/CIE bytes, full FDE body hash, every selected raw
operator/control/output witness, parameters and 203 analytic class intervals.
The five raw-span GNU exports and `native-rows.tsv` retain the actual decoding;
no whole-image pathname is supplied to native tools. There are no normalization
masks. `class-intervals.tsv` is a deterministic target-derived oracle consumed
by the independently authored sibling Rust component, not Rust-generated
expected answers.

The pure formula is established only for unsigned requests
`4097..=0x7000000000000000` and the entry gate described in the proof.
All 203 contiguous bins have classes 29..231; at the maximum logarithm, the
upper bound excludes the otherwise possible fourth quarter. The next class
limit therefore cannot reject this domain. The sibling Rust component has a
chosen numeric `None` outside that range; it does not represent captured
allocator failure, null, errno or any original type.

For a request above that maximum and the same zero gate, the observed path
calls opaque `0x7a68a0`, zeros R12D, stores four bytes with numeric value 12
through the returned RAX, and reaches a guard/epilogue. Zero is returned only
under its explicit normal-call, successful-store, guard, frame and hardware
return conditions. No name or behavior is inferred for the opaque call.

## Reproduce

Installed Python standard library and GNU objdump suffice for this static
packet; there are no downloads, install hooks or target execution. From root:

```sh
PYTHONDONTWRITEBYTECODE=1 TMPDIR=/tmp/<owned-0700-directory> python3 -B tools/visor_allocator_large_request.py --out-dir /tmp/<new-output-directory>
PYTHONDONTWRITEBYTECODE=1 TMPDIR=/tmp/<owned-0700-directory> python3 -B -m unittest discover -s tests -p test_visor_allocator_large_request.py -v
```

The output directory must not already exist. Compare all nine outputs against
`observed/`. Input admission hashes the pinned bytes, validates one source fd
and current path identity, then uses immutable copies; native tools see only
five owned 0600 non-executable raw snapshots in 0700 temporary directories.
The native command is GNU objdump `-D -b binary -m i386:x86-64 -M intel
--insn-width=16 --adjust-vma=<linked-VA> <span>.raw`. The exact version is in the
record. All metadata comes from the admitted byte view; native tools never
reopen the original ELF. Hard-link metadata changes alone are not treated as a
byte change. Real same-bytes path replacement and harmless private hard-link
changes have separate tests.

Twelve focused native/admission tests pass. `observed/controls.json` retains
21 actual copied-byte counterfactuals, each decoded by GNU. Changed constants
either change derived interval/store/call facts or violate an explicit proof
lemma; changed dataflow/edges/output witnesses are rejected before a certificate
is emitted. Mutants are deliberately checked without the target SHA rejection.
During independent review a negative CMP imm32 exposed an unsigned parsing
mistake in this unpinned seam. The pinned target immediate was unaffected.
[REVIEW-CORRECTION.json](REVIEW-CORRECTION.json) retains the actual before
acceptance and the corrected sign-extension-domain rejection. The original
failed source/test and peer receipt are preserved externally, not overwritten.

Repository-wide checks and actual independent Rust builds are separate evidence
in the sibling packet and final PR; this focused result does not imply hosted
CI, whole-program equivalence, allocator execution or completion credit.

## Rights, unknowns and next question

New Python, proof and Rust are independently authored MIT project work. Binary
bytes/native excerpts are evidence of the retained captured artifact and keep
their original ownership. No can1357 or other unlicensed inferred source was
read or copied. Pinned imports, all seven submodule revisions, captured inputs
and global progress/catalogue files are unchanged.

Unclosed: nonzero entry gate, initialization, requests up to 4096, later
class-size-table/allocation/cache/page behavior, opaque `0x7a68a0`, canary-failure
route `0x70b743`, exceptions, storage capacity/freshness/alignment/lifetime,
private types/ABI, physical deployment, target runtime and whole-visor identity.
Held lifecycle #45 and unwind #407 are untouched. No caller preservation,
allocator safety or all-input theorem is claimed. The next substantive question
is the large path's later class-size lookup and actual successful allocation
return, with its own helper/state closure and ownership review.
