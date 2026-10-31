# RE-001: node #115 TLS identity probe and two lazy-mutex-associated callers

- Component: foundation; bounded mapping of new #115 `base/src/lock_id.rs` / `base/src/lazy_mutex.rs` evidence.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source revision: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Question: what comparison does the shared caller slot actually perform, and how do these two callers use its true result?
- Claim status: actual instruction/data/relocation observations plus a conditional normal-path relation. Original symbols/source types are not recovered.
- No Rust reconstruction, concurrency guarantee, live operation or progress gate.

## Measured scope and evidence

| Role | Actual FDE half-open VA range | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| TLS identity probe | `0x154cd10..0x154ce3b` | 299 | 80 |
| three-cleanup caller | `0x14c2a40..0x14c2b4c` | 268 | 73 |
| two-cleanup caller | `0x14c2b50..0x14c2c47` | 247 | 67 |

Denominator: **three complete FDEs, 814 bytes / 220 native instructions**. All
native exports start at their actual FDE entry, cover the complete body and
match its original bytes. `records.json` retains raw FDE/CIE bytes, body hashes,
file offsets, source Location metadata, direct-call and relocated-slot bindings.
`frames.txt` and `selected-relocations.txt` are original GNU output rows selected
by the stated exact coordinates, not a complete global xref or relocation census.
No comparison normalization mask is used.

`base/src/lazy_mutex.rs:46:17` at Location `0x63f8db0` is referenced at
`0x14c2b0b` and `0x14c2c06`. `base/src/lock_id.rs:52:49`, Location `0x64015b8`,
is referenced at `0x154ce2e`. Pointer relocations, lengths, line/column and path
bytes are checked. These establish diagnostic associations, not an original
source implementation or the concrete names/types of the compared fields.
The paths are new #115 catalogue observations; no #94 address/ABI is reused.

## Probe relation, with explicit preconditions

The input RDI object has a byte at `+0x20`. If it is not exactly 1, the local
path returns EAX=0 without accessing this TLS vector. For the scan below assume
that byte is 1, the thread-local readiness byte is already 1, the borrowed
counter is below `2^63-1`, and all input/vector/byte regions are valid and do not
alias the counter/state being changed. The vector must be well formed with
non-wrapping `56*n` address arithmetic. Initialization, destruction and borrow
failure are separate paths, not covered by this normal scan relation.

The captured FS-relative base is **-0x1180**. Relative to it:

- `+0`: qword counter; its original value is saved, then incremented by one.
- `+0x10`: record-vector data pointer.
- `+0x18`: record count, multiplied by **56**; loop offset also advances by 56.
- `+0x20`: readiness byte. The value-2 branch calls an opaque helper, and other
  non-ready states take an initializer path; their effects are not closed here.

For a record at vector base plus `56*i`, the loop tests these fields in order:

| Record field | Input field | Width | Observed comparison |
| --- | --- | ---: | --- |
| `+0x18` | `+0x18` | 8 | `0x154cdd9` |
| `+0x10` | `+0x10` | 4 | `0x154cde0` |
| `+0x8` | `+0x8` | 8 | `0x154cde7` |

A mismatch advances to the next record. Only if those match does the code call
through `0x64df9f8`, passing record `+0` as the first pointer, input `+0` as the
second pointer, and input `+0x8` as length. The actual GLOB_DAT relocation names
symbol 11, **`bcmp@GLIBC_2.2.5`**, confirmed independently by readelf. This is not
an assumed local comparator or a `memcmp` label guessed from arguments.

The local test uses only whether the imported result is zero. Under the
standard imported `bcmp` contract, that means equality of the specified byte
regions. The external contract is corroborated by the [GNU C Library manual](https://www.gnu.org/software/libc/manual/2.33/pdf/libc.pdf)
(`bcmp` alias of `memcmp`); its actual runtime implementation and loader
interposition are outside this packet. At the instruction level the established
claim is conditional on the imported call returning zero, normally and according
to the observed ABI.

Any matching row sets **AL=1**; an empty/exhausted vector sets **AL=0**. Both
local returning scan outcomes restore the saved original counter at
`0x154ce1b`. The increment is a temporary scan/borrow guard, not a persistent
identity sequence. The `>= 2^63-1` failure branch is tied to the checked
`lock_id.rs` Location and an opaque callee. Panic/unwind behavior is not claimed.

Bytes `+0x14..+0x17` and the rest of the record beyond the listed fields are not
part of these scalar comparisons. The separate byte-pointer comparison remains
required: scalar equality alone is insufficient. Concrete semantic field names,
record ownership and a Rust layout/type are unresolved.

## Two callers and their true-result paths

Both callers preserve their incoming RSI payload separately and pass
`object+0x18` through the same RELATIVE slot `0x64dffe0 -> 0x154cd10`. Their
preliminary dword `object+0x40` can cause a call to separate cold guards
`0x15d3214` / `0x15d32ae` before returning to this sequence. Those guards remain
outside the measured semantic scope.

When the probe returns AL nonzero, each caller invokes an opaque helper with
a compact descriptor at `0x448a8e` containing `lazy mutex:` and a formatting
argument associated with `object+8`. The helper, callback and rendered message
are not recovered. The caller then makes conditional cleanup calls through
slot `0x64df4a0`: three incoming groups at `+0/+0x18/+0x30` in one body, two at
`+0/+0x18` in the other. Each is guarded by a **signed greater-than-zero** test
of its first qword. Arguments use the group's next qword and that positive
word, with EDX=0. These are raw call/argument observations, not a recovered
Vec/String/drop ABI or a promise about effects of the opaque callee.

The local returning true path explicitly sets AL=1 after the possible
clobbering calls. When the probe returns zero, the callers instead copy their
payload into a stack closure and call `0x154c2c0` / `0x154c4e0`; the resulting AL
is not classified here. Normal callee returns/ABI preservation are assumptions
for these caller-path conclusions. Cleanup/unwind blocks are retained in the
full disassembly but not closed.

Thus the bound shared slot is a TLS identity comparison relation, and these
caller paths react to its true result. This does not establish mutex acquisition,
exclusion, lock order, deadlock behavior, scheduling or complete lazy-initialization
semantics. Other callers exist; this packet does not claim a whole-program census.

## Reproduce and controls

macOS arm64; Python 3.12.14; GNU readelf/objdump 2.47.20260726. From repo root with
materialized captures and native GNU tools on PATH:

```sh
python3 -B tools/tls_lock_id_static.py --output work/tls-lock-id-check
# Compare generated files with this packet, except README/manifest.
python3 -B -m unittest discover -s tests -p test_tls_lock_id_static.py -v
make doctor verify test catalogue-check
make reproduce
(cd research/work-items/RE-001-node115-tls-lock-id && shasum -a 256 -c MANIFEST.sha256)
```

The producer authenticates the full capture before analysis/output/native calls.
Native tools read a private byte-identical snapshot. Complete byte coverage and
selected actual instruction starts are checked; UTF-8/LF byte writers preserve
exports. Public wrong-release, truncated and same-size modified captures are
rejected before output creation.

The independent scalar-projection controls alter each actual comparison's
record displacement by one: the extracted relation changes on a concrete
56-byte fixture before the analyzer rejects it. Other controls change the two
actual stride immediates, TLS base, enabled byte/value, borrow limit and restore,
caller branch polarity, cleanup operands and returned AL constants. Real call
slots, the `bcmp` dynamic relocation, all relative bindings and FDE extents are
also corrupted below the public hash gate. This does not claim arbitrary-byte
error detection below that gate, and the synthetic projections are not execution
or emulation of the captured code.

An initial producer run rejected a manually mistyped opaque helper relocation
(`0x5c9b400`); reading its actual RELATIVE addend corrected it to `0x5c9b900`
before retained generation or test validation. No target bytes were changed.

No captured executable/emulator, live TLS read, user process inspection, networking,
wallet, signing or chain action is performed. Original captures/imported code/pins
and all gates remain unchanged. No hosted-CI or complete behavior-equivalence claim.

Next question: close the zero-result callback/initialization path before
implementing any concurrency abstraction or assigning semantic names to its keys.

Observed local validation: six final focused tests passed in **36.992s**
(after adding the descriptor-byte check; the earlier six-test run was 37.398s).
`make doctor verify test catalogue-check` passed all **437 tests in 178.127s**,
three signatures, input/import/source-pin checks and catalogue consistency.
`make reproduce` passed. Packet manifest and staged whitespace checks passed.
