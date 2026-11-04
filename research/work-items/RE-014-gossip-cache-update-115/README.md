# Node115 gossip cache update and dual storage protocol

RE-014 / RE-001, component `node-runtime`. Bounded question: what does the
node115 cache update do on comparison mismatch, how are its keys selected,
and how does it request retention across its two storage representations?

Target: node115,105896032bytes,SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. All coordinates are linked
Linux x86-64 ELF virtual addresses, ends exclusive; file offsets/FDE records
are in records.json. This is new115-bound static research, not a Rust port,
full component gate or whole-node correctness claim.

## Evidence scope

| Role | FDE range | Bytes | Instructions |
| --- | --- | ---: | ---: |
| Update | 5a5d5a0..5a5d950 | 944 | 233 |
| Clear/reset helper | 4dc0950..4dc0ac0 | 368 | 103 |
| Insert wrapper | 4ddb720..4ddbc4f | 1327 | 318 |
| Removal wrapper | 4de4340..4de4551 | 529 | 122 |

The primary denominator is four complete FDE-described bodies,3168bytes and
776instructions. Complete GNU exports and independent Capstone decoding must
agree at every instruction start and byte; no bytes or operands are masked.
This is static disassembly equality, not compiled Rust identity. Both the
shared ELF header index and independent `.eh_frame` parser bind the ranges.

The fresh source Location at64b84d0 has raw pointer0, RELATIVE addend44af16,
length22, path `node/src/gossip_rpc.rs`, line245,column43. It is loaded at
5a5d8a8 on the removal-absence failure path. This associates source context,
not an original method name or complete source ownership. The indirect slot
64e76f0 resolves to the update entry. The whole-text FF15 census is recorded;
computed/register calls and arbitrary data references are not exhausted.

## New115 observations

The historical94 packet in Git history/PR1386 is only a migration lead: its
flag reset, container offsets and value widths are not transplanted. This
packet independently binds the115bodies above. No unlicensed inferred source
is copied; new producer, tests and documentation are project-authored MIT.

**Two storage forms.** Incoming RDI is an owner and `[owner+30]` is shared.
The four-word cache starts at shared+48. A first word8000000000000000 selects
its tree arm; otherwise it follows a ring-like arm. Tree node length is read
at+112, children at+118, and the rightmost key at node+b0+8*n. Ring-like
capacity/data/head/count occupy cache+0/+8/+10/+18, and rows have24-byte
stride. The latter follows directly from LEA times3 then SHL3, not an inferred
Rust type. Original allocator/collection types and valid global invariants
remain unclosed.

For the ring-like nonempty arm, the candidate row index is
`head+count-1`, followed by one unsigned capacity subtraction when >=capacity.
The first word of that row is selected. A missing tree root/empty selected
leaf or zero ring count selects owner+38 instead. Thus the tree arm follows
the rightmost key, while the ring arm reads its last logical row. Calling
both a global maximum would require the ring ordering invariant; not claimed.

**Incoming comparison and reset.** Incoming RSI is preserved in R15; the
third incoming argument is preserved separately. Word incoming+28 is tested
against8000000000000001. Its matching arm selects comparison word+60. The
other arm uses word+58 if incoming+b8 equals that sentinel, otherwise+e8.
These are byte-level selected fields; original enum types are unknown.

Inequality with the selected cache/fallback word calls4dc0950 on cache+0.
On normal return from its opaque destruction delegates, that helper stores
four words `[0,8,0,0]`, including zero head/count. This is a cache reset,
not the historical94 byte-flag clear. Concrete destructor, allocation,
unwinding and concurrent/contended-lock effects remain unclosed.

**Derived insertion key.** The later selector chooses incoming+50 when the
+28 word equals8000000000000001, otherwise incoming+a0. It reads that
member's+10 word x, increments it, and selects u64::MAX if the increment
becomes zero. Therefore the scalar key is saturating(x+1). The two input
payload arguments remain separate; there is no115copy of a historical94
32-byte payload. The wrapper's observed equality arm replaces two words
and returns the old pair, but complete insertion/growth semantics are not
claimed: their delegates are explicitly recorded as unclosed.

**Retention.** After the insert wrapper and old-payload release, the outer
body compares shared+60 against150001 with JB. The repeat compares the same
field against150000 with JBE. Both request another removal exactly when that
unsigned count is >150000. This is a count threshold, not key distance/time.
The wrapper result's second word must be nonzero; absence reaches the bound
Location/failure path. No termination guarantee on malformed state or opaque
helper failures is inferred.

The removal wrapper's ring arm advances head with one capacity wrap,
decrements count and copies a24-byte front row. Its tree arm calls51d9c50;
that delegate's first-key semantics are not recovered by this packet. Original
reference-count cleanup and exception paths remain visible and unclosed.

**Representation transition guards.** The insert wrapper selects a conversion
path for the sentinel/tree form with count<32 before insertion. In its other
form, a nonzero search-helper return combined with count>=64 selects another
conversion path. The exact search-result meaning and conversion helper
internals are not inferred. The removal wrapper also combines the tree tag
with post-delegate count<32 to choose a conversion path. These guards and
complete call records are evidence for later integration, not a recovered
collection implementation.

## Reproduce and checks

From repository root with existing pinned115input and native GNU binutils:

```
python3 tools/node115_gossip_cache_static.py --controls
python3 -m unittest discover -s tests -p test_node115_gossip_cache_static.py -v
make doctor verify catalogue-check
```

Producer authenticates the exact target before static parsing, invokes only
GNU objdump/version on it, and never executes the captured image, a CPU
interpreter, helpers or network. Python3.12.14,Capstone5.0.6 and GNUbinutils
2.47.20260726 are the local tool pins; actual version strings are recorded.
`--write` is an explicit initial-record operation; ordinary reproduction
compares outputs and preserves originals. Controls bypass target/body hashes
so declared instruction/data obligations must reject corruptions themselves.
First collection reached the180second resource bound and was not a PASS.
The active115analysis was blocked by reparsing unchanged whole-ELF layout for
all instruction edits. The smallest local producer adjustment reuses already
authenticated layout only for edits confined to .text or Location coordinate
bytes. Actual instruction/data bytes are still checked. FDE and relocation
corruptions always receive fresh independent parses. The corrected preliminary
collection passed exit0 in48.594wall seconds with38controls rejected. After
adding fresh-parse Location/update relocation controls, collection passed exit0
in62.741wall seconds with40controls rejected. Final read-only replay and focused/repository checks passed as below.
This does not modify shared ELF tooling or widen accepted input identity.

No Rust implementation or comparison is claimed in this static packet. No
component gate, byte-coverage credit, synchronization proof, original ABI,
full destructor/allocator/collection closure or live reachability claim.
Next: close the conversion/search/tree-removal delegates before composing an
actual115cache implementation. Keep retired94behavior as historical evidence.

## Actual validation

Read-only `--controls` reproduction, four focused tests, make doctor, make verify
and make catalogue-check passed in one115.716wall-second job at10% active duty.
Focused tests passed in15.222wall seconds. The checked signatures and29imports/
pins are authentic;29packetmanifests/464entries passed at that stage. Final
report/manifest additions are verified separately. Both FF15 candidates at
2b1e2d9 and5a6e4de are decoded instruction starts in their FDE owners.

A real `make test` attempt followed make catalogue, but reached the330second
resource bound: first8of77files completed, file9(cache_suffix_static) was still
running. This is incomplete, not a full-suite PASS or a claimed test failure
caused by this packet. No tests were removed, skipped or weakened. The raw
bounded-attempt log is retained in ignored work. Full make reproduce and hosted
CI are unrun; this packet's own read-only reproduction passed. Nonfatal xcrun
cache permission warnings and optional missing doctor tools are recorded.
Machine-readable commands/results and source/test hashes are in VALIDATION.json.
