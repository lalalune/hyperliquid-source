# Node115 time-lock filename collection: static argument

All coordinates are original ELF virtual addresses with exclusive ends. The
input is the authenticated node115 capture named in README. `obligations.json`
binds the cited instruction spans, and `records.json` retains all explicit calls,
relocations, dynamic imports, FDE/LSDA coordinates and selected incoming calls.
No instruction evaluator or captured execution is used.

## Assumptions and boundary

The local normal-return argument assumes valid readable/writable objects, no
concurrent mutation, the observed x86-64 calling convention, ordinary returning
helpers, and no helper modification of caller-owned inputs except the designated
output objects. In particular, diagnostic callbacks must preserve the parse-error
tag and input iterator fields. A throw, abort, allocation failure or opaque helper
side effect is not a normal returned value.

The path component helper at `0x5cab560`, conversion helper `0x16815e0`, provider
`0x15623e0`, file-reading helpers, formatter, logger, deallocator and unwinder are
bound call dependencies, not recovered implementations. The dynamic symbol is
**bcmp**, through `0x64df9f8` (GLOB_DAT symbol index 11). Suffix equality below
assumes its usual zero-for-equal contract; this packet does not reconstruct libc.
“Release” is a role label for slot `0x64df4a0 -> 0x635de30`; its allocator
contract is assumed, not closed here. Do not infer that every input string is
first reduced to a basename: the helper
results decide whether the original slice is replaced.

## Input and candidate projection

At `0x5961a41..0x5961a79`, RDI is saved as output, and the RSI descriptor supplies:

| Offset | Observed role |
| --- | --- |
| +0 | backing-allocation base B |
| +8 | current input cursor P |
| +16 | input allocation capacity C, in 24-byte records |
| +24 | input end E |
| +32 | pointer to a suffix (pointer,length) record |

The measured caller constructs P=B and E=B+24*N at `0x5a6a066..0x5a6a099`.
For this caller, assume 0<=N<=C and a valid allocation of 24*C bytes, without
pointer or allocation-size overflow. These are an observed descriptor contract
and conditional ownership interpretation, not a universal Rust ABI.

Each iteration (`0x5961aa9..0x5961ac4`) copies the current 24-byte record to stack
storage, advances P by 24, and writes the consumed cursor back to RSI+8 **before**
calling helpers. The original slice uses its pointer at record+8 and length at
record+16. The first-byte slash flag is read only when length is nonzero.
The helper request encodes bytes 6 and 0x0201 plus that flag. A return byte of 9
selects a conversion request. Only a conversion result whose first dword is not
1 replaces the candidate pointer and length. Otherwise the original slice stays
selected (`0x5961b15..0x5961b4b`). Full component/tag semantics remain open.

## Suffix and unsigned decimal grammar

`0x5961b4b..0x5961b65` subtracts suffix length from candidate length, skips on
unsigned borrow, and calls bcmp on exactly the trailing suffix-length bytes.
Only zero proceeds. The remaining prefix length is the difference. The measured
caller supplies `.json`, length 5, at `0x5a69f60..0x5a69f7b`; case changes or a
longer trailing extension do not satisfy that byte suffix.

The prefix parser has these local routes:

- Length zero constructs raw error code 0.
- A sole `+` or `-` constructs raw error code 1.
- A leading `+` is skipped; a leading `-` in a longer prefix is an invalid digit.
- Every remaining byte must be ASCII `0` through `9`. The 32-bit ADD of -48 and
  unsigned comparison against 9 establishes precisely this set over all 256
  possible input bytes. Whitespace, NUL, separators and non-ASCII bytes fail.
- Up to 16 remaining digits use the unchecked `v=10*v+d` LEA sequence at
  `0x5961be0..0x5961c06`. Its maximum is 10^16-1, below 2^64-1.
- At least 17 remaining digits use `MUL 10`, overflow testing, digit checking and
  carry-checked addition at `0x5961c10..0x5961c44`. Leading zeros do not impose a
  fixed 20-byte limit: arbitrarily many valid leading zeros can stay in range.

The admitted mathematical language is therefore nonempty ASCII digits with an
optional leading `+`, whose base-10 value is at most 2^64-1. Examples include
`0`, `+0`, `0007` and `18446744073709551615`. Empty/sign-only inputs, `-0`, ` 1`,
`1\n` and `18446744073709551616` fail. These examples describe the proven local
relation; they are not reported target executions.

The raw error codes are 0 empty, 1 invalid digit, 2 overflow; no public enum ABI
is asserted. On multiply overflow the current byte has already been loaded.
`0x5961d5b..0x5961d68` performs an 8-bit -48, comparison against 10, then
`MOV EAX,0; ADC AL,1`. MOV preserves carry, so an invalid current byte selects 1
and a valid digit selects 2 even on that overflow route. Processing stops at the
first failure. A later invalid byte does not override an earlier overflow.

On parse failure, the code writes tag 1 at stack+0x30 and a raw error byte at
+0x31, then requests a diagnostic containing `skipping bad file` and the source
Location `node/src/visor_time_lock.rs:233:36`. It reloads the tag after the opaque
call: bit0 clear appends the payload, bit0 set skips it. Under the preservation
assumption above, errors are skipped. The original entry's owned buffer is
conditionally released on both success and rejection; the candidate replacement
is not assumed to transfer a separately owned allocation.

## Stable in-place compaction and output

Successful values are stored as qwords at the output cursor, which advances by
8 (`0x5961a7b..0x5961a8c`). There is no numeric comparison, insertion, sorting or
deduplication in this accepted-value path. The output is a stable filter of the
provider's input order; duplicate numeric values remain duplicate entries.

After i records have been copied to temporary storage, at most i-1 values have
already been emitted. For the next accepted value with output index k<i,
8*(k+1)<=24*i. Thus the qword write lies entirely in the consumed prefix and
cannot overwrite the next unread 24-byte input record. Entry ownership is
released before the successful store. This proves the local storage geometry,
not complete allocator safety for arbitrary pointers or helper side effects.

`0x5961d6d..0x5961dcc` contains a remaining-entry release loop with stride 24 and
a reciprocal multiply/divide-by-24 count. For the measured caller and ordinary
unmodified iterator fields, normal traversal reaches P=E, so that loop has zero
remaining entries. Exceptional cleanup is separate below.

The return stores at `0x5961dcc..0x5961df6` are:

```
output[0]  = 3*C
output[8]  = B
output[16] = (output_cursor-B)/8
```

Interpreting the returned vector as u64 elements preserves allocation bytes:
24*C == 8*(3*C). The body makes no new allocation request for this output vector;
opaque normalization/diagnostic helpers can still allocate. The B pointer is
retained even when no value was accepted. This differs from a claim that an empty
result necessarily has zero capacity or a canonical dangling pointer.

## Concrete caller: last accepted value, not established maximum

At `0x5a6a030..0x5a6a060`, the caller sends the `.json` pointer/length to opaque
provider `0x15623e0`. It converts that provider's output to the iterator descriptor,
then calls this collector at `0x5a6a0a6`. It reads the resulting capacity/pointer/
length into R13/R12/RBX. On a non-sentinel result with nonzero length,
`0x5a69fef` loads **`[pointer + length*8 - 8]`**. It conditionally releases the
allocation and carries that last value onward at `0x5a6a014`.

For zero accepted length it instead requests `no local time lock files` through
`0x4ece1f0`; the branch rejoins the caller's error handling. The broader caller's
other file read, active-value parser, observer construction, thread handoff,
configuration admission and failure behavior are context, not recovered here.
No sorting guarantee is assigned to the provider. Consequently the selected
value cannot be called the largest timestamp from this evidence: e.g. the stable
input values [9,2,9,1] would leave last=1, while maximum=9. No timestamp units,
expiration policy, clock relation, or actual filesystem state is established.

The name builder at `0x5a69c10` selects exact bytes `visor_time_lock`/length15
when incoming SIL is zero, and `publisher_visor_time_lock`/length25 otherwise.
It binds them to a format program containing `/hyperliquid_data/` and a shared
root object. It also calls a path-check-shaped helper and conditionally passes options
0x1ff/1 to a creation-shaped helper before returning the formatted three-word
object. These role labels are inferred from the arguments and the retained
`could not create directory` diagnostic. These are statically visible
call requests; their contracts and the rendered path are not closed. No live
home directory, user configuration or filesystem is accessed by this research.

## Calls, unwind and scope accounting

The two native decoders agree on every byte and instruction start in all three
retained FDEs: collector1026/244, caller2005/459, directory583/124 (bytes/instructions).
Only the collector and the selected contextual relations above are semantic
claims. The total3614/827 is an export denominator, not reconstructed coverage.
No byte masks or source-built matching windows are introduced.

The limited incoming census finds three direct collector calls: two inside
`0x5a35f50..0x5a39623`, one in the retained caller. It also finds two RIP-relative
calls through the caller's RELATIVE slot `0x64e7420`, and eight direct calls to
the name builder. Those other caller bodies are not recovered. The census scans
E8 and RIP-relative FF15/FF25 encodings, qualifies instruction starts using the
owning FDE, and separately records all RELATIVE entry pointers. It does not prove
absence of arbitrary indirect or computed references or runtime reachability.

The collector's landing-shaped block `0x5961e08..0x5961e32` conditionally releases
the current entry, calls iterator cleanup `0x594f460`, then `_Unwind_Resume`.
Concrete LSDA action selection, personality behavior, transitive cleanup and the
broader caller/name-builder unwinds are not proved. Original function names,
source implementation, compiler settings and whole-node equivalence remain open.
