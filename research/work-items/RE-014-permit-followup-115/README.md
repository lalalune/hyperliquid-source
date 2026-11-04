# RE-014: empty-list permit follow-up and conditional restoration

Component: transport admission dependency, partial static research. Sole target
Linuxx86-64 node115 SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base8fd8db680ec4bfef40996e5616bce3d5156d0b86. New analysis/docs/tests are MIT;
original captures, imports and licenses remain untouched. Independently authored
from original instructions, with no unlicensed inferred source.

## Gap and selected boundary

Main's RE-001-node115-ip-permit-state explicitly leaves the zero-provider
follow-up5ce5310 unresolved and does not prove that acquiring one unit is undone.
This packet closes one conditional normal path of that actual helper, rather
than assigning semantics to an opaque callback or adding a fake Rust API.
The complete helper5ce5310..5ce56ec is988bytes/234instructions. The existing
caller4770f40..47710d9 supplies409bytes/101instructions as contextual evidence.
Both complete original bodies, FDE/CIE records, file offsets and SHA256 values
are in records.json/instructions.tsv. No visitation denominator is measured.
Addresses are unre-based ELF VAs; layout offsets below are hexadecimal.

## Caller-to-helper relation

After a winning acquire and zero provider result, the caller first writes its
failure output. At4771053 it forms L=owner+10. After its byte-lock operation,
4771063..477106e supplies (RDI=L,RSI=1,RDX=L) to5ce5310. A failed caller lock
operation takes a separate opaque slow path; that path is outside this result.
The constructor/acquire encoding is retained in the existing main packet:
capacity n<2^61 initializes2*n at owner+30 and a winning acquire subtracts2.
The new analyzer additionally checks those original parameter operands.

For this selected helper path, assume the incoming lock pointer is already
held (byte[L]=1), the list field [L+10] is null, input memory is valid and
nonaliasing, and there are no interfering writes through the return. The
null-field condition is the exact machine predicate; calling it an empty
waiter list is an inference from the surrounding link/callback accesses.

The nonzero third argument bypasses helper lock acquisition. Its initial local
callback count is0. The null-field branch at5ce53ca bypasses list draining and
all callback dispatch. At5ce54ad the requested count is checked against2^61.
With count1,5ce54c0 doubles it and the LOCK XADD at5ce54c4 adds2 to[L+20].
Because L=owner+10, this is the SAME owner+30 state word used by acquire.
XADD returns the old word; the following SHR1/ADD1/CMP checks its logical count
against2^61 AFTER the memory addition. A winning byte CMPXCHG1->0 at5ce54e9
releases L; zero pending callbacks and zero remaining count then reach RET
without calling a wake/destructor/slow-path helper. The original instructions
retain every other path, but those paths are unclosed here.

## Exact conditional arithmetic

For every1<=n<=2^61-1, suppose the state is stillw=2*n-2 when XADD occurs.
Then0<=w<=2^62-4; adding2 cannot wrap a u64; low bit0 is preserved;
(oldw>>1)+1=n<2^61, so both count guards admit the selected return.
The final state is2*n, exactly the pre-acquire state, and the held byte is0.
This is a conditional restoration theorem. It does NOT establish that the
opaque provider leaves state/list unchanged or that concurrent callers cannot
interfere. It does not claim unconditional failure rollback or fairness.

For arbitrary old words, the instruction still writes before the post-check.
For example oldw=2^62-2 becomes2^62 and fails the post-check; its cold behavior
is unclosed. The addition preserves the low bit even when the input word is
odd, but odd-word reachability on this selected caller route is unproved.
`empty_relation` is explicitly synthetic arithmetic derived from checked
operands. Its tests are not captured execution or differential evidence.

## Reproduce and remaining gaps

From repository root with Python3.12.14/Capstone5.0.6 and a new output directory:

```sh
python3 research/work-items/RE-014-permit-followup-115/analyze.py --out work/permit-review
python3 -m unittest discover -s tests -p test_node115_permit_followup_static.py -v
```

The analyzer invokes no external programs or target interpreter and substitutes
no calls. Native behavioral comparisons are explicitly0. Original instruction,
call, FDE and digest corruption controls validate the static record; synthetic
algebra checks cover extrema and bit boundaries without being called an
exhaustive native test. Exact actual checks are in validation.txt.

Non-null lists, contention, callback/vtable effects, provider behavior, cold
paths, memory-model/concurrency guarantees, cleanup/unwind and original Rust
object/owner ABI remain open. The caller's later reference decrement can have
its own cleanup effect; this packet's theorem stops at helper return. No Rust
implementation, whole-helper equivalence or full component gate is requested.
Next: close one nonempty-list wakeup path and the actual provider's effects
before extending this result to an unconditional admission/refund policy.
