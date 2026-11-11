# RE-001: map node #115 binary-search membership 0x5d5ad20 with its lower-bound loop and sole caller

Bounded question: what does node #115 routine 0x5d5ad20 (FDE
0x5d5ad20..0x5d5ae43, 291 bytes) compute over a range of records,
and who calls it?

## Answer

It answers whether a sorted range of 0x20-byte records holds a
record equal to a key record, returning 1 in eax when one is
present and 0 otherwise. The caller tests al. The routine pushes
r15, r14, r13, r12, rbp and rbx, reserves 0x28 bytes of stack,
and performs no canary check.

Range and records. rdi is the begin pointer (first record),
rsi is the end pointer (one past the last record), and rdx is
the key record pointer. Each record contributes only two fields:
a data pointer at +0x00 and a length at +0x08; the bytes at
+0x10..+0x1f are never read here, so their roles are not
claimed. The element count is (end - begin) >> 5, an arithmetic
shift; a count of 0 or less skips the loop and enters the
presence tail.

Search loop (a lower-bound binary search). Each iteration takes
mid = count >> 1 and examines the record at begin + mid * 32.
The comparison is lexicographic: a memcmp (PLT 0x63f0aa0) over
the shorter of the candidate length and the key length, then, on
a tie, the length difference (candidate length - key length),
clamped to the int32 range the code enforces (a difference at or
above 0x80000000 counts as non-negative, below -0x80000000 as
negative). A negative comparison means the candidate is less
than the key, so the search moves to the upper half (cursor
becomes the record after the candidate, count becomes
count - mid - 1); a non-negative comparison means the candidate
is not less than the key, so the search moves to the lower half
(cursor unchanged, count becomes mid). When the count reaches 0,
the cursor is the first record not less than the key, or the end
pointer.

Presence tail. If the cursor equals the end pointer, the answer
is 0. Otherwise the routine compares the key against the
candidate, this time with the key as the first compare operand:
a memcmp over the shorter length, then, on a tie, the length
difference (key length - candidate length), clamped so that a
difference above 0x7fffffff counts as positive and below
-0x80000000 counts as negative. The tail returns 1 exactly when
the key is not less than the candidate (byte compare positive,
or tied with key length >= candidate length). Because the
candidate is already the first record not less than the key,
that combination means equality, so the routine returns 1
exactly when an equal record is present.

Assumption stated plainly: the search is meaningful only on a
range ordered by this same record comparison. The routine does
not check ordering.

Consumers (executable-LOAD-segment exhaustive E8/E9 scan with
objdump confirmation, reproduced by the packet's census.py and
re-run inside verify.py): exactly 2 direct calls + 0 tail jumps,
both in the single caller FDE 0x5d7b620..0x5d7d442. At both
sites rdi comes from stack slot 0xc0(%rsp) and rsi from
0xc8(%rsp), the same range pair. The caller walks its own
0x20-stride table, advancing rbx by 0x20 per iteration: at the
first site it probes the range with the current record
(rdx = rbx); a nonzero result advances the loop, while a 0
result builds a derived record at 0x290(%rsp) through the call
at 0x603db00 (rdi = derived slot, rsi = rbx) and probes again
at the second site with rdx = that derived record. 0 stored
qwords in a full-file 8-byte scan, 0 RELATIVE relocations —
reached only by code, never by data. The derived-record
construction and the caller's branches after the second probe
are not traced here; they are recorded as unknowns.

Relation to neighbouring work: unlike the teardown routines
#2728–#2744, this packet pins a search, not a release or a
construction — the membership test its sole caller uses to
decide, per table record, whether a second probe is needed. It
is a complete behavior (search loop, presence tail, and the
two-site consumer loop), not a lone-window fragment.

## Evidence notes

The packet's JSON holds semantic records only. Detail at the
code level lives in the raw disassembly excerpt text files,
kept verbatim and whole-function: main.txt is the full routine,
and caller_sites.txt holds a verbatim 32-byte window starting
exactly at each call site. The excerpts were produced with
objdump, exactly as recorded in export_excerpts.py, and
verify.py regenerates them byte-for-byte from fresh objdump
runs on the real binary. Mnemonics such as `endbr64` in those
excerpts are genuine instructions present in the target binary,
not placeholders.

The objdump commands used are:

    objdump -d --start-address=0x5d5ad20 --stop-address=0x5d5ae43 work/hl-node-115.bin
    objdump -d --start-address=<site> --stop-address=<site+32> work/hl-node-115.bin
    (one window per call site; see callers.tsv for the site list)

The readelf command used for frames.txt is:

    readelf --debug-dump=frames work/hl-node-115.bin
