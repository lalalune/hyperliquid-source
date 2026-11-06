# RE-001: map node #115 rvalue string concatenation 0x5d5ab60 with its capacity-chosen append/insert paths and fifteen callers

Bounded question: what does node #115 routine 0x5d5ab60 (FDE
0x5d5ab60..0x5d5ad13, 435 bytes) compute from its two string
operands, how does it choose between its two paths, and who calls
it?

## Answer

It concatenates two strings, returning lhs bytes followed by rhs
bytes in the hidden return slot (rdi), and returns that slot in
rax. The operands are libstdc++ basic_string objects: data pointer
at +0x00, size at +0x08, SSO buffer or heap capacity at +0x10,
with SSO capacity 15. The routine pushes rbx only, reserves no
stack, and performs no canary check.

Path choice (total = lhs size + rhs size). The insert path is
taken exactly when total > capacity(lhs) AND total <=
capacity(rhs); every other case takes the append path. Capacity
is 15 for an SSO operand, else the value at +0x10. Concretely:
an SSO lhs with total <= 15 appends; an SSO lhs with total > 15
inserts only when the rhs is heap with capacity >= total, and
appends when the rhs is SSO (capacity 15 < total); a heap lhs
with capacity >= total appends, and with capacity < total
inserts exactly when rhs capacity >= total.

Append path. The length guard throws `__throw_length_error`
with the message string "basic_string::append" (at 0x4474d2)
when rhs size > 0x3fffffffffffffff - lhs size. Otherwise it
calls `_M_append` (PLT 0x63f0f40) with lhs as `this` and
(rhs data, rhs size), then steals lhs into the return slot: for
a heap lhs the return takes lhs's pointer, size and capacity and
lhs is reset to an empty SSO string (pointer = lhs + 0x10,
size 0, byte 0); for an SSO lhs the bytes plus the terminating
NUL are copied into the return SSO buffer (copy routine at
0x5d5ac58: qword loop with 4-byte, 2-byte and 1-byte tails) and
lhs keeps its appended bytes, since no heap ownership moves.

Insert path. It calls `_M_replace` (PLT 0x63f0d90) on rhs with
(position 0, count 0, lhs data, lhs size) — inserting the whole
lhs at the front of rhs — then move-constructs the return slot
from that result (PLT 0x63f0eb0). The rhs is left moved-from;
its fields are not pinned. This path performs no length check
of its own; that handling lives inside `_M_replace` and is not
pinned here.

In every path the result is SSO exactly when total <= 15, heap
otherwise.

Overload reading. The two-path shape — mutating lhs on one path
and rhs on the other, selected on the capacity condition — is
the libstdc++ `operator+` for two string rvalues
(basic_string&&, basic_string&&). The append-only and
insert-only overloads each have a single path, so the two-path
shape matches only the two-rvalue overload. That name is
inferred from the observed structure, not from a symbol in the
binary: the routine is local text and objdump labels it only by
a nearby symbol offset.

Consumers (executable-LOAD-segment exhaustive E8/E9 scan with
objdump confirmation, reproduced by the packet's census.py and
re-run inside verify.py): exactly 15 direct calls + 0 tail
jumps across 4 caller FDEs (0x5d7b620..0x5d7d442 with 4 sites,
0x60d2820..0x60d49d3 with 6 sites, 0x6117ed0..0x6119dad with 3
sites, 0x611fb10..0x61213db with 2 sites). At each site rdi is
a return slot (lea or stack-held pointer), rsi is the lhs temp
and rdx is the rhs pointer (register or stack-held); at 12 of
the 15 sites a move-construct call immediately precedes the
argument setup, building the lhs temp. 0 stored qwords in a
full-file 8-byte scan, 0 RELATIVE relocations — reached only
by code, never by data.

Relation to neighbouring work: unlike the teardown routines
#2728–#2743, this packet pins a construction, not a release —
the string-concatenation helper its callers use to build
messages. It is a complete behavior (both paths, the steal,
the throw, and the full consumer census), not a lone-window
fragment.

## Evidence notes

The packet's JSON holds semantic records only. Instruction-level
detail lives in the raw disassembly excerpt text files, kept
verbatim and whole-function: main.txt is the full routine, and
caller_sites.txt holds a verbatim 32-byte window starting
exactly at each call site. The excerpts were produced with
objdump, exactly as recorded in export_excerpts.py, and
verify.py regenerates them byte-for-byte from fresh objdump
runs on the real binary. Mnemonics such as `endbr64` in those
excerpts are genuine instructions present in the target binary,
not placeholders.

The objdump commands used are:

    objdump -d --start-address=0x5d5ab60 --stop-address=0x5d5ad13 work/hl-node-115.bin
    objdump -d --start-address=<site> --stop-address=<site+32> work/hl-node-115.bin
    (one window per call site; see callers.tsv for the site list)

The readelf command used for frames.txt is:

    readelf --debug-dump=frames work/hl-node-115.bin
