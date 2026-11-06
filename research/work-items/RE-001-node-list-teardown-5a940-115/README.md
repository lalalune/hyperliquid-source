# RE-001: map node #115 node-list teardown 0x5d5a940 with its plain 0x38-byte nodes, buffer clear and two callers

Bounded question: what does node #115 routine 0x5d5a940 (FDE
0x5d5a940..0x5d5a9c7, 135 bytes) do to the holder in rdi, end to
end, and who calls it?

## Answer

It destroys a holder's plain linked list, then clears and frees
the holder's buffer. The holder itself is never freed. The
routine pushes rbp/rbx, reserves 8 stack bytes, and performs no
canary check.

List phase. The list head lives at holder+0x10; a null head
skips the loop outright and the buffer phase still runs. Each
0x38-byte node carries no disposed payload: the next pointer at
node+0x00 is loaded before any free, then the node is freed
with a sized delete of exactly 0x38 through the _ZdlPvm PLT at
0x63f0d80, and the loop follows the loaded next pointer until
null. Node fields other than +0x00 are never read, so no
payload role is claimed for them.

Buffer phase (always runs, even for an empty list). The buffer
span is (begin at holder+0x00, count at holder+0x08): memset
(begin, 0, count * 8) runs through the memset PLT at 0x63f0a90,
holder+0x10 and holder+0x18 are zeroed, and then, unless begin
equals holder+0x30, the buffer span is freed with a sized delete
of (begin, count * 8) through the _ZdlPvm PLT, tail-jumped. A
begin equal to holder+0x30 returns plainly with no buffer free.
The count field at holder+0x08 is not cleared and the begin
field is not cleared; only the two zeroed fields and the
conditional free are pinned.

Consumers (executable-LOAD-segment exhaustive E8/E9 scan with
objdump confirmation, reproduced by the packet's census.py and
re-run inside verify.py): exactly 2 direct calls + 0 tail jumps,
both inside the single caller function 0x5d789ce..0x5d78b40 —
0x5d78a48 with rdi from mov -0x3e0(%rbp), and 0x5d78b36 with
rdi from lea -0x260(%rbp); both sites converge on 0x5d78a4d
after the call. That same caller function also calls the nested
teardown 0x5d58f10 (#2729) and the buffer-inner teardown
0x5d58ed0 (#2733) just before the first site, so this routine
is one member teardown inside a larger holder cleanup, not a
standalone fragment. 0 stored qwords in a full-file 8-byte scan,
0 RELATIVE relocations — reached only by code, never by data.

Relation to neighbouring work: this routine shares the buffer
tail (memset, zeroing of +0x10/+0x18, the +0x30 begin
comparison) with the plain list teardown 0x5d596f0 (#2728) and
the string-list teardown 0x5d5a720 (#2740), but the list phase
pinned here is different: 0x38-byte plain nodes, versus 0x18-byte
plain nodes in #2728 and 0x68-byte two-string nodes in #2740,
with a different caller. The 0x38 node size and these two call
sites are pinned here only; this is not a restatement of either
neighbour.

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

    objdump -d --start-address=0x5d5a940 --stop-address=0x5d5a9c7 work/hl-node-115.bin
    objdump -d --start-address=<call site> --stop-address=<call site + 32> work/hl-node-115.bin

and frames.txt holds the routine FDE plus the caller FDE from
`readelf --debug-dump=frames work/hl-node-115.bin`.

## Unknowns

- Source-level types of the holder and the list nodes; only
  sizes, strides and offsets are pinned.
- The source meaning of holder+0x18 (zeroed in the buffer
  phase) and of the holder+0x30 begin comparison beyond the
  observed inline-storage-shaped test; only the comparison and
  the exact free size are pinned.
- What the caller function does with the holder before or after
  the call, and what the list nodes represent.
- Node fields outside +0x00 are never read by this routine;
  their roles are not claimed.
- The null-begin buffer-phase case: the code memsets and
  conditionally frees through a null begin pointer when count
  is zero; behavior for a null begin with a nonzero count is
  not pinned and is not modelled.
