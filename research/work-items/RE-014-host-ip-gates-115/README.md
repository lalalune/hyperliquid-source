# RE-014: node115 IPv4 prefix parser and host-IP admission

Component: foundation (`base/src/u.rs`, source-location line457,column21).
Target: Linux x86-64 node115,
SHA256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
New independently authored code/evidence is MIT; original capture retains its
own rights. Historical project-MIT caller gate policy is disclosed in
FREEZE-NOTE.md. No unlicensed inferred source was consulted or copied.

## Question and before/after

The current115 tree lacks this host-IP parser/caller component. Resolve the
full leaf at VA0x167ccb0..0x167d082 (978bytes/278instructions) and the
admission boundary inside caller0x1562670..0x1563a5c (5100bytes/928instructions).
The new Rust component implements only established parser/cursor behavior
and selected caller gates. It does not implement IP discovery services.
All original addresses are ELF virtual addresses; owner metadata and exports
bind file coordinates, complete FDE extents and raw bytes. GNU and Capstone
are checked instruction-for-instruction, not merely counted.

## Observations

The leaf parses four decimal octets separated by periods. Out-of-range
values and multi-digit leading zeroes fail. Failure restores the original
cursor. Success publishes the four octets and independently updates cursor
pointer and remaining length; trailing non-digit bytes can remain.
The caller rejects lengths above15 before calling. The actual call instruction
0x1562c17 targets the leaf; its real return continues at0x1562c1c.
Remaining must equalzero and the return AL low bit must be set to reach the
collection handoff0x1562c2d; rejection stops at0x1562d31. These are handoff
boundaries, not whole-function returns. Raw AL values beyond0/1 are tested
separately as boundary states, not asserted reachable from this parser.

A separate post-reader gate at0x15627e8..0x1562800 compares the complete
raw override word with0x8000000000000000. Equality enters probing;
other words take0x1562903. No high-level original Result/String type,
empty-payload handling or final fallback outcome is inferred from that word.

RIP and ELF RELATIVE records bind commandlike data, three endpoint strings,
source location and three unclosed helper slots in audit.json. The command
literal and service names are evidence only: no command, resolver, socket,
HTTP request or captured process executes. The broader caller contains other
unclosed helpers and branches; only the selected path and pure leaf are modeled.

## Comparator and layout

`native.py` retains5,397 raw pre/post/override boundary rows. `parser.py`
interprets the complete leaf and authentic caller CALL/RET over synthetic
byte buffers, bounded descriptor/stack memory, and initially unknown GPRs.
No Python/Rust grammar supplies the native expected results. Synthetic addresses
and process memory are separate from original ELF coordinates. The decoder
is the existing maintained tools/decimal_scaled_u64.py; packet-private ELF
view has no external task lookup. Bounds reject unexpected reads, writes,
calls and CFG exits. Callee-saved unknown bytes are spilled/reloaded without
turning them into initialized data.

Leaf output normalization: AL0/1; on success bits8..39 of RAX as little-endian
IPv4; ignored unspecified payload on failure. Cursor pointer is normalized
to byte-buffer offset and remaining length is read separately. Caller B is
pre-parser length bypass, otherwise A/R plus the same parser observation.
This is semantic projection, not ABI, instruction-byte or whole-node equality.
Native corruptions change actual bytes in a private COW mmap only. Originals,
raw failed logs and every imported pin remain unchanged.

## Reproduce and acceptance

Run from repository root using Python3.12.14/Capstone5.0.6, GNU objdump and
owned rustc1.94.1 (LLVM21.1.8, macOSarm64). This is a pinned research compiler,
not a claimed original build recipe. Exact commands/results and denominators
are in validation.txt, audit.json and rust-results.json. Freeze producers
intentionally refuse an existing Rust component, including under python-O;
normal replay uses the native verifier/build script. No Cargo workspace is
invented. No helper stub stands in for the IPv4 parser.

All component acceptance gates remain false. Whole caller, service behavior,
original source/compiler identity and integrated node equivalence remain open.
Next question: close the override reader result layout and its cleanup path
with equally bounded target evidence before assigning an original Rust type.
