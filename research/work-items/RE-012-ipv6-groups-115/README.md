# RE-012: node115 IPv6 group reader and actual helper composition

Component: transport, bounded address-input conversion. Target Linuxx86-64
node115 SHA256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base8fd8db680ec4bfef40996e5616bce3d5156d0b86. Coordinates are ELF VAs before
load bias; full FDE/CIE records and GNU/Capstone exports bind raw bytes.
New code/evidence is MIT; original captures retain upstream rights.

## Question and observations

Recover group reader1686080..168625d, called at167d0c1 and167d152 by the
static wrapper167d090..167d1e5. It reads colon-separated1..4hex-digit groups,
with capacity0..8 following those caller bounds, and can terminate with a
dotted IPv4 suffix when at least two words remain. It publishes word count,
DLbit0(IPv4-tail indication), independently updated cursor pointer/remaining,
and the written host-order u16 groups. IPv4 octets are paired big-endian.
A failed next group restores the cursor to before its separator while keeping
earlier output groups; initial failure consumes nothing. Five hex digits are
rejected as one group rather than accepted as a four-digit prefix.

The full reader calls the actual numeric helper167c8b0..167cb14 and actual
IPv4 leaf167ccb0..167d082. Both real CALLs/RETs run in the offline instruction
model; no helper-result stubs, captured processes or network services run.
The numeric helper's other configurations are context, not closed semantics.
The original crate/source identity and valid Rust-language input restrictions
remain unproved. Arbitrary byte strings are raw machine-boundary inputs.

## Layout, memory effects and normalization

Synthetic RDI points to a16-byte pointer/length descriptor, RSI to eight u16
output slots, and RDX to the caller-bounded capacity. All other registers and
flags start unknown; callee-saved partly known stack bytes remain so. Reads,
reloads, stores and spills enforce separate input/descriptor/output/stack
bounds. Calls are limited to the four original reader-to-helper edges, and
CFG exits/unknown instructions fail. Only ROL16 is added locally for the actual
IPv4-word byte swap, with a preserved before-blocker/after-repair record.

All eight output words are independently observed, including slots beyond the
returned count, under both zero and5a00+index initialization. This catches
unintended clearing/writes that a zero-only output buffer would hide. Pointer
offset and remaining length are read independently. Only DLbit0 is compared,
because that is the actual wrapper's TEST; other return-register bits are not
asserted ABI payload. Only final descriptor/output snapshots are compared; intermediate cursor-write
traces and ordering are not. No aliasing/concurrency/whole-node equality is claimed.

## Evidence and checks

FREEZE.json supplies exact denominators and visited/unvisited context rows.
Native-control records change actual bytes in private COW mappings, including
both colon paths, numeric configurations and IPv4-word ordering. One control
changes the actual IPv4 callee's leading-zero behavior to demonstrate that the
composed result depends on the real callee. Original captures remain unchanged.

The wrapper and import/panic paths are explicit static boundaries; no ::
expansion, full-address acceptance or imported memcpy implementation is
claimed. The core's actual two caller contracts are context, not additional
recovered whole functions. Nothing advances a full-component gate.

Normal replay/build commands, source/input/output hashes, tool versions,
observed tests and limitations are recorded in validation.txt and build
reports. The freeze producer intentionally refuses an existing Rust component,
also under python-O. Use a new output directory for replay/build; all raw
streams and original failures remain in ignored work. Owned research compiler
rustc1.94.1(macOSarm64/LLVM21.1.8) is not an original node build recipe.

Next: establish complete address acceptance and wrapper
copy/import contracts before claiming the complete IPv6 parser.
