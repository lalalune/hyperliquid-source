# RE-001: node #94 report builder 0x5157d30

Task ID: RE-001 (#94 function map). Bounded question: what does
node #94 0x5157d30 do end to end — which map does it clear,
which header entries does it write, and which per-entry
count/bytes/percent entries does it rebuild from the snapshot?

## Bound to

work/hl-node-94.bin SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
matching provenance/artifacts.json for node #94.

## What the window does

The window (0x5157d30..0x5158ebe, FDE 0x00634b10) rebuilds the
render target's keyed report map from a snapshot, in place:

- Clear: call the teardown 0x514bf60 on [target+0x10], then
  reset the header ([target+0x10] = 0, [target+0x18] =
  [target+0x20] = target+0x08, [target+0x28] = 0).
- Header entries, each find-or-insert by key (0x5153a70 returns
  the node's value string at +0x40) followed by an assign:
  "id" gets the snapshot+0x20 identity string (copy-assign);
  "capacity" gets the plain decimal of snapshot+0x00 (itoa
  0x4faf340); "secs_for_last_collection" gets "%f" % (window /
  1,000,000.0), where window is the 0x514df50 accessor (0 when
  [snapshot+0x128] >= [snapshot+0x130] unsigned, else the
  difference); "secs_since_last_collection" gets the decimal
  secs_since, where secs_since = (clock - [snapshot+0x130]) mod
  2**64 divided by 1,000,000 with the 0x431bde82d7b634db magic
  (shift 82 after the 128-bit multiply), and clock is the
  [holder] +0x98 dispatch result.
- Per-entry loop, i = 0..13, three phases per entry: "count." +
  name[i] gets itoa(snapshot+0xb0 + i*8); "bytes." + name[i]
  gets itoa(snapshot+0x40 + i*8); "percent." + name[i] gets
  "%f" % (value * 100.0 / snapshot+0x00), with the
  unsigned-conversion arms for negative int64 inputs and divsd
  semantics on a zero denominator (inf, or nan for 0/0). Each
  phase find-or-inserts its key with the saturating string
  comparison (memcmp over the common prefix, then the length
  difference saturated to int32) and assigns the formatted
  string into the node's +0x40 value string; the SSO-copy vs
  heap-steal arms change allocation only, not contents.
- The itoa writes digits two at a time from the end using the
  "00".."99" pair table copied onto the stack (verified
  byte-for-byte against the binary's .rodata vectors); the
  digit count follows the <= 9 / <= 99 / <= 999 / <= 9999 ladder
  and then 4-digit chunks.
- Canary check, then return (void); the map is the result.

Callees cited only, not re-claimed: the teardown 0x514bf60,
the find-or-insert 0x5153a70, the insert 0x5153650, the itoa
0x4faf340, the double formatter 0x514c050 (format "%f"), the
accessor 0x514df50, and the static-key and per-phase key
helpers. The entry names come from 0x515f8d0(i): 32-byte records
(pointer, length) at the base loaded from GOT slot 0x5777978,
which is zero in the file (resolved at load); the names are
model parameters, not file contents.

Distinct from the 0x514f770 formatter (same snapshot, but it
renders one string with a scaled capacity and a clock chain)
and from the 0x5158ef0 accessor (this window is its render
callee at 0x51590ab).

## Evidence format

The packet's JSON holds semantic records only — header steps,
loop phases, the find-or-insert comparison, caller census and
unknowns. Instruction-level detail lives only in the raw
disassembly excerpt text files, kept verbatim and whole-function.
The excerpts below are unmodified objdump output, regenerated
by export_excerpts.py:

    python3 research/work-items/RE-001-report-builder-94/export_excerpts.py \
        --binary work/hl-node-94.bin

The objdump command is recorded here and in export_excerpts.py:
`objdump -d --start-address=<start> --stop-address=<stop>
work/hl-node-94.bin`, run from the repository root with the
relative binary path. The first bytes of these functions (for
example endbr64 at each function start) are genuine instructions
present in the target binary, not placeholders: they are verified
byte-for-byte against a fresh objdump run by verify.py.

## Verification

    python3 research/work-items/RE-001-report-builder-94/verify.py \
        --binary work/hl-node-94.bin

    python3 -m unittest tests.test_foundation_report_builder -v

The checker verifies the digest, byte-for-byte excerpt
regeneration, the MANIFEST, the semantic-only JSON, the recorded
call/branch sites, the digit-pair table reconstruction, and the
14-entry x 3-phase loop shape. The model tests pin the itoa
against str() on boundaries and 2,000 random 64-bit values, the
magic division against // 1,000,000 on edges and 2,000 random
64-bit values, the accessor clamp, the "%f" ratios (including
inf/nan on a zero denominator), and the ordered map against
bytes ordering.
