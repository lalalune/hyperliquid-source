# RE-005 node 115: who first writes the dispatcher derivation inputs

## Question

The limit-writers packet (`RE-005-node115-limit-writers`) pinned the four
top dispatchers — bulk a `0x2b67e50`, twin a `0x2b69d20`, bulk b
`0x5a64aa0`, twin b `0x5a6a640` — deriving their own limit fields from a
selector byte (bulk, byte-selected 1000 / 4,000,000,000), from sibling
slots and a source object (twin), and from an incoming limit value. It
left two questions open:

1. Who **first** sets those derivation inputs — the bulk selector bytes
   (`[rbx+0x1e8]` / `[r13+0xc08]`), the twin sibling slots (`+0x178` /
   `+0xa58`), the twin source-object fields (tag, start, end), and the
   incoming limit value on a downstream stage entry?
2. Who writes the twin-a stage result's `+0x28` field (the unanswered
   half of the state-construction packet's question)?

## Method

Static trace only, against the authenticated node 115 binary (SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).
Nine functions are pinned by exact FDE extent, body SHA-256 and
per-instruction byte pins: the dispatchers' direct callers (bulk a
`0x2ad7140..0x2adce3a` and `0x2cc1120..0x2cc971b`, twin a
`0x2ae0100..0x2ae0917` and `0x2cb1eb0..0x2cb2563`, the shared b-side
caller `0x5a82670..0x5a89535`), the two stack-image builders
(`0x2b14520..0x2b14696`, `0x2b146a0..0x2b14816`), the twin-a reader-state
constructor `0x26ff210..0x26ff830` and its stage function
`0x2e466b0..0x2e469a9`. The six small bodies retain full objdump exports;
the three large caller bodies are retained as hash plus pins. An access
census over fresh objdump text and a binary-wide E8 caller census are
re-derived on every run of `tools/input_writers_static.py`. No captured
code was executed.

## Findings — question 1

Every a-side caller hands its dispatcher an object it has just built on
its own stack. The object's tail, from `+0x70` on, is a verbatim copy of
a descriptor block inside the caller's context struct (bulk block
`0x4e0` bytes, twin block `0x428` bytes; the second caller of each pair
builds the image through a dedicated builder, `0x2b14520` / `0x2b146a0`,
each with exactly that one call site), so object offsets map to block
offsets shifted by `0x70`:

| dispatcher input | bulk a caller 1 | bulk a caller 2 | twin a (both callers) |
| --- | --- | --- | --- |
| selector byte | struct `+0x210` | struct `+0x2c8` | — |
| source pointer | — | — | struct `+0x50` |
| sibling slot | — | — | struct `+0x150` |
| incoming limit | struct `+0x248` | struct `+0x300` | struct `+0x158` |

- **Twin source object — answered inside the callers.** On the first
  entry arm, both twin-a callers store `struct +0x20` into the block's
  pointer slot (struct `+0x50`) and copy the struct's own head triple
  into `+0x20` (tag), `+0x28` (start) and `+0x30` (end). The source
  tag/start/end on that arm are therefore the caller struct's first
  three qwords. On the other entry arm the pointer keeps its incoming
  block value.
- **Selector byte, sibling slots, incoming limits — not written by the
  callers.** The census finds no store to, and no read of, the mapped
  offsets anywhere in either caller body of each a-side dispatcher,
  including the duplicate-block aliases; the builders only copy the
  block verbatim. On the b side the shared caller initialises only the
  head fields of each embedded object, and a census over every base
  register finds no access at all to the input offsets (`+0xc08`,
  `+0xc40`, `+0x958`, `+0xa58`, `+0xa60`) or to their arena-mapped
  offsets. All of these inputs arrive as the incoming contents of the
  descriptor blocks / the shared arena.

So the first writer of the bulk selector bytes, the twin sibling slots
and the incoming limits sits **above the traced window**: in whoever
fills the a-side caller context structs' descriptor blocks and the
b-side shared arena.

## Findings — question 2

The writer is the twin-a stage function `0x2e466b0` itself. It has
exactly one store to the result's `+0x28`, at `0x2e46968`, inside the
shared result store block at `0x2e46949`:

- On the nested-decode arm (first decoder result discriminant 2, state
  cursor marker byte 1, nested decoder `0x2ce1730` result tag not 2) the
  stored qword is the nested result's own `+0x28` field, loaded at
  `0x2e467a8` and forwarded verbatim.
- On the marker-byte-zero arm the same store executes (result tag forced
  to 2 at `0x2e46943`) with the stored register never loaded anywhere in
  the stage body, so the value is not determined inside the stage.
- Every other arm — first-result copy, discriminant 0, discriminant 1
  through the twin wrapper `0x2dd2980`, and the error arms through the
  store block at `0x2e4697b` — never stores `+0x28`.

Downstream, the constructor `0x26ff210` reloads its limit register from
the result `+0x28` slot at `0x26ff330`, `0x26ff3fd` and `0x26ff66c` —
the third reload is new here; the state-construction packet named only
the first two — and stores it to the saved/final record `+0x28` slots.

## Boundaries and next question

The census covers direct accesses in the nine pinned bodies; whole-block
copies move the input bytes without naming them, so for the copied
fields the negative result is a statement about direct accesses in the
traced bodies, not about the copies. Next questions: who fills the
caller context structs' descriptor blocks (block offsets: bulk selector
`+0x178`, bulk incoming limit `+0x1b0`, twin source pointer `+0x8`, twin
sibling `+0x108`, twin incoming limit `+0x110`) and the b-side arena
fields — and what writes the nested decoder `0x2ce1730` result's `+0x28`
field that the twin-a stage forwards?

## Files

- `records.json` — machine-readable owners, pins, censuses and findings
  (regenerated by `tools/input_writers_static.py --generate`).
- `frames.txt` — `readelf -wf` FDE lines for the nine pinned functions.
- `*.objdump.txt` — full disassembly exports of the six small bodies.
- `MANIFEST.sha256` — hashes of the retained files.
- Tests: `tests/test_input_writers_static.py`.
