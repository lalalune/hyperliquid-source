# RE-012: node115 startup end-height maximum and caller admission

Question: which end-height candidate does the startup-associated selector keep,
and how does an actual startup caller consume its value or error?

Target: node115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Source base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
This is bounded RE-012/RE-001 evidence. All component gates remain false. No
integrated startup, replay correctness, source implementation, persistent
schema or current-network compatibility is claimed.

## Complete measured extents

| Role | Half-open ELF VA range | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| end-height selector | `0x595b1a0..0x595b512` | 882 | 212 |
| startup caller | `0x2b41b70..0x2b43283` | 5,907 | 1,206 |

Denominator: **two full FDE-backed extents, 6,789 bytes / 1,418 instructions**.
These are actual unwind-backed extents, not a complete function inventory.
`records.json` retains original file offsets, body digests, FDE/CIE/LSDA records,
all decoded calls/branches and RIP-relative bindings with actual relocation
info/addends. GNU objdump exports cover every body byte and are independently
checked against Capstone5.0.7 decode boundaries. There is no byte normalization,
source-built match, completion percentage or target execution.

The selector's Location LEA binds `node/src/startup.rs:364:19`. The measured
caller contains eight additional Locations in the same file, including the
admission-failure Location `:206:37`. Original Rust function names are unproved.

## Selector: unsigned maximum of the accepted records

The selector prepares a path using an encoded format record at `0x448b77`
containing `/data/`, then calls slot `0x64e0968` with the line364 Location.
When the returned raw stack tag equals1, it returns RAX=1 and an associated
RDX value after cleanup. The precise filesystem helper contract is unclosed.

On the other observed route, call `0x5accff0` produces a vector-shaped set of
16-byte records. Its parsing, input source and complete validity conditions
remain unclosed. The measured selector treats a byte tag of0 as an accepted
candidate; other tags are skipped during selection and undergo the observed
cleanup. Thus no concrete file-name grammar is inferred from this packet.

The first tag0 record seeds R14. The paired scan and odd tail load subsequent
tag0 qwords and compare them against R14 at:

- `0x595b3a4` / CMOVBE `0x595b3a7`;
- `0x595b3b5` / CMOVBE `0x595b3b8`;
- `0x595b3d3` / CMOVBE `0x595b3d6`.

Each comparison selects the new qword when the old value is **unsigned <=**
the new value. This proves a local **u64 maximum**, including values with bit63
set; it is not a signed maximum and not selection by vector position. With an
accepted record present, the measured normal route sets R15d=0 and returns
RAX=0, RDX=selected maximum. If none is accepted, it prepares the diagnostic
`no end heights found` from `0x439f32`, calls `0x5966e00`, sets the raw return
tag to1 and returns its opaque associated value after cleanup.

The end-height interpretation is supported by the diagnostic and actual caller
below. It does not recover serialization, file provenance, validated chain
height, dataset completeness or corruption policy.

## Actual relocation-bound caller

At `0x2b41d3c`, the caller issues `CALL [RIP+...]` through slot **`0x64e7720`**.
Its `R_X86_64_RELATIVE` addend is **`0x595b1a0`**, binding this call to the
selector. This is a real decoded call site, not an inferred adjacency or a raw
byte match. Both caller and callee bodies are retained in full.

The path is entered after the caller's initial input low-bit test has taken
the zero arm and a separate saved input byte R12b equals1. Other input modes
take different routes; this is not the only startup path.

The returned raw tag is compared with **1** at `0x2b41d42`:

- Tag1 falls through to a register-indirect call through the returned object,
  then jumps to common continuation `0x2b41ecf`. Its normal-path behavior
  preserves the prior stored word; complete drop/unwind semantics are unclosed.
- Other tags branch to `0x2b41eb3`, which stores returned RDX at context
  **`+0x30`**, then compares the existing qword at the saved pointer
  (context+`0x38`) against RDX. **Unsigned JB** to `0x2b42d07` occurs if the
  existing word is smaller. Otherwise control reaches `0x2b41ecf`.

The JB destination prepares an encoded diagnostic containing
`invalid starting height=` and `last_applied_height=` from `0x436a4e`, passes
the line206 Location to slot `0x64df6b8`, and reaches UD2 at `0x2b42d46` on
the measured fallthrough. Its formatting arguments bind the first displayed
height to the saved context+`0x38` pointer and the latter to the selected RDX
temporary. This supports the startup-height admission interpretation. It does
not prove a validated resume checkpoint, monotonic state transition, complete
error recovery or all future-state branches of the larger caller.

The remainder of the caller includes async state jump tables, opaque helpers,
cleanup and unwind edges. Their bytes and decoded references are retained,
but they are not treated as fully reconstructed behavior by this packet.

## Reproduction and counterfactuals

Python3.12.3, Capstone5.0.7, GNU objdump2.42; Linux x86-64 analysis host.

```sh
python3 tools/startup_end_height_static.py --output work/startup-end-height
python3 -m unittest discover -s tests -p test_startup_end_height_static.py -v
python3 tools/verify_packets.py
git diff --check
```

The generator verifies full target size/SHA before output creation or native
inspection, then gives GNU objdump a private byte-identical copy. Exported
trailing whitespace is trimmed; addresses, instructions and raw bytes are not
normalized. No captured code, emulator, network, process adapter, chain action,
production key or paid dataset is executed.

Six focused tests pass. Boundary permutations cover u64 values0,1,2^63-1,
2^63 and2^64-1. Actual CMOVBE opcode counterfactuals select the minimum instead
of the maximum. Actual caller tag/store/condition/displacement changes alter
the recovered admission parameters. The real selector-slot displacement and
Location line are independently corrupted. Changing the file placeholder
does not falsely replace the RELA addend, while changing the actual RELA
record is rejected. Wrong, truncated and same-size-modified targets fail
before output creation. Scalar reduction tests exercise a recovered arithmetic
relation, not target-record memory or full selector execution.

Limits: no independent Rust build, differential execution, helper/parser closure,
full async-caller semantics, filesystem read, state-root validation or component
gate credit. Project-wide catalog regeneration and repository gates belong to
integration, separately from the focused evidence checks here.
