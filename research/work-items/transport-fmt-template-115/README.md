# transport: reconstruct node #115 compact format-template interpreter 0x1680500 and the peer-error Display body 0x564ad60

With this packet the node's compact message-template language (the byte code that every `format`-style error and log message in node #115 is written in) can be rebuilt as a plain function: `0x1680500` is an interpreter with six template forms, an argument table with width/precision indirection and a "first failing sink write aborts" rule, and `0x564ad60` is the 22-arm `Display` of the peer / client-block error enum that feeds it (Peer full, Timed out connecting to peer, Rate limited by peer, ...). The interpreter and the Display body are re-executed from ELF bytes (stdlib decoder + the repository's integer `Machine`), not described, and an independent Python model agrees with them on 13,391 byte-derived cases; 57 deliberately wrong models, corrupted instruction bytes and out-of-range inputs are all rejected.

- Component ID: **transport** (error handling of the network layer; TCP framing, LZ4, channels, rate limits and reconnects)
- Target release and full SHA-256: Linux x86-64 node #115, 105,896,032 bytes, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: `0781ce04826eeefd89fe336cb8ea073be0c1de30` (research base); no reference source was copied
- Claim status: observation (bytes, extents, call sites, templates), inference (names of the Rust-level pieces), unresolved (listed below)
- Scope: included `0x1680500..0x16806c0` (interpreter), `0x564ad60..0x564b1f9` (Display), the six argument printers it calls, and a census of all 1,143 calls through the interpreter slot. Excluded: the two hash/digest printers `0x53d55c0` and `0x57d1030`, the pad/str targets behind the slots, every other `Display` body.

## Reproduce

```sh
python3 tools/transport_fmt_template_115.py --out research/work-items/transport-fmt-template-115
python3 -m unittest tests.test_transport_fmt_template_115
```

The tool reads only the ELF bytes (SHA-256 checked first, stdlib `struct`, `tools/fde_extents.py` for function extents, `tools/evm_amount_scale.py` for the `Image` reader and the integer `Machine`). It does not call binutils and does not execute the binary; the "execution" is a Python interpretation of the decoded instruction bytes with every external call replaced by a recording stub. One regeneration takes about 25 s and well under 1 GB; output is byte-identical across runs. `MANIFEST.sha256` lists every file.

## Evidence

All addresses are linked ELF virtual addresses; the first PT_LOAD maps file offset = VA for `.rodata`.

| Item | Value |
| --- | --- |
| Interpreter FDE | `0x1680500..0x16806c0`, 138 instructions, bytes SHA-256 in `records.json` |
| Slot | RELATIVE slot `0x64df6f0` has addend `0x1680500`; 1,143 `call *slot(%rip)` sites in 626 FDEs (`call-sites.tsv`) |
| Display FDE | `0x564ad60..0x564b1f9`, 261 instructions; dispatch `sub $0x2e,%al; cmovae` into the 22-entry relative jump table at `0x92882c` |
| Template census | 1,115 sites load a static template with `lea disp(%rip),%rdx`; they name 337 distinct, well-formed templates (`templates.tsv`) |

What the bytes say about the template language (instruction-level, and checked by emulation of the real bytes):

1. `rcx & 1` set: `rcx >> 1` is a length and `rdx` a plain string; the body tail-jumps to the sink's `write_str` (vtable `+0x18`). Otherwise `rcx` is a table of 16-byte `{value, fn}` argument records.
2. The template is walked until a `0` byte. `1..0x7f` is a literal of that length; `0x80` is a literal with a little-endian `u16` length; `0xc0` is "next argument with default flags `0x60000020`, width 0, precision 0".
3. Every other byte `>= 0x81` is a spec byte: bit0 a `u32` flags field replaces the default, bit1 a `u16` width, bit2 a `u16` precision, bit3 a `u16` explicit argument index (read in that order); bit4 / bit5 replace width / precision by the `u16` stored at `+8` of the argument record that the width / precision number names. The argument counter becomes `index + 1` afterwards.
4. A formatter record `{out, writer, flags:u32, width:u16, precision:u16}` is built on the stack and `record.fn(record.value, &record)` is called. The first non-zero result (literal write or argument call) returns 1 immediately; reaching the terminator returns 0.
5. The 337 real templates use only five piece kinds: literal (516 pieces), default argument (389), `0xc1` flags only (13), `0xc3` flags + width (36) and `0xd3` flags + width taken from an argument (14).

The Display body (`display-arms.tsv`, tags `0x00..0x43`): tags below `0x2e` borrow in `sub $0x2e,%al`, take index 3 and print `Consensus error: {0}` of the whole value; tag `0x2e + i` selects arm `i`. Ten arms write a fixed string through the sink (for example arm 6 `Timed out connecting to peer`, arm 7 `Rate limited by peer`), twelve arms build a template plus one or two argument records (`Gossip error: {0}`, `Could not query client block range {0}-{1}`, `Invalid config file ({0}): {1}`). Arguments are `&&field` pairs at self offsets `0`, `1`, `8`, `0x10`, `0x20`, `0x21` using six printers. Tags above `0x43` index past the jump table; they are not modelled.

The printers: `0x4f0df50` loads `ptr/len` at `+8/+0x10` of a `String` and tail-jumps to the str writer (slot `0x64df720`); `0x5a2ee40` dereferences once and tail-jumps (slot `0x64ebf90`); `0x53d57b0` builds a one-argument table and re-enters the interpreter with the lone-default template `0x43b857`; `0x5616370` is an unsigned 64-bit decimal formatter (two-digit table `0x46ea12`, 20-byte buffer, `pad_integral(true, "", digits)` via slot `0x64dfa00`).

## Implementation and comparison

`tools/transport_fmt_template_115.py` contains: a stdlib x86-64 decoder for the instruction subset these bodies use (partition ends exactly at each FDE end), the Machine subclass for `movslq`, `movd`, `pinsrw`, an independent model `model_format` of the interpreter, a model of the Display dispatch (`ARMS`, `arm_for_tag`), models of the four printers, and the census, case, control and evidence code.

Comparison suites (every case runs the real bytes and the model and compares status, ordered sink writes and the formatter records handed to argument printers):

| Suite | Cases |
| --- | ---: |
| Random templates (all spec-byte combinations, long literals up to 600 bytes, count-referenced width/precision, failing sink at write 1..6) | 8,000 |
| All 337 census templates x 5 failure points | 1,685 |
| Display tags `0x00..0x43` x 5 failure points | 340 |
| `u64` decimal boundaries and random values, String/ref forwarding, wrapper re-entry | 3,366 |
| **Total** (`measure.json`) | **13,391** |

Negative controls (57, all detected, 0 equivalent): 11 wrong interpreter models (big-endian long length, literal off by one, wrong default flags, counter skip, ignored count references, swapped width/precision order, ...), 3 wrong Display models, 29 single-byte corruptions of the interpreter / Display bodies (compare immediates, flag masks, shift counts, jump polarity, vtable slot, plain-string lengths, field offsets), 9 corruptions of the printers (including the `1000` threshold of the `u64` formatter, found only by boundary values), 3 tags beyond the jump table, 2 target-identity corruptions.

## Results and limitations

- Observation: the interpreter, its slot, the 22-arm Display body, six printers and the 337 static templates reproduce byte-for-byte under emulation of the original instructions.
- Inference: the names "template interpreter", "peer error Display" and "`u64` Display" are mine; `0x4f0df50` is a `String`-field printer by its `{cap,ptr,len}` access. Which Rust type owns the tag byte (enum layout with a niche at tag `0x2e`) is inferred from the dispatch only.
- Not covered: the digest printers `0x53d55c0` / `0x57d1030`, the str / pad targets behind the slots, tags above `0x43`, callers that build templates at run time (28 of the 1,143 sites have no static `lea` template in reach), and any wire-level LZ4 or TCP framing. No component gate is requested.
- Emulation covers the integer subset; an instruction outside it raises instead of guessing.

## Next question

Resolve `0x53d55c0` and `0x57d1030` (the hash / digest printers used by two Display arms) and the str / pad targets so that the whole rendered message, not only the call into them, is reproduced.
