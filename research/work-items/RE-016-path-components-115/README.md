# RE-016: reconstruct node #115 path-component trio 0x5c8e790 / 0x5c8e8c0 / 0x5cab560 and prove it against the machine code

With this packet the Unix path iterator that the state/database path code walks can be rebuilt as three exact pure functions (`parse_back`, `as_path`, `next_back` in `tools/re16_path_components115.py`): which pieces of a path are skipped (empty, `.`), which become ParentDir/Normal/RootDir/CurDir, how many bytes each step consumes, and which bytes of the 0x3b-byte iterator state (`front` +0x38, `back` +0x39, `has_physical_root` +0x3a) change. All 18,240 generated cases agree with the real instruction bytes, including the post-call state and every reachable panic site.

- Component ID: abci (RE-016 state materializer call chain; the iterator is a std-library helper below it)
- Target release and full SHA-256: node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository main at run time; no reference source copied. The Rust-std shape (`Components`, `as_path`, `next_back`, `parse_next_component_back`) is an inference from the code, not proven by a string.
- Claim status: observation (byte-level behaviour, panic sites) / inference (function and field names)
- Scope included and excluded: only the three functions above plus the two panic slots they call (`.got` 0x64df570 bounds/overflow panic, 0x64df730 unreachable panic, stubbed as stop points). Excluded: the forward `next`, `Path::components` constructor, Windows prefix handling (the area at +0x10..0x38 is never read; cases fill it with random bytes to show that), callers. No component gate is requested.

## Reproduce

```
python3 tools/artifacts.py verify
python3 tools/re16_path_components115.py --out research/work-items/RE-016-path-components-115
python3 -m unittest tests.test_re16_path_components115
sha256sum -c research/work-items/RE-016-path-components-115/MANIFEST.sha256
```

Only the Python standard library and the repository tools `elf_index.py`, `fde_extents.py` (through `re16_state_materialize115.py`, which supplies the concrete x86-64 evaluator and ELF image) are used. The binary is read, never executed. Regeneration takes about one minute and well under 1 GB.

## Evidence

All addresses are virtual addresses in `hl-node` #115 (`.text` file-backed bytes read with `struct`).

- `0x5c8e790` parse_next_component_back(out = rdi, comps = rsi): start = `len_before_body` (1 when `front <= 1` and `has_physical_root`, else 1 when `front <= 1` and the path begins with `.` followed by end or `/`, else 0; a start past the path end panics with slice-start-index arguments (1, 0, 0)); the last `/` after start splits the piece; the 0x20-byte record is (consumed = piece length + 1 if a separator was found, kind, piece pointer, piece length), kind `0xa` for empty or `.`, 8 for `..`, 9 otherwise.
- `0x5c8e8c0` as_path(comps = rdi) -> (rax pointer, rdx length): copies the 0x40-byte state, `front == 2` trims leading empty/`.` pieces, `back == 2` repeatedly calls 0x5c8e790 while the remaining length exceeds the start floor and the kind is `0xa`; the original state is untouched.
- `0x5cab560` next_back(out = rdi, comps = rsi): returns a record whose first byte is 6 RootDir, 7 CurDir, 8 ParentDir, 9 Normal, 0xa None. Finished when `front == 3`, `back == 3` or `front > back`. In Body it consumes skipped pieces until a component appears; at StartDir it sets `back` straight to Done (3) and yields RootDir (path length - 1) or CurDir (leading `./`) or None. An invalid `back` byte reaches the "entered unreachable code" panic (0x28-byte message at 0x948f0b).
- `panic-sites.tsv`: the ten panic call sites and the location constants read from the `lea` bytes in front of them; reachable ones are exercised by the arbitrary-state cases, the rest are arithmetic guards that cannot trigger for in-bounds slices.
- `cases.tsv`: one row per case (entry, class, state bytes, path hex, outcome, match). `outcome-classes.tsv`: counts per entry/class/outcome. `negative-controls.tsv`, `measure.json`, `summary.json`: control and totals.
- Analysis complete for the three function bodies; callers are only referenced through data pointers (vtable-like words at file offsets 0x138418 and 0x138580) and were not followed.

Prior repository evidence names these addresses only as callees (for example the RE-012 and RE-015 packets); none reconstructs their behaviour.

## Implementation and comparison

Independent Rust implementation: not yet implemented; the reconstruction is the Python model `parse_back`/`as_path`/`next_back`, which a later Rust port can use as an oracle.

Comparison: 18,240 cases (1,400 next_back drains, 1,300 as_path and 1,200 parse_back runs from the reachable initial state `front = 0, back = 2, root = path starts with /`; 3,000 + 3,000 + 3,200 + 1,500 arbitrary-state runs; exhaustive paths up to length 5 over {`/`, `.`, `a`} for five state pairs and both root flags). A drain case runs next_back repeatedly until None, comparing the record tag, piece offset/length, new path length and `front`/`back`/`root` bytes after every step. A case passes only if the machine code and the model agree exactly, panics included (location constant and argument registers).

Negative controls (42, all detected): 8 wrong reconstructions (dot treated as a name, `..` treated as a name, missing start offset, first instead of last separator, separator not consumed, no trim floor, body-to-done transition, no CurDir), 32 single-byte code mutations (immediates, kind constants, state constants, jcc opcodes; the old byte is checked before each mutation), one flipped `.text` byte in the input binary and one address past `.text`.

## Results and limitations

`measure.json`: cases 18,240, negative_controls 42, negative_detected 42, mismatches 0. Unit tests: 13, no skips.

Limits: the evaluator is a concrete x86-64 subset interpreter; the panic functions are not followed. The unused Option<Prefix> area is shown to be ignored only for these three entry points. The forward iterator (`next`) was not found as a separate function in this window. No gate is requested.

Next question: find the callers behind the vtable-like words at file offsets 0x138418 and 0x138580 and the forward-direction parser, then connect the iterator to the state-file path normaliser used by the RE-016 loaders.
