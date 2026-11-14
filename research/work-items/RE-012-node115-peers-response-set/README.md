# RE-012: node #115 Peers response, from the frame to the normalized peer set

- Component ID: `transport` (frame, LZ4) with serialization (RE-005, response rows). Tasks RE-012, RE-005.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, ELF virtual addresses.
- Base commit: `a8616af9432b8d8517b2af677880e117b7c28ef3`.
- Claim status: observation for the quoted instructions; inference for the stability of the long sort (a reading, not a machine proof); unresolved for everything listed under Limits.
- Scope included: the selected Peers request (limit selector raw tag 1, limit 10,000) and its response: five-byte frame, optional size-prefixed LZ4, outer tag 1, row decode, then the wrapper `0x2dd2980` that sorts by the four key bytes, keeps the last row of a repeated key and picks small set (`<= 64`) or tree (`> 64`). Scope excluded: peer identity, signatures, networking, what the key/flag/scalar mean, the consumer of the set after `0x2e466b0` returns.
- Crate: [`src/node115-peers-response-set`](../../../src/node115-peers-response-set/README.md) (cross-reference: its README points back here).

## What exists already, and what this adds

The tree already decoded this response as far as a vector in wire order. Credited, reused through path dependencies, not modified, and not counted as new here:

| Piece | Where it lives | Used how |
| --- | --- | --- |
| Five-byte header, big-endian length, `flag == 1` selects LZ4, inclusive length gate, 4,000,000-byte read cap | `RE-012-tcp-frame-plan-115`, `src/node115-tcp-frame-plan` | through the stream crate |
| `Read` adapter joining frame and LZ4 | `RE-012-tcp-stream-frame-lz4-115`, `src/node115-tcp-stream-frame-lz4` | `read_frame`, two separate limits |
| Size-prefixed LZ4 adapter `0x477f8c0` | `RE-012-lz4-decode-115`, `src/node115-lz4-decode` | through the stream crate |
| Request limit selector: qword tag 2 gives 120, low32 tag 1 gives 10,000 | `RE-005-node115-limit-writers`, `RE-005-reader-budget-tag-width-115` | the constant `PEERS_LIMIT`; the three uses below were re-read |
| Outer tag routing, tag 1 to the address vector | `RE-005-node115-gossip-response-composition`, `src/node115-gossip-response-composed` | `decode_prefix` |
| Selected vector payload and NodeIp element (`0x4de6210`/`0x58251a0`/`0x5aaa460` twin) | #2795: `RE-005-gossip-address-vector-115`, `src/node115-gossip-address-vector` (read as a module by the composed crate) | rows, charge, cursor |
| u32/u64 readers, field 1-5 scalar | #2412, #2422, #2300 as cited by `RE-005-node115-state-construction`, `RE-005-node115-field1-5-caller-args` | below the vector crate |
| Value encoding of NodeIp | #1504, named in `RE-001-node115-node-ip-filter/README.md` ("studies value encoding"); its text is not in this tree | not used, not re-checked |

The same prior packets record `0x2dd2980..0x2dd2bd7` as a boundary whose prologue loads the element decoder and calls the vector helper. `RE-005-node115-input-writers` notes the call through the "twin wrapper `0x2dd2980`". None of them describes what the wrapper does after the helper returns, and the Rust of #2795 ends at the wire-order vector.

New here:

1. **The post-helper behaviour of `0x2dd2980`**, read from the bytes ([TIES.md](TIES.md), facts `W01`-`W31`): no sort for 0 or 1 rows; insertion sort for 2..20; the long stable sort for 21 or more; one in-place pass that keeps the last row of each run of equal keys; small set when at most 64 rows remain, tree otherwise.
2. **Which row survives a repeated key at every length**, including 21 or more, by reading each tie site of `0x4f99e70`, `0x4e880e0`, `0x5403600` ([TIES.md](TIES.md) observations 2 and 3). The input is not limited to 20 rows anywhere.
3. **Key order**: the four wire bytes compared as bytes (the sorts byte-swap the loaded dword), not as a little-endian number.
4. **The limit used three times**: stored at `+0x180`/`+0x1a8` (`L07`, `L08`), copied to the reader's `+0x28` (`R01`, `R02`), compared with the frame length with `jae` (inclusive, `R03`, `R04`), passed to the LZ4 adapter (`R05`, `R06`) and loaded again as the row decoder's limit argument (`L11`, `L12`).
5. **Rust**: `normalize` (insertion-sort port, keep-last pass port, storage choice) and one entry point from frame bytes to the set or an error; an independent oracle and corpus.

Without 1-5 a caller holding only the existing crates gets rows in wire order with repeated keys. It cannot say which rows the node keeps, in what order, or whether the result is a small set or a tree, and for 21 or more rows it would have had to settle the tie question itself before trusting any answer. This change does not show who uses the set afterwards.

## Reproduce

Run from the root of a clean checkout, each output directory new and outside the repository. `<hl-node>` is the hydrated #115 ELF (in the repository `artifacts/node/115/hl-node` after LFS fetch; the tools refuse any file whose SHA-256 is not the one above). Tools used: Python 3 (standard library only), GNU binutils `objdump` and `readelf`, `cargo` (here 1.99.1; the repository pins 1.95.0, which was not available).

```sh
python3 -I research/work-items/RE-012-node115-peers-response-set/oracle/gen_oracle.py --outdir <new>/oracle
cmp <new>/oracle/corpus.tsv src/node115-peers-response-set/tests/corpus.tsv
python3 -I research/work-items/RE-012-node115-peers-response-set/verify_target.py --binary <hl-node> --selftest
python3 -I research/work-items/RE-012-node115-peers-response-set/verify_target.py --binary <hl-node> --outdir <new>/verify
cargo test --offline --locked --target-dir <new>/target --manifest-path src/node115-peers-response-set/Cargo.toml
python3 -I research/work-items/RE-012-node115-peers-response-set/mutate.py --outdir <new>/mut-self --selftest
python3 -I research/work-items/RE-012-node115-peers-response-set/mutate.py --outdir <new>/mut
python3 -I -c "import sys; sys.path.insert(0, 'tools'); import verify_packets as v; from pathlib import Path; root = Path('.').resolve(); rows = v.parse_manifest(root / 'research/work-items/RE-012-node115-peers-response-set/MANIFEST.sha256'); bad = [rel for want, rel in rows if v.digest(root / rel) != want]; print('entries', len(rows), 'mismatches', len(bad)); sys.exit(1 if bad else 0)"
```

The last line checks this packet's `MANIFEST.sha256` (packet and crate files, 18 entries) with the repository's own `tools/verify_packets.py` functions. Running `python3 tools/verify_packets.py` itself, which walks every packet, fails in a fresh checkout on an unrelated packet (`RE-001-adjacent-last-115/catalogue-check.log.gz`, a Git LFS pointer that is not hydrated, so its digest does not match), so it was not used as a pass signal for this change.

`gen_oracle.py`, `verify_target.py` and `mutate.py` write only to a new `--outdir`, refuse one that exists or lies inside this packet or the crate, and never modify their inputs (`mutate.py` compares input hashes before and after and exits 5 if any changed). Recorded outputs of one run are in `results/`. None of this is part of `make test`, which collects Python test files only; the crate's tests are run by the `cargo test` line above.

## Evidence

- `spec/ranges.tsv`: 20 byte ranges of the binary with SHA-256 of their bytes; `spec/facts.tsv`: 146 instruction texts at pinned addresses with a role each; `spec/relocs.tsv`: the four slots `0x64e8678 -> 0x4f3a610`, `0x64eb548 -> 0x4e880e0`, `0x64e52d8 -> 0x4f3ac90`, `0x64e7790 -> 0x477f8c0`. The pins were generated from the binary once and are then only read; they show that the instructions are the ones [TIES.md](TIES.md) discusses, not that the discussion is right. The decode is GNU `objdump` on the extracted bytes, with no second decoder.
- Selected request path (static): `0x2b6a7d9..0x2b6a82e` choose 120 or 10,000 (`L01`-`L06`); `0x2b6a93a` calls the frame reader (`L10`); `0x2e466dd..0x2e467ea` route outer tag 1 to the wrapper (`P03`-`P05`).
- Element layout: the element decoder writes the key dword at result `+8`, the scalar at `+0x10`, the boolean at `+0x18` (`E02`-`E04`); the vector helper copies those 24 bytes into the vector (recorded in `RE-005-node115-state-construction`, not re-read here), so the sort and equality compares at row `+0` act on the key (`I01`-`I05`, `W17`, `W18`).
- Twin wrapper `0x4de6210..0x4de6467`: 155 instructions identical to `0x2dd2980` in mnemonics, operands and internal branch offsets (external call targets and rip displacements masked; script not shipped). Its callees other than the sort slot differ and were not read.

## Implementation and comparison

- Crate `src/node115-peers-response-set`, edition 2021, no crates.io dependency, no workspace; `Cargo.lock` committed. Path dependencies: `node115-gossip-response-composed`, `node115-gossip-response-v2-envelope`, `node115-tcp-stream-frame-lz4` (and what those use).
- API: `decode_frame(&[u8]) -> Result<(Decoded, &[u8]), Error>`, `decode_stream(&mut impl Read)`, `decode_payload(&[u8])`, `normalize(&[AddressRecord]) -> PeerSet`. One frame is read; bytes after it are returned. A clean end of stream is `Error::NoFrame`.
- Policy that is this API's and not a claim about the node: only the address-vector response is accepted for a Peers request; other well-formed responses return `NotPeers`. Bytes after the vector are reported in `payload_remaining`, no end-of-input check is assumed.
- For 21 or more rows `normalize` calls the standard library stable sort; for 2..20 it runs a port of `0x26ca410`; the keep-last pass is a port of `0x2dd2a7b..0x2dd2b3d`. The two long-sort branches give the same output, so this boundary rests on [TIES.md](TIES.md), not on a test (mutants `E01`, `E02` survive for that reason).
- Oracle, written and frozen before the Rust (see `ORACLE_FROZEN.txt`, including the one case defect found by the first run): a hand-written wire encoder; a LZ4 block encoder written from the public block format with a spec decoder as a self-check; an overwrite ledger (a dictionary keyed by the four bytes that records the input index of the surviving row, ordered with Python's bytes comparison). It shares no code with the crate. It shares the reading of the binary (tie policy, limits, charge formula) with the crate's author, so agreement shows consistency with that reading, not that the node behaves so.
- Corpus (`tests/corpus.tsv`, 229 cases): 195 success cases (41 end in a tree, 17 are LZ4 frames, 116 contain a repeated key), 34 error cases (limit 4, short input 6, bad boolean 1, bad node tag 1, bad scalar marker 1, outer tag 2, other response 1, clean EOF 1, truncated header 2, truncated payload 2, over the frame limit 3, LZ4 10). Boundaries: 19/20/21, 32/33, 63/64/65, 416/417 (the pre-charge `4 + 8 + 24n <= 10,000`), kept count 63/64/65/66 after replacement, 10,000 and 10,001 byte frames, LZ4 capacity 10,000 and 10,001, truncated frames, wrong outer tag, non-minimal scalars, trailing bytes, two frames back to back, run shapes (ascending, descending, ties inside runs, organ pipe, sawtooth, all equal, few distinct keys) for the long sort.
- Corruption controls: `mutate.py` runs 21 behaviour mutants (each must be killed by a named test, not just any failure), 2 equivalent mutants that must survive, and 4 corpus corruptions (one expectation field changed, one frame hex digit flipped) that the corpus test must reject. Its `--selftest` checks the baseline first and then that a non-compiling edit is `BUILD_ERROR`, a missing or unchanged replacement is `NOT_APPLIED`, a comment-only edit survives, a real change is killed and a missing `cargo` is `ENV_ERROR`. `verify_target.py --selftest` checks the baseline, then that a flipped byte, a moved or missing relocation and a wrong expected text are each rejected, and reports that a one-bit change at the first byte of a fact changed its decoded text in 145 of 146 facts with the byte pins switched off. The count of detected flips measures the text check, not the correctness of the facts.

## Results and limitations

- `cargo test`: 5 API tests and 1 corpus test (229 cases) pass in debug; mutation run: baseline passes, 21/21 behaviour mutants killed by their named tests, 2/2 equivalent mutants survive, 4/4 corpus controls rejected, 0 unexpected. Static check: 20 ranges, 146 facts, 4 relocations, 0 failures. These are consistency checks against the author's reading of the binary.
- Not run: `make verify`, `make test`, `make catalogue-check`, `make reproduce` (hydrated artifacts and the long suite were not available or not needed for a new packet), pinned Rust 1.95.0, `cargo fmt` and `cargo clippy` (no rustfmt/clippy component here). The target binary was only read, never executed or emulated; no network was used.
- Limits: the tie argument is a reading, not a machine proof. The long sort is the standard library's here, not a port. `0x1d0e4d0` (tree bulk build), the reallocation in `0x24d6e80`, allocation failure and panics are not modelled. The state constructor `0x26ff210` (mode 1, charge 0) is taken from `RE-005-node115-input-writers`, not re-read. The consumer of the set after `0x2e466b0` returns is not traced, so this does not show how the node uses the peers. The native async ABI and the node's own check that a response kind matches its request are not claimed. No claim is made about peer identity, signatures or addresses.
- Requested progress gate: none.

Next question: what does the caller of `0x2e466b0` (the constructor `0x26ff210` and the poll above it) do with the returned set or tree: is it merged into an existing collection, compared with one, or only counted?
