# RE-001: node #115 block-reader Location consumer and return-tag boundary

- Component: `storage`; bounded function/cross-reference research, not RE-009 completion.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Pinned source: `a8a165e65d53abc1c996bcc9b609749529cfc41a`.
- Prior integrated evidence: [`RE-001-node115-location-2b2c061`](../RE-001-node115-location-2b2c061/README.md), which explicitly leaves the pointer consumer unresolved.
- Status: static observations; consumer semantics and reachability unresolved. No gate change requested.

## Question and baseline

Where does the already anchored `db/src/block_reader.rs:29:26` Location pointer go immediately, and what control boundary follows that call? The prior packet identifies the Location load but does not follow it to a consumer. This extension records only that immediate edge and the following return-slot comparison. It does **not** identify a corruption diagnostic or label the compared value as an error.

## Evidence

Coordinates below are link-time ELF virtual addresses, not runtime addresses. The 42-byte instruction sequence from `0x2b2c061` through `0x2b2c08b` is checked exactly against the authenticated target. The previously established boundary at `0x2b2c061` supplies alignment; this packet does not re-disassemble the entire function. The single retained [native excerpt](native-excerpt.txt), with trailing whitespace removed, requests 128 bytes starting there; its tail stops part-way through a later instruction and is not used for the proof.

- `0x2b2c061`: `lea rcx,[rip+0x391eb18]` loads Location `0x644ab80`.
- The next instructions load `rdi = rsp+0x90`, `rsi = rsp+0x20`, and `rdx = r12`; none overwrites RCX before the direct call at `0x2b2c078` to `0x2698f40`.
- After the call, `0x2b2c07d` loads R14 from `[rsp+0x90]`, `0x2b2c085` compares R14 with 2, and `0x2b2c089` branches to `0x2b2c0a0` if unequal. Equal falls through at `0x2b2c08b`. This is a machine-level comparison, not a proven Rust enum discriminant or error condition.
- Caller FDE range: `[0x2b2be60,0x2b2c4f1)`. The call target is exactly the start of FDE `[0x2698f40,0x26990ca)`. FDE coverage does not establish reachability or function identity.
- Actual ELF PT_LOAD mapping places Location `0x644ab80` at file offset `0x6448b80`. Its unique symbol-zero `R_X86_64_RELATIVE` relocation addend is `0x4422bd`; this source VA is also file offset `0x4422bd`, **not** VA minus `0x1000`. A fixed subtraction is invalid across segments. The referenced 22 bytes are exactly `db/src/block_reader.rs`; the remaining descriptor fields are line 29, column 26.

The exact replay result is [record.json](record.json). This closes the local register-to-call edge only: RCX reaches a call with that value, but calling convention, callee use, panic/diagnostic identity, return type, interprocedural ownership and error handling are not established.

## Reproduce

From repository root with the pinned LFS target already materialized:

```sh
python3 research/work-items/RE-001-node115-block-reader-corruption-boundary/replay.py
python3 -m unittest discover -s tests -p test_node115_block_reader_consumer_boundary.py -v
```

Observed environment: Python 3.12.3, GNU readelf and objdump (GNU Binutils for Ubuntu) 2.42, Linux isolated runner. Python standard library only; GNU readelf reads unwind records. The replay authenticates the whole target before any interpretation, maps the descriptor through ELF program headers, reads actual relocation records, checks the observed code bytes and relative destinations, and verifies the FDE intervals. It never executes the target and uses no network, reference implementation, invented fixture binary, or paid dataset.

Native excerpt command (already run once; no broader disassembly needed):

```sh
objdump -d -M intel --start-address=0x2b2c061 --stop-address=0x2b2c0e1 artifacts/node/115/hl-node
```

The tests include the real target proof and negative controls for Location displacement, RCX preservation (change the pre-call move destination to RCX), direct-call displacement, branch displacement, Location layout, relocation addend, source bytes, caller/callee FDE ranges, digest, and unmapped VA. In field-level controls only, the outer digest gate is intentionally bypassed so the inner check is exercised; ordinary CLI replay never bypasses the digest. Instruction mutations fail the exact sequence check, not a general-purpose disassembler or semantic equivalence checker. Actual local test output is retained in [scoped-test.txt](scoped-test.txt). Independent project/global validation is separate and must be reported from its actual receipt, not inferred from these tests.

## Results and limits

One authenticated target, one already-known Location, one immediate direct-call edge and one following conditional edge are checked. The explicit instruction-proof denominator is 42 bytes within one 128-byte requested excerpt; no whole-function, binary-coverage or compatibility denominator is claimed. The static discovery stayed below its 120-second command-time bound and used only the single excerpt. Parsing/replay and corruption tests are proof work, not additional native discovery.

No reconstruction, independently authored Rust implementation, executable equivalence, build provenance, captured-code execution or component completion is claimed. All gates remain unchanged/false where previously false. Helpers, indirect calls and the callee body are outside scope. Root project-authored code is independently written; no inferred can1357 source is copied. The tiny native excerpt remains target evidence under the artifact's existing rights, not a new MIT grant over imported material.

Next question: with a separately bounded investigation, what does callee `0x2698f40` do with RCX, and can the return-slot value 2 be given a target-grounded meaning? Neither answer is implied here.
