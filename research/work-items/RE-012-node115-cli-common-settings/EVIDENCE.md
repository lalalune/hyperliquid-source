# RE-012: common output-option producer and style predicate

- Component ID: node-runtime.
- Sole target: Linux x86-64 node115; SHA256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
- Repository base: 8fd8db680ec4bfef40996e5616bce3d5156d0b86.
- Status: static observations plus explicitly bounded interpretations.
- Included: three complete FDEs,14 local declarations, one alias entry in two storage branches, two callback tables, one internal-name rewrite, exact three-case style predicate and two contextual factory calls.
- Excluded: full parser, vendor version, transitive grammar, arbitrary pointer aliases, Rust ABI, full startup/service effects, source-build/behavior equivalence and complete runtime caller census.

## Reproduce

Use README commands. Python3.12.1, GNU objdump2.47, native Windows.
The collector uses only the standard library and unchanged main ELF/FDE readers.
Initial independent instruction observations use Capstone binding5.0.7,
core5.0.1280. No target execution/emulation, network, keys or external service.

Inputs are the pinned artifact, spec.json and closed manifest. records.json has
no timestamps or local environment values; byte-level output must repeat under
different hash seeds and time zones before submission. The two-environment
check passed with byte-identical output; its source hashes and results are retained. Native output paths are separate from
the durable packet.

## Evidence

Addresses are linked ELF virtual addresses; file offsets, FDE/CIE records,
complete code bytes and bounded LSDA call-site tables are re-derived from the
original ELF. The three original GNU exports and independent instruction rows
cover11,696 bytes/1,575 rows. No instruction-byte normalization is allowed.

Two original FF15 instructions in the previously owned command factory bind
the sole RELATIVE constructor writer. Shared register/allocator/memcpy/drop
helpers remain prior or unresolved boundaries, not newly implemented coverage.
The alias interpretation is a licensed-source structural correspondence,
not an authenticated version claim. See README for the exact reference.

## Implementation and comparison

Independent Rust: not implemented. Cargo/toolchain/source-build comparison:
not applicable to this static packet. No byte transplantation or registered
implementation window. Complete record regeneration and native instruction
address/byte replay are separate from target behavior equivalence.

Actual input corruption controls cover an altered name pool, flags, call
displacement, alias byte, predicate operand, callback relocation, FDE extent
and LSDA encoding. The outer target digest is deliberately bypassed only by
internal derivation in these controls so a hash mismatch cannot hide a missing
semantic guard. The public CLI always requires the fixed target size/SHA256.

## Results and limits

Initial base doctor passed; verify checked six SHA256 values then failed in
Windows GPG public-key import. No signature or complete quality-gate success
is claimed from that run. The first collector refused an operator's unverified
third style spelling; original operands establish actions-and-responses.
Thirteen focused tests passed under normal and optimized Python after correcting
that transcription, including two native-output corruption controls. Fresh GNU
replay matched all1,575 address/byte rows. Final-head mandatory repository results
are recorded separately in the pull request.

No gate requested. All92 existing component gates remain false.
Next semantic question: connect the producer to the actual parser and output
consumer under an explicit helper/ABI contract. Final-head required checks and
submission status are reported in the pull request.

AI assistance: OpenAI / model unavailable in supported turn metadata;
client codex-desktop, exact client build unavailable. No value is inferred.
