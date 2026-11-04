# RE-005: node #115 `rmp_signable` source record and printable-run census

- Component ID: `serialization` (RE-005, Serialization/signing: `bincode_fork/*`,
  `l1/action/rmp_signable.rs`).
- Target release and full SHA-256: node #115, Linux x86-64, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`;
  no submodule commit is changed by this packet.
- Claim status: **observation** for the recorded `.rodata` / `.data.rel.ro`
  printable-run census; **unresolved** for every code-side binding stated below.
- Scope included: static read of the pinned target bytes; the census of maximal
  printable-ASCII runs in `.rodata` and `.data.rel.ro`; the recorded per-needle
  distinct-run counts for `l1/`, `bincode` and `rmp_signable`.
- Scope excluded: any execution of the target, any copy of the target, any
  network, signing or chain action, any reconstructed Rust, any codec or
  wire-format claim, and any component gate.

This packet does **not** claim that `rmp_signable` denotes MessagePack, that a
record is reachable from a signing caller, or that any decoding behaviour is
known. A source-path string in a binary is a Location record, not semantics.

## Reproduce

From the repository root:

```sh
python3 tools/rmp_signable_window.py
```

The saved committed checker for this packet is `tools/rmp_signable_window.py`.
It reads `artifacts/node/115/hl-node` in place, authenticates the pinned digest
and size before and after the analysis, parses the real ELF section headers to
re-derive the `.rodata` and `.data.rel.ro` coordinates, re-computes the
printable-run census, compares every derived value with this packet's
`evidence.json`, and carries corruption controls (wrong digest, truncated
image, altered path byte) that must be rejected. It writes no file, uses the
Python standard library only, and never executes or copies the target.

Working directory: repository root. Platform for the retained run: the
network-less validation container with `artifacts/` mounted read-only.
Any earlier proof pages in this job were recorded with
`currentSource=false`; they are historical context for the target bytes, not a
result for the current saved edits.

## Evidence

Addresses are ELF virtual addresses (VA); the file offsets of the two sections
are recorded below. All numbers come from the recorded static scan of the
pinned target and are re-derived by the checker rather than copied.

| Observation | Recorded value |
| --- | --- |
| ELF sections | 33, `shstrndx=32` |
| `.rodata` | VA `0x430400`, file offset `0x430400`, size `7792192` |
| `.data.rel.ro` | VA `0x63f3c20`, file offset `0x63f1c20`, size `964136` |
| `.rodata` printable runs | 1,536,525 |
| `.data.rel.ro` printable runs | 18,683 |
| Total printable runs (both sections) | 1,555,208 |
| Distinct runs containing `l1/` | 77 |
| Distinct runs containing `bincode` | 6 |
| Distinct runs containing `rmp_signable` | 1 |

What the bytes show: exactly one maximal printable-ASCII run in these two
sections contains `rmp_signable`, and that run is the action-signing source
path record. The checker derives the run at VA/file offset `0x4470c4`, length 29, and
`evidence.json` retains that result together with the census and section geometry.
The `.rela.dyn` RELATIVE slot whose addend points at it, neighbouring words of
the surrounding record, native code references and their containing FDEs remain
**unresolved**. A path string and printable-run census do not establish signing
semantics or first-party ownership.

Negative control already on record: an earlier hypothesis that scanned for
guessed action-wire prefixes (`l1/action/rmp_signable.rs`, `l1/action/`,
`l1/action_delayer.rs`) as literal prefixes reported zero hits and exited 1 with
a real assertion. That result is retained as evidence that the prefix guess was
wrong, not as a property of the target.

## Implementation and comparison

Not yet implemented/measured. No Rust is authored by this packet, no codec is
recovered, and no byte-window comparison against reconstructed code is claimed.

## Results and limitations

- Metrics with explicit denominator: 1,555,208 printable runs over the two
  named sections; 1 of them contains `rmp_signable`, 77 contain `l1/`, 6 contain
  `bincode`. The denominator covers only `.rodata` and `.data.rel.ro`, not the
  whole ELF.
- The census is a static observation. It does not establish reachability,
  call direction, record layout or behaviour, because the target was neither
  executed nor copied.
- No progress gate is requested. This is a bounded partial result and keeps
  every component gate false.
- Next question: for the single recorded `rmp_signable` run, which `.rela.dyn`
  RELATIVE slot holds its VA, which instruction reads that slot or string, and
  which authenticated FDE half-open extent contains that instruction?

## Integration validation

The original submission omitted `evidence.json`, so the committed checker failed
after deriving the pinned observations. The record is now saved from that same
checker against the authenticated #115 target. The complete checker, including
all three corruption controls, passes; no additional semantic claim is made.
