# RE-012: node94 nonblocking-connect call and result contract

- Component: peer transport / startup, bounded imported-socket boundary.
- Target: node #94, Linux x86-64, 91,774,280 bytes; SHA-256
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f.
- Source base: 966865f1637a29ce75b019e1bf11d5529cc6f519.
- Observation: complete FDE [0x3cd6330,0x3cd6427), 247 bytes / 69 instructions.
  Body SHA-256 dcfd7a6f8f405424b220460fcb0647e460437cb0d8ce3059d9fa454ba6c9cb14.
- This is reproducible static research plus an explicitly authorized offline
  Python instruction evaluation. No captured executable, libc, OS socket,
  peer, chain, signing, or private runtime state is executed or accessed.

## Question and prior gap

The existing RE-012 socket census establishes call sites, not this helper's
address marshalling, result-object writes, pending-connect acceptance or failure
cleanup. These are prerequisites to joining source-built transport components.
This packet closes that bounded interface question, not the caller's entire
async state machine. It adds no replacement libc or speculative Rust wrapper.
First-party versus shared dependency ownership and exact library version remain
unassigned; no first-party matched-byte credit is requested.

## Reproduce

From the repository root, with the pinned LFS input materialized and the normal
development environment selected:

    python3 tools/nonblocking_connect_contract.py --output work/connect-contract
    python3 -m unittest tests.test_nonblocking_connect_contract -v
    objdump -d -Mintel --start-address=0x3cd6330 --stop-address=0x3cd6427 artifacts/node/94/hl-node
    llvm-objdump -d --x86-asm-syntax=intel --start-address=0x3cd6330 --stop-address=0x3cd6427 artifacts/node/94/hl-node
    make doctor verify catalogue-check reproduce
    make test

The producer requires a new output directory. It checks the whole target size
and SHA before decoding, then the complete FDE and body hash and each dynamic
symbol slot. Native GNU/LLVM exports and raw FDE/CIE are retained beside this
record. All coordinates are original virtual addresses; tools map through ELF
load segments to file offsets. See environment.json for observed tool versions.
The producer regenerates all 1,200 comparison rows; vectors are transient rather
than committed. Their canonical JSONL SHA is in records.json. The six tests also
compare every instruction address, size and raw byte with Capstone over all
247 bytes, without treating mnemonic spelling as evidence.

## Observed input, calls and result

Qualified preconditions: RDI points to a separate writable 16-byte result;
RSI points to an initialized immutable 32-byte address view, with family u16
at +0 restricted to 0 or 1. Input, output, stack and errno storage do not alias.
Imported calls normally return under the x86-64 SysV calling convention.
The evaluator treats caller-saved registers, XMM state and flags as unknown
after each import; int returns define only low 32 RAX bits.

socket is called with domain 2+8*family, type 0x80801 and protocol 0.
A negative signed 32-bit return reads errno and returns an error without
connect or close. A nonnegative descriptor, including zero, proceeds:

| Input family | Address view | Bytes actually passed to connect |
|---|---|---|
| 0 | address +2..5, host port u16 +6 | family 2 LE; port BE; address4; eight zeros (16 bytes) |
| 1 | address16 +4; raw word +20; raw word +24; host port +28 | family 10 LE; port BE; raw word20; address16; raw word24 (28 bytes) |

The raw IPv6 words are copied without byte swaps. Flow/scope interpretations
are context, not recovered Rust field types. IPv4 has extra scratch writes
outside its passed 16-byte slice, including an unspecified ECX value; these are
not claimed as defined sockaddr bytes or compared as a full physical trace.

Any nonnegative signed connect return is accepted. Negative returns read errno;
115 is accepted as pending. Other errno values write the error result first,
then attempt close(fd) exactly once. A close failure or errno change is ignored;
the original saved error is retained. This proves a close attempt, not a
successful close. Pending acceptance is not proof of a connected socket.

| Result | Defined writes | Preserved bytes |
|---|---|---|
| Accepted | u32 +0 = 0; i32 fd +4 | +8..15 |
| Error | u32 +0 = 1; u64 +8 = (errno_u32 << 32) OR 2 | +4..7 |

RAX returns the original output pointer; saved registers and RSP are restored.
The packet records input-read and output-write offsets. Socket failure reads
only family bytes 0,1. Later IPv4 reads 0..7; IPv6 reads 0,1 and 4..29.
This describes observed raw memory, not an asserted original Rust enum or ABI.

All five actual call sites and raw instruction bytes are in records.json:
socket slot 0x5775210; errno slot 0x576e8d8 (two sites);
connect slot 0x576f150; close slot 0x576e708. Bindings are checked against
dynamic symbol/relocation evidence, rather than inferred from call order.

For context only, the Linux generic errno header names 115 EINPROGRESS:
https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/errno.h
and Linux documents sockaddr_in6 fields in:
https://github.com/torvalds/linux/blob/master/include/uapi/linux/in6.h
These do not establish the captured kernel or original dependency version.

## Implementation, controls and results

The existing project-authored integer instruction engine lacked this observed
ROL16 port conversion. A local subclass supports only count eight (byte swap)
and count zero. Its complete 65,536-value domain is checked. CF/OF stay unknown
for count eight; unaffected SF/ZF are preserved. Any later unknown flag use
fails closed. Other rotate counts are rejected. No shared engine is expanded.

All 1,200 actual-instruction evaluations match separate field/byte/call/result
equations: 2 families x 6 ports x 5 socket returns x 4 connect returns x 5
errno values. Ports: 0,1,255,256,0x1234,65535; socket results:
INT_MIN,-1,0,7,INT_MAX; connect results: INT_MIN,-1,0,1;
errno: -1,0,4,115,INT_MAX. Close returns 0/-1 by port parity and changes errno
to -999. Synthetic callback outcomes deliberately cover more than normal libc
success returns. All 69 of 69 decoded instructions are visited across this
finite corpus; this is not proof over every input, kernel, caller or trace.

Three actual private byte mutations are evaluated below the normal identity
gate: socket type, IPv4 port rotate and pending errno constant. All change
observations; complete-body admission also rejects all three. The first two
leave result words unchanged while changing the imported call, demonstrating
why final-output-only comparison is insufficient. FDE-size corruption,
unbound import, out-of-range control flow and invalid memory writes are rejected.
No original input is modified. controls.json preserves before/after observations.

Focused final result: 6 tests PASS in 3.968s, including golden regeneration,
independent raw decode, complete rotate-value domain, call traces, inactive
result bytes and actual mutation controls. Earlier local fixture mistakes
(missing synthetic errno; expecting condition() rather than jump() to reject an
unknown flag) were corrected without weakening the target comparator or
changing golden expectations. All required safe gates PASS; full make test
is recorded separately with its actual completion state in validation.json.

## Limits and next question

No independently authored Rust reconstruction or two-build comparison is
claimed in this research-only packet. Imported implementations, loader/kernel,
asynchronous caller states, original ownership/types and live network
compatibility remain open. No catalogue or full-scope milestone gate changes.
Next establish the exact caller's address handoff and lifetime across async
poll states, then use this contract as the import boundary.
