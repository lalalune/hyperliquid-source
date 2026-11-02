# Proposed safe value component

## Scope and real build

Proposed source is `src/visor-child-args/`: a real dependency-free Cargo component with Cargo-generated lockfile, safe Rust library, focused tests and README. No root workspace, registry crate, build script, placeholder supervisor or reuse of the unrelated Visor allocator-class API. The library has no process, filesystem, environment, socket or target interface. A separately linked validation client may read synthetic input from stdin and write result bytes to stdout.

The proposed toolchain is the already installed research rustc/cargo 1.94.1 for aarch64-apple-darwin. Exact compiler, sysroot, linker and dependency identities/configuration must be admitted before the later build. This is a host value reconstruction, not the original Linux compiler, native container layout or machine-code equivalence.

## Chosen API

`collect_child_args(items: &[Option<&[u8]>]) -> Result<Vec<String>, CollectError>`

Proposed new variants are `DescriptorCountOutsideDomain`, `InvalidUtf8 { argument_index: usize }` and `AllocationFailure`. They are chosen safe API types, not recovered native enums or error objects. No native error-helper result, message, unwind, panic or process-termination behavior is implemented.

Each `Some(bytes)` maps to one readable immutable native descriptor with a **nonzero** pointer and the exact byte length. `Some(&[])` is a real empty argument. `None` maps narrowly to a descriptor with pointer 0 and length 0: the actual validator accepts an empty span without reading bytes, the adapter returns (0,0), and the collector stops. This does not assign meaning to a zero-pointer positive-length descriptor or skip native validation of arbitrary unreadable bytes.

Let N be the input descriptor count and k the position of the first None, or N if absent. The operation checks the native descriptor-domain bound, then visits only indices 0 through k-1 in increasing order. For every visited span, canonical UTF-8 is required. On ordinary host allocation success it returns exactly k owned Strings with identical lengths and bytes, in the original order. Empty strings remain present, NUL bytes remain present, duplicate arguments remain duplicated, and whitespace/quotes/carets/slashes receive no transformation. Nothing after None is validated or copied, including malformed byte strings.

If a visited span is invalid, return the new `InvalidUtf8` refusal at the first such argument index. The native validator's finer invalid-prefix/width protocol remains credited evidence, but **is not exposed as a recovered collection error**. Host allocation failure may preempt a later invalid span and is explicitly host-specific. No deliberate OOM is tested. No partial successful list is returned with an error; Rust cleanup is host behavior, not a recovered native cleanup trace.

All strings own their storage independently of the borrowed input lifetime. This is a chosen safe representation of successful byte values. It does not equate Rust Vec/String capacity, allocator requests, addresses, empty sentinels or zero-sized allocations with the target.

A pure companion `native_descriptor_bytes(count: u64) -> Option<u64>` returns exactly 24*count when its mathematical value is at most 2^63-1, otherwise None. The production collection operation must call this admission rule for its descriptor count. It supports giant integer boundary tests without manufacturing invalid enormous slices or allocating huge objects. This is the explicit native interval premise, not a recovered standalone native function or native error code. The planned build is 64-bit; no untested 32-bit claim is made.

## Native relation and standard-library premise

The manual composition is in BRIDGE.md. In particular a successful actual UTF-8 adaptation does not imply pointer nonnull, and an empty accepted span can stop or append depending on that pointer. The typed input mapping retains that distinction. Native allocation/copy/frame conditions are explicit external premises; this component does not close allocator 0x70bf30 or memcpy runtime selection.

Using `std::str::from_utf8` is permitted for the production validity check, with safe owned copying afterward. Its public contract checks UTF-8 and preserves the admitted slice; the native proof establishes exactly the canonical byte language. For each scalar, shortest encoding from the standard bit decomposition gives the lead/continuation restrictions in #1029; conversely those restrictions decode to one non-surrogate scalar no greater than 0x10ffff with the shortest width. Concatenation is uniquely delimited by the lead widths. Thus the common accepted language, rather than a presumed compiler/private implementation identity, connects the two.

Official unversioned [from_utf8 documentation](https://doc.rust-lang.org/std/str/fn.from_utf8.html) was read as an API contract; it displayed 1.99.1. The attempted 1.94.1 documentation URLs were unavailable. The actual proposed 1.94.1 host implementation must still pass the frozen corpus in both build profiles. These docs do not independently corroborate the captured binary and no upstream implementation source is copied. The independent oracle does not call a host UTF-8 decoder.

## Independent expected corpus

`corpus.py` constructs the canonical shortest encoding of **each** scalar in 0..0x10ffff except 0xd800..0xdfff with integer bit extraction. From those complete encodings it builds a prefix-to-next-byte language; it does not translate native instructions or import prior packet models. Finite grammar certificates count all scalars and proper prefixes and bind the native lead-width table. A separate mathematical traversal decides whether a byte string is a concatenation of those encodings, then applies the ordered-prefix collection relation.

Only the oracle reads the target and credited proof identities. There is no program counter, register/flag state, simulated target memory, dispatch or captured instruction evaluator. Expected bytes are target-grounded through the reviewed manual proof, **not observed target execution** and not an independent external source for the binary.

The corpus separates input-only `inputs.tsv.gz` and `expected.tsv.gz`. It includes all one- and two-byte strings, every canonical proper multibyte prefix as truncation and with an invalid ASCII continuation, scalar/encoding boundaries, valid multibyte completions, long ASCII/UTF-8 prefixes, multi-argument order/duplicates, many empty arguments, embedded NUL, first-invalid-argument placement, None before malformed suffixes and descriptor-count boundaries. The generator and exact category counts precede production Rust.

## Required gate

First freeze this contract, bridge, native bindings, independent generator/corpus and source absence. Regenerate in two fresh trees and compare bytes; check handwritten witnesses independently. Parent/peer reviews those inputs before authorizing Rust. Any later correction needs an explicit amendment and a new gate, never silent replacement of pre-code evidence.
