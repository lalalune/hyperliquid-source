# RE-001: digit-stripped table lookup at 0x514e160 (node #94)

Bounded question: what does function 0x514e160 do with its one
string-view argument, and how does the global table at 0x578af60
decide the returned pointer?

## Target

Node #94 work binary `work/hl-node-94.bin`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
(the digest-pinned copy; `artifacts/node/94/hl-node` is still an LFS
pointer on this checkout). All records in `records.json` are bound to
that digest; `verify.py` re-checks them against the binary.

## The behavior

The argument is a string view: a byte pointer at +0x0 and an unsigned
length at +0x8. The function returns a pointer to a matched node's
payload, or 0 when nothing matches.

```text
stripped = view bytes with trailing ASCII digits removed
    # scan from the last byte; a byte b is a digit when
    # (b - 0x30) <= 9 unsigned; stop at the first non-digit
    # (an all-digit view strips to length 0)
key = stripped bytes, held in a temporary string built by the
    callee at 0x5427800 with flag 0 (its plain-assign arm)
table = the global table at 0x578af60
if table.size (at +0x18) > 20:
    h = library_hash(key, seed 0xc70f6907)   # PLT stub 0x56605a0
    bucket = h % table.bucket_count (at +0x08)
    node = *table.buckets (at +0x00)[bucket]  # slot dereferenced once
    while node is not null:
        if node is not the first node of the bucket
            and node.cached_hash % bucket_count != bucket:
            return 0                          # chain end guard
        if node.cached_hash (at +0x70) == h
            and node.key_length (at +0x10) == len(key)
            and (len(key) == 0 or node.key_bytes (at +0x08) == key):
            return node + 0x28
        node = node.next (at +0x00)
    return 0
else:
    node = table.head (at +0x10)
    while node is not null:
        if node.key_length (at +0x10) == len(key)
            and (len(key) == 0 or node.key_bytes (at +0x08) == key):
            return node + 0x28
        node = node.next (at +0x00)
    return 0
```

The temporary string is disposed after the lookup by the standard
rule: when its data pointer differs from its own SSO buffer address,
the sized-delete stub is called with (pointer, capacity + 1); an SSO
temporary deletes nothing. The function has a stack canary at
rsp + 0x58; a mismatch calls the `__stack_chk_fail` stub.

Node layout (minimum size 0x78 bytes): next at +0x00, key pointer at
+0x08, key length at +0x10, key SSO buffer / capacity at +0x18,
payload at +0x28, cached hash at +0x70. Table layout: buckets pointer
at +0x00, bucket count at +0x08, global head at +0x10, size at +0x18.

## Callees and callers

- The string-assign callee at 0x5427800 (390 bytes) is called with
  flag 0, so only its plain-assign arm is exercised by this window:
  it assigns the destination from the view struct's pointer and
  stripped length. Its flag-nonzero arm expands each byte through the
  nibble mapper at 0x5427770 (18 bytes: nibble 0..9 to 0x30 + value,
  10..15 to 0x37 + value, i.e. lowercase hex digits); that arm is
  recorded for completeness and is not taken here.
- The window has exactly 6 direct call sites and no tail jumps or
  qword references (full-binary censuses in `records.json`). The
  callers are cited as consumers only: two sampled sites pass their
  own third argument (a view pointer) as the window's argument. The
  callers' wider semantics and the reaching path beyond them are not
  claimed. One enclosing caller function (0x4fc35d0) is shipped whole
  as `caller.objdump.txt`.

## The hash

The hash is the libstdc++ `_Hash_bytes` PLT symbol with seed
0xc70f6907. The Python model implements that library's published
algorithm (MurmurHash64A), and the seven vectors in `records.json`
were cross-checked against the VM's own libstdc++ `_Hash_bytes` at
the same seed (empty, 1-, 3-, 5-, 6- and 16-byte inputs). Those
vectors validate the model implementation against the library
algorithm; they are not an execution of the target binary, whose
hash lives behind a PLT stub. Instruction-level detail lives only in
the raw disassembly excerpts in this packet, which are whole
functions (plus int3 padding to the next FDE) exactly as objdump
emitted them; `records.json` carries semantic records only. The
mnemonics that appear in those excerpts (for example `endbr64` at
the window entry) are genuine instructions present in the target
binary, not placeholders.

## Unknowns

- The semantics of the payload at node + 0x28 and of the table's
  contents: the model returns the payload as an opaque value.
- How the table at 0x578af60 is populated, and what the keys denote.
- The reason for the size threshold of 20: recorded only as the
  observed branch condition.
- The bucket slot's predecessor-link reading: the code dereferences
  the bucket slot once to reach the first node; the packet records
  that dereference as observed without naming the container's
  implementation.

## Verification

```text
python3 research/work-items/RE-001-digit-stripped-lookup-94/verify.py \
    --binary work/hl-node-94.bin
python3 research/work-items/RE-001-digit-stripped-lookup-94/export_excerpts.py \
    --binary work/hl-node-94.bin
python3 -m unittest tests.test_foundation_digit_stripped_lookup -v
```

`verify.py` checks the target digest, all carve SHAs and int3
padding, every direct-call target, the table address / hash seed /
size threshold immediates, the PLT stubs with their GOT slots, the
FDE records, the full caller censuses, the hash vectors and the
manifest. The tests in `tests/` exercise the model end to end
(strip, both lookup paths, bucket-guard corruption, hash vectors,
packet verification, excerpt regeneration and corruption controls).
