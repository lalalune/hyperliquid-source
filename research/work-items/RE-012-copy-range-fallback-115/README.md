# RE-012 node115 copy_file_range capability and fallback

This packet maps the returned byte count, raw result tag and capability
cache across the file-copy path and its actual probe. Target Linux
x86-64 node #115 SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The caller at 0x5ca1670 reads the byte at 0x650008b. Value 1 bypasses
the copy and writes tag 2 with count zero. The live copy chooses the
imported copy_file_range when its slot is populated and otherwise
uses syscall number 326. Requests are capped at 0x40000000 bytes.
The first successful copy return stores cache byte 2 when the cache
was initially zero. Tag 0 carries the completed count.

At 0x5ca189f the relative table at 0x948888 dispatches errno values
1 through 38. Every target is retained in scope.json. The special
entries and out-of-table checks produce the following output.

| Errno | Progress predicate | Result |
| --- | --- | --- |
| 9, 18, 22 | Count zero | Tag 2, with cache 2 stored on the initial unknown-state arm |
| 1, 38, 95 | Count zero | Tag 2, with capability probe on the initial unknown-state arm |
| 75 | Any | Tag 2 with completed count |
| Other cases, including nonzero count in the first two rows | As stated | Tag 1 with completed count and packed errno |

The tag-1 error word is the zero-extended errno shifted 32 bits and
ORed with 2. Tag 2 carries the count in the same +8 field. The
special cases follow the table's actual signed relative targets
and the two comparisons at 0x5ca18be and 0x5ca18c3.

The probe at 0x5ca5510 calls the same implementation selection with
both descriptors -1, both offset pointers null, count 1 and flags 0.
A -1 return reads errno. The probe returns byte 2 for errno 9 and 1
for other errno values. Any non--1 return enters the diagnostic call
at 0x5ca55b6. The caller stores the returned probe byte directly
at 0x650008b. This is a static result contract through the imported
calls. It does not simulate a kernel, filesystem or fallback copier.

## Reproduce

Run from the repository root with authenticated artifacts, Capstone
5.0.7, GNU 2.45 and LLVM 23.1.4.

```sh
python3 -B research/work-items/RE-012-copy-range-fallback-115/collect.py --out work/copy-range-fresh
python3 -B research/work-items/RE-012-copy-range-fallback-115/verify.py --out work/copy-range-check-fresh.json
```

Two full FDEs cover 875 bytes and 237 instructions. GNU, LLVM and
Capstone agree and GNU readelf confirms the extents. Corruption
controls exercise real instruction windows, the errno table, the
three dynamic symbol writers and artifact identity. The collector
scaffold is reused from the MIT ELF Build ID packet. Neither captured
code nor file-copy syscalls are executed.
