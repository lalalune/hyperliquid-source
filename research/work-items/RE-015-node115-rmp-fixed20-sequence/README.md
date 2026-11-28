# RE-015 — Node #115 MessagePack sequence of 20-byte values

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The [pair-vector packet](../RE-015-rmp-pair-vec-115/) identifies sibling `0x2270910` as an unresolved shape.

For the selected normal row sequence the serializer reads buffer and count, issues the array header through `0x25e7940` and advances in 20-byte input strides. In the selected compact path the element call uses slot `0x64e4d08 -> 0x2eabb50` and passes a 42-byte scratch capacity, a 20-byte input length and a zero option byte. The formatter writes `0x` and uses the lowercase hex alphabet at `0x455d40`. The caller passes the returned span to the string writer `0x25e8750` and checks that each element write returns 2. One entry can be handled before the loop, with the same formatter and string writer.

The ten-byte marker `_ExtStruct` instead branches to a returned descriptor carrying the exact literal `expected tuple`. This distinguishes the ordinary array output from its special-marker result. Other configuration paths, large counts and error ownership are outside scope. The hex formatter internals are already covered elsewhere.

Run `PYTHONPATH=tools python3 research/work-items/RE-015-node115-rmp-fixed20-sequence/verify.py` from the repository root for static instructions, relocation and literal checks.
