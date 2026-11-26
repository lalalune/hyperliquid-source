# Node115 certificate caller and variant-zero digest

This logical source adapter composes the selected caller's supplied front-end
check with the existing nested-certificate decision, then checks the selected
parent digest, the domain-separated variant-zero block digest, and the two
saturating round increments in native order. Known mismatch tags are exposed;
a nested no-return condition stays distinct. The front-end closure receives the
same block, nested certificate and context, but its correctness is a caller
premise. Existing stake provider and signature primitive traits remain explicit;
no actual signature is verified by test stand-ins.

The variant-zero encoder takes already-projected timestamp seconds/nanoseconds
and timeout rows in native iterator order. It reuses the existing compact-u64
writer, `SigMap::entries` and Keccak implementation; it does not reconstruct
native calendar conversion, container ABI, iterator validation, allocation
failure, wire decoding or complete consensus acceptance. The nested
certificate is a caller input and is intentionally not part of the variant-zero
block preimage. See the target-bound evidence packet for scope and premises.
