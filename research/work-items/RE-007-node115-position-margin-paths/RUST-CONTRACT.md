# Frozen Node115 position mode and margin arithmetic contract

Target node115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The selected position body is `0x448b800..0x448b967`, 359 bytes. Its five
observed mode paths are:

- mode 0: no division or margin helper;
- mode 1: unsigned floor division by descriptor divisor;
- mode 2: opaque margin-table relation A;
- mode 3: opaque margin-table relation B;
- mode 4: unsigned floor division by `min(divisor, cap)`.

The safe API also models the signed product magnitude, direct quotient and active
offset saturation needed by this body. It does not implement the opaque table
constructors, original ABI, units, leverage names, malformed mode checks, panic
boundaries or broader position accounting.
