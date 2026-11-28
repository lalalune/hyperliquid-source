"""Generate synthetic linked digest vectors using the separate blake3 1.0.8 package."""

from blake3 import blake3, __version__


def main():
    assert __version__ == "1.0.8"
    assert blake3(b"abc").hexdigest() == (
        "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
    )
    root = bytes(range(32))
    state = bytes.fromhex("81a66865696768742a")
    print(f"Independent reference: blake3 {__version__}")
    for span in (b"", state, bytes(i % 251 for i in range(1025))):
        first = blake3(span).digest()
        result = blake3(first + root).hexdigest()
        print(f"len={len(span)} inner={first.hex()} linked={result}")
    inner = blake3(state).digest()
    expected = blake3(inner + root).digest()
    reversed_order = blake3(root + inner).digest()
    extra_height = blake3(inner + root + (42).to_bytes(8, "little")).digest()
    extended_span = blake3(blake3(state + b"outside").digest() + root).digest()
    for name, result in (
        ("reversed", reversed_order),
        ("extra-height", extra_height),
        ("trailing-capacity", extended_span),
    ):
        assert result != expected
        print(f"Control {name}={result.hex()}")


if __name__ == "__main__":
    main()
