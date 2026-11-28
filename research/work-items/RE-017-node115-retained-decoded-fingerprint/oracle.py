"""Independent ordinary retained-link wire and Keccak regression vector."""

from Crypto.Hash import keccak


DOMAIN = b"Hyperliquid Consensus Payload"
KNOWN_ABC = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"


def compact(value):
    if value <= 250:
        return bytes([value])
    for marker, width in ((251, 2), (252, 4), (253, 8)):
        if value < (1 << (8 * width)):
            return bytes([marker]) + value.to_bytes(width, "little")
    raise ValueError("fixture integer exceeds u64")


def header(address, hashes, seconds, nanos, fields, parent_digest):
    zigzag = 2 * seconds if seconds >= 0 else -2 * seconds - 1
    return (address + compact(len(hashes)) + b"".join(hashes) + compact(zigzag)
            + compact(nanos) + b"\0" + b"".join(compact(field) for field in fields)
            + parent_digest + b"\0")  # Direct quorum with zero votes.


def wire(body):
    # Structural replay tag, unused fixture signature slot, header and two absent options.
    return b"\0" + bytes(9) + body + bytes(2)


def fixture():
    assert keccak.new(digest_bits=256, data=b"abc").hexdigest() == KNOWN_ABC
    previous_body = header(bytes([0x31] * 20), [bytes([0x56] * 32)], -1, 999_999_999,
                           (11, 19, 40, 57, 64), bytes([0x71] * 32))
    canonical = b"\0" + previous_body
    digest = keccak.new(digest_bits=256, data=DOMAIN + canonical).digest()

    def following(identity, fingerprint):
        return wire(header(bytes([0x32] * 20), [], 0, 120_000_000,
                           (11, 19, identity, 57, 64), fingerprint))

    changed_digest = bytes([digest[0] ^ 1]) + digest[1:]
    return {
        "previous.bin": wire(previous_body),
        "next.bin": following(41, digest),
        "changed-digest.bin": following(41, changed_digest),
        "changed-identity.bin": following(42, digest),
    }, canonical, digest


if __name__ == "__main__":
    from pathlib import Path

    folder = Path(__file__).resolve().parent
    files, document, digest = fixture()
    for name, value in files.items():
        (folder / name).write_bytes(value)
    print(f"canonical={document.hex()}\nkeccak={digest.hex()}")
