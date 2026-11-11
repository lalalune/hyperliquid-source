#!/usr/bin/env python3
"""Static #115 evidence and synthetic EIP-712 vector for one UsdSend path."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections  # noqa: E402
from fde_extents import fde_extents  # noqa: E402

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TYPE_DOMAIN = (
    "EIP712Domain(string name,string version,uint256 chainId,"
    "address verifyingContract,bytes32 salt)"
)
TYPE_USD_SEND = (
    "HyperliquidTransaction:UsdSend(string hyperliquidChain,string destination,"
    "string amount,uint64 time)"
)
EXPECTED_USD_SEND_TYPEHASH = "c7410964737e2180e258d649f23f74a49460432fecbd94688103ecc63fb66b4c"

FDE_EXPECTED = {
    0x443399F: (0x44338B0, 0x4433C1B),
    0x43D2B56: (0x43D2B20, 0x43D312E),
    0x43D3130: (0x43D3130, 0x43D342C),
    0x169E950: (0x169E950, 0x169F713),
}
RELOCS_EXPECTED = {
    0x64EA890: 0x43D2B20,
    0x64EA898: 0x43D3130,
    0x64E2178: 0x169E950,
    0x64E0140: 0x169E350,
    0x64E0148: 0x5CDA910,
    0x64E0150: 0x5CDAD40,
}
INDIRECT_CALLS = {
    0x443399F: 0x64E2178,
    0x44339EE: 0x64EA890,
    0x4433B34: 0x64E0148,
    0x4433B62: 0x64E0150,
    0x43D2B56: 0x64EA898,
    0x43D2F55: 0x64E0148,
    0x43D2F86: 0x64E0150,
    0x169EB06: 0x64E0148,
    0x169EB34: 0x64E0150,
    0x169F220: 0x64E0140,
    0x169F2C3: 0x64E0148,
    0x169F2F1: 0x64E0150,
}
DIRECT_CALLS = {0x4433A8F: 0x44E5DB0}
DOMAIN_NAME_VA = 0x7D2FE5
DOMAIN_NAME = b"HyperliquidSignTransaction"
PREFIX_VA = 0x7D06A1
PREFIX = bytes.fromhex("1901")

MASK = (1 << 64) - 1
ROT = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)


def _rol(value: int, count: int) -> int:
    if count == 0:
        return value
    return ((value << count) | (value >> (64 - count))) & MASK


def _permutation(state: list[int]) -> None:
    for rc in RC:
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        for x in range(5):
            d = c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1)
            for y in range(5):
                state[x + 5 * y] ^= d
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(state[x + 5 * y], ROT[x][y])
        for y in range(5):
            for x in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        state[0] ^= rc


def keccak256(message: bytes) -> bytes:
    """Keccak-256 (legacy Keccak padding), independently written from FIPS 202."""
    rate = 136
    padded = bytearray(message)
    padded.append(0x01)
    padded.extend(bytes((-len(padded)) % rate))
    padded[-1] ^= 0x80
    state = [0] * 25
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")
        _permutation(state)
    return b"".join(x.to_bytes(8, "little") for x in state)[:32]


def word_uint(value: int) -> bytes:
    if not 0 <= value < 1 << 256:
        raise ValueError("uint256 outside range")
    return value.to_bytes(32, "big")


def word_address(value: str) -> bytes:
    raw = bytes.fromhex(value.removeprefix("0x"))
    if len(raw) != 20:
        raise ValueError("address must contain exactly 20 bytes")
    return bytes(12) + raw


def hex0(raw: bytes) -> str:
    return "0x" + raw.hex()


def make_vector(values: dict | None = None) -> dict:
    values = values or {
        "hyperliquidChain": "Testnet",
        "destination": "0x00000000000000000000000000000000000000a1",
        "amount": "1.25",
        "time": 1700000000,
        "domain": {
            "name": DOMAIN_NAME.decode(),
            "version": "1",
            "chainId": 1337,
            "verifyingContract": "0x0000000000000000000000000000000000000000",
            "salt": "0x" + "00" * 32,
        },
    }
    domain = values["domain"]
    if not 0 <= values["time"] < 1 << 64:
        raise ValueError("UsdSend time is outside uint64")
    usd_typehash = keccak256(TYPE_USD_SEND.encode())
    if usd_typehash.hex() != EXPECTED_USD_SEND_TYPEHASH:
        raise ValueError("UsdSend typehash differs from the independently recorded #5398 value")
    action_parts = [
        usd_typehash,
        keccak256(values["hyperliquidChain"].encode()),
        keccak256(values["destination"].encode()),
        keccak256(values["amount"].encode()),
        word_uint(values["time"]),
    ]
    action_preimage = b"".join(action_parts)
    action_hash = keccak256(action_preimage)
    salt = bytes.fromhex(domain["salt"].removeprefix("0x"))
    if len(salt) != 32:
        raise ValueError("domain salt must contain exactly 32 bytes")
    domain_typehash = keccak256(TYPE_DOMAIN.encode())
    domain_parts = [
        domain_typehash,
        keccak256(domain["name"].encode()),
        keccak256(domain["version"].encode()),
        word_uint(domain["chainId"]),
        word_address(domain["verifyingContract"]),
        salt,
    ]
    domain_preimage = b"".join(domain_parts)
    domain_hash = keccak256(domain_preimage)
    final_preimage = PREFIX + domain_hash + action_hash
    return {
        "scope": "synthetic EIP-712 vector; no node execution, signature, or live account",
        "values": values,
        "types": {"domain": TYPE_DOMAIN, "action": TYPE_USD_SEND},
        "action": {
            "typehash": hex0(usd_typehash),
            "preimage": hex0(action_preimage),
            "preimage_parts": [hex0(x) for x in action_parts],
            "struct_hash": hex0(action_hash),
        },
        "domain": {
            "typehash": hex0(domain_typehash),
            "preimage": hex0(domain_preimage),
            "preimage_parts": [hex0(x) for x in domain_parts],
            "separator": hex0(domain_hash),
        },
        "final": {
            "prefix": hex0(PREFIX),
            "preimage": hex0(final_preimage),
            "digest": hex0(keccak256(final_preimage)),
        },
    }


def _section_for_va(data: bytes, secs: list[dict], va: int, size: int) -> tuple[dict, int]:
    hits = [s for s in secs if s["type"] != 8 and s["address"] <= va and va + size <= s["address"] + s["size"]]
    if len(hits) != 1:
        raise ValueError(f"VA {va:#x}+{size:#x} lacks a unique file-backed section")
    sec = hits[0]
    return sec, sec["offset"] + va - sec["address"]


def _relocations(data: bytes, secs: list[dict]) -> dict[int, int]:
    rows = [s for s in secs if s["name"] == ".rela.dyn"]
    if len(rows) != 1 or rows[0]["size"] % 24:
        raise ValueError("expected one integral ELF64 .rela.dyn table")
    sec = rows[0]
    result: dict[int, int] = {}
    for pos in range(sec["offset"], sec["offset"] + sec["size"], 24):
        offset, info, addend = struct.unpack_from("<QQq", data, pos)
        if info & 0xFFFFFFFF == 8:  # R_X86_64_RELATIVE
            result[offset] = addend & MASK
    return result


def _check_call(data: bytes, secs: list[dict], va: int, expected: int, indirect: bool) -> str:
    length = 6 if indirect else 5
    _, off = _section_for_va(data, secs, va, length)
    insn = data[off:off + length]
    if indirect:
        if insn[:2] != b"\xff\x15":
            raise ValueError(f"{va:#x} is not a RIP-relative indirect call")
        disp = struct.unpack_from("<i", insn, 2)[0]
        actual = va + 6 + disp
    else:
        if insn[0] != 0xE8:
            raise ValueError(f"{va:#x} is not a direct rel32 call")
        actual = va + 5 + struct.unpack_from("<i", insn, 1)[0]
    if actual != expected:
        raise ValueError(f"call {va:#x} targets {actual:#x}, expected {expected:#x}")
    return insn.hex()


def verify_target(data: bytes, *, check_digest: bool = True) -> dict:
    digest = hashlib.sha256(data).hexdigest()
    if check_digest and digest != DIGEST:
        raise ValueError(f"target SHA-256 mismatch: {digest}")
    secs = sections(data)
    fde_summary, fdes, _ = fde_extents(data)
    fde_facts = {}
    for va, expected in FDE_EXPECTED.items():
        hits = [f for f in fdes if f["start"] <= va < f["end"]]
        if len(hits) != 1 or (hits[0]["start"], hits[0]["end"]) != expected:
            raise ValueError(f"unexpected FDE extent at {va:#x}: {hits}")
        fde_facts[hex(va)] = {"start": hex(hits[0]["start"]), "end": hex(hits[0]["end"]), "section": hits[0]["section"]}
    relocs = _relocations(data, secs)
    for slot, target in RELOCS_EXPECTED.items():
        if relocs.get(slot) != target:
            raise ValueError(f"relocation {slot:#x}: got {relocs.get(slot)!r}, expected {target:#x}")
    call_bytes = {}
    for va, slot in INDIRECT_CALLS.items():
        call_bytes[hex(va)] = {"slot": hex(slot), "bytes": _check_call(data, secs, va, slot, True)}
    for va, target in DIRECT_CALLS.items():
        call_bytes[hex(va)] = {"target": hex(target), "bytes": _check_call(data, secs, va, target, False)}
    _, name_off = _section_for_va(data, secs, DOMAIN_NAME_VA, len(DOMAIN_NAME))
    _, prefix_off = _section_for_va(data, secs, PREFIX_VA, len(PREFIX))
    if data[name_off:name_off + len(DOMAIN_NAME)] != DOMAIN_NAME:
        raise ValueError("domain name literal differs")
    if data[prefix_off:prefix_off + len(PREFIX)] != PREFIX:
        raise ValueError("final EIP-712 prefix differs")
    vector = make_vector()
    negative = {
        "changed_amount_digest": make_vector({**vector["values"], "amount": "1.26"})["final"]["digest"],
        "changed_chain_id_digest": make_vector({**vector["values"], "domain": {**vector["values"]["domain"], "chainId": 1338}})["final"]["digest"],
        "changed_prefix_digest": hex0(keccak256(bytes.fromhex("1900") + bytes.fromhex(vector["domain"]["separator"][2:]) + bytes.fromhex(vector["action"]["struct_hash"][2:]))),
    }
    if len(set([vector["final"]["digest"], *negative.values()])) != 4:
        raise ValueError("synthetic mutation controls did not produce distinct digests")
    return {
        "target_sha256": digest,
        "target_size": len(data),
        "fde_count": fde_summary["fde_records"],
        "fde_extents_are_unwind_ranges_not_validated_function_bounds": True,
        "selected_fdes": fde_facts,
        "relative_relocations": {hex(k): hex(relocs[k]) for k in sorted(RELOCS_EXPECTED)},
        "call_bytes": call_bytes,
        "literals": {"domain_name_va": hex(DOMAIN_NAME_VA), "domain_name": DOMAIN_NAME.decode(),
                     "final_prefix_va": hex(PREFIX_VA), "final_prefix": hex0(PREFIX)},
        "mutations": negative,
        "vector": vector,
        "interpretation": {
            "observed": [
                "0x44338b0 FDE calls the domain-result slot then the unique UsdSend message-hash slot.",
                "The same FDE concatenates the 0x1901 literal and two 32-byte values before the final sponge update/final calls.",
                "The UsdSend hash FDE calls its own type-builder slot; the domain FDE hashes its typed field records.",
            ],
            "inferred": [
                "The two 32-byte values are the EIP-712 domain separator and UsdSend struct hash, based on the type builders, record layout, and 0x1901 prefix.",
                "The synthetic vector follows the standard EIP-712 encodeType/hashStruct rules; no target execution or output comparison is claimed.",
            ],
            "unknown": [
                "Runtime values and their outer caller ABI are not recovered.",
                "No private key, signature, chain action, or runtime target execution is used.",
                "Other action families and signature/replay validation remain outside this packet.",
            ],
        },
    }


def generate(target: Path, output: Path) -> dict:
    data = target.read_bytes()
    result = verify_target(data)
    output.mkdir(parents=True, exist_ok=True)
    (output / "verification.json").write_text(json.dumps(result, indent=2) + "\n")
    (output / "vector.json").write_text(json.dumps(result["vector"], indent=2) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=ROOT / "artifacts/node/115/hl-node")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = verify_target(args.target.read_bytes()) if args.out is None else generate(args.target, args.out)
    print(json.dumps({"target_sha256": result["target_sha256"], "vector_digest": result["vector"]["final"]["digest"],
                      "selected_fdes": result["selected_fdes"], "mutations": result["mutations"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
