"""Project one #115 replica JSON line into ordered, typed fixture data."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
import json
import re

U64_MAX = 2**64 - 1


@dataclass(frozen=True)
class SignatureParts:
    r: bytes
    s: bytes
    v: int


@dataclass(frozen=True)
class SignedAction:
    signature: SignatureParts
    action: object
    nonce: int
    vault_address: bytes | None
    is_frontend: bool | None
    expires_after: int | None


@dataclass(frozen=True)
class Bundle:
    key: bytes
    broadcaster: bytes
    broadcaster_nonce: int
    signed_actions: tuple[SignedAction, ...]


def mapping(value, name):
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    return value


def sequence(value, name):
    if not isinstance(value, list):
        raise ValueError(f"{name} must be an array")
    return value


def unsigned(value, maximum, name):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"{name} must be an unsigned integer up to {maximum}")
    return value


def fixed_hex(value, width, name):
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-f]+", value) or len(value) != 2 + 2 * width:
        raise ValueError(f"{name} must be a fixed {width}-byte lowercase hex string")
    return bytes.fromhex(value[2:])


def limb(value, name):
    if not isinstance(value, str) or not re.fullmatch(r"0x(?:0|[1-9a-f][0-9a-f]{0,63})", value):
        raise ValueError(f"{name} must be a compact 256-bit lowercase hex integer")
    return int(value[2:], 16).to_bytes(32, byteorder="big")


def boolean(value, name):
    if type(value) is not bool:
        raise ValueError(f"{name} must be a boolean")
    return value


def signed_action(raw):
    entry = mapping(raw, "signed action")
    sig = mapping(entry["signature"], "signature")
    return SignedAction(
        SignatureParts(limb(sig["r"], "signature.r"), limb(sig["s"], "signature.s"),
                       unsigned(sig["v"], 255, "signature.v")),
        entry["action"],
        unsigned(entry["nonce"], U64_MAX, "nonce"),
        fixed_hex(entry["vaultAddress"], 20, "vaultAddress") if "vaultAddress" in entry else None,
        boolean(entry["isFrontend"], "isFrontend") if "isFrontend" in entry else None,
        unsigned(entry["expiresAfter"], U64_MAX, "expiresAfter") if "expiresAfter" in entry else None,
    )


def bundle(raw):
    entry = sequence(raw, "bundle")
    if len(entry) != 2:
        raise ValueError("bundle needs exactly two elements")
    payload = mapping(entry[1], "bundle payload")
    actions = sequence(payload["signed_actions"], "signed_actions")
    return Bundle(
        fixed_hex(entry[0], 32, "bundle key"),
        fixed_hex(payload["broadcaster"], 20, "broadcaster"),
        unsigned(payload["broadcaster_nonce"], U64_MAX, "broadcaster_nonce"),
        tuple(signed_action(action) for action in actions),
    )


def object_from_pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError(f"duplicate JSON key {name}")
        result[name] = value
    return result


def reject_constant(value):
    raise ValueError(f"{value} is outside JSON")


def project(line: bytes) -> tuple[Bundle, ...]:
    try:
        raw = json.loads(
            line.decode("utf-8"), object_pairs_hook=object_from_pairs,
            parse_constant=reject_constant, parse_float=Decimal,
        )
        record = mapping(raw, "replica row")
        block = mapping(record["abci_block"], "abci_block")
        return tuple(bundle(item) for item in sequence(block["signed_action_bundles"], "signed_action_bundles"))
    except KeyError as error:
        raise ValueError(f"missing field {error.args[0]}") from error
