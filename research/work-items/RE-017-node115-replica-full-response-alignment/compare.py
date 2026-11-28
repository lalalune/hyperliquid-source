"""Compare Full replica outcomes at bundle-key and action-index granularity."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
import json
import re


@dataclass(frozen=True)
class Unavailable:
    source: str
    variant: str


@dataclass(frozen=True)
class Result:
    user: bytes
    status: str
    response: object


@dataclass(frozen=True)
class Difference:
    bundle: bytes
    action_index: int
    fields: tuple[str, ...]


def _object(value, label):
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _array(value, label):
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    return value


def _hex(value, width, label):
    if not isinstance(value, str) or len(value) != 2 + 2 * width or not re.fullmatch(r"0x[0-9a-f]+", value):
        raise ValueError(f"{label} must be a fixed {width}-byte lowercase hex value")
    return bytes.fromhex(value[2:])


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key}")
        result[key] = value
    return result


def _not_json(value):
    raise ValueError(f"{value} is outside JSON")


def _load(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_int=Decimal,
                      parse_float=Decimal, parse_constant=_not_json)


def _indexed_rows(rows, label):
    indexed = {}
    for row in _array(rows, label):
        if not isinstance(row, list) or len(row) != 2:
            raise ValueError(f"{label} row must be a two-element array")
        key = _hex(row[0], 32, "bundle key")
        if key in indexed:
            raise ValueError(f"duplicate bundle key in {label}: 0x{key.hex()}")
        indexed[key] = row[1]
    return indexed


def _result(raw):
    entry = _object(raw, "action result")
    user = _hex(entry["user"], 20, "response user")
    result = _object(entry["res"], "res")
    status, response = result["status"], result["response"]
    if status == "err" and isinstance(response, str):
        return Result(user, status, response)
    if status == "ok" and isinstance(response, dict):
        return Result(user, status, response)
    raise ValueError("response must be an err string or an ok object")


def _full(raw, source):
    if raw is None:
        return Unavailable(source, "null")
    variant = _object(raw, "resps")
    if set(variant) == {"Hash"}:
        _hex(variant["Hash"], 32, "response digest")
        return Unavailable(source, "Hash")
    if set(variant) != {"Full"}:
        raise ValueError("resps must be null or have exactly one known variant")
    return {
        key: tuple(_result(item) for item in _array(entries, "action results"))
        for key, entries in _indexed_rows(variant["Full"], "Full").items()
    }


def _json_value(value):
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, bool):
        # Python also considers True equal to decimal one. Keep JSON types here.
        return ("bool", value)
    return value


def _validate_alignment(response, counts, source):
    if response.keys() != counts.keys():
        raise ValueError(f"{source} Full bundle keys do not match the archive")
    for key, count in counts.items():
        if len(response[key]) != count:
            raise ValueError(f"{source} Full action count differs for bundle 0x{key.hex()}")


def compare(archive_line: bytes, replay_resps_json: bytes) -> tuple[Difference, ...] | Unavailable:
    """Align an archive row and an independent local response projection."""
    try:
        archive = _object(_load(archive_line), "archive row")
        archived = _full(archive["resps"], "archive")
        if isinstance(archived, Unavailable):
            return archived

        block = _object(archive["abci_block"], "abci_block")
        bundles = _indexed_rows(block["signed_action_bundles"], "signed_action_bundles")
        counts = {
            key: len(_array(_object(payload, "bundle payload")["signed_actions"], "signed_actions"))
            for key, payload in bundles.items()
        }
        _validate_alignment(archived, counts, "archive")
        replayed = _full(_load(replay_resps_json), "replay")
        if isinstance(replayed, Unavailable):
            return replayed
        _validate_alignment(replayed, counts, "replay")
    except KeyError as error:
        raise ValueError(f"missing field {error.args[0]}") from error

    differences = []
    for key in counts:
        for index, (actual, expected) in enumerate(zip(replayed[key], archived[key])):
            fields = tuple(name for name in ("user", "status", "response")
                           if _json_value(getattr(actual, name)) != _json_value(getattr(expected, name)))
            if fields:
                differences.append(Difference(key, index, fields))
    return tuple(differences)
