"""Decode the archived #115 replay header and supply its preflight comparands."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re

U64_MAX = 2**64 - 1


@dataclass(frozen=True)
class Hardfork:
    version: int
    round: int

    @property
    def words(self) -> tuple[int, int]:
        return (self.version, self.round)


@dataclass(frozen=True)
class ReplayHeader:
    height: int
    prev_round: int
    new_round: int
    time: str
    proposer: bytes
    hardfork: Hardfork

    def pipeline_comparands(self, restored_hardfork: Hardfork) -> dict[str, tuple[int, int]]:
        """Supply the two tuple values under the Rust pipeline's existing field names."""
        return {
            "state_time": restored_hardfork.words,
            "block_parent_time": self.hardfork.words,
        }


def object_from_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key}")
        result[key] = value
    return result


def _u64(value, name) -> int:
    if type(value) is not int or not 0 <= value <= U64_MAX:
        raise ValueError(f"{name} must be an unsigned 64-bit integer")
    return value


def _object(value, name) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    return value


def _reject_constant(value):
    raise ValueError(f"{value} is outside JSON")


def load_header(raw: bytes, *, expected_height: int | None = None) -> ReplayHeader:
    """Decode one archived row. A heightless row needs an external shard coordinate."""
    try:
        record = _object(json.loads(raw.decode("utf-8"), object_pairs_hook=object_from_pairs,
                                    parse_constant=_reject_constant), "replica row")
        if expected_height is not None:
            _u64(expected_height, "external height")
        if "height" in record:
            height = _u64(record["height"], "record height")
            if expected_height is not None and height != expected_height:
                raise ValueError("record height disagrees with external height")
        elif expected_height is None:
            raise ValueError("missing external height for heightless record")
        else:
            height = expected_height

        block = _object(record["abci_block"], "abci_block")
        hardfork = _object(block["hardfork"], "abci_block.hardfork")
        time = block["time"]
        if not isinstance(time, str) or not re.fullmatch(
            r"(?:[0-9]{4}|[+-][0-9]{4,})-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?", time
        ):
            raise ValueError("time must be a zone-free ISO timestamp string")
        proposer = block["proposer"]
        if not isinstance(proposer, str) or not re.fullmatch(r"0x[0-9a-f]{40}", proposer):
            raise ValueError("proposer must be a fixed 20-byte lowercase hex string")
        return ReplayHeader(
            height=height,
            prev_round=_u64(block["parent_round"], "parent_round"),
            new_round=_u64(block["round"], "round"),
            time=time,
            proposer=bytes.fromhex(proposer[2:]),
            hardfork=Hardfork(_u64(hardfork["version"], "hardfork.version"), _u64(hardfork["round"], "hardfork.round")),
        )
    except KeyError as error:
        raise ValueError(f"missing field {error.args[0]}") from error
