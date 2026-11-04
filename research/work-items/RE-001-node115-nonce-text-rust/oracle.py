#!/usr/bin/env python3
"""Independent abstract admission/value oracle; never reads captured code.

The grammar is a byte regular expression, values are mathematical integers,
and ordering is a relation over a completed sequence. This is not an emulator,
native parser-state model, numeric-helper model, or allocator model.
"""

from dataclasses import dataclass
import re

WHITE = rb"[\x09\x0a\x0d\x20]*"
INTEGER = rb"(?:0|[1-9][0-9]*)"
OPENING = re.compile(WHITE + rb"\[")
PREFIX = re.compile(
    WHITE + rb"\[" + WHITE
    + rb"(?P<body>(?:" + INTEGER
    + rb"(?:" + WHITE + rb"," + WHITE + INTEGER + rb")*)?)"
    + WHITE + rb"\]"
)
DECIMAL_WORD = re.compile(rb"[0-9]+")
U64_MAX_DECIMAL = b"18446744073709551615"


@dataclass(frozen=True)
class Outcome:
    kind: str
    consumed: int | None = None
    values: tuple[int, ...] = ()


def evaluate(data: bytes, mode: int, depth: int) -> Outcome:
    """Chosen value result, conditional on successful own host resources.

NotAdmitted is logical non-admission, with no native termination guarantee.
Only a parsed outcome has a consumption observation. Raw mode/depth cover all
byte values. Source resource outcomes are outside this mathematical oracle.
    """
    if not isinstance(data, bytes):
        raise TypeError("the chosen input domain is bytes")
    if type(mode) is not int or type(depth) is not int:
        raise TypeError("mode and depth are integer byte values")
    if not (0 <= mode <= 255 and 0 <= depth <= 255):
        raise ValueError("mode and depth must lie in 0..255")
    if OPENING.match(data) is None:
        return Outcome("not-admitted")
    if mode == 0 and depth == 0:
        return Outcome("depth-zero")
    if mode == 0 and depth == 1:
        return Outcome("depth-one")

    complete = PREFIX.match(data)
    if complete is None:
        return Outcome("not-admitted")
    lexemes = DECIMAL_WORD.findall(complete.group("body"))
    # Lexical magnitude bounds avoid Python's long decimal conversion limit.
    # Every surviving token is canonical and at most twenty decimal digits.
    if any(len(word) > len(U64_MAX_DECIMAL)
           or (len(word) == len(U64_MAX_DECIMAL) and word > U64_MAX_DECIMAL)
           for word in lexemes):
        return Outcome("not-admitted")
    values = tuple(int(word, 10) for word in lexemes)
    if any(left >= right for left, right in zip(values, values[1:])):
        return Outcome("order-invariant")
    return Outcome("parsed", complete.end(), values)


def output_line(case_id: str, result: Outcome) -> str:
    if result.kind == "parsed":
        words = ",".join(str(word) for word in result.values) or "-"
        return f"{case_id}\tparsed\t{result.consumed}\t{words}\n"
    return f"{case_id}\t{result.kind}\n"


def input_line(case_id: str, mode: int, depth: int, data: bytes) -> str:
    return f"{case_id}\t{mode}\t{depth}\t{data.hex() or '-'}\n"
