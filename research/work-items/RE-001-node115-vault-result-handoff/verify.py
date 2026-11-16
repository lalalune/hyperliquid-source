"""Static wrapper relation only; never executes captured code."""
from pathlib import Path
import hashlib
import importlib.util
import json
import re
import struct
import subprocess

BASE = Path("research/work-items/RE-001-node115-vault-diagnostic")
spec = importlib.util.spec_from_file_location("vault_coordinates", BASE / "verify.py")
coordinates = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coordinates)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def structural(data):
    binding = coordinates.structural(data)
    def at(va, size):
        offset = binding["instruction_file_offset"] + va - coordinates.XREF
        return data[offset:offset + size]
    def expect(va, raw, message):
        expected = bytes.fromhex(raw)
        require(at(va, len(expected)) == expected, message)

    # No path or stack adjustment is omitted between the Location load and call.
    expect(0x283c6b0, "534881eca00000004889d04989f24889fb48c7442418000000008b5210895424100f10000f2904244883ec08", "wrapper prelude")
    expect(0x283c6e3, "488d7c2438488d5424084c8d4c24204889ce31c94531c04153415250", "argument setup and push order")
    require(at(0x283c6ff, 1) == b"\xe8", "direct call opcode")
    target = 0x283c704 + struct.unpack("<i", at(0x283c700, 4))[0]
    require(target == 0x2c39ab0, "direct call destination")
    expect(0x283c704, "4883c420b00e66817c2430a201", "stack restoration and result comparison")
    require(at(0x283c711, 1) == b"\x74", "equal branch opcode")
    taken = 0x283c713 + struct.unpack("<b", at(0x283c712, 1))[0]
    require(taken == 0x283c75a, "equal branch destination")
    expect(0x283c713, "0f288424900000000f2943700f288424800000000f2943600f284424700f2943500f284424300f284c24400f285424500f285c24600f295b400f2953300f294b200f294310b00f", "non-equal payload projection and tag")
    expect(0x283c75a, "88034889d84881c4a00000005bc3", "shared tag store and return")
    return {
        "target_sha256": coordinates.DIGEST,
        "wrapper_fde": [hex(binding["start"]), hex(binding["end"])],
        "source": binding["source"], "line": binding["line"], "column": binding["column"],
        "location_va": hex(binding["location"]), "location_load_va": hex(binding["xref"]),
        "call_va": "0x283c6ff", "direct_target_va": hex(target),
        "location_stack_offset_at_callee_entry": "0x18",
        "output_pointer_setup_va": "0x283c6e3",
        "result_comparison_va": "0x283c70a", "result_word": "[restored rsp+0x30]",
        "comparison_immediate": "0x1a2", "equal_destination": hex(taken),
        "equal_output_tag": "0x0e", "non_equal_output_tag": "0x0f",
        "non_equal_copy": {"source_stack_offsets": [hex(x) for x in range(0x30, 0xa0, 0x10)],
                           "output_offsets": [hex(x) for x in range(0x10, 0x80, 0x10)], "bytes": 7 * 16},
        "validated_relations": 1, "selected_relation_denominator": 1,
        "limits": "Static argument placement and result projection only; no callee consumption, runtime reachability, accounting semantics, equivalence or completed gate."
    }


def verify(path=coordinates.TARGET):
    data = path.read_bytes()
    require(len(data) == 105896032 and hashlib.sha256(data).hexdigest() == coordinates.DIGEST, "target size/SHA256")
    result = structural(data)
    command = ["objdump", "-d", "-Mintel", "--start-address=0x283c6b0", "--stop-address=0x283c768", str(path)]
    native = subprocess.check_output(command, text=True, timeout=20)
    for address, instruction in [("283c6dc", "lea"), ("283c6ff", "call"), ("283c70a", "cmp"), ("283c711", "je"), ("283c75a", "mov")]:
        require(re.search(r"^\s*" + address + r":\s+(?:[0-9a-f]{2}\s+)+" + instruction + r"\s", native, re.M), "native aligned instruction " + address)
    result["native_command"] = command
    return result


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
