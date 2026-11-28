"""Build the live Debug formatters for the recorded Linux target with whole-program ThinLTO."""
import os
from pathlib import Path
import subprocess
import tempfile


RUSTC = ["rustup", "run", "1.95.0", "rustc"]
TARGET = "x86_64-unknown-linux-gnu"


def build_objects(source, flags):
    # Older packet recipes include rustup's selector among the compiler flags.
    if flags[:1] == ["+1.95.0"]:
        flags = flags[1:]
    crate_name = flags[flags.index("--crate-name") + 1]
    args = [*RUSTC, *flags, "--target", TARGET]
    linker = os.environ.get("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER")
    if linker:
        args.extend(["-C", f"linker={linker}"])
    with tempfile.TemporaryDirectory(prefix="node115-thinlto-") as temp:
        # Request a real link: --emit=obj alone omits cross-crate ThinLTO imports.
        subprocess.run([*args, str(source), "-o", crate_name], cwd=temp, check=True)
        paths = sorted(Path(temp).glob(f"{crate_name}.{crate_name}.*.rcgu.o"))
        if not paths:
            raise ValueError(f"No primary ThinLTO object produced for {crate_name}")
        return [path.read_bytes() for path in paths]
