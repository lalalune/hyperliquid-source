"""Build a fixed Rust dependency, change its consumer's flags, and compare output."""
from pathlib import Path
import subprocess
import tempfile

SOURCE = Path(__file__).with_suffix(".rs")


def run_control():
    print(subprocess.check_output(["rustc", "-V"], text=True).strip())
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        library = root / "libchecked_dependency.rlib"
        common = ["rustc", str(SOURCE), "--edition=2021", "-Copt-level=2",
                  "-Cpanic=unwind"]
        subprocess.run(common + ["--cfg", "dependency", "--crate-name", "checked_dependency",
                                 "--crate-type", "rlib", "-Coverflow-checks=yes",
                                 "-o", library], check=True)
        for checks, root_boundary in [("yes", "panic"), ("no", "value(0)")]:
            executable = root / "consumer"
            subprocess.run(common + ["--extern", f"checked_dependency={library}",
                                     f"-Coverflow-checks={checks}", "-o", executable], check=True)
            observed = subprocess.check_output([executable], text=True).splitlines()
            print(f"dependency=yes root={checks}", *observed, sep="\n")
            expected = [f"dependency max-1={2**64-1} max=panic",
                        f"root max-1={2**64-1} max={root_boundary}"]
            if observed != expected:
                raise SystemExit(f"expected {expected!r}, observed {observed!r}")


if __name__ == "__main__":
    run_control()
