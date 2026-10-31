"""Keep ignored scratch files out of analysis of a committed Rust tree."""
import os
from pathlib import Path
import subprocess


def rust_files(directory: Path):
    repository = next((parent for parent in (directory, *directory.parents)
                       if (parent / '.git').exists()), None)
    if repository is None:
        # Explicit unversioned diagnostic views have no commit to enumerate.
        # They retain their old behavior, without gaining a provenance claim.
        return directory.rglob('*.rs')
    # Read the committed tree, not the user's index or ignore rules. A file
    # deliberately committed despite an ignore pattern is still an input.
    names = subprocess.check_output(
        ['git', '-C', str(repository), 'ls-tree', '-r', '--name-only', '-z', 'HEAD'],
        env=dict(os.environ, GIT_OPTIONAL_LOCKS='0'),
    )
    committed = {os.fsdecode(name) for name in names.split(b'\0') if name}
    return (path for path in directory.rglob('*.rs')
            if path.relative_to(repository).as_posix() in committed)
