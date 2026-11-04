#!/usr/bin/env python3
"""Run the complete flat test file set with fresh imports for every file.

Some tests retain full captured images in module globals. Sequential children
release that memory after each file without changing any tests or suppressing
their ordinary unittest output. Packages need a separate discovery design;
refuse them instead of silently omitting their tests or load_tests hooks.
"""
import argparse
import ast
import os
import fnmatch
from pathlib import Path
import re
import subprocess
import sys


VALID_MODULE = re.compile(r'[_a-z]\w*\.py$', re.IGNORECASE)


def test_files(start):
    start = start.resolve()
    if not start.is_dir():
        raise ValueError('test start directory does not exist: ' + str(start))
    if any(start.rglob('__init__.py')):
        raise ValueError('isolated discovery requires a flat test directory, without packages')
    matching = [p for p in start.rglob('*.py') if p.is_file()
                and VALID_MODULE.match(p.name) and fnmatch.fnmatch(p.name, 'test*.py')]
    if any(p.parent != start for p in matching):
        raise ValueError('isolated discovery requires a flat test directory, without nested tests')
    return sorted(matching)



def test_command(python, start, path):
    """Keep unittest isolation while admitting function and script test suites."""
    if path is not None:
        try:
            tree = ast.parse(path.read_text())
        except (SyntaxError, UnicodeError):
            tree = None  # Let normal discovery report the original import error.
        if tree is not None:
            functions = any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                            and node.name.startswith('test_') for node in tree.body)
            pytest_classes = any(isinstance(node, ast.ClassDef)
                                 and node.name.startswith('Test')
                                 and not any(isinstance(base, ast.Attribute)
                                             and base.attr == 'TestCase'
                                             or isinstance(base, ast.Name)
                                             and base.id == 'TestCase'
                                             for base in node.bases)
                                 for node in tree.body)
            if functions or pytest_classes:
                return [*python, '-m', 'pytest', '-q', str(path.resolve())]
            methods = any(isinstance(node, ast.ClassDef)
                          and any(isinstance(child, ast.FunctionDef)
                                  and child.name.startswith('test_')
                                  for child in node.body) for node in tree.body)
            script = any(isinstance(node, ast.If)
                         and isinstance(node.test, ast.Compare)
                         and len(node.test.ops) == 1
                         and isinstance(node.test.ops[0], ast.Eq)
                         and {ast.unparse(node.test.left),
                              ast.unparse(node.test.comparators[0])}
                             in ({"__name__", "'__main__'"}, {"__name__", '"__main__"'})
                         for node in tree.body)
            if not methods and (script or any(isinstance(node, ast.Assert) for node in tree.body)):
                return [*python, str(path.resolve())]
    return [*python, '-m', 'unittest', 'discover', '-s', str(start.resolve()),
            '-p', path.name if path is not None else 'test*.py', '-v']


def run(start):
    files = test_files(start)
    # The stdlib helper also preserves -O/-B/-W/-X, as for multiprocessing.
    python = [sys.executable, *subprocess._args_from_interpreter_flags()]
    failed = 0
    # Even an empty directory keeps this interpreter's standard unittest result.
    for ordinal, path in enumerate(files or [None], 1):
        if path is not None:
            print(f'\n[{ordinal}/{len(files)}] {path.name}', file=sys.stderr, flush=True)
        command = test_command(python, start, path)
        try:
            env = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD='1')
            child = subprocess.Popen(command, env=env)
            try:
                returncode = child.wait()
            except BaseException:
                # Unlike Popen's special KeyboardInterrupt context exit, this
                # explicitly reaps the child even for a parent-only interrupt.
                child.kill()
                child.wait()
                raise
        except OSError as error:
            print(f'Could not start unittest child: {error}', file=sys.stderr, flush=True)
            failed += 1
        else:
            if returncode:
                print(f'Unittest child exited with status {returncode}',
                      file=sys.stderr, flush=True)
                failed += 1
    print(f'\nIsolated unittest discovery: {len(files)} files attempted; {failed} failed.',
          file=sys.stderr, flush=True)
    return int(bool(failed))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('start_directory', nargs='?', type=Path, default=Path('tests'))
    args = parser.parse_args(argv)
    try:
        return run(args.start_directory)
    except ValueError as error:
        parser.error(str(error))
    except KeyboardInterrupt:
        print('\nInterrupted; unittest inventory is incomplete.', file=sys.stderr, flush=True)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
