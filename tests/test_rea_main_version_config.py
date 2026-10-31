import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import rea


class MainVersionConfigTests(unittest.TestCase):
    def setUp(self):
        self._config = dict(rea.CONFIG)
        self._root = rea.ROOT
        self._tmp = tempfile.TemporaryDirectory()
        package = Path(self._tmp.name) / 'node_modules' / 'rea-agents'
        package.mkdir(parents=True)
        (package / 'package.json').write_text(json.dumps({'version': '6.8.0'}))
        rea.ROOT = Path(self._tmp.name)

    def tearDown(self):
        rea.CONFIG = self._config
        rea.ROOT = self._root
        self._tmp.cleanup()

    def _run(self, config):
        rea.CONFIG = config
        with patch.object(rea, 'find_node', return_value=Path('/tmp/node/bin/node')), \
                patch.object(rea, 'environment', return_value={}), \
                patch.object(rea.os, 'chdir', lambda *args: None), \
                patch.object(rea.os, 'execvpe') as execvpe:
            rea.main([])
            return execvpe

    def test_missing_version_fails_closed(self):
        # Sibling of open #359 (targets, main branch), #366 (provider,
        # target()), #361 (default_target) and #642 (targets, target()):
        # main()'s version comparison is the remaining bare CONFIG
        # subscript in rea.py, and the launcher's __main__ handler catches
        # only ValueError, so a config missing 'version' died with a raw
        # KeyError traceback instead of the one-line diagnostic.
        config = {k: v for k, v in self._config.items() if k != 'version'}
        with self.assertRaisesRegex(ValueError, 'missing version'):
            self._run(config)

    def test_present_version_still_launches(self):
        execvpe = self._run(dict(self._config))
        execvpe.assert_called_once()
        prog, argv = execvpe.call_args[0][0], execvpe.call_args[0][1]
        self.assertTrue(str(prog).endswith('node'))
        self.assertTrue(str(argv[1]).endswith('scripts/rea.mjs'))

    def test_missing_version_does_not_block_install(self):
        # The install branch never reads the version, so the guard must
        # sit at the comparison, not at the top of main().
        config = {k: v for k, v in self._config.items() if k != 'version'}
        rea.CONFIG = config
        with patch.object(rea, 'find_node', return_value=Path('/tmp/node/bin/node')), \
                patch.object(rea, 'environment', return_value={}):
            with self.assertRaisesRegex(ValueError, 'npm missing'):
                rea.main(['install'])


if __name__ == '__main__':
    unittest.main()
