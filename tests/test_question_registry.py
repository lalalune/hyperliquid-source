"""The pilot exposes discovery work and rejects broken prerequisite records."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('question_registry', ROOT / 'tools/question_registry.py')
REGISTRY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REGISTRY)


class QuestionRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / 'research/questions', self.root / 'research/questions')
        for relative in ('provenance/artifacts.json', 'research/components.json'):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)

    def change(self, question_id, mutate):
        target = self.root / 'research/questions' / (question_id + '.json')
        row = json.loads(target.read_text())
        mutate(row)
        target.write_text(json.dumps(row))

    def test_discovery_unknown_is_ready_while_its_consumer_stays_blocked(self):
        rows = {row['question_id']: row for row in REGISTRY.load_questions(self.root)}
        discovery = rows['qcp-expected-root-provenance']
        self.assertEqual(discovery['work_type'], 'discovery')
        self.assertEqual(discovery['readiness'], 'ready')
        self.assertEqual(discovery['dependencies'], [])
        self.assertEqual(rows['qcp-checkpoint-replay-root-fixture']['readiness'], 'blocked')
        _, rendered = REGISTRY.render_question_catalogue(self.root)
        ready = rendered.split('## Ready\n', 1)[1].split('## Evidence-recorded', 1)[0]
        self.assertIn('qcp-expected-root-provenance', ready)
        self.assertNotIn('qcp-checkpoint-replay-root-fixture', ready)
        self.assertIn('Reservation: **unknown**', rendered)

    def test_wrong_target_digest_is_rejected(self):
        self.change('qcp-expected-root-provenance', lambda row: row['target'].update(sha256='0' * 64))
        with self.assertRaisesRegex(ValueError, 'target digest differs'):
            REGISTRY.load_questions(self.root)

    def test_missing_dependency_reference_is_rejected(self):
        self.change('qcp-checkpoint-replay-root-fixture', lambda row: row['dependencies'][0].update(question_id='qcp-does-not-exist'))
        with self.assertRaisesRegex(ValueError, 'missing dependency'):
            REGISTRY.load_questions(self.root)

    def test_hard_dependency_cycle_is_rejected(self):
        self.change('qcp-expected-root-provenance', lambda row: row['dependencies'].append({
            'question_id': 'qcp-checkpoint-replay-root-fixture', 'kind': 'hard',
            'contract': 'counterfactual prerequisite', 'condition': 'must be established',
        }))
        with self.assertRaisesRegex(ValueError, 'hard dependency cycle'):
            REGISTRY.load_questions(self.root)

    def test_empty_acceptance_is_rejected(self):
        self.change('qcp-expected-root-provenance', lambda row: row.update(acceptance_requirements=[]))
        with self.assertRaisesRegex(ValueError, 'acceptance requirements'):
            REGISTRY.load_questions(self.root)

    def test_empty_consumer_is_rejected(self):
        self.change('qcp-expected-root-provenance', lambda row: row.update(downstream_consumer=''))
        with self.assertRaisesRegex(ValueError, 'downstream_consumer'):
            REGISTRY.load_questions(self.root)

    def test_invalid_prior_attempt_reference_is_rejected(self):
        self.change('qcp-expected-root-provenance', lambda row: row['prior_attempts'][0].update(url='https://example.invalid/pull/4157'))
        with self.assertRaisesRegex(ValueError, 'invalid prior pull request reference'):
            REGISTRY.load_questions(self.root)

    def test_duplicate_question_id_is_rejected(self):
        self.change('qcp-expected-root-provenance', lambda row: row.update(question_id='qcp-first-replay-key'))
        with self.assertRaisesRegex(ValueError, 'question ID does not match its filename'):
            REGISTRY.load_questions(self.root)

    def test_invalid_readiness_is_rejected(self):
        self.change('qcp-expected-root-provenance', lambda row: row.update(readiness='complete'))
        with self.assertRaisesRegex(ValueError, 'invalid readiness state'):
            REGISTRY.load_questions(self.root)


if __name__ == '__main__':
    unittest.main()
