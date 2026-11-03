import unittest
from lab import Attempt, decision, experiment, workload, run_pipeline

class LabTests(unittest.TestCase):
    def row(self, **changes):
        values = dict(identity='synthetic', source='shared', legitimate=True, known_device=True,
                      suspicious_fingerprint=False, challenge_passes=True, correct_password=True)
        values.update(changes)
        return Attempt(**values)

    def test_success_requires_correct_password(self):
        result = run_pipeline([self.row(correct_password=False)], True)
        self.assertFalse(result['events'][0]['accepted'])
        self.assertTrue(result['events'][0]['verified'])

    def test_challenge_failure_avoids_hash(self):
        row = self.row(known_device=False, suspicious_fingerprint=True, challenge_passes=False)
        result = run_pipeline([row], True)
        self.assertEqual(result['counts'].get('verifications', 0), 0)
        self.assertEqual(result['counts']['legitimate_blocked'], 1)

    def test_successful_challenge_still_checks_password(self):
        row = self.row(known_device=False, suspicious_fingerprint=True, correct_password=False)
        event = run_pipeline([row], True)['events'][0]
        self.assertTrue(event['verified'])
        self.assertFalse(event['accepted'])

    def test_shared_source_can_block_legitimate_user(self):
        row = self.row(known_device=False, suspicious_fingerprint=True)
        self.assertEqual(decision(row, 2)[0], 'reject')

    def test_bounded_deterministic_workload(self):
        self.assertEqual(workload(), workload())
        for count in (0, 201, True, '20'):
            with self.assertRaises(ValueError): workload(count=count)
        with self.assertRaises(ValueError): workload(scenario='https://external.example')

    def test_comparison_accounting(self):
        result = experiment(count=20)
        self.assertEqual(result['baseline']['counts']['verifications'], 20)
        self.assertEqual(result['avoided'] + result['protected']['counts'].get('verifications', 0), 20)
        for event in result['protected']['events']:
            if event['accepted']: self.assertTrue(event['verified'])

if __name__ == '__main__': unittest.main()
