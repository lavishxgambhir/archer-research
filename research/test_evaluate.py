"""Reporting regressions; no clones, builds or application execution required."""
import unittest
from evaluate import candidate_metrics, source_metrics


class CandidateMetricsTests(unittest.TestCase):
    def setUp(self):
        self.routes = [{'method': 'GET', 'path': '/' + name, 'handler': name}
                       for name in ['one', 'two']]

    def test_missing_and_null_observations_are_unavailable(self):
        for extra in [{}, {'candidate_relationships': None}]:
            result = candidate_metrics({'routes': self.routes, **extra}, set())
            self.assertIsNone(result['candidate_pairs'])
            self.assertIsNone(result['candidate_coverage'])

    def test_measured_empty_relationships_have_zero_coverage(self):
        result = candidate_metrics({'routes': self.routes, 'candidate_relationships': []}, set())
        self.assertEqual(result['candidate_coverage'], 0)
        self.assertEqual(result['candidate_pairs']['actual'], 0)
        self.assertIsNone(result['candidate_pairs']['precision'])

    def test_observed_pairs_have_measured_coverage(self):
        report = {'routes': self.routes, 'candidate_relationships': [{'left': 0, 'right': 1}]}
        expected = {(('GET', '/one', 'one'), ('GET', '/two', 'two'))}
        result = candidate_metrics(report, expected)
        self.assertEqual(result['candidate_coverage'], 1)
        self.assertEqual(result['candidate_pairs']['precision'], 1)
        self.assertEqual(result['candidate_pairs']['recall'], 1)

    def test_empty_inventory_has_no_coverage_denominator(self):
        self.assertIsNone(candidate_metrics({'routes': [], 'candidate_relationships': []}, set())['candidate_coverage'])


class SourceMetricsTests(unittest.TestCase):
    def test_wrong_target_is_not_a_correct_resolution(self):
        route = {'method': 'GET', 'path': '/records', 'handler': 'list'}
        labels = {'peer_scope': [], 'peer_pairs': [], 'handler_targets': [{'route': ['GET', '/records', 'list'], 'file': 'src/right.rs'}]}
        report = {'peer_groups': [], 'invariants': [], 'summary': {'peer_compared_routes': 0, 'total_routes': 1}, 'security_assessments': [], 'parse_errors': [], 'finding_details': []}
        self.assertIsNone(source_metrics(report, labels)['handler_resolution'])
        for file, correct, incorrect, unresolved in [('C:/project/src/right.rs', 1, 0, 0), ('C:/project/src/decoy.rs', 0, 1, 0), (None, 0, 0, 1)]:
            report['handler_resolution_evidence'] = [{'route': route, 'definition_file': file, 'definition_path': 'crate::list'}]
            metrics = source_metrics(report, labels)['handler_resolution']
            self.assertEqual((metrics['correct'], metrics['incorrect_resolutions'], metrics['unresolved']), (correct, incorrect, unresolved))


    def test_missing_resource_observations_are_not_zero_coverage(self):
        labels = {'peer_scope': [], 'peer_pairs': [], 'handler_targets': []}
        report = {'peer_groups': [], 'invariants': [], 'summary': {'peer_compared_routes': 0, 'total_routes': 1}, 'security_assessments': [], 'parse_errors': [], 'finding_details': []}
        self.assertIsNone(source_metrics(report, labels)['resource_coverage'])
        self.assertIsNone(source_metrics(report, labels)['drift_abstentions'])
        report['resource_evidence'] = [{'resources': [], 'abstention_reasons': ['No supported identity']}]
        measured = source_metrics(report, labels)['resource_coverage']
        self.assertEqual(measured['routes_with_evidence'], 0)
        self.assertEqual(measured['routes_with_abstentions'], 1)


if __name__ == '__main__':
    unittest.main()
