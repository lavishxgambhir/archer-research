"""Reproduce scans and evaluate against manually authored application-route labels.

Usage: python research/evaluate.py --auth PATH --seaorm PATH
Requires a built target/debug/archer executable. Does not modify input repositories.
"""
import argparse
from collections import Counter
import itertools
import hashlib
import json
import pathlib
import subprocess
import tempfile
import shutil

ROOT = pathlib.Path(__file__).resolve().parents[1]


def comparison(expected, actual):
    matched = expected & actual
    return {'expected': len(expected), 'actual': len(actual), 'true_positive': len(matched),
            'false_positive': len(actual - expected), 'false_negative': len(expected - actual),
            'precision': len(matched) / len(actual) if actual else None,
            'recall': len(matched) / len(expected) if expected else None}


def candidate_metrics(report, expected_pairs):
    """Missing discovery observations are unavailable, not an empty measured set."""
    relationships = report.get('candidate_relationships')
    if relationships is None:
        return {'candidate_pairs': None, 'candidate_coverage': None}
    identity = lambda r: (r['method'], r['path'], r['handler'])
    routes = {identity(r) for r in report['routes']}
    pairs = {tuple(sorted((identity(report['routes'][r['left']]),
                           identity(report['routes'][r['right']])))) for r in relationships}
    pairs = {p for p in pairs if p[0] != p[1]}
    return {'candidate_pairs': comparison(expected_pairs, pairs),
            'candidate_coverage': len(set(itertools.chain.from_iterable(pairs))) / len(routes) if routes else None}


def evaluate_validation(base, binary, output_dir):
    labels = json.loads((ROOT / 'research/ground-truth.json').read_text())['_validation']
    results = {'criteria': labels['criteria'], 'datasets': {}}
    identity = lambda r: (r['method'], r['path'], r['handler'])
    pair = lambda a, b: tuple(sorted((tuple(a), tuple(b))))
    for dataset in labels['datasets']:
        path = base / dataset['path']
        revision = subprocess.run(['git', '-C', str(path), 'rev-parse', 'HEAD'], check=True, capture_output=True, text=True).stdout.strip()
        if revision != dataset['revision']:
            raise RuntimeError(f"Pinned revision mismatch: {path}")
        report = json.loads(subprocess.run([str(binary), str(path), '--json'], check=True, capture_output=True, text=True).stdout)
        actual_routes = {identity(r) for r in report['routes']}
        expected_routes = {tuple(r) for r in dataset['routes']}
        expected_pairs = {pair(*p) for p in dataset['candidate_pairs']}
        findings = {identity(f['suspicious_route']) for f in report['finding_details']}
        metrics = {
            'revision': revision,
            'route_extraction': comparison(expected_routes, actual_routes),
            'raw_route_observations': len(report['routes']),
            'duplicate_observations': len(report['routes']) - len(actual_routes),
            **candidate_metrics(report, expected_pairs),
            'contract_coverage': report['summary'].get('peer_compared_routes'),
            'drift_targets': comparison({tuple(r) for r in dataset['drift_targets']}, findings),
            'summary': report['summary'], 'parse_errors': report['parse_errors'],
            'source_sha256': {s: hashlib.sha256((path / s).read_bytes()).hexdigest() for s in dataset['sources']},
        }
        results['datasets'][dataset['name']] = metrics
        if output_dir:
            (output_dir / (dataset['name'] + '-report.json')).write_text(json.dumps(report, indent=2), encoding='utf-8')
    if output_dir:
        (output_dir / 'validation-metrics.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(json.dumps(results, indent=2))


def evaluate_real_source_mutations(base, binary, output_dir):
    """Mutate real Diesel handler bodies in isolated copies; never run the apps.

    Added role checks and route aliases are controlled fixtures, not claims of
    vulnerabilities in the original application. Original DB access is retained.
    """
    origin = base / 'validation-examples/databases/diesel'
    expected_revision = '4d2df245c67b5219b78e489cd27d60cdcc72e637'
    revision = subprocess.run(['git', '-C', str(origin), 'rev-parse', 'HEAD'], check=True, capture_output=True, text=True).stdout.strip()
    if revision != expected_revision:
        raise RuntimeError('Mutation source revision mismatch')
    original = (origin / 'src/main.rs').read_text()
    handler = original[original.index('#[get("/user/{user_id}")]'):original.index('/// Creates new user.')]
    start = ') -> actix_web::Result<impl Responder> {'
    if handler.count(start) != 1:
        raise RuntimeError('Pinned handler extraction changed')
    prefix = original[:original.index('/// Finds user by UID.')]
    helper = '''
fn check_role(role: &str) -> Result<(), actix_web::Error> {
    if std::env::var("ARCHER_MUTATION_ROLE").ok().as_deref() != Some(role) {
        return Err(actix_web::error::ErrorForbidden("role mismatch"));
    }
    Ok(())
}
'''
    cases = [('baseline', 'check_role("Admin")?;', False),
             ('wrong_role', 'check_role("User")?;', True),
             ('missing_role', '', True),
             ('ignored_result', 'check_role("Admin");', False)]
    records = []
    for name, change, positive in cases:
        for target in range(3):
            with tempfile.TemporaryDirectory(prefix='archer-real-source-') as tmp:
                copy = pathlib.Path(tmp) / 'app'
                shutil.copytree(origin, copy)
                handlers = []
                for i in range(3):
                    check = change if i == target else 'check_role("Admin")?;'
                    changed = handler.replace('get_user', f'read_{i}').replace('/user/{user_id}', f'/resource_{i}/{{user_id}}')
                    handlers.append(changed.replace(start, start + '\n    ' + check))
                app = 'fn app() { App::new().service(read_0).service(read_1).service(read_2); }'
                (copy / 'src/main.rs').write_text(prefix + helper + '\n'.join(handlers) + app)
                report = json.loads(subprocess.run([str(binary), str(copy), '--json'], check=True, capture_output=True, text=True).stdout)
                actual = {f['suspicious_route']['handler'] for f in report['finding_details']}
                expected = {f'read_{target}'} if positive else set()
                records.append({'mutation': name, 'position': target, **comparison(expected, actual),
                                'routes': report['summary']['total_routes'],
                                'unknown': report['summary']['unknown_routes'],
                                'passed': actual == expected and not report['parse_errors']})
    totals = {k: sum(r[k] for r in records) for k in ['true_positive', 'false_positive', 'false_negative']}
    tp, fp, fn = (totals[k] for k in ['true_positive', 'false_positive', 'false_negative'])
    result = {'source_revision': revision, 'note': 'Controlled mutations of real source, not naturally occurring vulnerabilities; no application code executed.',
              'cases': records, 'totals': {**totals, 'precision': tp/(tp+fp) if tp+fp else None, 'recall': tp/(tp+fn) if tp+fn else None}}
    if output_dir:
        (output_dir / 'real-source-mutations.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))
    if not all(r['passed'] for r in records):
        raise SystemExit('Real-source mutation expectation failed')


def source_metrics(report, labels):
    """Score labeled targets; a resolved flag alone never counts as correct."""
    identity = lambda r: (r['method'], r['path'], r['handler'])
    pair = lambda a, b: tuple(sorted((tuple(a), tuple(b))))
    scope = {tuple(r) for r in labels['peer_scope']}
    predicted = set()
    for group in report['peer_groups']:
        members = {identity(r) for r in group['routes']} & scope
        predicted.update(pair(a, b) for a, b in itertools.combinations(members, 2))
    peer_members = set(itertools.chain.from_iterable(predicted))
    targets = {tuple(t['route']): t['file'].replace('\\', '/') for t in labels['handler_targets']}
    resolution = None
    if 'handler_resolution_evidence' in report:
        observed = {identity(e['route']): e for e in report['handler_resolution_evidence']}
        correct = incorrect = unresolved = 0
        for route, expected in targets.items():
            evidence = observed.get(route, {})
            actual = evidence.get('definition_file')
            if actual is None:
                unresolved += 1
            elif (actual.replace('\\', '/').endswith('/' + expected)
                  and evidence.get('definition_path', '').split('::')[-1] == route[2]):
                correct += 1
            else:
                incorrect += 1
        resolution = {'labeled': len(targets), 'correct': correct, 'incorrect_resolutions': incorrect,
                      'unresolved': unresolved, 'precision': correct / (correct + incorrect) if correct + incorrect else None,
                      'accuracy': correct / len(targets) if targets else None}
    invariant_dimensions = {}
    for invariant in report['invariants']:
        words = invariant['description'].split()
        if len(words) > 1 and words[0] == 'Supported':
            invariant_dimensions[words[1]] = invariant_dimensions.get(words[1], 0) + 1
    invariant_regressions = {dimension: {'expected_minimum': count, 'actual': invariant_dimensions.get(dimension, 0),
                                        'passed': invariant_dimensions.get(dimension, 0) >= count}
                            for dimension, count in labels.get('expected_invariant_dimensions', {}).items()}
    summary = report['summary']
    resource_rows = report.get('resource_evidence')
    resource_coverage = None
    if resource_rows is not None and len(resource_rows) == summary['total_routes']:
        covered = sum(bool(r['resources']) for r in resource_rows)
        resource_coverage = {'routes_with_evidence': covered, 'total': len(resource_rows),
                             'fraction': covered / len(resource_rows) if resource_rows else None,
                             'routes_with_abstentions': sum(bool(r['abstention_reasons']) for r in resource_rows)}
    stages = report.get('analysis_evidence')
    drift_abstentions = None if stages is None else dict(Counter(reason for e in stages if e['stage'] == 'drift' for reason in e['abstention_reasons']))
    statuses = {}
    for assessment in report['security_assessments']:
        status = assessment['route']['status']['status']
        statuses[status] = statuses.get(status, 0) + 1
    return {'peer_pairs': comparison({pair(*p) for p in labels['peer_pairs']}, predicted),
            'peer_population_coverage': {'covered': len(peer_members), 'labeled_routes': len(scope), 'fraction': len(peer_members) / len(scope) if scope else None},
            'handler_resolution': resolution, 'invariant_regressions': invariant_regressions,
            'policy_comparison_coverage': {'compared': summary['peer_compared_routes'], 'total': summary['total_routes'],
                                           'fraction': summary['peer_compared_routes'] / summary['total_routes'] if summary['total_routes'] else None},
            'resource_coverage': resource_coverage, 'drift_abstentions': drift_abstentions,
            'classifications': statuses, 'summary': summary, 'parse_errors': report['parse_errors'],
            'natural_findings': {'emitted': len(report['finding_details']), 'precision': None, 'recall': None,
                                 'false_positives': None, 'note': 'No independently validated natural drift labels; zero findings is not proof of security'}}


def evaluate_source_understanding(args, binary):
    labels = json.loads(args.source_labels.read_text(encoding='utf-8'))
    paths = {'auth_actix': args.auth, 'seaorm': args.seaorm, 'lemmy': str(args.validation_root / 'heldout-lemmy')}
    results = {'criteria': labels['criteria'], 'datasets': {}}
    for name, dataset in labels['datasets'].items():
        path = pathlib.Path(paths[name])
        if dataset.get('revision'):
            revision = subprocess.check_output(['git', '-C', str(path), 'rev-parse', 'HEAD'], text=True).strip()
            if revision != dataset['revision']:
                raise RuntimeError('Pinned revision mismatch: ' + str(path))
        report = json.loads(subprocess.check_output([str(binary), str(path), '--json'], text=True))
        metrics = source_metrics(report, dataset)
        metrics['source_sha256'] = {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(path.rglob('*.rs')) if 'target' not in p.relative_to(path).parts}
        results['datasets'][name] = metrics
        if args.output_dir:
            (args.output_dir / (name + '-report.json')).write_text(json.dumps(report, indent=2), encoding='utf-8')
    if args.output_dir:
        (args.output_dir / 'source-metrics.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    print(json.dumps(results, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--auth')
    parser.add_argument('--seaorm')
    parser.add_argument('--validation-root', type=pathlib.Path)
    parser.add_argument('--binary', type=pathlib.Path)
    parser.add_argument('--source-labels', type=pathlib.Path, help='Versioned source-resolution and resource-peer development labels')
    parser.add_argument('--real-source-mutations', action='store_true')
    parser.add_argument('--output-dir', type=pathlib.Path, help='Optional directory for saved reports; default prints metrics only')
    args = parser.parse_args()
    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
    binary = ROOT / 'target' / 'debug' / 'archer.exe'
    if not binary.exists():
        binary = binary.with_suffix('')
    binary = args.binary.resolve() if args.binary else binary
    if args.source_labels:
        if not args.auth or not args.seaorm or not args.validation_root:
            parser.error('--source-labels requires --auth, --seaorm and --validation-root')
        evaluate_source_understanding(args, binary)
        return
    if args.validation_root:
        if args.real_source_mutations:
            evaluate_real_source_mutations(args.validation_root, binary, args.output_dir)
            return
        evaluate_validation(args.validation_root, binary, args.output_dir)
        return
    if not args.auth or not args.seaorm:
        parser.error('--auth and --seaorm are required unless --validation-root is supplied')
    labels = json.loads((ROOT / 'research' / 'ground-truth.json').read_text())
    results = {}
    for name, path in [('auth_actix', args.auth), ('seaorm', args.seaorm), ('demo', str(ROOT / 'demo'))]:
        completed = subprocess.run([str(binary), path, '--json'], check=True, capture_output=True, text=True)
        report = json.loads(completed.stdout)
        if args.output_dir:
            (args.output_dir / f'{name}-after.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
        expected = {tuple(row[:3]): row[3] for row in labels[name]['routes']}
        actual = {(r['method'], r['path'], r['handler']): r for r in report['routes']}
        matched = expected.keys() & actual.keys()
        auth_kinds = {'RoleCheck', 'PermissionCheck', 'AuthorizationGuard', 'AuthorizationMiddleware', 'OwnershipCheck', 'ManualAuthorizationCheck'}
        correct = 0
        labeled = 0
        for key in matched:
            wanted = expected[key]
            if wanted is None:
                continue
            labeled += 1
            route = actual[key]
            kinds = {e['kind'] for e in route['authorization']}
            status = 'Protected' if kinds & auth_kinds else ('Unknown' if 'Unknown' in kinds or (route['handler_resolution'] or {}).get('kind') in {'Unresolved', 'Ambiguous'} else 'Unprotected')
            correct += status == wanted
        actual_pairs = set()
        for group in report['peer_groups']:
            members = [(r['method'], r['path']) for r in group['routes']]
            actual_pairs.update(tuple(sorted(pair)) for pair in itertools.combinations(members, 2))
        wanted_pairs = set()
        for group in labels[name]['peer_groups']:
            wanted_pairs.update(tuple(sorted(tuple(member) for member in pair)) for pair in itertools.combinations(group, 2))
        results[name] = {
            'extraction': {'matched': len(matched), 'expected': len(expected), 'actual': len(actual), 'recall': len(matched) / len(expected), 'precision': len(matched) / len(actual) if actual else None},
            'authorization': {'correct_on_matched_labeled_routes': correct, 'matched_labeled_routes': labeled, 'accuracy': correct / labeled if labeled else None},
            'peers': {'expected_pairs': len(wanted_pairs), 'actual_pairs': len(actual_pairs), 'matched_pairs': len(wanted_pairs & actual_pairs), 'precision': len(wanted_pairs & actual_pairs) / len(actual_pairs) if actual_pairs else None, 'recall': len(wanted_pairs & actual_pairs) / len(wanted_pairs) if wanted_pairs else None},
            'findings': {'actual_count': len(report['finding_details']), 'expected_count': labels[name]['expected_findings'], 'precision': None, 'recall': None, 'note': 'No validated positive vulnerability corpus; precision/recall are not established'},
            'summary': report['summary'],
            'parse_errors': report['parse_errors'],
            'source_sha256': {str(p.relative_to(pathlib.Path(path))): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(pathlib.Path(path).rglob('*.rs'))},
        }
        if name == 'demo':
            results[name]['peers'] = {'precision': None, 'recall': None, 'note': 'Demo security primitives are stubs; policy peers are not ground-truth labeled'}
    output = json.dumps(results, indent=2)
    if args.output_dir:
        (args.output_dir / 'metrics.json').write_text(output, encoding='utf-8')
    print(output)


if __name__ == '__main__':
    main()
