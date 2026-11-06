# ARCHER peer inference and evaluation

## Current architecture

Route Discovery -> Peer Group Formation -> Authorization Invariant Inference -> Drift Detection.

Repo 2 (SeaORM) lost two groups because production grouping used policy-transfer eligibility as membership: identical HTTP methods and database operations were required. This excluded GET/PUT/DELETE on one user resource. Sibling action paths lacked qualifying shared database evidence. Independently, inference required two OTHER supporters, preventing a two-member group from establishing an invariant.

Resource membership now permits cross-operation normalized resources, shared database resources, and sibling actions beneath the same parameterized resource, within application and mount boundaries. Conflicting known database resources reject membership. Public operational and authentication routes are excluded from these broader relationships. Bounded handler traversal supplies data-access evidence; security helpers do not establish resource identity. Direct pairwise groups allow overlap without merging incompatible transitive neighbors. Broad sibling URLs alone remain insufficient.

A group invariant requires at least two unambiguous observed supporters and a strict majority. Drift requires two supporting OTHER peers. Unknown enforcement and conflicting overlapping proposals abstain. Roles, permissions, authentication and ownership remain separate requirements. Narrower role allowlists are not treated as weakened protection. Group coverage and supported drift-comparison coverage are separate counts. Candidate relationships remain internal, omitted from normal CLI/JSON reports. Diagnostics explain groups without inferred invariants and routes without supported comparisons.

## Regression observations

| Source | Routes | Groups | Group coverage | Invariants | Findings |
|---|---:|---:|---:|---:|---:|
| SeaORM / Repo 2 | 10 | 2 | 5 | 2 | 0 |
| auth_actix | 6 | 0 | 0 | 0 | 0 |
| rust-actix-example | 8 | 2 | 5 | 0 | 0 |
| Actix Diesel | 2 | 0 | 0 | 0 | 0 |
| Lemmy | 240 | 23 | 58 | 0 | 0 |

SeaORM groups contain GET/PUT/DELETE /api/users/{id} and PATCH /api/users/{id}/{restore,soft-delete}. Both support UserRole::Admin. The three-member group permits three held-out comparisons; the two-member group establishes an invariant but lacks enough independent supporters for drift detection. Restoring grouping does not imply restoring unsafe policy transfer.

## Reproduction

```
cargo test --locked --offline
cargo build --locked --offline
python research/evaluate.py --validation-root target/peer-evaluation
python research/evaluate.py --validation-root target/peer-evaluation --real-source-mutations
```

Pinned clones must already exist; external application code is never executed. Real-source mutations use isolated temporary copies and may need Windows permission approval. Generated clones, binaries and evaluation outputs stay under target/peer-evaluation. Labels are in ground-truth.json; they were reviewed by the implementing assistant, not an independent human auditor.

The existing 90 tests are preserved. Added regression cases cover three distinct resource names across role removal/change controls, cross-method membership independent of policy, two-member invariant inference, and unrelated structural siblings. The existing matrix covers permission/ownership mutations, each target position, uncertainty, allowlists, overlapping conflicts, registration and negative controls.

## Historical validation context

Previous evaluation used ddimaria/rust-actix-example d4cdc238c88c09ea748ef5f42243d96b682caf31 and actix/examples 4d2df245c67b5219b78e489cd27d60cdcc72e637 (Diesel, PostgreSQL, MySQL). It recovered 21/21 annotated routes and 22/22 candidate pairs with zero supported comparisons. Those candidate metrics describe the previous engine, not current peer-group accuracy. Twelve controlled Diesel source mutations previously detected six injected positives and emitted no findings on six controls. These are injected findings, not natural vulnerability accuracy.

Lemmy ca5193d171987f19dc0891a225b9d0609b962a9d was originally held out. The frozen audit recovered 20/20 sampled endpoints, with candidate precision 67.6% and recall 37.9%, zero supported comparisons and zero findings. Its frozen executable and hashes remain under target/peer-evaluation. Lemmy has now been inspected and is a regression baseline, not a fresh held-out evaluation. No rules are specialized to its names or Repo 2.

## Limitations

This is bounded static analysis, not a whole-program enforcement proof. Cross-crate methods/traits, arbitrary extractors and middleware, dynamic SQL, query macros, and combined policies remain incomplete. Resource evidence is syntactic rather than precise data flow. Structural resource identity can still conceal legitimate operation-specific exceptions; findings require review. Dense graph handling uses direct cliques/triangles rather than exhaustive maximal-clique enumeration. Natural vulnerability precision and recall remain unestablished. Zero findings with zero supported comparisons is abstention, not a successful security assessment.

## Controlled maintenance verification

The active production path is documented in the root README. Legacy prototype inference is test-only. The maintenance refactor preserves detection rules, report fields and evidence wording; it consolidates repeated support counting, comparison keys and invariant construction.

Run evaluator reporting regressions with `python -m unittest discover -s research -p test_evaluate.py`. Missing/null candidate observations produce null pair metrics and coverage; an explicitly measured empty relationship list produces zero coverage when routes exist. Historical reports are left as recorded. Do not interpret their historical candidate fields as current peer-group measurements.

Refactor verification uses a separate `target/refactor-verification/` directory. It compares JSON content and CLI line multisets against pre-refactor snapshots on demo, SeaORM, auth_actix, REST, Diesel, PostgreSQL, MySQL and Lemmy, allowing existing unordered collection iteration. All 93 Rust tests, four evaluator reporting tests and 12 real-source mutation cases pass. Existing evaluation JSON and executable hashes are checked for preservation. These checks establish regression equivalence on those inputs, not natural vulnerability accuracy.

## Source-understanding development pass

The current engine loads Cargo metadata with `--frozen --no-deps --format-version 1`, without building applications, fetching dependencies, or updating their lockfiles. It follows only indexed path dependencies, including workspace-inherited dependencies and aliases. Module/type/function re-exports are traversed segment by segment. External paths require public exports; unknown dependencies, private paths, cycles and ambiguous imports abstain. Resolution provenance includes the actual target file, function path and source line; a resolved flag is not a correctness metric.

Security assessment reuses the discovery index. Resolved helper aliases retain their call-site spelling for argument/control-flow analysis. Returned error branches and propagated helper results are supported; ignored results and cyclic/depth-limited summaries are not promoted to enforcement. Existing named role-middleware models follow resolved constructors and implementation modules, including aliases/re-exports. Arbitrary middleware and receiver/trait dispatch remain unsupported rather than guessed.

Resolved record converters must return an indexed record and project fields from an indexed input record. Their evidence can connect collection/item/self-resource operations without naming any special route. Unit-returning shared helpers and shared context parameters alone do not establish resource identity. Authentication observations can agree across these routes; role, permission and ownership comparisons do not transfer across different path shapes. Existing same-shape comparisons remain available. These are bounded syntactic facts, not whole-program data flow.

`analysis_evidence` separates peer membership, invariant dimensions and target drift comparisons. Confidence is ordinal, with explicit evidence and abstention reasons. No numerical confidence probability is claimed. All four dimensions remain distinct. Two supporters and a strict majority are still required; drift leaves the target out. No alternative thresholds were tested or selected.

Development labels and two reserved, source-uninspected final repository revisions are in `source-understanding-labels.json`. The source-reviewed handler sample contains 6 auth_actix, 10 SeaORM and 20 Lemmy targets; it is not an independent audit of all handlers. The resolver regression matrix additionally checks exact definitions and required abstentions on renamed dependencies/imports, public/private exports, multiple globs, missing dependencies and cycles. Frozen historical labels and reports are unchanged.

Reproduction (provide your local paths):

```
cargo test --locked --offline
python -m unittest discover -s research -p test_evaluate.py
cargo build --locked --offline
python research/evaluate.py --source-labels research/source-understanding-labels.json --auth AUTH_PATH --seaorm SEAORM_PATH --validation-root target/peer-evaluation --output-dir NEW_OUTPUT_DIRECTORY
```

The pre-change source/binary snapshot, manifest, reports and new results are under `target/source-understanding-20261106-140333/`. Do not delete that directory as ordinary build cache. The reserved repositories have not been cloned, inspected, or scanned; the final evaluation protocol must be applied before using them. Lemmy and Repo 2 are development/regression cases.

### Measured development results (current source-understanding pass)

| Dataset | Routes | Peer groups | Routes in groups | Invariants | Routes compared | Unknown | Drift findings |
|---|---:|---:|---:|---:|---:|---:|---:|
| auth_actix | 6 | 1 | 2 | 1 | 0 | 0 | 0 |
| SeaORM | 10 | 2 | 5 | 4 | 3 | 0 | 0 |
| Lemmy | 240 | 29 | 76 | 0 | 0 | 184 | 0 |

Auth_actix's collection/self group supports authentication, not a shared role policy. SeaORM retains both Admin-role invariants and now records authentication separately. Lemmy's unresolved handlers decreased from 161 to 1, but this is coverage, not correctness. Source-reviewed handler targets match 6/6, 10/10 and 20/20 respectively, with zero incorrect resolutions in those samples. Whole-repository resolution accuracy is not established. The 18-case synthetic path-resolution matrix separately checks nine exact target definitions and nine required abstentions, including private/glob/re-export/alias decoys.

On the versioned resource-peer labels, auth_actix has 1/1 expected pair and SeaORM 4/4, with no extra pairs. Lemmy's annotated population has 8 true-positive pairs, zero false-positive pairs and 58 false-negative pairs: precision 100%, recall 12.1%. This conservative sampled recall is unchanged from the frozen pre-change engine under the same labels. The 29 whole-repository groups are not all source-labeled; do not extrapolate sampled precision to all of them. The new auth_actix resource label intentionally differs from historical strict policy-family labels; historical metrics are preserved.

All 100 Rust tests (including the original 93) and five Python reporting tests pass. Twelve real-Diesel-source mutations produce six true positives, zero false positives and zero false negatives; six negative/control cases emit none. Added tests cover generic collection/item/self selectors, legitimate role differences, missing authentication, alias enforcement, ignored wrapper results, cycles, cross-crate middleware placement and unresolved-import decoys. These synthetic results do not establish natural-vulnerability accuracy. The other four validation applications recover 21/21 route labels with zero findings.

The final reports are in `corrected-development/`, mutation evidence in `mutations-final/`, and the binary/source hash manifest in `final-verification-manifest.json`, all inside the new source-understanding directory. Historical evaluation JSON/executable hashes and upstream Rust source hashes were verified unchanged; the Lemmy checkout remains clean. Earlier development reports, including the caught middleware re-export regression, are retained rather than overwritten.

Remaining limitations include arbitrary middleware semantics, associated receiver/trait dispatch, complex macro-generated code, cross-crate type/data-flow identity, and implicit policy values. A resolved handler can still have Unknown security behavior. There are no natural drift findings on these baselines, and no evidence supports relaxing thresholds yet. Reserved final-evaluation sources remain uninspected.

## Peer-recall development pass

See [peer-recall.md](peer-recall.md) for the source-reviewed 58-pair root-cause breakdown, bounded tracing changes, adversarial controls and unchanged safety thresholds. On the fixed Lemmy development labels, peer pairs improve from 8 TP / 0 FP / 58 FN to 62 TP / 0 FP / 4 FN (93.9% recall). All baseline pairs remain. This does not establish whole-repository precision or improved natural drift detection: Unknown remains 184 and supported drift comparisons remain zero. The two reserved evaluation sources remain uninspected. Final evidence lives under `target/peer-recall-20261106-151715/peer-recall-verification/`; historical evidence is preserved.
