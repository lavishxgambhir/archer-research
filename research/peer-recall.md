# Peer-recall development report

This pass preserves Route Discovery -> Peer Groups -> Authorization Invariants -> Drift Detection. Lemmy and Repo 2 are development/regression inputs. The two repositories reserved in `source-understanding-labels.json` remain uninspected and unscanned. No source code contains Lemmy-specific route, module or resource rules.

## Baseline diagnosis

The fixed Lemmy population has 17 scored endpoints, 136 possible pairs, 66 labeled positive pairs and 70 labeled negative pairs. The starting engine recovered 8 positive pairs, emitted no negative pairs, and missed 58 positive pairs (12.1% recall).

The following are source-reviewed PRIMARY buckets, not an independent causal ablation. Secondary causes overlap. Classification precedence is: distinct mount veto, explicit query receiver, report/view indirection, then missing canonical resource identity. Every missed pair and its handler source file/line is recorded in the new evaluation directory's `root-causes.json`.

| Primary cause | Missed pairs | Supporting source evidence |
|---|---:|---|
| Missing resource identity | 34 | `crates/db_schema/src/impls/site.rs:17` implements `Crud for Site`; the declaration in `source/site.rs` carries table metadata. Before this pass, implementations were indexed in their implementation-file namespace, and module-level schema imports were not canonical resource facts. `crates/db_views/site/src/impls.rs:57` illustrates a record reader. |
| Method/trait dispatch | 8 | `crates/api/api_crud/src/community/list.rs` constructs `CommunityQuery` and invokes `.list(...)`; `crates/db_views/community/src/impls.rs:128` defines that concrete receiver implementation. The old trace skipped receiver calls. |
| Indirect service/database access | 7 | `crates/api/api/src/reports/community_report/resolve.rs` calls `ReportCombinedViewInternal::read_community_report`; its implementation starts at `crates/db_views/report_combined/src/impls.rs:94`. Repository traits and SQL/view builders separate the handler from the owning data resource. |
| Overly restrictive grouping | 9 | `crates/api/routes/src/lib.rs:224` mounts creation at the parent scope, unlike other lifecycle endpoints. The baseline membership rule required identical `scope_prefix` values even for source-corroborated resource relationships. |
| Registration context | 0 | All sampled handlers resolve and share the same application key. Creation's distinct mount is real, not an unresolved registration. This does not prove every runtime mount in the repository. |

All paths above are relative to pinned Lemmy revision `ca5193d171987f19dc0891a225b9d0609b962a9d` under `target/peer-evaluation/heldout-lemmy/`.

## Targeted implementation

The changes stay in the existing analyzer/index and peer-analysis modules, with tests appended to existing test files. No dependencies or production modules were added.

1. Associate concrete inherent/trait implementations with the declared type's canonical crate/module identity while retaining the implementation's lexical context for imports and helper calls. Follow uniquely applicable in-scope traits and explicit default bodies. Generic specialization, dynamic dispatch, ambiguous traits and receiver-adjustment conflicts abstain.
2. Canonicalize Diesel table metadata and schema access across workspace dependency aliases. Follow resolved associated calls, concrete receiver calls, record fields and eligible service helpers within the existing eight-level bound. Transparent result aliases retain call-site namespaces. Opaque wrappers can permit inspection of a record-bearing helper without pretending to identify its receiver type.
3. Keep concrete receivers distinct from container payloads and futures. Scope-local shadowing, match/loop/closure bindings, unknown receiver types and assignments are treated conservatively. Ordinary discovery's legacy unique-name fallback remains available, but it is not accepted as resource proof.
4. Exclude security helpers and generic unit-returning utilities as independent resource witnesses. Discarded reads, including `let _ = ...`, are auxiliary. Unit-returning model methods need verified model/table ownership. Private query factories can be traced only where their visibility and owner are resolved. Cache identities distinguish crate, owner, implementation trait, source line and column.
5. Admit nested resource mounts only when a shared canonical source table corroborates their common route structure and application context. URL similarity alone is insufficient. Policy comparisons stay within the same mount context; collection/item/self differences do not automatically transfer roles, permissions or ownership requirements.
6. Retain direct pairwise group compatibility and overlapping groups. A route touching two resources can overlap two groups, but does not connect unrelated endpoints into one transitive group. Resource evidence and call-chain/abstention explanations are reported separately from security Unknown status.

The two-supporter, strict-majority, leave-target-out drift threshold is unchanged. Its helper body is compared against the baseline during verification. Authentication, roles, permissions and ownership remain distinct dimensions. No alternative thresholds were tested or selected.

## Measured results

| Lemmy annotated pairs | Before | After |
|---|---:|---:|
| True positives | 8 | 62 |
| False positives | 0 | 0 |
| False negatives | 58 | 4 |
| Precision | 100% | 100% |
| Recall | 12.1% | 93.9% |
| Annotated endpoints covered by a scored pair | 10/17 | 17/17 |

All eight original true positives remain. The combined improvements recover 54 of the 58 misses. These metrics apply only to the source-reviewed development population, not all whole-repository pairs or a fresh held-out benchmark.

| Current repository scan | Routes | Groups | Routes in groups | Invariants | Routes compared for drift | Unknown | Findings |
|---|---:|---:|---:|---:|---:|---:|---:|
| auth_actix | 6 | 1 | 2 | 1 | 0 | 0 | 0 |
| SeaORM / Repo 2 | 10 | 2 | 5 | 4 | 3 | 0 | 0 |
| Lemmy | 240 | 162 | 199 | 0 | 0 | 184 | 0 |

Group count is not an acceptance metric. The 162 groups overlap and have not all been independently labeled. Lemmy's 184 Unknown classifications and zero supported policy comparisons are unchanged by this resource-recall pass. More peer coverage has NOT established better natural vulnerability detection. Natural drift precision/recall and false-positive rates remain unavailable without validated vulnerability labels.

The source-reviewed handler targets remain correct on 6/6 auth_actix, 10/10 SeaORM and 20/20 Lemmy samples. That is not whole-repository method-resolution accuracy. Raw resource tracing establishes evidence on 215/240 Lemmy routes; 199/240 participate in groups. Every Lemmy route still has some partial-trace abstentions. These are distinct from security Unknown classifications. Overlapping groups repeat target/dimension abstention observations, so those counts must not be interpreted as unique routes.

## Remaining four misses

The labels are unchanged. The remaining pairs are:

- Delete community vs resolve community report.
- Get community vs create community.
- Create community vs resolve community report.
- Follow community vs resolve community report.

Two retain the baseline indirection bucket and two retain the baseline mount bucket. Owning-resource identity through report SQL/view construction and the direct witness needed to cross certain mounts remain insufficient. Do not infer ownership from similarly named types, bridge through a shared site/settings utility, or relax policy thresholds to recover them. `remaining-misses.json` records exact endpoints. No baseline true-positive pair was sacrificed for the higher aggregate recall.

## Verification and preservation

All 111 Rust tests pass, including the original 100. Six Python reporting tests pass. Added cases cover three arbitrary resource names, cross-crate services, trait defaults, aliases, nested mount policy differences, private query factories, competing traits, container receivers, pattern shadowing, shared cache/logging utilities, same-named methods, same-line trait cache entries, legacy name-guessing exclusions and non-transitive overlap.

Four other applications (REST, Diesel, PostgreSQL and MySQL) recover 21/21 annotated routes with no findings. Twelve preserved real-source mutation cases detect six injected positives with zero false positives and false negatives; all six controls remain clean. Existing permission, ownership, ignored-check, allowlist and middleware-placement regression cases remain intact. These controlled mutations are not naturally occurring vulnerabilities.

The pre-change source/binary snapshot and hashes are under `target/peer-recall-20261106-151715/baseline/`. The completed engine hash manifest is `peer-recall-engine-freeze.json`. Final reports, mutation results and preservation checks are in `peer-recall-verification/` in the same directory. Earlier diagnostic runs are retained as development history. Historical evaluation JSON/executable hashes and upstream Rust source hashes are checked unchanged; the Lemmy checkout stays clean. Nothing was committed or pushed.

## Reproduction

```
cargo test --locked --offline
python -m unittest discover -s research -p test_evaluate.py
cargo build --locked --offline
python research/evaluate.py --source-labels research/source-understanding-labels.json --auth AUTH_PATH --seaorm SEAORM_PATH --validation-root target/peer-evaluation --output-dir NEW_DIRECTORY
python research/evaluate.py --validation-root target/peer-evaluation --real-source-mutations --output-dir ANOTHER_NEW_DIRECTORY
```

Temporary mutation copies may require Windows permission approval. No upstream application code is executed. Keep the reserved final-evaluation repositories untouched until a separately frozen evaluation run; do not tune against their results afterward.

## Practical limits

This is bounded syntactic source analysis, not a Rust compiler, complete data-flow analysis, runtime security proof or primary-resource oracle. Macro-generated SQL, generic/trait-object dispatch, complex type aliases, implicit model relationships, unmodeled helper returns and contextual policies can still abstain or produce incomplete resource summaries. Unlabeled whole-repository groups require review. Source-understanding gains should be evaluated on unseen data before claiming generalized precision or natural drift accuracy.
