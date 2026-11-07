# ARCHER peer inference and evaluation

## Latest verified pass: source predicates and fresh evaluation (2026-11-08)

The pipeline remains Route Discovery -> Peer Groups -> separate authorization invariants -> Drift Detection. Source-verified typed boolean rejection helpers now retain canonical field predicates. Standard conditional Result aliases supply control-flow evidence only; they do not imply a payload type or validated identity. Ignored/conditional checks, opaque early-success macros, escaping arguments and differing source predicates retain conservative abstentions. No dependencies or production modules were added, and peer membership and numeric drift thresholds are unchanged.

Lemmy retains 240 routes, 162 groups, 199 covered routes and 62 TP / zero FP / four FN on its development peer sample. It now supports six role invariants covering 16 routes, but still zero supported drift comparisons/findings. Unknown rises from 183 to 190 because five conditional role checks and two inline rejection paths lose overly certain classifications. Verified authentication provenance remains incomplete. SeaORM retains two groups/four invariants/three compared routes, with two newly conservative Unknown classifications; auth_actix retains one group/one invariant and zero Unknown.

The new actual-source benchmark across three apps yields three TP / zero FP / five FN (37.5% recall), unchanged from the starting executable. The four controls produce no findings. All 125 Rust tests, six reporting tests and twelve earlier mutation expectations pass (six TP / zero FP / zero FN). Those older synthetic-helper fixtures are reported separately from actual enforcement mutations.

Fresh frozen V1 evaluation is poor: rustypaste yields zero TP / three FP / ten FN peer pairs and discovers six of eight literal route instances. A separately declared 20-route Meilisearch macro-coverage challenge discovers none of its routes and misses all 34 positive peer pairs. Neither supports invariants or drift comparisons. The challenge is not the original literal-builder protocol population; unmeasured natural accuracy remains unavailable. Broad generalization and improved mutation recall are not established.

After V1 evaluation, independent adversarial review prompted conservative safety fixes. The current V2 executable is frozen separately; replays have unchanged held-out metrics but are consumed-source regressions, not fresh generalization evidence for V2. Both repositories are now consumed data. Historical statements below that they are reserved describe earlier checkpoints.

Detailed source diagnosis, exact groups, separate metrics, real-source demonstration, methodological limitations, reproduction and next priorities: `target/enforcement-generalization-20261108/REPORT.md`. Frozen V1 is under `accepted/`; final V2 under `safety/`; earlier experimental reports remain preserved. All 132 historical evidence hashes captured before this pass match. Generated evidence/downloaded apps remain ignored under `target/`; preserve that directory separately when transferring the project. No commit or push was made.

## Latest verified pass: registration and constructor dispatch (2026-11-08)

Source-resolved legacy `.to_async` targets now follow the same registration and middleware expansion as current `.to` targets. Actix builder aliases are normalized only with a proven API origin; nested calls inside guards cannot supply a handler. Configuration delegates preserve their first `cfg` argument plus additional context arguments. Missing targets retain the existing null JSON representation and receive uncertainty evidence.

Resource tracing now carries constructor facts per receiver value through immutable bindings, standard Box/Arc/Rc/Data constructors, source-defined factories, named fields and bounded cross-crate calls. A trait target requires both a concrete value and its source-resolved trait implementation. Mutations, opaque factories, runtime selection and unknown injected state abstain. Facts are not attached globally to a service type; constructing one instance does not specialize every `Data<State>` parameter. Direct static receiver types remain usable after struct updates and ordinary field mutations.

All 122 Rust tests and six reporting tests pass. The twelve existing mutations retain six TP / zero FP / zero FN. The consumed Actix 1.x RealWorld case improves from zero to 19 correct handler targets, with zero incorrect targets; labeled peer recall remains 20% and all 19 security classifications remain Unknown. Across existing handler samples, 64 correct / 19 unresolved becomes 83 correct / zero unresolved / zero incorrect (mixed file/function and stricter file/path/line labels; development data). The original RealWorld still has 19 correct controller-to-service targets but unproven injected trait-repository provenance. No new natural invariants or drift comparisons are claimed. Lemmy retains 183 Unknown, 162 groups and its 62 TP / zero FP / four FN labeled peer result. Repo 2 and auth_actix retain classifications, groups, invariants and comparisons.

Details, remaining support boundaries and separate metrics: `target/registration-dispatch-20261108/REPORT.md`. Accepted snapshots and measurements are under `accepted/`; earlier failed development attempts remain separate. Fresh rustypaste and Meilisearch revisions are reserved by metadata only in `reserved-unseen.json`; their source has not been opened or scanned. No new dependencies or production modules, no changes to peer-membership/invariant/drift rules or authorization analysis, and no commits or pushes.

## Latest verified pass: generalization (2026-11-08)

The active pipeline remains Route Discovery -> Peer Groups -> separate authorization invariants -> Drift Detection. The older observations below are historical development checkpoints, not current totals.

The two former held-out repositories are now development cases. Their failures were source-understanding gaps: RealWorld's concrete application-state calls stopped before trait-object repositories, and the Actix example's unresolved competing glob imports prevented four attribute services from acquiring application/middleware context. Those declarations must remain Unknown. The two identity-gated password/account operations formerly reported Unprotected are no longer reported as known negatives.

Canonical Actix `Data` and standard `Arc`/`Rc` wrappers now expose concrete service receivers through nested state fields and existing cross-crate resolution. All 19 source-labeled RealWorld controller-to-service targets resolve correctly, compared with zero previously; no incorrect targets occur in that sample. Trait-object dispatch remains unsupported unless the existing resolver can prove the target. A bounded Diesel `table!` declaration index supports unambiguous table/dsl aliases without guessing model names. New table-query tracing skips deferred callbacks unless the supported execution target is proven. Historical syntactic callback handling is retained: attempting to restrict it globally broke the preserved mutation baseline, so that unrelated restriction was withdrawn before the final freeze. It remains a documented limitation.

There is no natural authorization/peer-recall gain in those two development applications yet: RealWorld retains 8 TP / 0 FP / 60 FN peer pairs and 20 Unknown; the Actix example retains 0 TP / 0 FP / 7 FN and now has six Unknown. Neither supports invariants or drift comparisons. More correctly resolved service calls do not establish database identity or authentication by themselves.

The final executable, implementation hashes and criteria were frozen before opening new evaluation sources. mCaptcha has two literal routes, both correctly resolved, both Unknown, and no supported comparisons; its 54 symbolic custom-codegen route declarations are outside the frozen literal population. The reserved LibreSpeed revision was ineligible because it has no Actix-Web dependency. A recorded replacement, fairingrey's older Actix RealWorld implementation, has 19/19 method/path registrations discovered, but 0/19 handlers resolved due to unsupported `.to_async`. Its labeled peer result is 8 TP / 0 FP / 32 FN (20% recall), with 19 Unknown and no supported invariants/comparisons. Its shared RealWorld specification limits domain diversity. Single-analyst source labels and these small samples do not establish broad generalization or natural vulnerability accuracy.

All 118 Rust tests, six reporting tests and twelve existing mutation expectations pass (six positive detections, zero false positives/misses). Repo 2 retains two groups/four dimension-specific invariants/three compared routes; auth_actix retains one group/one invariant; Lemmy retains 183 Unknown and 62 TP / 0 FP / 4 FN on its development peer sample. Their route classifications, memberships, invariants and findings are unchanged. All 263 historical evidence files checked retain their hashes. No dependencies, production modules, grouping rules, invariant thresholds or drift thresholds were added or changed by this pass. No commit or push was made.

Detailed source causes, metrics, limits, next priorities and an end-to-end test demonstration: `target/general-purpose-20261108-000542/REPORT.md`. Reproduce the fresh frozen scans with `python target/general-purpose-20261108-000542/stage-c/reproduce.py`. Generated reports, binaries and downloaded evaluation repositories remain under `target`; production source remains under `src`. Frozen evaluation repositories are now consumed evaluation data, not a future unseen set.

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

## Awaited authorization helpers (2026-11-07)

The next bounded source-understanding change handles `check_permission("edit").await?` and resolved cross-crate wrappers that propagate or return an awaited result. Parentheses and invisible expression groups preserve the consumed value. Ignored futures/results, unresolved targets, recursive summaries, deferred closures and deferred async blocks do not independently establish enforcement. The existing eight-level bound and all peer/invariant/drift thresholds are unchanged. This remains evidence of a possible rejection path, not proof that every request executes the check.

The production flow remains route discovery, authorization-independent peer groups, separate authentication/role/permission/ownership invariants, then conservative drift comparisons. No modules or dependencies were added. The implementation changes only `security.rs`; two existing test files cover 13 cross-crate helper cases (four accepted, nine negative controls) and five end-to-end permission mutations (two detected changes and three clean/abstaining controls). All 113 Rust tests and six Python reporting tests pass; all 12 pre-existing real-source mutations retain their expectations (six TP, zero FP/FN).

Development results: auth_actix and SeaORM metrics are unchanged; their annotated peer pairs remain 1/1 and 4/4. Lemmy remains 62 TP / 0 FP / 4 FN on the same development sample. Handler labels remain 36/36 correct across these three repositories, with no incorrect resolutions or unresolved labeled targets. The four additional applications still recover 21/21 route labels. Lemmy Unknown changes from 184 to 182 because two awaited helper calls are now observed. Source review confirms that the helper rejects a user without moderator/admin eligibility; one caller executes it conditionally. Role values remain unavailable, so neither call produces a role invariant. Lemmy still has zero supported drift comparisons and zero findings; natural vulnerability precision/recall remain unavailable. These are development results, not held-out generalization claims.

The baseline source/executable snapshot, overlapping authorization-abstention counters, pre-evaluation implementation/criteria freeze, new reports and preservation verification are in `target/authorization-evidence-20261107-002459/`. Historical reports and the public evidence archive are unchanged. Reserved repositories remain uninspected. Reproduce with the commands above and the mutation evaluator documented in `peer-recall.md`, writing to a new output directory.

## Bounded extractor and middleware provenance (2026-11-07)

Custom `FromRequest` implementations now resolve across indexed workspace crates and renamed imports. The supported rejection form returns a ready result from an extension lookup, cloning the present value and rejecting absence. Required and standard optional extractor parameters are reported separately. A missing extension alone is not authentication evidence. An observed authentication fact additionally requires a mounted Transform/Service implementation to insert the matching concrete type, produced through resolved helpers from verified JWT decoding of a credential from that request, and then forward the same request. Immutable local App-builder bindings preserve their middleware and concrete mount identity; shadowing, separate App instances, conditional wrappers, unchecked values and extension removal cannot borrow that proof.

This is a bounded first implementation, not general identity data-flow analysis. The initial credential source model is a required request cookie; the validation model is `jsonwebtoken::decode` with inline default validation. Supported value flow includes projections, concrete tuple-record constructors and straight-line resolved helpers, with an eight-call bound. It does not prove deployment key trust or whole-program dominance. Header parsing helpers, customized validation, arbitrary adapters, database-to-user mappings, conditional insertion and more complex Service futures abstain. Optional extraction never creates a mandatory authentication fact. Existing unresolved middleware remains unresolved even when an extractor fact is observed, so the drift safeguards remain in force.

All 114 Rust tests and six Python reporting tests pass. The added AST fixture matrix covers 18 configurations / 57 mounted route instances: nine expected verified authentication classifications, zero incorrect promotions, zero misses on the supported positive paths, and 48 non-promotions/abstentions. Positive configurations infer authentication invariants; the fixtures do not establish runtime or natural-vulnerability accuracy. The existing 12 real-source mutation cases retain six TP / zero FP / zero FN. All seven development applications retain their peer memberships, invariants and findings; original handler-resolution labels remain correct.

Lemmy now has explicit rejection evidence for 163 required extractor routes and recognized optional-extractor evidence for 17 routes. Session middleware is visible on 220 routes after recovering the bound App context. Its full identity-production chain remains unsupported, so no new Lemmy authentication facts, invariants or drift comparisons are claimed. Unknown changes from 182 to 183: `/pictrs/image/{file}` previously lacked its App middleware evidence and is now conservatively Unknown. The 183-route inventory contains 125 required-extractor provenance abstentions, 17 recognized optional-extractor cases, 12 additional optional signatures with unsupported resolution/shape, 28 other middleware cases and one unresolved closure. These primary diagnostic buckets overlap secondary middleware uncertainty. Peer labels remain 62 TP / 0 FP / 4 FN; natural authentication accuracy and false-negative rates remain unavailable.

Baseline source/executable snapshots and hashes are in `target/extractor-provenance-20261107-012552/`. `implementation-freeze-final.json` records criteria and source hashes before final development scans. `final/` contains reports, a route-by-route Unknown ledger, mutation results and `verification.json`. Historical evidence and reserved evaluation sources are preserved. No peer rules, policy dimensions, drift thresholds, dependencies or production modules were added or changed by this pass; the existing resource type resolver is reused for security type identity. No commits or pushes were made.

## Success-preserving identity wrappers (2026-11-07)

The diagnostic chain has separate unsupported links: middleware creates its Service future after cloning self fields; a cross-crate helper extracts an optional request credential; validation uses a local default configuration and an error adapter; claims are parsed into an ID used in a database lookup; nested successful Option branches insert the resulting user. Extractor rejection and mount context were already available. Recognizing one of these links does not establish the whole chain.

This pass extends the existing value summaries with immutable local default validation, typed standard Result error mapping, uniquely scoped source-defined error adapters whose body preserves the successful value through `self.map_err`, Result-to-Option-to-Result success propagation, explicit concrete From/TryFrom implementations, struct construction, typed local bindings, return expressions and bounded helper chains. Ambiguous conversions/adapters and generic Result-name shadowing abstain. String-preserving token operations retain request origin. Service futures may have immutable self-field clones before construction and response work after awaiting forwarding of the same request. Opaque local calls before forwarding and shadowed Result constructors cannot be skipped as if they were harmless. No peer or policy rules were changed.

The fixed AST fixture comparison uses 39 configurations and 120 mounted route instances. The previous executable correctly supports 15 authentication cases, misses 24 supported cases and makes six unsupported promotions on the opaque-request-effect and shadowed-constructor controls. The new implementation supports all 39 expected positive cases, misses none of those supported cases and makes no unsupported promotions; the remaining 81 instances do not receive verified authentication facts. Emitted authentication invariants change from seven to thirteen; two former invariant emissions belong to unsupported controls and are removed. Drift comparisons remain zero because unresolved middleware is still retained. Fixture peer memberships are identical. These are syntactic regression labels, not runtime or natural-vulnerability accuracy estimates.

All 114 Rust tests and six reporting tests pass. The twelve preserved real-source mutation cases retain six TP / zero FP / zero FN. All seven development applications retain their per-route security classifications, peer memberships, invariants and findings. Lemmy remains at 183 Unknown, 38 Protected, zero supported invariants and zero drift comparisons. Its 125 required-extractor provenance abstentions, 17 recognized optional cases, 12 optional signatures with unsupported resolution/shape, 28 other middleware cases and one unresolved closure remain unchanged. The annotated peer sample remains 62 TP / zero FP / four FN. Natural authentication accuracy and false-positive/negative rates remain unavailable.

Lemmy's first remaining provenance boundary is the request credential helper's optional header/cookie return paths. Claim parsing, database key-to-returned-row identity and conditional successful insertion also remain unproven. No database method is treated as authentication merely because it accepts a validated ID, and optional identity, token issuance or response filtering does not become a mandatory contract. The improved wrapper mechanisms therefore do not yet justify new Lemmy authentication facts. Baseline code/binary, before/after fixtures, frozen implementation hashes, reports, Unknown inventory and preservation checks are in `target/identity-wrappers-20261107-015050/`; final application evidence is under `final/`. Reserved evaluation sources remain untouched, historical evidence is preserved, and nothing was committed or pushed.
