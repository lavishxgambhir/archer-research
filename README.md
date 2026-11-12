# ARCHER

ARCHER is a Rust/Actix-Web research prototype for finding repository-local authorization inconsistencies. It infers supported requirements from related routes; findings require source review and may reflect legitimate policy differences. It does not establish the application's intended policy or prove that a repository is secure.

## Active pipeline

**Route Discovery → Peer Groups → Authorization Invariants → Drift Detection**

1. `src/analyzer.rs` indexes workspace source, imports, handlers and bounded calls. `registration.rs` expands supported route registrations, scopes and middleware mounts.
2. `policy_drift.rs` forms explicit resource-related peer groups independently of authorization. Relationships may overlap; shared utilities alone do not establish peers.
3. `security.rs` records authentication, role, permission and ownership requirements separately. It distinguishes observed rejection behavior from potential or unresolved checks.
4. `policy_drift.rs` infers supported invariants and compares targets with other peers. `reporting.rs` builds the graph and compares base/current reports.

Inference requires at least two agreeing supporters and a strict majority. Drift comparisons require two supporting **other** peers. Unknown enforcement, conflicting proposals and inadequate support cause abstention. These thresholds are unchanged by the release-correctness work.

`legacy.rs` is compiled only for historical tests. Production never calls its earlier inference or taxonomy implementation.

## Build and use

```powershell
cargo build --locked
cargo run --locked -- /path/to/repository
cargo run --locked -- /path/to/repository --json
cargo run --locked -- /path/to/repository --graph
cargo run --locked -- /path/to/repository --explain /roles/{id}
cargo run --locked -- /path/to/repository --diff HEAD~1 --json
```

Use `--offline` when dependencies are cached. The repository root is required for diff analysis. Paths and requirements in JSON carry source evidence; summary fields report discovered routes, groups, coverage, invariants, comparisons, findings and Unknown classifications separately.

### Security classifications

- **Protected:** observed authorization evidence under the supported source models. This is not proof of complete protection across every authorization dimension.
- **Unprotected:** no recognized authorization enforcement under the supported analysis. This is not proof that all possible enforcement is absent. An authentication-only route can have this coarse classification while its authentication requirement is observed separately.
- **Unknown:** unresolved handler, middleware, extractor or control-flow evidence prevents a reliable conclusion. Unknown is not an observed missing requirement.

Ignored boolean/Result checks, optional identities, unchecked extension insertion and unresolved dispatch must not automatically become enforced authorization. Required identity provenance remains unsupported in many real applications.

## Production taxonomy

Exactly three categories are emitted by the active comparison engine:

| Category | Actual comparison |
|---|---|
| `MissingEnforcement` | Supported authentication requirement is missing or deviates. |
| `MissingOwnershipValidation` | Supported ownership requirement is missing or deviates. This is a potential inconsistency, not a proven IDOR exploit. |
| `InconsistentRoleOrPermission` | Supported role/permission requirement is absent or differs. Role allowlists use set comparison; narrower allowlists are not treated as weaker, and no role hierarchy is assumed. |

`AuthenticationOnlyWithoutAuthorization`, `InconsistentMechanism` and `UnresolvedSecurityPosture` remain compatibility enum variants, not active production finding categories. Unresolved posture is reported through assessments and abstentions. A role requirement absent from an authentication-only route is reported in the role/permission category, not a separate authentication-only category.

## Change-aware analysis

`--diff <base-ref>` analyzes committed base source in a disposable Git-object snapshot, then analyzes the current working tree with the **same analyzer**. It does not check out, reset, stash or commit the user's repository. With no reference, the base is `HEAD~1`.

Finding identity uses HTTP method, literal route path, scope, matched application population, requirement dimension and sorted normalized expected policy values. Snapshot directories, source lines, group ordinals and changed-file membership do not define finding identity. Application correspondence requires unique endpoint overlap; ambiguous overlapping App populations fail explicitly rather than being merged.

JSON preserves the earlier fields and additionally reports:

- `newly_introduced_drifts`: supported current findings absent from base, excluding targets whose base enforcement is unresolved.
- `unchanged_drifts`: same route/requirement findings in both reports.
- `resolved_drifts`: removed routes or findings whose same requirement now has a supported satisfying comparison.
- `unverified_drifts`: disappearance into abstention/lost comparison support, a current finding whose prior target evidence was unresolved, or changed requirement identities whose equivalence cannot be verified. These are not verified fixes or newly introduced weaknesses.
- `regressions`: observed Protected→Unprotected transitions or a previously supported satisfying comparison that now deviates under the same expected contract. A new peer consensus alone is not proof of regression.
- `base_summary`, `current_summary`, `analysis_warnings`: coverage and unresolved registration diagnostics for both analyses.

Invalid references, Git failures, parse failures and unsupported snapshot source modes are errors. Git submodules and source symlinks are rejected. The snapshot includes tracked Rust source and Cargo manifests/locks; build scripts and procedural macros are not executed. Unresolved source-model coverage remains visible rather than being interpreted as security. Findings removed by changed peer support can remain unverified. Arbitrary source reorganizations or changed App populations may prevent correspondence.

## Authorization Relationship Graph

The ARG includes routes, application scopes, resolved module-qualified handlers, evidence, finding-backed contracts and findings. Handler identities include the application, definition file and qualified source path. Without a definition, graph construction uses a qualified call-site fallback scoped to its route rather than merging unresolved occurrences by short name.

Verified checks use enforcement relations; unresolved evidence uses `UnresolvedCheck` / `UnresolvedEvidence`. Potential identity evidence uses `PotentialEvidence`; an observed authentication check uses `ExtractsIdentity`. Graph evidence retains source locations. DOT identifiers, labels and edge endpoints escape quotes, backslashes and line breaks consistently.

## Reproducible live demonstration

The executable Actix app in `demo` uses public, fixed demo credentials to make denial behavior reproducible. **These fixtures are not production authentication.** Its role checks propagate errors, and ownership predicates actually reject requests. No no-op helper is presented as authorization.

```powershell
cargo build --locked
cargo run --locked -- demo --json
cargo test --manifest-path demo/Cargo.toml --locked
python demo/reproduce.py
python demo/reproduce.py --runtime
```

The reproduction script creates disposable copies and Git repositories. It never edits `demo/src/main.rs` or the caller's Git state. It verifies a clean baseline and three isolated enforcement-removal mutations, including real `--diff HEAD` output. `--runtime` also executes Actix request tests on each clean/mutated copy; cached demo dependencies are required.

Verified analyzer results:

| Demo | Routes | Groups / covered routes | Invariants | Compared routes | Findings |
|---|---:|---:|---:|---:|---:|
| Clean | 12 | 4 / 11 | 3 | 9 | 0 |
| Role check removed | 12 | 4 / 11 | 3 | 7 | 1 role/permission |
| Authentication check removed | 12 | 4 / 11 | 3 | 7 | 1 missing enforcement |
| Ownership rejection removed | 12 | 4 / 11 | 3 | 7 | 1 ownership |

The clean coarse classification is 8 Protected / 4 Unprotected / 0 Unknown: three authentication-only handlers account for three of the Unprotected labels. Authentication evidence is still observed for those handlers. Public `/public/info` and differing Member/Admin profile operations generate no findings. The two-member profile group has no common majority role contract and insufficient independent drift support; this is an abstention, not a proof that all differing policies are legitimate.

The source markers identify mutations for the reproduction script; detector code contains no demo-specific rules. All three production categories have production-pipeline regression tests. These are controlled demonstrations, not evidence of naturally occurring vulnerabilities or broad generalization.

To inspect the running app:

```powershell
cargo run --manifest-path demo/Cargo.toml --locked
curl.exe -X DELETE http://127.0.0.1:8088/roles/owned -H "Authorization: Bearer demo-member"
curl.exe -X DELETE http://127.0.0.1:8088/roles/owned -H "Authorization: Bearer demo-admin"
```

The clean app returns 403 then 200. Ownership requires `Bearer demo-owner` and resource ID `owned`; wrong credentials or a different resource are rejected.

## Verification and research limits

The current Rust suite contains **138 tests**, including the preserved 134 tests, plus **six Python reporting tests**. The demo has a separate Actix request test covering clean enforcement and legitimate policy differences. Reproduction additionally checks each mutation's actual HTTP behavior.

```powershell
cargo test --locked
python research/test_evaluate.py
```

Git-backed regression tests initialize only disposable fixture repositories. Restricted environments may need permission for those temporary Git operations. Existing compiler/cache warnings are not test failures.

Lemmy is development/regression data, not a held-out benchmark. Its last measured baseline has 240 routes, 162 groups, six role invariants, 190 Unknown and zero supported drift comparisons. Its 62 TP / 0 FP / 4 FN peer result is a labeled development sample, not whole-repository accuracy. The separate actual-source mutation baseline remains 3 TP / 0 FP / 5 FN; the older controlled fixtures remain 6 TP / 0 FP / 0 FN. Unmeasured natural-vulnerability metrics are unavailable, not zero.

Consumed rustypaste and Meilisearch results are regression data. Macro-generated registration, complex identity/database provenance, runtime dispatch and opaque middleware remain significant limitations. Bounded cross-crate/constructor tracing is supported where source establishes the target; ARCHER is not a full Rust compiler, symbolic executor or multi-framework frontend.

Current research notes are in `research/README.md`. Preserve historical evaluation evidence: generated snapshots, binaries and reports under ignored `target/` are not automatically included in ordinary Git pushes. Earlier evidence under `evidence/` remains historical, not rewritten by this release.

## Credits

ARCHER originated with Vidit Gupta. This repository contains subsequent research and evaluation work by Lavish Gambhir. Historical commit attribution is preserved.
