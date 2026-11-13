# Backend packaging verification

Verified 14 November 2026 on Windows with rustc 1.99.1, Cargo 1.99.1, Python 3.13 and curl 8.22.0. This is the current research implementation, not ARCHER Core. All 23 src Rust files, Cargo.toml, Cargo.lock and the OpenAPI specification are byte-identical to the original working tree. No analyzer algorithm, threshold, classification, diagnostic or informational analysis was changed.

## Executed checks

| Check | Result |
| --- | --- |
| Clean build from a new staging target directory, default features, locked/offline | Passed |
| API-enabled locked/offline build, both binaries | Passed |
| Release API/CLI build, locked/offline | Passed |
| Default Rust suite | 153 passed, zero failed/ignored |
| API-enabled unit suite | 158 passed, zero failed/ignored |
| HTTP/worker Rust integration suite | 4 passed |
| Live HTTP/OpenAPI 3.1 checks | Passed: public health/spec, auth, jobs/status/result/ARG/delete, schemas, privacy/topology/header parity and three demo mutation categories |
| Fresh generated snapshot graph acceptance | Two different repository snapshots, clean and weakened; distinct job-derived DOT; JSON/Graphviz/SVG topology matches |
| Actual GitHub archive ingestion | Passed for allowlisted pinned ddimaria/rust-actix-example |
| Release-binary HTTP/ARG smoke tests | Passed for fresh clean/weakened snapshots; release CLI demo has 12 routes and zero findings |
| Hostile graph labels, duplicate handlers and unresolved evidence | Passed retained Graphviz/escaping regression |
| Original-versus-packaged development/mutation reports | 24 full reports equivalent after canonicalizing list order; duplicate list items preserved |

The accepted real GitHub source was `https://github.com/ddimaria/rust-actix-example` at `d4cdc238c88c09ea748ef5f42243d96b682caf31`. The backend performed its real bounded network fetch and archive extraction. It returned eight routes, two peer groups covering five routes, eight Unknown routes, zero inferred invariants/comparisons/findings, and an ARG with 34 nodes/31 edges which rendered successfully. This is functional ingestion and honest abstention, not a claim of verified security.

The fresh controlled acceptance sources have random per-run route prefixes. The weakened job has three routes, one peer group, one inferred invariant, one finding and an 11-node/12-edge ARG. The clean job has three routes, one peer group, one invariant, zero findings and a 10-node/9-edge ARG. These generated fixtures are independent of old graph files. The Rust backend never invokes Graphviz; only the local development test does.

## Fetch restriction observed in practice

A separate real fetch of pinned `actix/examples` (`4d2df245c67b5219b78e489cd27d60cdcc72e637`) was correctly rejected with `invalid_source: Links and special archive entries are prohibited`. The strict archive policy rejects links/special entries anywhere in the archive, including entries unrelated to accepted Rust source. It was not weakened to make that repository pass. Repository admission therefore depends on both the allowlist and a supported archive/path/manifest layout, as well as size/time limits.

## Critical analyzer regressions

| Input | Routes | Peer groups | Covered routes | Invariants | Compared routes | Findings | Informational contrasts |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| realworld | 20 | 6 | 13 | 0 | 0 | 0 | 3 |
| actix-realworld | 19 | 5 | 13 | 0 | 0 | 0 | 3 |
| seaorm | 10 | 2 | 5 | 4 | 3 | 0 | 0 |
| auth_actix | 6 | 1 | 2 | 1 | 0 | 0 | 0 |
| rest | 8 | 2 | 5 | 0 | 0 | 0 | 0 |
| diesel | 2 | 1 | 2 | 0 | 0 | 0 | 0 |
| postgres | 2 | 1 | 2 | 0 | 0 | 0 | 0 |
| mysql | 9 | 4 | 8 | 0 | 0 | 0 | 0 |
| rustypaste | 8 | 1 | 3 | 0 | 0 | 0 | 0 |
| mcaptcha | 2 | 0 | 0 | 0 | 0 | 0 | 0 |
| meilisearch_macro_challenge | 3 | 0 | 0 | 0 | 0 | 0 | 0 |
| mutation-lemmy-clean | 240 | 162 | 199 | 6 | 0 | 0 | 0 |

RealWorld retains its six groups and three informational contrasts; none of the Core edition removals were applied. It still has 20 Unknown routes, no supported comparisons and no findings. SeaORM retains its actual peer groups, four invariants, three compared routes, and all four detected actual-source mutation cases (`missing_role`, `different_role`, `missing_both`, `wrong_mount`).

The complete frozen actual-source suite remains **4 TP / 0 FP / 4 FN**, identical to the original executable. Four expected weakened operations remain missed; packaging did not improve recall. Multiple requirement findings for one operation count as one operation-level TP. No natural vulnerability precision is inferred from these development mutations.

## Dependency closure and retained exceptions

- `demo/src/main.rs` is embedded by an analyzer regression test via `include_str!("../../demo/src/main.rs")`; it is essential test source. Demo manifests/lockfile and `reproduce.py` support the existing optional runtime/diff demonstration.
- `demo/verify_arg_labels.py` imports `graph_check` from `demo/render_real_arg.py`; the new dynamic acceptance test also uses that helper. Both scripts are retained as test dependencies, not runtime renderers.
- `src/analyzer/legacy.rs` and the existing test modules remain test-only; removing them would drop regression coverage rather than reduce runtime dependencies.
- Existing research-only Python reporting/evaluation suites and their datasets are excluded. Rust report/serialization/API tests remain self-contained. External regression replay is an additional packaging audit and is not a dependency of the packaged build/tests.
- All 16 direct Rust dependencies remain locked; none is a local path dependency. Python packages in requirements-dev.txt are optional test dependencies only. The actual validation used a separate local installation matching those versions, outside the source tree.

## Artifact locations and reproducibility

The clean source tree is accompanied by a separate `archer-research-verification` directory containing build/test logs, before/after report comparisons, source fingerprints and generated acceptance artifacts. Build caches/binaries and previously generated graphs are not in the source archive. No reference to that sibling directory is required to compile or run ARCHER.

Build/test commands are in README.md. To reproduce live contract checks, build API/CLI debug binaries, install requirements-dev.txt in a Python environment and run `python tests/verify_api_openapi.py`. To reproduce the real remote test after installing Graphviz:

```sh
python tests/verify_dynamic_arg.py --dot /path/to/dot --github-url https://github.com/ddimaria/rust-actix-example --commit d4cdc238c88c09ea748ef5f42243d96b682caf31
```

Use `--bin-dir target/release` to run the graph test against a release build. All test-created API servers are owned temporary loopback processes and are stopped by the tests. No service was deployed and no project Git operations were performed.

## Limits of this verification

Windows builds/runtime, real GitHub fetch, fresh snapshot jobs and graph rendering were executed. Linux process limits, systemd, a reverse proxy, public gateway/user authorization, horizontal scaling and browser/LLM implementations were not deployed or tested. The service remains single-tenant, in-memory and allowlist-restricted. These are explicit deployment constraints, not unresolved compile/test failures.
