# ARCHER Rust backend

This is the proposed `archer-research` backend handoff. It retains the complete current research analyzer, REST API, ARG generator and explanation-provider interface. Production Rust source and Cargo manifests/lockfile are copied unchanged. Historical datasets, generated results and build artifacts are excluded. No frontend or LLM provider is implemented.

## Build and test

Use Rust with edition 2024 support, Cargo, the host C/C++ linker toolchain, and Git for the diff tests. The verified toolchain is recorded in `packaging/VERIFICATION.md`; a minimum supported Rust version has not been independently established.

```sh
cargo build --locked
cargo test --locked
cargo build --locked --features api --bins
cargo test --locked --features api --all-targets
```

Use `--offline` only when the locked dependencies are already cached. Dependencies are ordinary crates.io packages, not local path dependencies. Do not remove `demo/src/main.rs`: an analyzer regression test embeds it at compile time. `src/analyzer/legacy.rs` is test-only. Neither the research directory nor historical graph files are build/runtime dependencies.

For a deployment build: `cargo build --locked --release --features api --bins`. The Rust API executable also runs its isolated analysis workers; deploy it with a trusted Cargo/rustc toolchain and curl 8.4+ when GitHub fetching is enabled. Python, Graphviz and Git are not needed for the snapshot API runtime. Git is needed for CLI `--diff` and related tests.

## Start the API

Set `ARCHER_API_TOKEN` to an operator-managed random secret (32–256 ASCII graphic characters). Supply it through service environment/secrets management; `.env.example` is a reference and is not auto-loaded. The default listener is `127.0.0.1:8080`.

```powershell
# PowerShell 7+
$env:ARCHER_API_TOKEN = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
.\target\debug\archer-api.exe
```

Or, in a POSIX shell, export a securely generated token and run `./target/debug/archer-api`. Use the release executable and the supplied launcher/service template for deployment.

Public endpoints: `GET /api/v1/health`, `GET /api/v1/openapi.json`. Analysis/job/result/ARG/delete endpoints require `Authorization: Bearer <secret>`.

**GitHub submission is disabled by default.** It accepts only explicitly configured public `owner/repo` entries and a full 40-hex commit SHA. Arbitrary URLs, branches, private repository credentials and local filesystem paths are unsupported. Source snapshots are supported. This backend is a single-tenant trusted-client service; public frontend code must never contain the operator token.

## Handoff documents

- [Frontend integration](docs/frontend-integration.md): requests, polling, result interpretation, View Graph, and the LLM boundary.
- [Backend contract and environment variables](docs/backend.md): exact schemas, limits and safeguards.
- [ARG rendering](docs/arg-visualization.md): dynamic DOT/JSON and safe client rendering.
- [Deployment](docs/deployment.md): runtime dependencies, service template and public deployment restrictions.
- [OpenAPI 3.1](docs/openapi.json): machine-readable contract; also available from the API.
- [Packaging manifest](packaging/manifest.json), [verification](packaging/VERIFICATION.md), and [statistics](packaging/statistics.json).

## Optional HTTP and graph acceptance tests

```sh
python -m venv .venv
# Activate .venv using your shell's normal activation command.
python -m pip install -r requirements-dev.txt
python tests/verify_api_openapi.py
python tests/verify_dynamic_arg.py --dot /path/to/dot
```

Build debug binaries with `--features api --bins` first. On Windows pass the installed `dot.exe` path; the test never adds a rendering endpoint to the server. The dynamic test creates two distinct new source snapshots, checks job-specific graph semantics, renders their DOT, and verifies unauthorized access is rejected. Optional allowlisted GitHub acceptance flags are described by `--help`. All generated artifacts go under ignored `target/`.

## Security and analysis limitations

ARCHER is bounded static analysis, not a whole-program security proof. `finding_details` contains supported inferred authorization drift; operation-specific policy exceptions still need review. `review_observations` and `check_comparisons` are separate exploratory/informational categories. Unknown evidence and zero comparison coverage must stay visible. A clean result is not a security certificate. No thresholds, classification rules, advanced source models or existing informational mechanisms were removed for packaging.
