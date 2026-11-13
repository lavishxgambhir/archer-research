# Handoff readiness

**Ready for the teammate's controlled backend integration.** The original stronger analyzer, locked source closure, REST API, dynamic ARG, OpenAPI and explanation interface are retained. Clean default/API/release builds, essential tests, a real allowlisted GitHub fetch, per-job graph rendering and critical original-versus-packaged regressions were executed successfully. See VERIFICATION.md for exact results.

**Not ready for an unrestricted public, multi-user GitHub-URL website.** Before that rollout:

1. Add/deploy a trusted gateway with user authentication, per-user job ownership, request/rate quotas and server-side custody of the operator bearer token. The current token can access every retained job.
2. Configure repository admission and obtain/select full immutable commit SHAs. Remote fetching is disabled by default and restricted to at most 64 explicit public repositories; arbitrary public URL or branch submission is unsupported. Archives with links/special entries and unsafe/unsupported paths/manifests are rejected.
3. Configure and test the target host: TLS/private API access, dedicated unprivileged account, private work-root permissions, trusted Cargo/rustc, curl 8.4+, public-IPv4 DNS/provider HTTPS egress, memory sizing and supervisor cleanup. Linux/systemd behavior still needs target-host validation; Windows is verified.
4. Integrate the client View Graph renderer safely using each job's JSON/DOT. There is no hosted SVG endpoint and no frontend implementation in this source tree.
5. Implement any optional LLM explanation service separately with privacy/consent, timeout and evidence-reference checks. Deterministic reports remain authoritative and are never rewritten by explanations.

Jobs expire and are lost on restart; multi-instance/durable operation requires an appropriate routing/storage design. None of these public-hosting capabilities is silently supplied by packaging. A trusted allowlisted/snapshot integration can proceed using the documented current contracts.

The original research working tree and uncommitted work remain untouched. No commit, push, merge, reset, branch switch, hosting change or deployment was performed.
