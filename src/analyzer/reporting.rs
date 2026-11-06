//! Existing graph output and change-aware report selection.
use super::*;

pub fn build_authorization_graph(
    routes: &[Route],
    findings: &[Finding],
) -> AuthorizationRelationshipGraph {
    let route_key = |method: &str, path: &str, application: &Option<String>| {
        format!(
            "route:{method}:{path}{}",
            application
                .as_ref()
                .map(|a| format!("@{a}"))
                .unwrap_or_default()
        )
    };
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut node_ids = HashSet::new();

    let add_node = |nodes: &mut Vec<GraphNode>,
                    node_ids: &mut HashSet<String>,
                    id: String,
                    label: String,
                    kind: NodeKind,
                    file: Option<PathBuf>,
                    line: Option<usize>| {
        if node_ids.insert(id.clone()) {
            nodes.push(GraphNode {
                id,
                label,
                kind,
                file,
                line,
            });
        }
    };

    // Scopes and Routes
    for route in routes {
        let route_id = route_key(&route.method, &route.path, &route.application);
        let mut scope_id = format!(
            "scope:{}",
            if route.scope_prefix.is_empty() {
                "/"
            } else {
                &route.scope_prefix
            }
        );
        if let Some(app) = &route.application {
            scope_id.push_str(&format!("@{app}"));
        }

        add_node(
            &mut nodes,
            &mut node_ids,
            scope_id.clone(),
            format!(
                "Scope: {}",
                if route.scope_prefix.is_empty() {
                    "/"
                } else {
                    &route.scope_prefix
                }
            ),
            NodeKind::Scope,
            None,
            None,
        );

        add_node(
            &mut nodes,
            &mut node_ids,
            route_id.clone(),
            format!("{} {}", route.method, route.path),
            NodeKind::Route,
            Some(route.file.clone()),
            Some(route.line),
        );

        edges.push(GraphEdge {
            from: route_id.clone(),
            to: scope_id,
            relation: EdgeRelation::BelongsToScope,
        });

        if let Some(handler) = &route.handler {
            let handler_id = format!(
                "handler:{}{}",
                handler,
                route
                    .application
                    .as_ref()
                    .map(|a| format!("@{a}"))
                    .unwrap_or_default()
            );
            add_node(
                &mut nodes,
                &mut node_ids,
                handler_id.clone(),
                format!("fn {}()", handler),
                NodeKind::Handler,
                Some(route.file.clone()),
                None,
            );
            edges.push(GraphEdge {
                from: route_id.clone(),
                to: handler_id.clone(),
                relation: EdgeRelation::RoutesTo,
            });

            for (idx, evidence) in route.authorization.iter().enumerate() {
                let evidence_id = format!("evidence:{}:{}:{}", handler_id, idx, evidence.mechanism);
                let (kind, relation) = match evidence.kind {
                    AuthEvidenceKind::AuthorizationGuard => {
                        (NodeKind::Guard, EdgeRelation::GuardedBy)
                    }
                    AuthEvidenceKind::AuthorizationMiddleware => {
                        (NodeKind::Middleware, EdgeRelation::WrappedBy)
                    }
                    AuthEvidenceKind::IdentityExtraction => {
                        (NodeKind::IdentityExtraction, EdgeRelation::ExtractsIdentity)
                    }
                    _ => (NodeKind::AuthorizationCheck, EdgeRelation::EnforcesCheck),
                };
                add_node(
                    &mut nodes,
                    &mut node_ids,
                    evidence_id.clone(),
                    format!("{:?}: {}", evidence.kind, evidence.mechanism),
                    kind,
                    Some(evidence.file.clone()),
                    Some(evidence.line),
                );
                edges.push(GraphEdge {
                    from: handler_id.clone(),
                    to: evidence_id,
                    relation,
                });
            }
        }
    }

    // Invariants & Findings
    for (i, finding) in findings.iter().enumerate() {
        let contract_id = format!(
            "contract:{}:{}",
            finding.peer_group_id, finding.invariant.description
        );
        let finding_id = format!("finding:{}:{:?}", i + 1, finding.category);

        add_node(
            &mut nodes,
            &mut node_ids,
            contract_id.clone(),
            format!("Invariant: {}", finding.invariant.description),
            NodeKind::InvariantContract,
            None,
            None,
        );

        for peer in &finding.authorized_peer_routes {
            let peer_id = route_key(&peer.method, &peer.path, &peer.application);
            edges.push(GraphEdge {
                from: peer_id,
                to: contract_id.clone(),
                relation: EdgeRelation::ImplementsContract,
            });
        }

        add_node(
            &mut nodes,
            &mut node_ids,
            finding_id.clone(),
            format!(
                "Drift ({:?}): {} {}",
                finding.category, finding.suspicious_route.method, finding.suspicious_route.path
            ),
            NodeKind::Finding,
            Some(finding.suspicious_route.file.clone()),
            Some(finding.suspicious_route.line),
        );

        let suspicious_id = route_key(
            &finding.suspicious_route.method,
            &finding.suspicious_route.path,
            &finding.suspicious_route.application,
        );
        edges.push(GraphEdge {
            from: finding_id.clone(),
            to: suspicious_id,
            relation: EdgeRelation::FlagsRoute,
        });

        edges.push(GraphEdge {
            from: finding_id,
            to: contract_id,
            relation: EdgeRelation::ViolatesContract,
        });
    }

    AuthorizationRelationshipGraph { nodes, edges }
}

pub fn analyze_repository_diff(root: &Path, git_ref: Option<&str>) -> Result<DiffAnalysisReport> {
    let base_ref = git_ref.unwrap_or("HEAD~1");
    let output = std::process::Command::new("git")
        .args(["diff", "--name-only", base_ref])
        .current_dir(root)
        .output();

    let mut changed_files = Vec::new();
    if let Ok(out) = output {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.ends_with(".rs") {
                    changed_files.push(root.join(trimmed));
                }
            }
        }
    }

    if changed_files.is_empty() {
        let status_out = std::process::Command::new("git")
            .args(["status", "--porcelain"])
            .current_dir(root)
            .output();
        if let Ok(out) = status_out {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                for line in text.lines() {
                    let trimmed = line.trim();
                    if trimmed.len() > 3 {
                        let path_part = trimmed[3..].trim();
                        if path_part.ends_with(".rs") {
                            changed_files.push(root.join(path_part));
                        }
                    }
                }
            }
        }
    }

    let report = analyze_repository(root)?;
    let mut affected_routes = Vec::new();
    let mut newly_introduced_drifts = Vec::new();
    let mut unchanged_drifts = Vec::new();
    let regressions = Vec::new();

    for route in &report.routes {
        let is_changed = changed_files.iter().any(|cf| {
            cf.canonicalize().ok() == route.file.canonicalize().ok()
                || route.file.ends_with(cf)
                || cf.ends_with(&route.file)
        });
        if is_changed {
            affected_routes.push(route.into());
        }
    }

    for finding in report.finding_details {
        let is_in_changed = changed_files.iter().any(|cf| {
            cf.canonicalize().ok() == finding.suspicious_route.file.canonicalize().ok()
                || finding.suspicious_route.file.ends_with(cf)
                || cf.ends_with(&finding.suspicious_route.file)
        });
        if is_in_changed {
            newly_introduced_drifts.push(finding);
        } else {
            unchanged_drifts.push(finding);
        }
    }

    let summary = format!(
        "Change Analysis against '{}': {} changed Rust file(s) examined. {} affected route(s). {} newly introduced drift(s). {} pre-existing drift(s).",
        base_ref,
        changed_files.len(),
        affected_routes.len(),
        newly_introduced_drifts.len(),
        unchanged_drifts.len()
    );

    Ok(DiffAnalysisReport {
        base_ref: base_ref.to_string(),
        changed_files,
        affected_routes,
        newly_introduced_drifts,
        regressions,
        unchanged_drifts,
        summary,
    })
}
