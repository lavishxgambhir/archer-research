//! Requirement-specific comparisons over existing peer groups. Findings are
//! inferred inconsistencies, not proofs of the application's intended policy.
use super::*;
use security::{Assessment, Enforcement};

/// Ordinal evidence explanations, never calibrated probabilities.
#[derive(Debug, Serialize)]
pub struct StageEvidence {
    pub stage: String,
    pub peer_group_id: String,
    pub route: Option<RouteReference>,
    pub dimension: Option<String>,
    pub confidence: String,
    pub evidence: Vec<String>,
    pub abstention_reasons: Vec<String>,
}

impl StageEvidence {
    fn drift(
        group: &PeerGroup,
        target: &Assessment,
        dimension: &str,
        reason: &str,
        evidence: Vec<String>,
    ) -> Self {
        Self {
            stage: "drift".into(),
            peer_group_id: group.id.clone(),
            route: Some(target.route.clone()),
            dimension: Some(dimension.into()),
            confidence: if reason.is_empty() {
                "Medium"
            } else {
                "Unavailable"
            }
            .into(),
            evidence,
            abstention_reasons: if reason.is_empty() {
                vec![]
            } else {
                vec![reason.into()]
            },
        }
    }
}

pub(super) fn group_evidence(
    groups: &[PeerGroup],
    routes: &[Route],
    relationships: &[Relationship],
    invariants: &[AuthorizationInvariant],
    assessments: &[Assessment],
) -> Vec<StageEvidence> {
    let mut result = Vec::new();
    for group in groups {
        let edges: Vec<_> = relationships
            .iter()
            .filter(|r| {
                membership(r, routes)
                    && group
                        .routes
                        .iter()
                        .any(|a| same_route(a, &RouteReference::from(&routes[r.left])))
                    && group
                        .routes
                        .iter()
                        .any(|a| same_route(a, &RouteReference::from(&routes[r.right])))
            })
            .collect();
        let evidence: std::collections::BTreeSet<_> = edges
            .iter()
            .flat_map(|r| r.evidence.iter().cloned())
            .collect();
        let limits: std::collections::BTreeSet<_> = edges
            .iter()
            .flat_map(|r| {
                r.conflicts
                    .iter()
                    .filter(|s| !s.contains("transferring a policy"))
                    .cloned()
            })
            .collect();
        result.push(StageEvidence {
            stage: "peer_membership".into(),
            peer_group_id: group.id.clone(),
            route: None,
            dimension: None,
            confidence: if evidence
                .iter()
                .any(|s| s.starts_with("shared resolved resource:"))
            {
                "Medium"
            } else {
                "Low"
            }
            .into(),
            evidence: evidence.into_iter().collect(),
            abstention_reasons: limits.into_iter().collect(),
        });
        let members = members(group, assessments);
        for dimension in DIMENSIONS {
            let prefix = format!("Supported {dimension} requirement:");
            let supported: Vec<_> = invariants
                .iter()
                .filter(|i| i.peer_group_id == group.id && i.description.starts_with(&prefix))
                .collect();
            let support = policy_support(&members, dimension);
            let mut evidence: Vec<_> = support
                .iter()
                .map(|(v, a)| format!("{} observed member(s): {}", a.len(), v.join(", ")))
                .collect();
            evidence.sort();
            let mut reasons = Vec::new();
            if members
                .iter()
                .any(|a| a.route.scope_prefix != members[0].route.scope_prefix)
            {
                evidence.push("Policy comparisons remain within the same mount context; cross-mount resource membership is not a shared policy".into());
                if supported.is_empty() {
                    reasons.push("Different mount contexts do not justify a group-wide authorization invariant".into());
                }
            }
            if supported.is_empty() {
                if matches!(dimension, "roles" | "permissions" | "ownership")
                    && members
                        .iter()
                        .any(|a| path_shape(&a.route.path) != path_shape(&members[0].route.path))
                {
                    reasons.push("Collection/item or self-resource operations do not justify transferring role/permission/ownership policy across path shapes".into());
                }
                reasons.push("No unambiguous observed policy has sufficient comparable support (minimum two and strict majority); thresholds are unchanged".into());
            }
            result.push(StageEvidence {
                stage: "invariant".into(),
                peer_group_id: group.id.clone(),
                route: None,
                dimension: Some(dimension.into()),
                confidence: if supported.is_empty() {
                    "Unavailable"
                } else {
                    "Medium"
                }
                .into(),
                evidence,
                abstention_reasons: reasons,
            });
        }
    }
    result
}

#[derive(Debug, Clone, Serialize)]
pub struct Relationship {
    pub left: usize,
    pub right: usize,
    pub kind: String,
    pub evidence: Vec<String>,
    pub conflicts: Vec<String>,
    /// Supporting observations (some correlated), not a probability.
    pub evidence_score: usize,
    pub confidence: String,
    pub contract_eligible: bool,
}

#[derive(Debug, Serialize)]
pub struct ResourceEvidence {
    pub route: RouteReference,
    pub resources: Vec<String>,
    pub call_chain_evidence: Vec<String>,
    pub abstention_reasons: Vec<String>,
}

#[derive(Default)]
struct ResourceTrace {
    cache: HashMap<String, (usize, HashSet<String>)>,
    calls: std::collections::BTreeSet<String>,
    abstentions: std::collections::BTreeSet<String>,
}

#[derive(Default)]
struct ResourceAccess {
    resources: HashSet<String>,
    calls: Vec<(Vec<String>, bool)>,
    discarded: HashSet<(usize, usize)>,
    write_operation: bool,
    schema_paths: HashSet<String>,
    query_operation: bool,
    table_paths: Vec<Vec<String>>,
}
impl<'ast> Visit<'ast> for ResourceAccess {
    fn visit_stmt(&mut self, stmt: &'ast Stmt) {
        let discarded = match stmt {
            Stmt::Expr(expr, Some(_)) => Some(expr),
            Stmt::Local(local) if matches!(local.pat, Pat::Wild(_)) => {
                local.init.as_ref().map(|init| &*init.expr)
            }
            _ => None,
        };
        if let Some(expr) = discarded {
            let mut root = expr;
            loop {
                match root {
                    Expr::Try(e) => root = &e.expr,
                    Expr::Await(e) => root = &e.base,
                    Expr::Paren(e) => root = &e.expr,
                    _ => break,
                }
            }
            if matches!(root, Expr::Call(_) | Expr::MethodCall(_)) {
                let p = root.span().start();
                self.discarded.insert((p.line, p.column));
            }
        }
        visit::visit_stmt(self, stmt);
    }
    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(path) = &*call.func {
            if path.qself.is_some() {
                return;
            }
            let names: Vec<_> = path
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            if let Some(entity) = names.iter().position(|n| n == "Entity") {
                if entity > 0 {
                    self.resources
                        .insert(format!("entity:{}", names[..=entity].join("::")));
                    if let Some(operation) = names.last() {
                        let operation = match operation.as_str() {
                            "find" | "find_by_id" => "read",
                            "insert" | "insert_many" => "create",
                            "update" | "update_many" => "update",
                            "delete" | "delete_many" | "delete_by_id" => "delete",
                            _ => "unknown",
                        };
                        self.resources.insert(format!("@{operation}"));
                    }
                }
            }
            if names.first().is_some_and(|n| n == "sqlx")
                && names.last().is_some_and(|n| n.starts_with("query"))
            {
                if let Some(Expr::Lit(ExprLit {
                    lit: Lit::Str(sql), ..
                })) = call.args.first()
                {
                    // Only literal, simple SQL table references are supported.
                    let words: Vec<_> = sql.value().split_whitespace().map(str::to_owned).collect();
                    if let Some(first) = words.first() {
                        let operation = match first.to_uppercase().as_str() {
                            "SELECT" => "read",
                            "INSERT" => "create",
                            "UPDATE" => "update",
                            "DELETE" => "delete",
                            _ => "unknown",
                        };
                        self.resources.insert(format!("@{operation}"));
                    }
                    for pair in words.windows(2) {
                        if ["FROM", "JOIN", "UPDATE", "INTO"]
                            .contains(&pair[0].to_uppercase().as_str())
                        {
                            let table =
                                pair[1].trim_matches(|c: char| c == '"' || c == '`' || c == ';');
                            if table
                                .chars()
                                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
                            {
                                self.resources.insert(format!("sql:{table}"));
                            }
                        }
                    }
                }
            }
            self.write_operation |= names.last().is_some_and(|n| {
                ["insert_into", "update", "delete", "delete_from"].contains(&n.as_str())
            });
            let position = call.span().start();
            self.calls.push((
                names,
                self.discarded.contains(&(position.line, position.column)),
            ));
        }
        // Arguments may contain callbacks or further resource calls. The callee
        // path itself is already recorded; do not re-add a discarded read as used.
        for arg in &call.args {
            self.visit_expr(arg);
        }
    }
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        fn walk(tree: &UseTree, prefix: Vec<String>, output: &mut HashSet<String>) {
            match tree {
                UseTree::Path(p) => {
                    let mut next = prefix;
                    next.push(p.ident.to_string());
                    walk(&p.tree, next, output);
                }
                UseTree::Group(g) => {
                    for tree in &g.items {
                        walk(tree, prefix.clone(), output);
                    }
                }
                _ => {
                    if let Some(i) = prefix.iter().position(|s| s == "schema") {
                        if prefix.len() > i + 1 {
                            output.insert(format!("diesel:{}", prefix[..i + 2].join("::")));
                        }
                    }
                }
            }
        }
        walk(&item.tree, Vec::new(), &mut self.schema_paths);
    }
    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        self.query_operation |= [
            "load",
            "first",
            "get_result",
            "get_results",
            "execute",
            "select",
        ]
        .contains(&call.method.to_string().as_str());
        visit::visit_expr_method_call(self, call);
    }
    fn visit_expr_path(&mut self, path: &'ast ExprPath) {
        if path.qself.is_some() {
            return;
        }
        if path
            .path
            .segments
            .last()
            .is_some_and(|s| s.ident == "table")
        {
            self.table_paths.push(
                path.path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect(),
            );
        }
        if path.path.segments.len() > 1 {
            self.calls.push((
                path.path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect(),
                false,
            ));
        }
        visit::visit_expr_path(self, path);
    }
    fn visit_item_fn(&mut self, _: &'ast ItemFn) {}
}

fn canonical_table(
    index: &HandlerIndex,
    context: &ModuleKey,
    path: &[String],
    depth: usize,
) -> Option<String> {
    if depth >= 8 || path.is_empty() {
        return None;
    }
    if let Some(imports) = index
        .scope(&context.0, &context.1)
        .and_then(|s| s.imports.get(&path[0]))
    {
        let [import] = imports.as_slice() else {
            return None;
        };
        let mut expanded = import.segments.clone();
        expanded.extend_from_slice(&path[1..]);
        return canonical_table(index, context, &expanded, depth + 1);
    }
    let (table, prefix) = path.split_last()?;
    // A schema-qualified imported table is evidence even when Diesel generated
    // the final module. No arbitrary identifier is promoted into a table.
    if !prefix.iter().any(|s| s == "schema") {
        return None;
    }
    let module = index.resolve_module(
        &context.0,
        &context.1,
        &UsePath {
            segments: prefix.to_vec(),
            leading_colon: false,
        },
        0,
    )?;
    Some(format!(
        "table:{}:{}::{table}",
        module.0.display(),
        module.1.join("::")
    ))
}

fn model_table(index: &HandlerIndex, owner: &ModuleKey) -> Option<String> {
    fn table(meta: &syn::Meta) -> Option<Vec<String>> {
        let syn::Meta::List(list) = meta else {
            return None;
        };
        if !list.path.is_ident("cfg_attr") && !list.path.is_ident("diesel") {
            return None;
        }
        let fields = list
            .parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            )
            .ok()?;
        for field in fields {
            if list.path.is_ident("diesel") {
                if let syn::Meta::NameValue(value) = &field {
                    if value.path.is_ident("table_name") {
                        if let Expr::Path(path) = &value.value {
                            return Some(
                                path.path
                                    .segments
                                    .iter()
                                    .map(|s| s.ident.to_string())
                                    .collect(),
                            );
                        }
                    }
                }
            }
            if let Some(found) = table(&field) {
                return Some(found);
            }
        }
        None
    }
    let path = index
        .record_attributes
        .get(owner)?
        .iter()
        .find_map(|a| table(&a.meta))?;
    canonical_table(
        index,
        &(owner.0.clone(), owner.1[..owner.1.len() - 1].to_vec()),
        &path,
        0,
    )
}

fn substitute_type(ty: &mut syn::Type, replacements: &HashMap<String, syn::Type>) {
    match ty {
        syn::Type::Path(path) => {
            if let Some(name) = path.path.get_ident() {
                if let Some(value) = replacements.get(&name.to_string()) {
                    *ty = value.clone();
                    return;
                }
            }
            for segment in &mut path.path.segments {
                if let syn::PathArguments::AngleBracketed(args) = &mut segment.arguments {
                    for arg in &mut args.args {
                        if let syn::GenericArgument::Type(ty) = arg {
                            substitute_type(ty, replacements);
                        }
                    }
                }
            }
        }
        syn::Type::Reference(r) => substitute_type(&mut r.elem, replacements),
        syn::Type::Slice(r) => substitute_type(&mut r.elem, replacements),
        _ => {}
    }
}

fn record_type(
    index: &HandlerIndex,
    handler: &HandlerDefinition,
    ty: &syn::Type,
) -> Option<ModuleKey> {
    record_type_depth(index, handler, ty, 0)
}

fn record_type_depth(
    index: &HandlerIndex,
    handler: &HandlerDefinition,
    ty: &syn::Type,
    depth: usize,
) -> Option<ModuleKey> {
    if depth >= 8 {
        return None;
    }
    match ty {
        syn::Type::Reference(r) => record_type_depth(index, handler, &r.elem, depth + 1),
        syn::Type::Slice(s) => record_type_depth(index, handler, &s.elem, depth + 1),
        syn::Type::Path(path) => {
            if path.path.is_ident("Self") {
                return handler.owner.clone();
            }
            let lexical = handler.module.as_slice();
            let target = UsePath {
                segments: path
                    .path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect(),
                leading_colon: path.path.leading_colon.is_some(),
            };
            if let Some(record) = index.resolve_module(&handler.crate_key, lexical, &target, 0) {
                if index.record_types.contains(&record) {
                    return Some(record);
                }
                if let Some(alias) = index.type_aliases.get(&record) {
                    let params: Vec<_> = alias.generics.type_params().collect();
                    let args: Vec<_> = path
                        .path
                        .segments
                        .last()
                        .and_then(|s| match &s.arguments {
                            syn::PathArguments::AngleBracketed(a) => Some(
                                a.args
                                    .iter()
                                    .filter_map(|a| {
                                        if let syn::GenericArgument::Type(t) = a {
                                            Some(t.clone())
                                        } else {
                                            None
                                        }
                                    })
                                    .collect::<Vec<_>>(),
                            ),
                            _ => None,
                        })
                        .unwrap_or_default();
                    if params.len() != args.len() {
                        return None;
                    }
                    // Preserve the call site's namespace for a transparent
                    // Result/Option/Vec-style alias parameter.
                    fn parameter(ty: &syn::Type) -> Option<String> {
                        let syn::Type::Path(path) = ty else {
                            return None;
                        };
                        if let Some(name) = path.path.get_ident() {
                            return Some(name.to_string());
                        }
                        let segment = path.path.segments.last()?;
                        if !["Result", "Option", "Vec", "Box", "Json"]
                            .contains(&segment.ident.to_string().as_str())
                        {
                            return None;
                        }
                        if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                            if let Some(syn::GenericArgument::Type(inner)) = args.args.first() {
                                return parameter(inner);
                            }
                        }
                        None
                    }
                    if let Some(name) = parameter(&alias.ty) {
                        if let Some(position) = params.iter().position(|p| p.ident == name.as_str())
                        {
                            return record_type_depth(index, handler, &args[position], depth + 1);
                        }
                    }
                    let replacements: HashMap<_, _> = params
                        .iter()
                        .zip(args)
                        .map(|(p, t)| (p.ident.to_string(), t))
                        .collect();
                    let mut expanded = (*alias.ty).clone();
                    substitute_type(&mut expanded, &replacements);
                    let context = HandlerDefinition {
                        crate_key: record.0,
                        module: record.1[..record.1.len() - 1].to_vec(),
                        owner: None,
                        ..handler.clone()
                    };
                    return record_type_depth(index, &context, &expanded, depth + 1);
                }
            }
            let last = path.path.segments.last()?;
            if ["Vec", "Option", "Box", "Result", "Json"].contains(&last.ident.to_string().as_str())
            {
                if let syn::PathArguments::AngleBracketed(args) = &last.arguments {
                    if let Some(syn::GenericArgument::Type(inner)) = args.args.first() {
                        return record_type_depth(index, handler, inner, depth + 1);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

// Eligibility to inspect a consumed helper is weaker than return-type
// inference: an opaque wrapper can still explicitly mention a concrete record.
// This never infers a receiver type through that opaque wrapper.
fn mentions_record(index: &HandlerIndex, handler: &HandlerDefinition, ty: &syn::Type) -> bool {
    if record_type(index, handler, ty).is_some() {
        return true;
    }
    match ty {
        syn::Type::Path(p) => p.path.segments.iter().any(|s| match &s.arguments {
            syn::PathArguments::AngleBracketed(a) => a.args.iter().any(
                |a| matches!(a, syn::GenericArgument::Type(t) if mentions_record(index,handler,t)),
            ),
            _ => false,
        }),
        syn::Type::Reference(r) => mentions_record(index, handler, &r.elem),
        _ => false,
    }
}

// Receiver identity is concrete: unlike data-return eligibility, it never
// unwraps Vec/Option/Result/Json into an element or payload type.
fn concrete_receiver(
    index: &HandlerIndex,
    handler: &HandlerDefinition,
    ty: &syn::Type,
    depth: usize,
) -> Option<ModuleKey> {
    if depth >= 8 {
        return None;
    }
    match ty {
        syn::Type::Reference(r) => concrete_receiver(index, handler, &r.elem, depth + 1),
        syn::Type::Path(path) => {
            if path.path.is_ident("Self") {
                return handler.owner.clone();
            }
            let target = UsePath {
                segments: path
                    .path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect(),
                leading_colon: path.path.leading_colon.is_some(),
            };
            let key = index.resolve_module(&handler.crate_key, &handler.module, &target, 0)?;
            if index.record_types.contains(&key) {
                return Some(key);
            }
            let alias = index.type_aliases.get(&key)?;
            if !alias.generics.params.is_empty() {
                return None;
            }
            let context = HandlerDefinition {
                crate_key: key.0,
                module: key.1[..key.1.len() - 1].to_vec(),
                owner: None,
                ..handler.clone()
            };
            concrete_receiver(index, &context, &alias.ty, depth + 1)
        }
        _ => None,
    }
}

fn called_definition<'a>(
    index: &'a HandlerIndex,
    handler: &HandlerDefinition,
    expr: &Expr,
    bindings: &HashMap<String, Option<ModuleKey>>,
    depth: usize,
) -> Option<&'a HandlerDefinition> {
    if depth >= 8 {
        return None;
    }
    match expr {
        Expr::Await(e) => called_definition(index, handler, &e.base, bindings, depth + 1),
        Expr::Call(call) => {
            let Expr::Path(path) = &*call.func else {
                return None;
            };
            if path.qself.is_some() {
                return None;
            }
            index.resource_call(
                handler,
                &path
                    .path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect::<Vec<_>>(),
            )
        }
        Expr::MethodCall(call) => {
            let owner = expression_record(index, handler, &call.receiver, bindings, depth + 1)?;
            index
                .resource_method(handler, &owner, &call.method.to_string(), true)
                .filter(|d| d.function.sig.receiver().is_some())
        }
        _ => None,
    }
}

fn expression_record(
    index: &HandlerIndex,
    handler: &HandlerDefinition,
    expr: &Expr,
    bindings: &HashMap<String, Option<ModuleKey>>,
    depth: usize,
) -> Option<ModuleKey> {
    if depth >= 8 {
        return None;
    }
    match expr {
        Expr::Struct(record) => concrete_receiver(
            index,
            handler,
            &syn::Type::Path(syn::TypePath {
                attrs: Vec::new(),
                qself: record.qself.clone(),
                path: record.path.clone(),
            }),
            depth + 1,
        ),
        Expr::Path(path) => bindings.get(&path.path.get_ident()?.to_string())?.clone(),
        Expr::Reference(e) => expression_record(index, handler, &e.expr, bindings, depth + 1),
        Expr::Paren(e) => expression_record(index, handler, &e.expr, bindings, depth + 1),
        Expr::Field(field) => {
            let owner = expression_record(index, handler, &field.base, bindings, depth + 1)?;
            let syn::Member::Named(name) = &field.member else {
                return None;
            };
            let (ty, public) = index.record_fields.get(&owner)?.get(&name.to_string())?;
            if !public
                && !(handler.crate_key == owner.0
                    && handler.module.starts_with(&owner.1[..owner.1.len() - 1]))
            {
                return None;
            }
            let context = HandlerDefinition {
                module: owner.1[..owner.1.len() - 1].to_vec(),
                crate_key: owner.0.clone(),
                owner: None,
                ..handler.clone()
            };
            concrete_receiver(index, &context, ty, depth + 1)
        }
        Expr::Try(e) => {
            let callee = called_definition(index, handler, &e.expr, bindings, depth + 1)?;
            if callee.function.sig.asyncness.is_some() != matches!(&*e.expr, Expr::Await(_)) {
                return None;
            }
            let syn::ReturnType::Type(_, ty) = &callee.function.sig.output else {
                return None;
            };
            let syn::Type::Path(path) = &**ty else {
                return None;
            };
            let last = path.path.segments.last()?;
            let segments: Vec<_> = path
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            if segments.len() > 1
                && !matches!(segments.first().map(String::as_str), Some("std" | "core"))
            {
                return None;
            }
            if segments.len() == 1
                && (index
                    .scope(&callee.crate_key, &callee.module)
                    .is_some_and(|s| s.imports.contains_key(&segments[0]))
                    || index.is_module(&callee.crate_key, &{
                        let mut module = callee.module.clone();
                        module.push(segments[0].clone());
                        module
                    }))
            {
                return None;
            }
            if !["Result", "Option"].contains(&last.ident.to_string().as_str()) {
                return None;
            }
            if let syn::PathArguments::AngleBracketed(args) = &last.arguments {
                if let Some(syn::GenericArgument::Type(payload)) = args.args.first() {
                    return concrete_receiver(index, callee, payload, depth + 1);
                }
            }
            None
        }
        Expr::Await(e) => {
            let callee = called_definition(index, handler, &e.base, bindings, depth + 1)?;
            if callee.function.sig.asyncness.is_none() {
                return None;
            }
            match &callee.function.sig.output {
                syn::ReturnType::Type(_, ty) => concrete_receiver(index, callee, ty, depth + 1),
                _ => None,
            }
        }
        Expr::Call(_) | Expr::MethodCall(_) => {
            let callee = called_definition(index, handler, expr, bindings, depth + 1)?;
            if callee.function.sig.asyncness.is_some() {
                return None;
            }
            match &callee.function.sig.output {
                syn::ReturnType::Type(_, ty) => concrete_receiver(index, callee, ty, depth + 1),
                _ => None,
            }
        }
        _ => None,
    }
}

fn resource_condition_bindings(expr: &Expr, names: &mut HashSet<String>) {
    match expr {
        Expr::Let(pattern) => pattern_bindings(&pattern.pat, names),
        Expr::Binary(binary) if matches!(binary.op, BinOp::And(_)) => {
            resource_condition_bindings(&binary.left, names);
            resource_condition_bindings(&binary.right, names);
        }
        Expr::Paren(p) => resource_condition_bindings(&p.expr, names),
        _ => {}
    }
}

fn receiver_calls<'a>(
    index: &'a HandlerIndex,
    handler: &HandlerDefinition,
    discarded: &HashSet<(usize, usize)>,
    abstentions: &mut std::collections::BTreeSet<String>,
) -> Vec<(&'a HandlerDefinition, bool)> {
    struct TypedCalls<'a, 'b> {
        index: &'a HandlerIndex,
        handler: &'b HandlerDefinition,
        bindings: HashMap<String, Option<ModuleKey>>,
        calls: Vec<(&'a HandlerDefinition, bool)>,
        discarded: &'b HashSet<(usize, usize)>,
        abstentions: &'b mut std::collections::BTreeSet<String>,
    }
    impl<'ast> Visit<'ast> for TypedCalls<'_, '_> {
        fn visit_block(&mut self, block: &'ast Block) {
            let previous = self.bindings.clone();
            visit::visit_block(self, block);
            self.bindings = previous;
        }
        fn visit_local(&mut self, local: &'ast syn::Local) {
            if let Some(init) = &local.init {
                self.visit_expr(&init.expr);
            }
            let (pat, declared) = match &local.pat {
                Pat::Type(p) => (
                    &*p.pat,
                    concrete_receiver(self.index, self.handler, &p.ty, 0),
                ),
                p => (p, None),
            };
            let inferred = declared.or_else(|| {
                local.init.as_ref().and_then(|i| {
                    expression_record(self.index, self.handler, &i.expr, &self.bindings, 0)
                })
            });
            let mut names = HashSet::new();
            pattern_bindings(pat, &mut names);
            for name in names {
                self.bindings.insert(
                    name,
                    if matches!(pat, Pat::Ident(_)) {
                        inferred.clone()
                    } else {
                        None
                    },
                );
            }
        }
        fn visit_expr_assign(&mut self, expr: &'ast syn::ExprAssign) {
            self.visit_expr(&expr.right);
            if let Expr::Path(p) = &*expr.left {
                if let Some(name) = p.path.get_ident() {
                    self.bindings.insert(name.to_string(), None);
                }
            }
        }
        fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
            if let Some(owner) =
                expression_record(self.index, self.handler, &call.receiver, &self.bindings, 0)
            {
                if classify_check_name(&call.method.to_string()).is_none() {
                    if let Some(callee) = self
                        .index
                        .resource_method(self.handler, &owner, &call.method.to_string(), true)
                        .filter(|d| d.function.sig.receiver().is_some())
                    {
                        let p = call.span().start();
                        self.calls
                            .push((callee, self.discarded.contains(&(p.line, p.column))));
                    } else {
                        self.abstentions.insert(format!(
                            "No unique applicable implementation for {}::{} at {}:{}",
                            owner.1.join("::"),
                            call.method,
                            self.handler.file.display(),
                            call.span().start().line
                        ));
                    }
                }
            } else if [
                "load",
                "list",
                "first",
                "get_result",
                "get_results",
                "execute",
            ]
            .contains(&call.method.to_string().as_str())
            {
                self.abstentions.insert(format!(
                    "Query receiver type is unavailable for {} at {}:{}",
                    call.method,
                    self.handler.file.display(),
                    call.span().start().line
                ));
            }
            visit::visit_expr_method_call(self, call);
        }
        fn visit_expr_if(&mut self, expr: &'ast ExprIf) {
            let previous = self.bindings.clone();
            let mut names = HashSet::new();
            resource_condition_bindings(&expr.cond, &mut names);
            for name in names {
                self.bindings.insert(name, None);
            }
            self.visit_expr(&expr.cond);
            self.visit_block(&expr.then_branch);
            self.bindings = previous.clone();
            if let Some((_, other)) = &expr.else_branch {
                self.visit_expr(other);
            }
            self.bindings = previous;
        }
        fn visit_expr_while(&mut self, expr: &'ast ExprWhile) {
            let previous = self.bindings.clone();
            let mut names = HashSet::new();
            resource_condition_bindings(&expr.cond, &mut names);
            for name in names {
                self.bindings.insert(name, None);
            }
            self.visit_expr(&expr.cond);
            self.visit_block(&expr.body);
            self.bindings = previous;
        }
        fn visit_expr_match(&mut self, expr: &'ast syn::ExprMatch) {
            self.visit_expr(&expr.expr);
            let previous = self.bindings.clone();
            for arm in &expr.arms {
                let mut names = HashSet::new();
                pattern_bindings(&arm.pat, &mut names);
                for name in names {
                    self.bindings.insert(name, None);
                }
                self.visit_pat(&arm.pat);
                self.visit_expr(&arm.body);
                self.bindings = previous.clone();
            }
        }
        fn visit_expr_closure(&mut self, closure: &'ast ExprClosure) {
            let previous = self.bindings.clone();
            for input in &closure.inputs {
                let mut names = HashSet::new();
                pattern_bindings(input, &mut names);
                for name in names {
                    self.bindings.insert(name, None);
                }
            }
            self.visit_expr(&closure.body);
            self.bindings = previous;
        }
        fn visit_expr_for_loop(&mut self, expr: &'ast ExprForLoop) {
            self.visit_expr(&expr.expr);
            let previous = self.bindings.clone();
            let mut names = HashSet::new();
            pattern_bindings(&expr.pat, &mut names);
            for name in names {
                self.bindings.insert(name, None);
            }
            self.visit_block(&expr.body);
            self.bindings = previous;
        }
        fn visit_item_fn(&mut self, _: &'ast ItemFn) {}
    }
    let mut visitor = TypedCalls {
        index,
        handler,
        bindings: HashMap::new(),
        calls: Vec::new(),
        discarded,
        abstentions,
    };
    if handler.function.sig.receiver().is_some() {
        visitor
            .bindings
            .insert("self".into(), handler.owner.clone());
    }
    for input in &handler.function.sig.inputs {
        if let FnArg::Typed(arg) = input {
            if let Pat::Ident(name) = &*arg.pat {
                visitor.bindings.insert(
                    name.ident.to_string(),
                    concrete_receiver(index, handler, &arg.ty, 0),
                );
            }
        }
    }
    visitor.visit_block(&handler.function.block);
    visitor.calls
}

fn auxiliary_unit_method(index: &HandlerIndex, callee: &HandlerDefinition) -> bool {
    fn unit(ty: &syn::Type) -> bool {
        match ty {
            syn::Type::Tuple(tuple) => tuple.elems.is_empty(),
            syn::Type::Path(path) => path.path.segments.last().is_some_and(|s| match &s.arguments {
                syn::PathArguments::AngleBracketed(args) => matches!(args.args.first(), Some(syn::GenericArgument::Type(ty)) if unit(ty)),
                _ => false,
            }),
            _ => false,
        }
    }
    let returns_unit = match &callee.function.sig.output {
        syn::ReturnType::Default => true,
        syn::ReturnType::Type(_, ty) => unit(ty),
    };
    returns_unit
        && !callee
            .owner
            .as_ref()
            .is_some_and(|owner| model_table(index, owner).is_some())
}

fn resources(
    index: &HandlerIndex,
    handler: &HandlerDefinition,
    trace: &mut ResourceTrace,
    depth: usize,
) -> HashSet<String> {
    let key = format!(
        "{}:{}:{}:{}:{:?}:{}",
        handler
            .owner
            .as_ref()
            .map(|k| k.0.as_path())
            .unwrap_or(&handler.crate_key)
            .display(),
        handler.file.display(),
        handler.function.sig.ident.span().start().line,
        handler.function.sig.ident.span().start().column,
        handler.implemented_trait,
        handler.rust_path()
    );
    if depth >= 8 {
        trace.abstentions.insert(format!(
            "Eight-level resource tracing bound reached at {}:{}",
            handler.file.display(),
            handler.function.sig.ident.span().start().line
        ));
        return HashSet::new();
    }
    if let Some((previous, facts)) = trace.cache.get(&key) {
        if *previous <= depth {
            return facts.clone();
        }
    }
    trace.cache.insert(key.clone(), (depth, HashSet::new()));
    let mut access = ResourceAccess::default();
    access.visit_block(&handler.function.block);
    // A converter must return a resolved record and actually project fields
    // from its input model. Shared context arguments alone are not resources.
    if let syn::ReturnType::Type(_, output) = &handler.function.sig.output {
        if record_type(index, handler, output).is_some() {
            for input in &handler.function.sig.inputs {
                if let FnArg::Typed(arg) = input {
                    if let (Pat::Ident(binding), Some((key, model))) =
                        (&*arg.pat, record_type(index, handler, &arg.ty))
                    {
                        struct Projection<'a> {
                            binding: &'a syn::Ident,
                            observed: bool,
                        }
                        impl<'ast> Visit<'ast> for Projection<'_> {
                            fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
                                self.observed |= matches!(&*field.base, Expr::Path(p) if p.path.is_ident(self.binding));
                                visit::visit_expr_field(self, field);
                            }
                            fn visit_item_fn(&mut self, _: &'ast ItemFn) {}
                        }
                        let mut projection = Projection {
                            binding: &binding.ident,
                            observed: false,
                        };
                        projection.visit_block(&handler.function.block);
                        if projection.observed {
                            access.resources.insert(format!(
                                "model:{}:{}",
                                key.display(),
                                model.join("::")
                            ));
                        }
                    }
                }
            }
        }
    }
    if access.query_operation {
        access.resources.insert(
            if access.write_operation {
                "@write"
            } else {
                "@read"
            }
            .into(),
        );
        access.resources.extend(access.schema_paths);
        if let Some(owner) = &handler.owner {
            if let Some(table) = model_table(index, owner) {
                access.resources.insert(table);
            }
        }
        for path in &access.table_paths {
            if let Some(table) = canonical_table(
                index,
                &(handler.crate_key.clone(), handler.module.clone()),
                &path[..path.len() - 1],
                0,
            ) {
                access.resources.insert(table);
            }
        }
    }
    for (segments, discarded) in access.calls {
        if segments
            .last()
            .is_some_and(|name| classify_check_name(name).is_some())
        {
            continue;
        }
        if let Some(callee) = index.resource_call(handler, &segments) {
            if auxiliary_unit_method(index, callee) {
                trace.abstentions.insert(format!(
                    "Unit-returning utility {}:{} has no verified model ownership",
                    callee.file.display(),
                    callee.function.sig.ident.span().start().line
                ));
                continue;
            }

            // A generic unit/scalar utility is not independent resource evidence.
            if callee.owner.is_none()
                && !matches!(&callee.function.sig.output, syn::ReturnType::Type(_, ty) if mentions_record(index, callee, ty))
            {
                trace.abstentions.insert(format!("Auxiliary free helper {}:{} has no resolved record return; not an independent resource witness", callee.file.display(),callee.function.sig.ident.span().start().line));
                continue;
            }
            if classify_check_name(&callee.name).is_some() {
                continue;
            }
            let child = resources(index, callee, trace, depth + 1);
            let writes = child
                .iter()
                .any(|s| ["@write", "@create", "@update", "@delete"].contains(&s.as_str()));
            trace.calls.insert(format!(
                "{}:{} {} -> {}:{} {}",
                handler.file.display(),
                handler.function.sig.ident.span().start().line,
                handler.rust_path(),
                callee.file.display(),
                callee.function.sig.ident.span().start().line,
                callee.rust_path()
            ));
            if !discarded || writes {
                access.resources.extend(child);
            } else {
                trace.abstentions.insert(format!(
                    "Discarded read from {}:{} is auxiliary evidence",
                    callee.file.display(),
                    callee.function.sig.ident.span().start().line
                ));
            }
        }
    }
    for (callee, discarded) in
        receiver_calls(index, handler, &access.discarded, &mut trace.abstentions)
    {
        if auxiliary_unit_method(index, callee) {
            trace.abstentions.insert(format!(
                "Unit-returning utility {}:{} has no verified model ownership",
                callee.file.display(),
                callee.function.sig.ident.span().start().line
            ));
            continue;
        }

        let child = resources(index, callee, trace, depth + 1);
        let writes = child
            .iter()
            .any(|s| ["@write", "@create", "@update", "@delete"].contains(&s.as_str()));
        trace.calls.insert(format!(
            "{}:{} {} -> {}:{} {}",
            handler.file.display(),
            handler.function.sig.ident.span().start().line,
            handler.rust_path(),
            callee.file.display(),
            callee.function.sig.ident.span().start().line,
            callee.rust_path()
        ));
        if !discarded || writes {
            access.resources.extend(child);
        } else {
            trace.abstentions.insert(format!(
                "Discarded receiver read from {}:{} is auxiliary evidence",
                callee.file.display(),
                callee.function.sig.ident.span().start().line
            ));
        }
    }
    trace.cache.insert(key, (depth, access.resources.clone()));
    access.resources
}

fn nested_resource_mount(
    a: &Route,
    b: &Route,
    common: &std::collections::BTreeSet<String>,
) -> bool {
    let a: Vec<_> = a.path.split('/').filter(|s| !s.is_empty()).collect();
    let b: Vec<_> = b.path.split('/').filter(|s| !s.is_empty()).collect();
    // A shared application is checked separately. Only a nested route family
    // corroborated by a canonical source table can cross a mount boundary.
    common
        .iter()
        .filter(|s| s.starts_with("table:"))
        .any(|table| {
            let table = table.rsplit("::").next().unwrap_or("");
            a.iter()
                .zip(&b)
                .take_while(|(a, b)| a == b)
                .any(|(segment, _)| {
                    !is_dynamic_segment(segment)
                        && (*segment == table
                            || segment.strip_suffix('s') == Some(table)
                            || table.strip_suffix('s') == Some(*segment))
                })
        })
}

/// Candidate membership depends on application/resource/operation evidence,
/// never on the presence of security checks. Shared utilities are not resources.
pub(super) fn discover(
    root: &Path,
    routes: &[Route],
    index: &HandlerIndex,
) -> (Vec<Relationship>, Vec<ResourceEvidence>) {
    let mut facts = Vec::new();
    let mut resource_evidence = Vec::new();
    for route in routes {
        let mut trace = ResourceTrace::default();
        let resources = if route.handler_resolution == Some(HandlerResolution::UniqueName) {
            trace.abstentions.insert(
                "Legacy unique-name handler fallback is not a reliable resource witness".into(),
            );
            HashSet::new()
        } else if let Some(handler) = index.route_handler(route) {
            resources(index, handler, &mut trace, 0)
        } else {
            trace
                .abstentions
                .insert("Handler is unresolved; resource identity is unavailable".into());
            HashSet::new()
        };
        let mut identities: Vec<_> = resources
            .iter()
            .filter(|s| !s.starts_with('@'))
            .cloned()
            .collect();
        identities.sort();
        if identities.is_empty() {
            trace
                .abstentions
                .insert("No supported canonical resource identity was established".into());
        }
        resource_evidence.push(ResourceEvidence {
            route: RouteReference::from(route),
            resources: identities,
            call_chain_evidence: trace.calls.into_iter().collect(),
            abstention_reasons: trace.abstentions.into_iter().collect(),
        });
        facts.push(resources);
    }
    let normalize = |path: &str| {
        path.split('/')
            .filter(|s| !s.is_empty())
            .map(|s| {
                if is_dynamic_segment(s) {
                    "{}".to_owned()
                } else {
                    s.to_owned()
                }
            })
            .collect::<Vec<_>>()
    };
    let paths: Vec<_> = routes.iter().map(|r| normalize(&r.path)).collect();
    let crates: Vec<_> = routes
        .iter()
        .map(|r| module_location(root, &r.file).0)
        .collect();
    let mut seen = HashSet::new();
    let representatives: Vec<_> = routes
        .iter()
        .enumerate()
        .filter_map(|(i, r)| {
            seen.insert((
                crates[i].clone(),
                r.application.clone(),
                r.method.clone(),
                r.path.clone(),
                r.handler_path.clone(),
            ))
            .then_some(i)
        })
        .collect();
    let mut result = Vec::new();
    for (position, &left) in representatives.iter().enumerate() {
        for &right in &representatives[position + 1..] {
            let (a, b) = (&routes[left], &routes[right]);
            if crates[left] != crates[right] || a.application != b.application {
                continue;
            }
            let (pa, pb) = (&paths[left], &paths[right]);
            let same_path = pa == pb;
            let collection = (pa.len() + 1 == pb.len()
                && pb.last().is_some_and(|s| s == "{}")
                && pb.starts_with(pa))
                || (pb.len() + 1 == pa.len()
                    && pa.last().is_some_and(|s| s == "{}")
                    && pa.starts_with(pb));
            let siblings =
                pa.len() == pb.len() && pa.len() > 1 && pa[..pa.len() - 1] == pb[..pb.len() - 1];
            let common: std::collections::BTreeSet<_> = facts[left]
                .intersection(&facts[right])
                .filter(|s| !s.starts_with('@'))
                .cloned()
                .collect();
            if !(same_path || collection || siblings || !common.is_empty()) {
                continue;
            }
            let mut evidence = Vec::new();
            let mut conflicts = Vec::new();
            if same_path {
                evidence.push("same normalized resource path".into());
            }
            if collection {
                evidence.push("collection/item structure".into());
                conflicts.push("collection/item policies may differ".into());
            }
            if siblings {
                evidence.push("sibling path structure".into());
            }
            if !common.is_empty() {
                evidence.push(format!(
                    "shared resolved resource: {}",
                    common.iter().cloned().collect::<Vec<_>>().join(", ")
                ));
            }
            let conflicting_resources = facts[left].iter().any(|s| !s.starts_with('@'))
                && facts[right].iter().any(|s| !s.starts_with('@'))
                && common.is_empty();
            let left_operations: HashSet<_> =
                facts[left].iter().filter(|s| s.starts_with('@')).collect();
            let right_operations: HashSet<_> =
                facts[right].iter().filter(|s| s.starts_with('@')).collect();
            let conflicting_operations = !left_operations.is_empty()
                && !right_operations.is_empty()
                && left_operations != right_operations;
            if conflicting_operations {
                conflicts.push("different database operations".into());
            }
            if conflicting_resources {
                conflicts.push("known database resources differ".into());
            }
            if a.scope_prefix == b.scope_prefix {
                evidence.push("same mount scope".into());
            } else {
                conflicts.push("different mount scopes".into());
            }
            if a.method == b.method {
                evidence.push("same HTTP operation".into());
            } else {
                conflicts.push("different HTTP operations".into());
            }
            let contract_eligible = a.method == b.method
                && a.scope_prefix == b.scope_prefix
                && !collection
                && !conflicting_resources
                && !conflicting_operations
                && (same_path
                    || (!common.is_empty()
                        && dynamic_segment_shape(a) == dynamic_segment_shape(b)));
            if !contract_eligible {
                conflicts.push("relationship does not justify transferring a policy".into());
            }
            let nested_mount =
                a.scope_prefix != b.scope_prefix && nested_resource_mount(a, b, &common);
            if nested_mount {
                evidence.push("canonical data table corroborates a nested resource mount; policy contexts remain separate".into());
            }
            result.push(Relationship {
                left,
                right,
                kind: if nested_mount {
                    "nested_resource_mount"
                } else if same_path {
                    "same_resource"
                } else if collection {
                    "collection_item"
                } else if !common.is_empty() {
                    "shared_database_resource"
                } else {
                    "sibling_operations"
                }
                .into(),
                evidence_score: evidence.len(),
                confidence: if !conflicts.is_empty() {
                    "limited"
                } else if !common.is_empty() {
                    "corroborated"
                } else {
                    "structural"
                }
                .into(),
                evidence,
                conflicts,
                contract_eligible,
            });
        }
    }
    (result, resource_evidence)
}
pub(super) fn same_route(a: &RouteReference, b: &RouteReference) -> bool {
    a.application == b.application
        && a.scope_prefix == b.scope_prefix
        && a.method == b.method
        && a.path == b.path
        && a.handler == b.handler
        && a.file == b.file
        && a.line == b.line
}

// Resource membership is independent of authorization and of policy transfer.
// Cross-operation peers can share identity/ownership while differing in roles.
fn membership(r: &Relationship, routes: &[Route]) -> bool {
    let a = &routes[r.left];
    let b = &routes[r.right];
    if r.contract_eligible {
        return true;
    }
    if a.application != b.application
        || (a.scope_prefix != b.scope_prefix && r.kind != "nested_resource_mount")
        || is_authentication_route(a)
        || is_authentication_route(b)
        || is_operational_public_route(a)
        || is_operational_public_route(b)
        || r.conflicts
            .iter()
            .any(|c| c == "known database resources differ")
    {
        return false;
    }
    r.kind == "same_resource"
        || r.kind == "shared_database_resource"
        || r.kind == "nested_resource_mount"
        || (r.kind == "collection_item"
            && r.evidence
                .iter()
                .any(|e| e.starts_with("shared resolved resource:")))
        || (r.kind == "sibling_operations"
            && a.path.split('/').rev().skip(1).any(is_dynamic_segment)
            && dynamic_segment_shape(a) == dynamic_segment_shape(b))
}

pub(super) fn families(routes: &[Route], relationships: &[Relationship]) -> Vec<PeerGroup> {
    let edges: HashSet<_> = relationships
        .iter()
        .filter(|r| membership(r, routes))
        .map(|r| (r.left.min(r.right), r.left.max(r.right)))
        .collect();
    let connected = |a: usize, b: usize| a == b || edges.contains(&(a.min(b), a.max(b)));
    let mut sets = std::collections::BTreeSet::new();
    for anchor in 0..routes.len() {
        let neighbors: Vec<_> = (0..routes.len())
            .filter(|&i| connected(anchor, i))
            .collect();
        if neighbors.len() < 2 {
            continue;
        }
        if neighbors
            .iter()
            .all(|&a| neighbors.iter().all(|&b| connected(a, b)))
        {
            sets.insert(neighbors);
        } else {
            for &a in &neighbors {
                if a == anchor {
                    continue;
                }
                let mut pair = vec![anchor, a];
                pair.sort();
                sets.insert(pair);
                for &b in &neighbors {
                    if b == anchor || b <= a || !connected(a, b) {
                        continue;
                    }
                    let mut triangle = vec![anchor, a, b];
                    triangle.sort();
                    sets.insert(triangle);
                }
            }
        }
    }
    let maximal: Vec<_> = sets
        .iter()
        .filter(|s| {
            !sets
                .iter()
                .any(|t| t.len() > s.len() && s.iter().all(|i| t.contains(i)))
        })
        .collect();
    maximal
        .into_iter()
        .enumerate()
        .map(|(i, members)| PeerGroup {
            id: format!("peer-group-{:03}", i + 1),
            description: format!(
                "Related resource routes, supported by direct pairwise evidence: {}",
                relationships
                    .iter()
                    .filter(|r| members.contains(&r.left) && members.contains(&r.right))
                    .flat_map(|r| r.evidence.iter().cloned())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            routes: members
                .iter()
                .map(|&i| RouteReference::from(&routes[i]))
                .collect(),
        })
        .collect()
}

// Several checks of one dimension can have AND/OR semantics. Compare only one
// observed requirement; do not flatten separate checks into an invented policy.
fn policy(assessment: &Assessment, dimension: &str) -> Option<Vec<String>> {
    let requirements: Vec<_> = assessment
        .requirements
        .iter()
        .filter(|r| r.dimension == dimension)
        .collect();
    if dimension == "authentication"
        && requirements
            .iter()
            .any(|r| r.enforcement == Enforcement::Observed)
        && !requirements
            .iter()
            .any(|r| r.enforcement == Enforcement::Unresolved)
    {
        return Some(vec!["authenticated identity".into()]);
    }
    if requirements.len() != 1 || requirements[0].enforcement != Enforcement::Observed {
        return None;
    }
    if dimension == "authentication" {
        return Some(vec!["authenticated identity".into()]);
    }
    let mut values = requirements[0].values.clone();
    values.sort();
    values.dedup();
    if requirements[0].mechanism == "helper" && dimension != "ownership" && values.len() != 1 {
        return None;
    }
    if dimension == "ownership" {
        // Argument names are local bindings, not comparable resource identities.
        Some(vec!["ownership check".into()])
    } else if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

const DIMENSIONS: [&str; 4] = ["authentication", "roles", "permissions", "ownership"];

fn members<'a>(group: &PeerGroup, assessments: &'a [Assessment]) -> Vec<&'a Assessment> {
    group
        .routes
        .iter()
        .filter_map(|r| assessments.iter().find(|a| same_route(r, &a.route)))
        .collect()
}

fn policy_population<'a>(
    members: &[&'a Assessment],
    target: &Assessment,
    dimension: &str,
) -> Vec<&'a Assessment> {
    members
        .iter()
        .copied()
        .filter(|a| !same_route(&a.route, &target.route))
        .filter(|a| a.route.scope_prefix == target.route.scope_prefix)
        .filter(|a| {
            !matches!(dimension, "roles" | "permissions" | "ownership")
                || path_shape(&a.route.path) == path_shape(&target.route.path)
        })
        .collect()
}

fn path_shape(path: &str) -> Vec<bool> {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(is_dynamic_segment)
        .collect()
}

fn policy_support<'a>(
    members: &[&'a Assessment],
    dimension: &str,
) -> HashMap<Vec<String>, Vec<&'a Assessment>> {
    let mut support = HashMap::new();
    for member in members {
        if let Some(values) = policy(member, dimension) {
            support.entry(values).or_insert_with(Vec::new).push(*member);
        }
    }
    support
}

fn sufficient_support(supporters: usize, population: usize) -> bool {
    supporters >= 2 && supporters * 2 > population
}

fn invariant(
    group: &PeerGroup,
    members: &[&Assessment],
    description: String,
    values: &[String],
    supporters: usize,
) -> AuthorizationInvariant {
    AuthorizationInvariant {
        peer_group_id: group.id.clone(),
        description,
        total_routes: members.len(),
        routes_with_authorization: supporters,
        routes_without_authorization: members
            .iter()
            .filter(|a| a.route.status == RouteSecurityStatus::Unprotected)
            .count(),
        evidence_patterns: values.to_vec(),
        strength: AuthStrength::Medium,
    }
}

fn policy_key(route: &RouteReference, dimension: &str) -> String {
    format!("{}:{dimension}", comparison_key(route))
}

#[cfg(test)]
pub(super) fn extend(
    groups: &[PeerGroup],
    assessments: &[Assessment],
    details: &mut Vec<Finding>,
    findings: &mut Vec<String>,
) {
    infer(
        groups,
        assessments,
        details,
        findings,
        &mut Vec::new(),
        &mut HashSet::new(),
        &mut Vec::new(),
    );
}

pub(super) fn infer(
    groups: &[PeerGroup],
    assessments: &[Assessment],
    details: &mut Vec<Finding>,
    findings: &mut Vec<String>,
    invariants: &mut Vec<AuthorizationInvariant>,
    compared: &mut HashSet<String>,
    explanations: &mut Vec<StageEvidence>,
) {
    // Gather proposals before emitting findings: overlapping families must not
    // let traversal order choose between incompatible requirements.
    let mut proposals: HashMap<String, HashSet<Vec<String>>> = HashMap::new();
    for group in groups {
        let members = members(group, assessments);
        for target in &members {
            for dimension in DIMENSIONS {
                // Keep conflict proposals conservative across all overlapping groups;
                // a narrower comparison must not hide a conflicting proposal.
                let others: Vec<_> = members
                    .iter()
                    .copied()
                    .filter(|a| !same_route(&a.route, &target.route))
                    .collect();
                for (values, supporters) in policy_support(&others, dimension) {
                    if sufficient_support(supporters.len(), others.len()) {
                        proposals
                            .entry(policy_key(&target.route, dimension))
                            .or_default()
                            .insert(values);
                    }
                }
            }
        }
    }
    let mut emitted = HashSet::new();
    for group in groups {
        let members = members(group, assessments);
        // A shared observation from two members supports a group invariant;
        // detecting a deviation still requires two OTHER supporting peers.
        for dimension in DIMENSIONS {
            if members
                .iter()
                .any(|a| a.route.scope_prefix != members[0].route.scope_prefix)
            {
                continue;
            }
            if matches!(dimension, "roles" | "permissions" | "ownership")
                && members
                    .iter()
                    .any(|a| path_shape(&a.route.path) != path_shape(&members[0].route.path))
            {
                continue;
            }
            for (values, supporters) in policy_support(&members, dimension) {
                if sufficient_support(supporters.len(), members.len()) {
                    invariants.push(invariant(
                        group,
                        &members,
                        format!("Supported {dimension} requirement: {}", values.join(", ")),
                        &values,
                        supporters.len(),
                    ));
                }
            }
        }

        for target in &members {
            // Unknown behavior is not evidence of a missing requirement.
            if matches!(target.route.status, RouteSecurityStatus::Unknown { .. })
                || target
                    .requirements
                    .iter()
                    .any(|r| r.enforcement == Enforcement::Unresolved)
                || target
                    .route
                    .authorization
                    .iter()
                    .any(|e| e.kind == AuthEvidenceKind::Unknown)
            {
                for dimension in DIMENSIONS {
                    explanations.push(StageEvidence::drift(
                        group,
                        target,
                        dimension,
                        "Target enforcement is unresolved or contains unknown security behavior",
                        vec![],
                    ));
                }
                continue;
            }
            for dimension in DIMENSIONS {
                let others = policy_population(&members, target, dimension);
                let policies = policy_support(&others, dimension);
                // Require two supporting peers and a strict majority of all
                // other members, including unknown/unsupported members.
                let Some((expected, supporters)) = policies
                    .iter()
                    .find(|(_, peers)| sufficient_support(peers.len(), others.len()))
                else {
                    explanations.push(StageEvidence::drift(
                        group,
                        target,
                        dimension,
                        "Fewer than two agreeing comparable OTHER peers, or no strict majority",
                        vec![format!("{} comparable other members", others.len())],
                    ));
                    continue;
                };
                let actual = policy(target, dimension);
                let has_dimension = target.requirements.iter().any(|r| r.dimension == dimension);
                if has_dimension && actual.is_none() {
                    explanations.push(StageEvidence::drift(
                        group,
                        target,
                        dimension,
                        "Target requirement values are ambiguous, unsupported, or unresolved",
                        vec![],
                    ));
                    continue;
                }
                let key = policy_key(&target.route, dimension);
                if proposals.get(&key).is_some_and(|values| values.len() > 1) {
                    explanations.push(StageEvidence::drift(
                        group,
                        target,
                        dimension,
                        "Overlapping peer groups propose conflicting expectations",
                        vec![],
                    ));
                    continue;
                }
                compared.insert(comparison_key(&target.route));
                let contract = invariant(
                    group,
                    &members,
                    format!("Supported {dimension} requirement: {}", expected.join(", ")),
                    expected,
                    supporters.len(),
                );
                if !invariants.iter().any(|i| {
                    i.peer_group_id == contract.peer_group_id
                        && i.description == contract.description
                }) {
                    invariants.push(contract);
                }
                let mismatch = match &actual {
                    None => true,
                    Some(values) if dimension == "roles" =>
                    // Role values are allowlists. Narrower allowlists do
                    // not weaken the peer restriction; no role hierarchy is assumed.
                    {
                        values.iter().any(|v| !expected.contains(v))
                    }
                    Some(values) => values != expected,
                };
                explanations.push(StageEvidence::drift(
                    group,
                    target,
                    dimension,
                    "",
                    vec![
                        format!(
                            "{} of {} comparable other peers support {}",
                            supporters.len(),
                            others.len(),
                            expected.join(", ")
                        ),
                        if mismatch {
                            "Observed deviation; operation-specific exceptions still require review"
                                .into()
                        } else {
                            "Target satisfies the supported comparison".into()
                        },
                    ],
                ));
                if !mismatch || !emitted.insert(key) {
                    continue;
                }
                let category = if dimension == "authentication" {
                    DriftCategory::MissingEnforcement
                } else if dimension == "ownership" {
                    DriftCategory::MissingOwnershipValidation
                } else {
                    DriftCategory::InconsistentRoleOrPermission
                };
                let description = format!(
                    "Comparable peers support {dimension}: {}",
                    expected.join(", ")
                );
                let explanation = format!(
                    "Potential {dimension} drift: {} {} has {}; {} of {} other peers support {}. Confirm operation-specific policy exceptions before treating this as a vulnerability.",
                    target.route.method,
                    target.route.path,
                    actual
                        .as_ref()
                        .map(|v| v.join(", "))
                        .unwrap_or_else(|| "no observed requirement in this dimension".into()),
                    supporters.len(),
                    others.len(),
                    expected.join(", ")
                );
                details.push(Finding {
                    peer_group_id: group.id.clone(),
                    // Compatibility: finding evidence counts all authorized members,
                    // whereas the inferred contract counts policy supporters.
                    invariant: invariant(group, &members, description, expected,
                        members.iter().filter(|a| a.route.authorized).count()),
                    suspicious_route: target.route.clone(), suspicious_route_evidence: target.route.authorization.clone(),
                    authorized_peer_routes: supporters.iter().map(|a| a.route.clone()).collect(),
                    category, confidence: DriftConfidence::Medium,
                    explanation: explanation.clone(),
                    remediation: format!("Verify the intended {dimension} requirement and enforce it, or document the legitimate policy difference."),
                });
                findings.push(explanation);
            }
        }
    }
}
