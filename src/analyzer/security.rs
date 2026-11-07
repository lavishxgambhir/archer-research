//! Framework-neutral security observations, separate from peer inference.
use super::*;

pub(super) fn known_nonsecurity_constructor(expr: &Expr) -> bool {
    let mut root = expr;
    while let Expr::MethodCall(call) = root {
        root = &call.receiver;
    }
    matches!(root, Expr::Call(call) if matches!(&*call.func, Expr::Path(path) if path.path.segments.iter().any(|s| ["Cors", "Logger", "Compress", "NormalizePath", "DefaultHeaders"].contains(&s.ident.to_string().as_str()))))
}

pub(super) fn unknown_middleware(node: &ExprMethodCall, file: &Path) -> Vec<AuthEvidence> {
    let mut current = node;
    let mut evidence = Vec::new();
    loop {
        if current.method == "wrap" {
            for arg in &current.args {
                struct Names(Vec<String>);
                impl<'ast> Visit<'ast> for Names {
                    fn visit_expr_path(&mut self, p: &'ast ExprPath) {
                        self.0
                            .extend(p.path.segments.iter().map(|s| s.ident.to_string()));
                    }
                }
                let mut names = Names(Vec::new());
                names.visit_expr(arg);
                let known_nonsecurity = names.0.iter().any(|n| {
                    [
                        "Cors",
                        "Logger",
                        "Compress",
                        "NormalizePath",
                        "DefaultHeaders",
                    ]
                    .contains(&n.as_str())
                });
                if route_configuration_name_in_expr(arg).is_none() && !known_nonsecurity {
                    evidence.push(AuthEvidence {
                        kind: AuthEvidenceKind::Unknown,
                        mechanism: "UnresolvedMiddleware".into(),
                        symbol: Some(arg.to_token_stream().to_string()),
                        file: file.to_path_buf(),
                        line: arg.span().start().line,
                        handler: None,
                        strength: AuthStrength::Weak,
                    });
                }
            }
        }
        match &*current.receiver {
            Expr::MethodCall(next) => current = next,
            _ => break,
        }
    }
    evidence
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum Enforcement {
    Observed,
    Potential,
    Unresolved,
}

#[derive(Debug, Clone, Serialize)]
pub struct Requirement {
    pub dimension: String,
    pub values: Vec<String>,
    pub mechanism: String,
    pub enforcement: Enforcement,
    pub confidence: AuthStrength,
    pub file: PathBuf,
    pub line: usize,
    pub symbol: String,
    pub explanation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Assessment {
    pub route: RouteReference,
    pub requirements: Vec<Requirement>,
    pub uncertainty: Vec<String>,
}

// Resolve modeled external APIs through explicit imports, never by suffix or
// unique-name fallback. Local definitions and ambiguous/glob imports abstain.
pub(super) fn external_path(
    index: &HandlerIndex,
    context: &ModuleKey,
    path: &syn::Path,
    depth: usize,
) -> Option<String> {
    if depth >= 8 {
        return None;
    }
    let names: Vec<_> = path.segments.iter().map(|s| s.ident.to_string()).collect();
    let first = names.first()?;
    if let Some(imports) = index
        .scope(&context.0, &context.1)
        .and_then(|s| s.imports.get(first))
    {
        let [import] = imports.as_slice() else {
            return None;
        };
        let mut expanded = import.segments.clone();
        expanded.extend_from_slice(&names[1..]);
        let next: syn::Path = syn::parse_str(&expanded.join("::")).ok()?;
        if expanded == names {
            return None;
        }
        return external_path(index, context, &next, depth + 1);
    }
    if index
        .resolve_module(
            &context.0,
            &context.1,
            &UsePath {
                segments: vec![first.clone()],
                leading_colon: path.leading_colon.is_some(),
            },
            0,
        )
        .is_some()
    {
        return None;
    }
    if index
        .resolve_module(
            &context.0,
            &context.1,
            &UsePath {
                segments: names.clone(),
                leading_colon: path.leading_colon.is_some(),
            },
            0,
        )
        .is_some()
        || index
            .dependencies
            .contains_key(&(context.0.clone(), first.clone()))
        || index
            .scope(&context.0, &context.1)
            .is_some_and(|s| !s.globs.is_empty())
    {
        return None;
    }
    Some(names.join("::"))
}

fn impl_context(
    file: &Path,
    context: &ModuleKey,
    method: &syn::ImplItemFn,
) -> Option<HandlerDefinition> {
    Some(HandlerDefinition {
        file: file.into(),
        function: syn::parse2(method.to_token_stream()).ok()?,
        crate_key: context.0.clone(),
        module: context.1.clone(),
        name: method.sig.ident.to_string(),
        evidence: vec![],
        owner: None,
        implemented_trait: None,
    })
}

fn call_path(expr: &Expr) -> Option<&syn::Path> {
    if let Expr::Call(c) = expr {
        if let Expr::Path(p) = &*c.func {
            return Some(&p.path);
        }
    }
    None
}

// Deliberately small identity-value summary: verified JWT decode with default
// validation, projections, concrete constructors, and resolved local wrappers.
// Opaque database loads, callbacks and ambiguous conversions/adapters abstain.
fn token_alias(expr: &Expr, tokens: &HashSet<String>) -> bool {
    match expr {
        Expr::Path(p) => p
            .path
            .get_ident()
            .is_some_and(|n| tokens.contains(&n.to_string())),
        Expr::Reference(r) => token_alias(&r.expr, tokens),
        Expr::Paren(r) => token_alias(&r.expr, tokens),
        Expr::MethodCall(c)
            if c.args.is_empty()
                && matches!(
                    c.method.to_string().as_str(),
                    "to_owned" | "to_string" | "as_str" | "clone"
                ) =>
        {
            token_alias(&c.receiver, tokens)
        }
        _ => false,
    }
}

fn result_type(index: &HandlerIndex, context: &ModuleKey, ty: &syn::Type, depth: usize) -> bool {
    if depth >= 8 {
        return false;
    }
    let syn::Type::Path(p) = ty else { return false };
    if matches!(
        external_path(index, context, &p.path, 0).as_deref(),
        Some("Result" | "std::result::Result" | "core::result::Result")
    ) {
        return true;
    }
    let target = UsePath {
        segments: p
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect(),
        leading_colon: p.path.leading_colon.is_some(),
    };
    let Some(key) = index.resolve_module(&context.0, &context.1, &target, 0) else {
        return false;
    };
    if index.conditional_result_kinds.contains(&key) {
        return true;
    }
    index.type_aliases.get(&key).is_some_and(|a| {
        // A generic parameter named Result is not std::result::Result.
        if matches!(&*a.ty,syn::Type::Path(p) if p.path.segments.first().is_some_and(|s|a.generics.type_params().any(|t|t.ident==s.ident))) {return false;}
        result_type(
            index,
            &(key.0.clone(), key.1[..key.1.len() - 1].to_vec()),
            &a.ty,
            depth + 1,
        )
    })
}

// A name alone is not a conversion or a success-preserving error adapter.
// Inspect exactly one applicable concrete standard conversion implementation.
fn conversion(
    index: &HandlerIndex,
    caller: &HandlerDefinition,
    path: &syn::Path,
) -> Option<HandlerDefinition> {
    let name = path.segments.last()?.ident.to_string();
    if !matches!(name.as_str(), "from" | "try_from") {
        return None;
    }
    let mut owner_path = path.clone();
    owner_path.segments.pop();
    let ty = syn::Type::Path(syn::TypePath {
        attrs: vec![],
        qself: None,
        path: owner_path,
    });
    let owner = policy_drift::record_type(index, caller, &ty)?;
    let mut candidates = Vec::new();
    for (file, context, item) in &index.pending_impls {
        if item.generics.type_params().next().is_some()
            || item.generics.const_params().next().is_some()
        {
            continue;
        }
        let Some((p, _)) = &item.trait_ else { continue };
        let Some(api) = external_path(index, context, p, 0) else {
            continue;
        };
        if !matches!(
            (name.as_str(), api.as_str()),
            (
                "from",
                "std::convert::From" | "core::convert::From" | "From"
            ) | (
                "try_from",
                "std::convert::TryFrom" | "core::convert::TryFrom" | "TryFrom"
            )
        ) {
            continue;
        }
        for member in &item.items {
            let syn::ImplItem::Fn(method) = member else {
                continue;
            };
            if method.sig.ident != name {
                continue;
            }
            let mut c = impl_context(file, context, method)?;
            if policy_drift::record_type(index, &c, &item.self_ty).as_ref() != Some(&owner) {
                continue;
            }
            c.owner = Some(owner.clone());
            candidates.push(c);
        }
    }
    (candidates.len() == 1).then(|| candidates.remove(0))
}

fn error_adapter(index: &HandlerIndex, caller: &HandlerDefinition, name: &str) -> bool {
    if name == "map_err" {
        return true;
    }
    let mut candidates = Vec::new();
    for (_, context, item) in &index.pending_impls {
        if !result_type(index, context, &item.self_ty, 0) {
            continue;
        }
        let Some((path, _)) = &item.trait_ else {
            continue;
        };
        let target = UsePath {
            segments: path.segments.iter().map(|s| s.ident.to_string()).collect(),
            leading_colon: path.leading_colon.is_some(),
        };
        let Some(key) = index.resolve_module(&context.0, &context.1, &target, 0) else {
            continue;
        };
        let scoped = (caller.crate_key == key.0 && caller.module == key.1[..key.1.len() - 1])
            || index
                .scope(&caller.crate_key, &caller.module)
                .is_some_and(|s| {
                    s.imports.values().flatten().any(|p| {
                        index
                            .resolve_module(&caller.crate_key, &caller.module, p, 0)
                            .as_ref()
                            == Some(&key)
                    })
                });
        if !scoped {
            continue;
        }
        for member in &item.items {
            let syn::ImplItem::Fn(m) = member else {
                continue;
            };
            if m.sig.ident != name {
                continue;
            }
            let preserves = matches!(m.block.stmts.as_slice(),[Stmt::Expr(Expr::MethodCall(c),None)] if c.method=="map_err" && c.args.len()==1 && matches!(&*c.receiver,Expr::Path(p) if p.path.is_ident("self")));
            candidates.push(preserves);
        }
    }
    candidates.as_slice() == [true]
}

fn result_source(
    index: &HandlerIndex,
    caller: &HandlerDefinition,
    expr: &Expr,
    depth: usize,
) -> bool {
    if depth >= 8 {
        return false;
    }
    match expr {
        Expr::Await(e) => result_source(index, caller, &e.base, depth + 1),
        Expr::Paren(e) => result_source(index, caller, &e.expr, depth + 1),
        Expr::MethodCall(c) => {
            result_source(index, caller, &c.receiver, depth + 1)
                && error_adapter(index, caller, &c.method.to_string())
        }
        Expr::Call(_) => {
            let Some(p) = call_path(expr) else {
                return false;
            };
            let context = (caller.crate_key.clone(), caller.module.clone());
            if external_path(index, &context, p, 0).as_deref() == Some("jsonwebtoken::decode") {
                return true;
            }
            let target = HandlerTarget::Path {
                segments: p.segments.iter().map(|s| s.ident.to_string()).collect(),
                leading_colon: p.leading_colon.is_some(),
            };
            let helper = index.resolve_handler(&caller.crate_key, &caller.module, &target);
            if matches!(helper.1, HandlerResolution::UniqueName) {
                return false;
            }
            let found = helper.0.cloned().or_else(|| conversion(index, caller, p));
            found.is_some_and(|h|h.function.sig.generics.type_params().next().is_none() && matches!(&h.function.sig.output,syn::ReturnType::Type(_,ty) if result_type(index,&(h.crate_key.clone(),h.module.clone()),ty,0)))
        }
        _ => false,
    }
}

fn default_validation(index: &HandlerIndex, caller: &HandlerDefinition, expr: &Expr) -> bool {
    let Expr::Reference(r) = expr else {
        return false;
    };
    let context = (caller.crate_key.clone(), caller.module.clone());
    let is_default = |e: &Expr| {
        call_path(e).is_some_and(|p| {
            external_path(index, &context, p, 0).as_deref()
                == Some("jsonwebtoken::Validation::default")
        })
    };
    if is_default(&r.expr) {
        return true;
    }
    let Expr::Path(p) = &*r.expr else {
        return false;
    };
    let Some(name) = p.path.get_ident() else {
        return false;
    };
    let mut found = false;
    for stmt in &caller.function.block.stmts {
        if stmt.span().start() >= expr.span().start() || stmt.span().end() >= expr.span().end() {
            break;
        }
        if let Stmt::Local(local) = stmt {
            if matches!(&local.pat,Pat::Ident(p) if p.ident==*name && p.mutability.is_none())
                && local.init.as_ref().is_some_and(|i| is_default(&i.expr))
            {
                if found {
                    return false;
                }
                found = true;
                continue;
            }
        }
        struct Uses<'a> {
            name: &'a syn::Ident,
            found: bool,
        }
        impl<'ast> Visit<'ast> for Uses<'_> {
            fn visit_ident(&mut self, id: &'ast syn::Ident) {
                self.found |= id == self.name;
            }
        }
        let mut uses = Uses { name, found: false };
        uses.visit_stmt(stmt);
        if uses.found {
            return false;
        }
    }
    found
}

// A deliberately narrow request credential source: a required request cookie.
// Unrelated constants, app credentials and arbitrary parsing helpers abstain.
fn request_token(expr: &Expr, request: &syn::Ident, tokens: &HashSet<String>) -> bool {
    if token_alias(expr, tokens) {
        return true;
    }
    let Expr::MethodCall(value) = expr else {
        return false;
    };
    if value.method != "value" || !value.args.is_empty() {
        return false;
    }
    let Expr::Try(required) = &*value.receiver else {
        return false;
    };
    let Expr::MethodCall(error) = &*required.expr else {
        return false;
    };
    if error.method != "ok_or" || error.args.len() != 1 {
        return false;
    }
    let Expr::MethodCall(cookie) = &*error.receiver else {
        return false;
    };
    cookie.method == "cookie"
        && cookie.args.len() == 1
        && matches!(&*cookie.receiver,Expr::Path(p) if p.path.is_ident(request))
}

fn validated_value(
    index: &HandlerIndex,
    caller: &HandlerDefinition,
    expr: &Expr,
    values: &HashSet<String>,
    tokens: &HashSet<String>,
    depth: usize,
) -> bool {
    if depth >= 8 {
        return false;
    }
    match expr {
        Expr::Try(e) => validated_value(index, caller, &e.expr, values, tokens, depth),
        Expr::Await(e) => validated_value(index, caller, &e.base, values, tokens, depth),
        Expr::Paren(e) => validated_value(index, caller, &e.expr, values, tokens, depth),
        Expr::Reference(e) => validated_value(index, caller, &e.expr, values, tokens, depth),
        Expr::Return(e) => e
            .expr
            .as_ref()
            .is_some_and(|e| validated_value(index, caller, e, values, tokens, depth)),
        Expr::Block(e) => validated_block(
            index,
            caller,
            &e.block,
            values.clone(),
            tokens.clone(),
            depth,
        ),
        Expr::Path(e) => e
            .path
            .get_ident()
            .is_some_and(|n| values.contains(&n.to_string())),
        Expr::Field(e) => validated_value(index, caller, &e.base, values, tokens, depth),
        Expr::Struct(s) => {
            let ty = syn::Type::Path(syn::TypePath {
                attrs: vec![],
                qself: None,
                path: s.path.clone(),
            });
            s.rest.is_none()
                && !s.fields.is_empty()
                && policy_drift::record_type(index, caller, &ty).is_some()
                && s.fields
                    .iter()
                    .all(|f| validated_value(index, caller, &f.expr, values, tokens, depth))
        }
        Expr::MethodCall(c) => {
            if error_adapter(index, caller, &c.method.to_string())
                && result_source(index, caller, &c.receiver, 0)
            {
                return validated_value(index, caller, &c.receiver, values, tokens, depth);
            }
            // Round-tripping a verified Result through Option preserves only its
            // successful value. Error defaults and unchecked unwraps are not supported.
            if matches!(c.method.to_string().as_str(), "ok_or" | "ok_or_else") && c.args.len() == 1
            {
                if let Expr::MethodCall(ok) = &*c.receiver {
                    return ok.method == "ok"
                        && ok.args.is_empty()
                        && result_source(index, caller, &ok.receiver, 0)
                        && validated_value(index, caller, &ok.receiver, values, tokens, depth);
                }
            }
            false
        }
        Expr::Call(c) => {
            let Some(path) = call_path(expr) else {
                return false;
            };
            let context = (caller.crate_key.clone(), caller.module.clone());
            if external_path(index, &context, path, 0).as_deref() == Some("jsonwebtoken::decode") {
                return c.args.len() == 3
                    && token_alias(&c.args[0], tokens)
                    && c.args
                        .last()
                        .is_some_and(|e| default_validation(index, caller, e));
            }
            let ok_shadowed = caller.function.sig.inputs.iter().any(
                |a| matches!(a,FnArg::Typed(p) if matches!(&*p.pat,Pat::Ident(n) if n.ident=="Ok")),
            ) || caller.function.block.stmts.iter().any(
                |s| matches!(s,Stmt::Local(l) if matches!(&l.pat,Pat::Ident(n) if n.ident=="Ok")),
            ) || index
                .resolve_handler(
                    &caller.crate_key,
                    &caller.module,
                    &HandlerTarget::Path {
                        segments: vec!["Ok".into()],
                        leading_colon: false,
                    },
                )
                .1
                != HandlerResolution::Unresolved;
            if path.is_ident("Ok")
                && c.args.len() == 1
                && !ok_shadowed
                && index
                    .scope(&caller.crate_key, &caller.module)
                    .is_none_or(|s| !s.imports.contains_key("Ok"))
            {
                return validated_value(index, caller, &c.args[0], values, tokens, depth);
            }
            let target = HandlerTarget::Path {
                segments: path.segments.iter().map(|s| s.ident.to_string()).collect(),
                leading_colon: path.leading_colon.is_some(),
            };
            let (resolved, resolution) =
                index.resolve_handler(&caller.crate_key, &caller.module, &target);
            let converted = if resolved.is_none() {
                conversion(index, caller, path)
            } else {
                None
            };
            if let Some(helper) = resolved.or(converted.as_ref()) {
                if matches!(resolution, HandlerResolution::UniqueName) {
                    return false;
                }
                let args: HashSet<_> = helper
                    .function
                    .sig
                    .inputs
                    .iter()
                    .zip(&c.args)
                    .filter_map(|(p, e)| {
                        let FnArg::Typed(p) = p else { return None };
                        let Pat::Ident(p) = &*p.pat else { return None };
                        validated_value(index, caller, e, values, tokens, depth)
                            .then(|| p.ident.to_string())
                    })
                    .collect();
                let token_args = helper
                    .function
                    .sig
                    .inputs
                    .iter()
                    .zip(&c.args)
                    .filter_map(|(p, e)| {
                        let FnArg::Typed(p) = p else { return None };
                        let Pat::Ident(p) = &*p.pat else { return None };
                        token_alias(e, tokens).then(|| p.ident.to_string())
                    })
                    .collect();
                return validated_block(
                    index,
                    helper,
                    &helper.function.block,
                    args,
                    token_args,
                    depth + 1,
                );
            }
            // A concrete tuple-record constructor preserves only its supplied values.
            let ty = syn::Type::Path(syn::TypePath {
                attrs: vec![],
                qself: None,
                path: path.clone(),
            });
            policy_drift::record_type(index, caller, &ty).is_some()
                && !c.args.is_empty()
                && c.args
                    .iter()
                    .all(|e| validated_value(index, caller, e, values, tokens, depth))
        }
        _ => false,
    }
}

fn validated_block(
    index: &HandlerIndex,
    caller: &HandlerDefinition,
    block: &Block,
    mut values: HashSet<String>,
    mut tokens: HashSet<String>,
    depth: usize,
) -> bool {
    for (i, stmt) in block.stmts.iter().enumerate() {
        match stmt {
            Stmt::Local(local) => {
                let pattern = if let Pat::Type(t) = &local.pat {
                    &*t.pat
                } else {
                    &local.pat
                };
                let Pat::Ident(p) = pattern else {
                    return false;
                };
                if p.mutability.is_some() {
                    return false;
                }
                let trusted = local.init.as_ref().is_some_and(|v| {
                    validated_value(index, caller, &v.expr, &values, &tokens, depth)
                });
                let token = local
                    .init
                    .as_ref()
                    .is_some_and(|v| token_alias(&v.expr, &tokens));
                tokens.remove(&p.ident.to_string());
                if token {
                    tokens.insert(p.ident.to_string());
                }
                values.remove(&p.ident.to_string());
                if trusted {
                    values.insert(p.ident.to_string());
                }
            }
            Stmt::Expr(e, None) if i + 1 == block.stmts.len() => {
                return validated_value(index, caller, e, &values, &tokens, depth);
            }
            Stmt::Expr(Expr::Return(e), Some(_)) if i + 1 == block.stmts.len() => {
                return e
                    .expr
                    .as_ref()
                    .is_some_and(|e| validated_value(index, caller, e, &values, &tokens, depth));
            }
            // An ignored call, branch, assignment, or early return cannot be
            // silently interpreted as a successful validation summary.
            _ => return false,
        }
    }
    false
}

fn rejecting_extractor(index: &HandlerIndex, owner: &ModuleKey) -> Option<HandlerDefinition> {
    let mut found = Vec::new();
    for (file, context, item) in &index.pending_impls {
        let Some((path, _)) = &item.trait_ else {
            continue;
        };
        if external_path(index, context, path, 0).as_deref() != Some("actix_web::FromRequest") {
            continue;
        }
        for member in &item.items {
            let syn::ImplItem::Fn(method) = member else {
                continue;
            };
            if method.sig.ident != "from_request" {
                continue;
            }
            let Some(caller) = impl_context(file, context, method) else {
                continue;
            };
            if policy_drift::record_type(index, &caller, &item.self_ty).as_ref() != Some(owner) {
                continue;
            }
            // The supported form returns ready(match request.extensions().get::<Self>() ...).
            let Some(Stmt::Expr(Expr::Call(ready), None)) = method.block.stmts.last() else {
                continue;
            };
            if method.block.stmts.len() != 1 {
                continue;
            }
            let Some(path) = call_path(&Expr::Call(ready.clone())).cloned() else {
                continue;
            };
            if !matches!(
                external_path(index, context, &path, 0).as_deref(),
                Some("std::future::ready" | "core::future::ready")
            ) {
                continue;
            }
            let Some(Expr::Match(m)) = ready.args.first() else {
                continue;
            };
            let Expr::MethodCall(get) = &*m.expr else {
                continue;
            };
            if get.method != "get" || !get.args.is_empty() {
                continue;
            }
            let Expr::MethodCall(ext) = &*get.receiver else {
                continue;
            };
            if ext.method != "extensions" || !ext.args.is_empty() {
                continue;
            }
            let Some(FnArg::Typed(arg)) = method.sig.inputs.first() else {
                continue;
            };
            let Pat::Ident(req) = &*arg.pat else { continue };
            if !matches!(&*ext.receiver,Expr::Path(p) if p.path.is_ident(&req.ident)) {
                continue;
            }
            let Some(args) = &get.turbofish else { continue };
            let Some(syn::GenericArgument::Type(ty)) = args.args.first() else {
                continue;
            };
            let mut self_context = caller.clone();
            self_context.owner = Some(owner.clone());
            if policy_drift::record_type(index, &self_context, ty).as_ref() != Some(owner) {
                continue;
            }
            let mut yes = false;
            let mut no = false;
            if m.arms.len() != 2 {
                continue;
            }
            for arm in &m.arms {
                match &arm.pat {
                    Pat::TupleStruct(p) if p.path.is_ident("Some") && p.elems.len() == 1 => {
                        if let Pat::Ident(binding) = &p.elems[0] {
                            if let Expr::Call(ok) = &*arm.body {
                                yes = call_path(&arm.body).is_some_and(|p| p.is_ident("Ok"))
                                    && ok.args.len() == 1
                                    && matches!(&ok.args[0],Expr::MethodCall(c) if c.method=="clone" && c.args.is_empty() && matches!(&*c.receiver,Expr::Path(p) if p.path.is_ident(&binding.ident)));
                            }
                        }
                    }
                    Pat::Ident(p) if p.ident == "None" && p.subpat.is_none() => {
                        no = call_path(&arm.body).is_some_and(|p| p.is_ident("Err"))
                    }
                    _ => {}
                }
            }
            if yes && no {
                found.push(caller);
            }
        }
    }
    (found.len() == 1).then(|| found.remove(0))
}

fn middleware_identity(
    index: &HandlerIndex,
    evidence: &AuthEvidence,
    identity: &ModuleKey,
) -> bool {
    let Some((crate_key, module)) = index.file_modules.get(&evidence.file) else {
        return false;
    };
    let Some(expr) = evidence
        .symbol
        .as_ref()
        .and_then(|s| syn::parse_str::<Expr>(s).ok())
    else {
        return false;
    };
    let Some(path) = call_path(&expr) else {
        return false;
    };
    let mut ty_path = path.clone();
    ty_path.segments.pop();
    let ty = syn::Type::Path(syn::TypePath {
        attrs: vec![],
        qself: None,
        path: ty_path,
    });
    let Some(template) = index.definitions.iter().find(|d| d.crate_key == *crate_key) else {
        return false;
    };
    let context = HandlerDefinition {
        crate_key: crate_key.clone(),
        module: module.clone(),
        ..template.clone()
    };
    let Some(wrapper) = policy_drift::record_type(index, &context, &ty) else {
        return false;
    };
    let mut services = Vec::new();
    for (file, scope, item) in &index.pending_impls {
        let Some((p, _)) = &item.trait_ else { continue };
        if !matches!(
            external_path(index, scope, p, 0).as_deref(),
            Some("actix_web::dev::Transform" | "actix_service::Transform")
        ) {
            continue;
        }
        let c = HandlerDefinition {
            crate_key: scope.0.clone(),
            module: scope.1.clone(),
            file: file.clone(),
            ..context.clone()
        };
        if policy_drift::record_type(index, &c, &item.self_ty).as_ref() != Some(&wrapper) {
            continue;
        }
        for member in &item.items {
            if let syn::ImplItem::Type(t) = member {
                if t.ident == "Transform" {
                    if let Some(owner) = policy_drift::record_type(index, &c, &t.ty) {
                        services.push(owner);
                    }
                }
            }
        }
    }
    if services.len() != 1 {
        return false;
    }
    let mut proofs = 0;
    for (file, scope, item) in &index.pending_impls {
        let Some((p, _)) = &item.trait_ else { continue };
        if !matches!(
            external_path(index, scope, p, 0).as_deref(),
            Some("actix_web::dev::Service" | "actix_service::Service")
        ) {
            continue;
        }
        for member in &item.items {
            let syn::ImplItem::Fn(method) = member else {
                continue;
            };
            if method.sig.ident != "call" {
                continue;
            }
            let Some(c) = impl_context(file, scope, method) else {
                continue;
            };
            if policy_drift::record_type(index, &c, &item.self_ty).as_ref() != Some(&services[0]) {
                continue;
            }
            if insertion_proof(index, &c, identity) {
                proofs += 1;
            }
        }
    }
    proofs == 1
}

fn insertion_proof(index: &HandlerIndex, caller: &HandlerDefinition, identity: &ModuleKey) -> bool {
    let Some(FnArg::Typed(arg)) = caller
        .function
        .sig
        .inputs
        .iter()
        .find(|a| matches!(a, FnArg::Typed(_)))
    else {
        return false;
    };
    let Pat::Ident(req) = &*arg.pat else {
        return false;
    };
    let mut block = &*caller.function.block;
    // Permit immutable self-field clones before constructing the Service future.
    // Request aliases, arbitrary calls and branch-dependent preambles abstain.
    if let Some(Stmt::Expr(Expr::Call(c), None)) = block.stmts.last() {
        if let Some(Expr::Async(a)) = c.args.first() {
            if !call_path(&Expr::Call(c.clone())).is_some_and(|p| {
                p.segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect::<Vec<_>>()
                    == ["Box", "pin"]
            }) {
                return false;
            }
            for stmt in &block.stmts[..block.stmts.len() - 1] {
                let Stmt::Local(l) = stmt else { return false };
                let Pat::Ident(p) = &l.pat else { return false };
                if p.mutability.is_some() || p.ident == req.ident {
                    return false;
                }
                let Some(init) = &l.init else { return false };
                let Expr::MethodCall(c) = &*init.expr else {
                    return false;
                };
                if c.method != "clone" || !c.args.is_empty() {
                    return false;
                }
                let mut root = &*c.receiver;
                while let Expr::Field(f) = root {
                    root = &f.base;
                }
                if !matches!(root,Expr::Path(p) if p.path.is_ident("self")) {
                    return false;
                }
            }
            block = &a.block;
        }
    }
    let mut producers = HashSet::new();
    let mut tokens = HashSet::new();
    let mut inserted = false;
    for (position, stmt) in block.stmts.iter().enumerate() {
        if inserted {
            let expr = match stmt {
                Stmt::Expr(expr, None) if position + 1 == block.stmts.len() => expr,
                Stmt::Local(local) => {
                    let Some(init) = &local.init else {
                        return false;
                    };
                    if !matches!(&*init.expr,Expr::Try(t) if matches!(&*t.expr,Expr::Await(_)))
                        && !matches!(&*init.expr, Expr::Await(_))
                    {
                        return false;
                    }
                    &init.expr
                }
                _ => return false,
            };
            let expr = if let Expr::Try(t) = expr {
                &t.expr
            } else {
                expr
            };
            let Expr::MethodCall(call) = consumed_expression(expr) else {
                return false;
            };
            return call.method == "call"
                && call.args.len() == 1
                && matches!(&call.args[0],Expr::Path(p) if p.path.is_ident(&req.ident));
        }
        match stmt {
            Stmt::Local(local) => {
                let Pat::Ident(p) = &local.pat else {
                    return false;
                };
                if p.mutability.is_some() {
                    return false;
                }
                producers.remove(&p.ident.to_string());
                let Some(init) = &local.init else {
                    return false;
                };
                let token = request_token(&init.expr, &req.ident, &tokens);
                tokens.remove(&p.ident.to_string());
                if token {
                    tokens.insert(p.ident.to_string());
                    continue;
                }
                let producer = (|| {
                    let Expr::Try(t) = &*init.expr else {
                        return false;
                    };
                    let mut value = consumed_expression(&t.expr);
                    for _ in 0..8 {
                        let Expr::MethodCall(c) = value else { break };
                        if !error_adapter(index, caller, &c.method.to_string())
                            || !result_source(index, caller, &c.receiver, 0)
                        {
                            break;
                        }
                        value = consumed_expression(&c.receiver);
                    }
                    let Some(path) = call_path(value) else {
                        return false;
                    };
                    let target = HandlerTarget::Path {
                        segments: path.segments.iter().map(|s| s.ident.to_string()).collect(),
                        leading_colon: path.leading_colon.is_some(),
                    };
                    let (Some(helper), resolution) =
                        index.resolve_handler(&caller.crate_key, &caller.module, &target)
                    else {
                        return false;
                    };
                    if matches!(resolution, HandlerResolution::UniqueName) {
                        return false;
                    }
                    let syn::ReturnType::Type(_, ty) = &helper.function.sig.output else {
                        return false;
                    };
                    policy_drift::record_type(index, helper, ty).as_ref() == Some(identity)
                        && validated_value(index, caller, value, &HashSet::new(), &tokens, 0)
                })();
                if producer {
                    producers.insert(p.ident.to_string());
                    continue;
                }
                // Unknown local calls can mutate a request or hide control flow;
                // never skip them just because their return value is unused.
                fn inert(e: &Expr) -> bool {
                    match e {
                        Expr::Path(_) | Expr::Lit(_) => true,
                        Expr::Reference(r) => inert(&r.expr),
                        Expr::Field(f) => inert(&f.base),
                        _ => false,
                    }
                }
                if !inert(&init.expr) {
                    return false;
                }
            }
            Stmt::Expr(Expr::MethodCall(insert), Some(_))
                if insert.method == "insert" && insert.args.len() == 1 =>
            {
                let Expr::MethodCall(ext) = &*insert.receiver else {
                    return false;
                };
                if ext.method == "extensions_mut"
                    && matches!(&*ext.receiver,Expr::Path(p) if p.path.is_ident(&req.ident))
                    && matches!(&insert.args[0],Expr::Path(p) if p.path.get_ident().is_some_and(|n|producers.contains(&n.to_string())))
                {
                    inserted = true;
                } else {
                    return false;
                }
            }
            // No branch/assignment can be skipped on the way to the insertion.
            _ => return false,
        }
    }
    false
}

struct ConstructorVisitor {
    calls: Vec<(usize, String, Vec<String>, Vec<String>)>,
}
impl<'ast> Visit<'ast> for ConstructorVisitor {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if let Expr::Path(path) = &*node.func {
            let segments: Vec<_> = path
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            if segments.len() >= 2 && segments.last().is_some_and(|s| s == "allowed_roles") {
                let mut values = Vec::new();
                for arg in &node.args {
                    // vec! is an opaque macro in syn; parse its expression list explicitly.
                    if let Expr::Macro(m) = arg {
                        use syn::parse::Parser;
                        if m.mac.path.is_ident("vec") {
                            let parser = syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated;
                            if let Ok(items) = parser.parse2(m.mac.tokens.clone()) {
                                for item in items {
                                    if let Expr::Path(p) = item {
                                        values.push(
                                            p.path.to_token_stream().to_string().replace(' ', ""),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                self.calls.push((
                    node.span().start().line,
                    segments[segments.len() - 2].clone(),
                    values,
                    segments,
                ));
            } else if segments.len() >= 2 && segments.last().is_some_and(|s| s == "admin") {
                self.calls.push((
                    node.span().start().line,
                    segments[segments.len() - 2].clone(),
                    vec!["Admin".into()],
                    segments,
                ));
            }
        }
        visit::visit_expr_call(self, node);
    }
}

pub(super) fn assess(
    routes: &mut [Route],
    files: &[(ModuleKey, PathBuf, syn::File)],
    index: &HandlerIndex,
) -> Vec<Assessment> {
    let constructors: HashMap<_, _> = files
        .iter()
        .map(|(_, path, ast)| {
            let mut visitor = ConstructorVisitor { calls: Vec::new() };
            visitor.visit_file(ast);
            (path.clone(), visitor.calls)
        })
        .collect();
    let mut extractor_cache: HashMap<ModuleKey, Option<HandlerDefinition>> = HashMap::new();
    let mut provenance_cache = HashMap::new();
    routes.iter_mut().map(|route| {
        let mut requirements = Vec::new();
        let mut uncertainty = Vec::new();
        let handler = index.route_handler(route);
        if let Some(handler) = handler {
            // Resolve aliases before classifying helper names. Evidence retains
            // the spelling at the call site so control-flow checks still match.
            struct Calls(Vec<(String, usize)>);
            impl<'ast> Visit<'ast> for Calls {
                fn visit_expr_call(&mut self, call: &'ast ExprCall) {
                    if let Expr::Path(path) = &*call.func {
                        self.0.push((path.path.to_token_stream().to_string().replace(' ', ""), call.span().start().line));
                    }
                    visit::visit_expr_call(self, call);
                }
                fn visit_item_fn(&mut self, _: &'ast ItemFn) {}
            }
            let mut calls = Calls(Vec::new()); calls.visit_block(&handler.function.block);
            for (symbol, line) in calls.0 {
                if route.authorization.iter().any(|e| e.symbol.as_ref() == Some(&symbol) && e.line == line) { continue; }
                let target = HandlerTarget::Path { segments: symbol.trim_start_matches("::").split("::").map(str::to_owned).collect(), leading_colon: symbol.starts_with("::") };
                if let (Some(helper), _) = index.resolve_handler(&handler.crate_key, &handler.module, &target) {
                    if let Some(mut evidence) = evidence_for_handler_method(&helper.name, line, &handler.file, &handler.name) {
                        evidence.symbol = Some(symbol); route.authorization.push(evidence);
                    }
                }
            }
            for input in &handler.function.sig.inputs {
                if let FnArg::Typed(arg) = input {
                    let ty = arg.ty.to_token_stream().to_string();
                    if ["Authenticated", "Claims", "Identity", "ReqData"].iter().any(|name| ty.contains(name)) {
                        requirements.push(Requirement {
                            dimension: "authentication".into(), values: vec![ty.clone()], mechanism: "extractor".into(),
                            enforcement: Enforcement::Potential, confidence: AuthStrength::Weak,
                            file: handler.file.clone(), line: arg.span().start().line, symbol: ty,
                            explanation: "Security-relevant typed parameter; extractor rejection semantics require verification".into(),
                        });
                    }
                }
            }
        }
        for evidence in &mut route.authorization {
            let constructor = constructors.get(&evidence.file).and_then(|calls| calls.iter().find(|(line, symbol, _, path)| *line == evidence.line && (symbol == &evidence.mechanism || evidence.symbol.as_ref().is_some_and(|s| s.replace(' ', "").contains(&path.join("::"))))));
            if let Some((_, symbol, roles, path)) = constructor {
                let location = index.file_modules.get(&evidence.file);
                let resolved = location.and_then(|(key, module)| index.resolve_handler(key, module, &HandlerTarget::Path { segments: path.clone(), leading_colon: false }).0);
                let canonical = resolved.and_then(|d| d.owner.as_ref().and_then(|k| k.1.last()).or_else(|| d.module.last())).map(String::as_str).unwrap_or(symbol);
                let explicit_origin = path.len() > 2 || location.is_some_and(|(key, module)|
                    path.first().is_some_and(|name| index.scope(key, module).is_some_and(|scope| scope.imports.contains_key(name))));
                let crate_key = resolved.map(|d| &d.crate_key).or_else(||
                    if explicit_origin { None } else { location.map(|(key, _)| key) });
                // Existing named models are reused only in the resolved constructor's
                // crate. An identically named implementation elsewhere is not evidence.
                let model_module = resolved.map(|d| d.module.as_slice());
                let implementations: Vec<_> = files.iter().filter(|(key, _, _)| Some(&key.0) == crate_key)
                    .filter_map(|(key, _, ast)| {
                        let relative = if let Some(module) = model_module { module.strip_prefix(key.1.as_slice())? } else { &[] };
                        module_items(&ast.items, relative)
                    }).collect();
                let roles = if canonical == "RoleGuard" {
                    implementations.iter().flat_map(|items| constructor_roles(items)).collect::<Vec<_>>()
                } else { roles.clone() };
                let validated = implementations.iter().any(|items| middleware_has_role_gate(items, canonical));
                if !roles.is_empty() && validated {
                    // Explicit API model. This records the model's scope instead of
                    // promoting arbitrary Auth/Role identifiers to authorization.
                    evidence.kind = AuthEvidenceKind::RoleCheck;
                    evidence.strength = AuthStrength::Medium;
                    requirements.push(Requirement {
                        dimension: "roles".into(), values: roles.clone(), mechanism: "middleware".into(),
                        enforcement: Enforcement::Observed, confidence: AuthStrength::Medium,
                        file: evidence.file.clone(), line: evidence.line, symbol: symbol.clone(),
                        explanation: "Parameterized middleware model with a local role-dependent service-call/rejection branch; role arguments retained. Not a whole-program proof.".into(),
                    });
                    requirements.push(Requirement {
                        dimension: "authentication".into(), values: Vec::new(), mechanism: "middleware".into(),
                        enforcement: Enforcement::Observed, confidence: AuthStrength::Medium,
                        file: evidence.file.clone(), line: evidence.line, symbol: symbol.clone(),
                        explanation: "Identity prerequisite of modeled role middleware".into(),
                    });
                    continue;
                }
                evidence.kind = AuthEvidenceKind::Unknown;
                uncertainty.push("Role middleware arguments or local enforcement implementation could not be verified".into());
            }
            let dimension = match evidence.kind {
                AuthEvidenceKind::IdentityExtraction => "authentication",
                AuthEvidenceKind::RoleCheck => "roles",
                AuthEvidenceKind::PermissionCheck => "permissions",
                AuthEvidenceKind::OwnershipCheck => "ownership",
                AuthEvidenceKind::Unknown => "unresolved",
                _ => "authorization",
            };
            let mechanism = match evidence.kind {
                AuthEvidenceKind::AuthorizationGuard => "route_guard",
                AuthEvidenceKind::AuthorizationMiddleware => "middleware",
                _ if evidence.mechanism.ends_with("Middleware") || evidence.mechanism == "RequireAuth" => "middleware",
                _ => "helper",
            };
            let mut values = Vec::new();
            let mut observed = false;
            let mut source_predicate=false;
            if let Some(handler) = handler {
                let mut arguments = CallArguments { symbol: evidence.symbol.as_deref().unwrap_or(""), values: Vec::new() };
                arguments.visit_block(&handler.function.block);
                values = arguments.values;
                let mut control = ControlledCalls::default();
                control.visit_block(&handler.function.block);
                if let Some(symbol) = &evidence.symbol {
                    let target = HandlerTarget::Path { segments: symbol.split("::").map(str::to_owned).collect(), leading_colon: false };
                    let (helper, _) = index.resolve_handler(&handler.crate_key, &handler.module, &target);
                    if let Some(helper) = helper {
                        observed = control.predicates.contains(symbol) || (control.propagated.contains(symbol) && helper_may_reject(index, helper, 0, &mut HashSet::new()));
                        if !observed && !helper_may_reject(index, helper, 0, &mut HashSet::new()) && evidence.is_authorization() {
                            evidence.kind = AuthEvidenceKind::Unknown;
                            uncertainty.push(format!("Local helper {symbol} has no supported rejection path; its name is not enforcement proof"));
                        }
                        if observed && values.is_empty() && matches!(dimension,"roles"|"permissions") {
                            let predicate=field_gate_policy(index,helper);
                            let candidate=helper.function.block.stmts.iter().any(|s|matches!(s,Stmt::Expr(Expr::If(i),_) if matches!(&*i.cond,Expr::Field(_)) || matches!(&*i.cond,Expr::Unary(u) if matches!(&*u.expr,Expr::Field(_)))));
                            if predicate.is_some() || candidate {
                                if mandatory_helper_call(index,handler,symbol) {
                                    if let Some(predicate)=predicate {values.push(predicate);source_predicate=true;} else {observed=false;}
                                } else {observed=false;}
                                if !observed {uncertainty.push("Field-based helper has no proven mandatory predicate on every successful request path".into());}
                            }
                        }
                    }
                }
            }
            if evidence.is_authorization() && !observed {
                evidence.kind = AuthEvidenceKind::Unknown;
                uncertainty.push("Lexical authorization evidence lacks a verified local enforcement path".into());
            }
            requirements.push(Requirement {
                dimension: dimension.into(), values, mechanism: mechanism.into(),
                enforcement: if observed { Enforcement::Observed } else if evidence.kind == AuthEvidenceKind::Unknown { Enforcement::Unresolved } else { Enforcement::Potential },
                confidence: if observed { evidence.strength.clone() } else { AuthStrength::Weak }, file: evidence.file.clone(), line: evidence.line,
                symbol: evidence.symbol.clone().unwrap_or_default(),
                explanation: if source_predicate {"Unconditional consumed helper requires this source-resolved boolean field predicate on every successful return; this does not establish identity provenance or authentication".into()} else if observed { "Local predicate controls a rejection branch, or a local fallible helper propagates rejection".into() } else { "Lexical evidence; acceptance/rejection control flow has not been proven".into() },
            });
        }
        if requirements.iter().any(|r| r.enforcement == Enforcement::Potential) {
            uncertainty.push("Potential evidence is retained separately from observed enforcement".into());
        }
        if let Some(handler) = handler {
            if !requirements.iter().any(|r|matches!(r.dimension.as_str(),"roles"|"permissions"|"ownership") && r.enforcement==Enforcement::Observed) && unmodeled_field_rejection(handler) {
                route.authorization.push(AuthEvidence{kind:AuthEvidenceKind::Unknown,mechanism:"UnclassifiedFieldRejection".into(),symbol:None,file:handler.file.clone(),line:handler.function.sig.ident.span().start().line,handler:Some(handler.name.clone()),strength:AuthStrength::Weak});
                requirements.push(Requirement{dimension:"unresolved".into(),values:vec![],mechanism:"inline predicate".into(),enforcement:Enforcement::Unresolved,confidence:AuthStrength::Weak,file:handler.file.clone(),line:handler.function.sig.ident.span().start().line,symbol:handler.rust_path(),explanation:"A field predicate can reject the request; its authorization meaning is unclassified, so absence of a named helper is not absence of enforcement".into()});
            }
            for input in &handler.function.sig.inputs {
                let FnArg::Typed(arg)=input else{continue};
                let syn::Type::Path(outer)=&*arg.ty else{continue};
                let context=(handler.crate_key.clone(),handler.module.clone());
                let optional=matches!(external_path(index,&context,&outer.path,0).as_deref(),Some("Option"|"std::option::Option"|"core::option::Option"));
                let path=if optional {
                    let Some(segment)=outer.path.segments.last() else{continue};
                    let syn::PathArguments::AngleBracketed(args)=&segment.arguments else{continue};
                    let Some(syn::GenericArgument::Type(syn::Type::Path(inner)))=args.args.first() else{continue}; inner
                } else {outer};
                let target=UsePath{segments:path.path.segments.iter().map(|s|s.ident.to_string()).collect(),leading_colon:path.path.leading_colon.is_some()};
                // Other wrappers and unresolved aliases do not establish a required extractor.
                let Some(owner)=index.resolve_module(&handler.crate_key,&handler.module,&target,0).filter(|k|index.record_types.contains(k)) else{continue};
                let Some(extractor)=extractor_cache.entry(owner.clone()).or_insert_with(||rejecting_extractor(index,&owner)) else{continue};
                let observed=!optional && route.authorization.iter().any(|e| e.mechanism=="UnresolvedMiddleware" && *provenance_cache.entry((e.file.clone(),e.line,e.symbol.clone(),owner.clone())).or_insert_with(||middleware_identity(index,e,&owner)));
                let explanation=if optional {"Optional identity extractor permits absence; it does not establish mandatory authentication".into()} else if observed {format!("Required extractor rejects missing extension ({}:{}); mounted middleware inserts a value derived from verified JWT decoding",extractor.file.display(),extractor.function.sig.ident.span().start().line)} else {format!("Required extractor rejects missing extension ({}:{}), but validated identity production on this mount is unverified",extractor.file.display(),extractor.function.sig.ident.span().start().line)};
                requirements.push(Requirement{dimension:"authentication".into(),values:vec!["authenticated identity".into()],mechanism:"extractor".into(),enforcement:if observed{Enforcement::Observed}else{Enforcement::Potential},confidence:if observed{AuthStrength::Medium}else{AuthStrength::Weak},file:handler.file.clone(),line:arg.span().start().line,symbol:arg.ty.to_token_stream().to_string(),explanation:explanation.clone()});
                if observed {
                    route.authorization.push(AuthEvidence{kind:AuthEvidenceKind::AuthorizationGuard,mechanism:"VerifiedIdentityExtractor".into(),symbol:Some(arg.ty.to_token_stream().to_string()),file:handler.file.clone(),line:arg.span().start().line,handler:Some(handler.name.clone()),strength:AuthStrength::Medium});
                } else if !optional { route.authorization.push(AuthEvidence{kind:AuthEvidenceKind::Unknown,mechanism:"UnverifiedIdentityExtractor".into(),symbol:Some(arg.ty.to_token_stream().to_string()),file:handler.file.clone(),line:arg.span().start().line,handler:Some(handler.name.clone()),strength:AuthStrength::Weak}); uncertainty.push(explanation); }
            }
        }
        if let RouteSecurityStatus::Unknown { reason } = route.security_status() {
            if !uncertainty.contains(&reason) { uncertainty.push(reason); }
        }
        Assessment { route: RouteReference::from(&*route), requirements, uncertainty }
    }).collect()
}

fn module_items<'a>(items: &'a [Item], path: &[String]) -> Option<&'a [Item]> {
    let Some((name, rest)) = path.split_first() else {
        return Some(items);
    };
    items.iter().find_map(|item| match item {
        Item::Mod(module) if module.ident == name.as_str() => module
            .content
            .as_ref()
            .and_then(|(_, items)| module_items(items, rest)),
        _ => None,
    })
}

fn constructor_roles(items: &[Item]) -> Vec<String> {
    struct Values(Vec<String>);
    impl<'ast> Visit<'ast> for Values {
        fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
            for field in &node.fields {
                if matches!(&field.member, syn::Member::Named(name) if name == "role") {
                    if let Expr::Path(value) = &field.expr {
                        self.0
                            .push(value.path.to_token_stream().to_string().replace(' ', ""));
                    }
                }
            }
        }
    }
    let mut values = Values(Vec::new());
    for item in items {
        if let Item::Impl(item) = item {
            if matches!(&*item.self_ty, syn::Type::Path(ty) if ty.path.is_ident("RoleGuard")) {
                for method in &item.items {
                    if let syn::ImplItem::Fn(method) = method {
                        if method.sig.ident == "admin" {
                            values.visit_block(&method.block);
                        }
                    }
                }
            }
        }
    }
    values.0
}

#[derive(Default)]
struct ControlledCalls {
    predicates: HashSet<String>,
    propagated: HashSet<String>,
}
impl<'ast> Visit<'ast> for ControlledCalls {
    fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
        if let Expr::Call(call) = consumed_expression(&node.expr) {
            self.propagated
                .insert(call.func.to_token_stream().to_string().replace(' ', ""));
        }
        visit::visit_expr_try(self, node);
    }
    fn visit_expr_closure(&mut self, _: &'ast ExprClosure) {}
    fn visit_item_fn(&mut self, _: &'ast ItemFn) {}
    fn visit_expr_async(&mut self, _: &'ast syn::ExprAsync) {}
    fn visit_expr_if(&mut self, node: &'ast ExprIf) {
        struct Calls {
            names: HashSet<String>,
            rejects: bool,
        }
        impl<'ast> Visit<'ast> for Calls {
            fn visit_expr_return(&mut self, node: &'ast syn::ExprReturn) {
                self.rejects |= node.expr.as_deref().is_some_and(|expr| matches!(expr, Expr::Call(call) if matches!(&*call.func, Expr::Path(p) if p.path.is_ident("Err"))));
                visit::visit_expr_return(self, node);
            }
            fn visit_expr_call(&mut self, call: &'ast ExprCall) {
                let name = call.func.to_token_stream().to_string().replace(' ', "");
                self.names.insert(name);
                visit::visit_expr_call(self, call);
            }
        }
        let mut branches = Calls {
            names: HashSet::new(),
            rejects: false,
        };
        branches.visit_block(&node.then_branch);
        if let Some((_, other)) = &node.else_branch {
            branches.visit_expr(other);
        }
        if branches.rejects {
            let mut condition = Calls {
                names: HashSet::new(),
                rejects: false,
            };
            condition.visit_expr(&node.cond);
            self.predicates.extend(condition.names);
        }
        visit::visit_expr_if(self, node);
    }
}

fn middleware_has_role_gate(items: &[Item], symbol: &str) -> bool {
    let expected = if symbol == "RequireAuth" {
        "AuthMiddleware"
    } else {
        "RoleGuardMiddleware"
    };
    #[derive(Default)]
    struct Gate {
        role: bool,
        forwards: bool,
        rejects: bool,
        bindings: HashSet<String>,
        conditional: bool,
    }
    impl<'ast> Visit<'ast> for Gate {
        fn visit_local(&mut self, node: &'ast syn::Local) {
            if let (Pat::Ident(name), Some(init)) = (&node.pat, &node.init) {
                let mut value = Gate::default();
                value.visit_expr(&init.expr);
                if value.role {
                    self.bindings.insert(name.ident.to_string());
                }
            }
            visit::visit_local(self, node);
        }
        fn visit_expr_if(&mut self, node: &'ast ExprIf) {
            let mut condition = Gate::default();
            condition.visit_expr(&node.cond);
            let bound = matches!(&*node.cond, Expr::Path(p) if p.path.get_ident().is_some_and(|n| self.bindings.contains(&n.to_string())));
            if condition.role || bound {
                let mut branches = Gate::default();
                branches.visit_block(&node.then_branch);
                if let Some((_, other)) = &node.else_branch {
                    branches.visit_expr(other);
                }
                self.conditional |= branches.forwards && branches.rejects;
            }
            visit::visit_expr_if(self, node);
        }
        fn visit_expr_field(&mut self, node: &'ast syn::ExprField) {
            self.role |= matches!(&node.member, syn::Member::Named(name) if name == "role" || name == "allowed_roles");
            visit::visit_expr_field(self, node);
        }
        fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
            self.forwards |= node.method == "call";
            visit::visit_expr_method_call(self, node);
        }
        fn visit_expr_call(&mut self, node: &'ast ExprCall) {
            if let Expr::Path(p) = &*node.func {
                self.rejects |= p.path.is_ident("Err");
            }
            visit::visit_expr_call(self, node);
        }
    }
    items.iter().any(|item| {
        let Item::Impl(item) = item else { return false };
        let syn::Type::Path(ty) = &*item.self_ty else {
            return false;
        };
        if ty.path.segments.last().is_none_or(|s| s.ident != expected) {
            return false;
        }
        item.items.iter().any(|member| {
            let syn::ImplItem::Fn(method) = member else {
                return false;
            };
            if method.sig.ident != "call" {
                return false;
            }
            let mut gate = Gate::default();
            gate.visit_block(&method.block);
            gate.conditional
        })
    })
}

struct CallArguments<'a> {
    symbol: &'a str,
    values: Vec<String>,
}

// Preserve a checked source predicate, not a role inferred from a field name.
// This establishes no authentication/identity-provenance fact.
fn field_gate_policy(index: &HandlerIndex, helper: &HandlerDefinition) -> Option<String> {
    let syn::ReturnType::Type(_, output) = &helper.function.sig.output else {
        return None;
    };
    let context = (helper.crate_key.clone(), helper.module.clone());
    if !result_type(index, &context, output, 0)
        || matches!(helper.function.sig.safety, syn::Safety::Unsafe(_))
    {
        return None;
    }
    fn result_branch(
        index: &HandlerIndex,
        helper: &HandlerDefinition,
        block: &Block,
        expected: &str,
        require_return: bool,
    ) -> bool {
        let [Stmt::Expr(expr, semi)] = block.stmts.as_slice() else {
            return false;
        };
        let expr = match expr {
            Expr::Return(r) => match r.expr.as_deref() {
                Some(e) => e,
                None => return false,
            },
            e if !require_return && semi.is_none() => e,
            _ => return false,
        };
        let Expr::Call(call) = consumed_expression(expr) else {
            return false;
        };
        let Expr::Path(path) = &*call.func else {
            return false;
        };
        let Some(canonical) = external_path(
            index,
            &(helper.crate_key.clone(), helper.module.clone()),
            &path.path,
            0,
        ) else {
            return false;
        };
        if ![
            expected.to_string(),
            format!("std::result::Result::{expected}"),
            format!("core::result::Result::{expected}"),
        ]
        .contains(&canonical)
            || call.args.len() != 1
        {
            return false;
        }
        if path.path.is_ident(expected) {
            if helper.function.sig.inputs.iter().any(|a|matches!(a,FnArg::Typed(a) if matches!(&*a.pat,Pat::Ident(p) if p.ident==expected))) {return false;}
            let target = HandlerTarget::Path {
                segments: vec![expected.into()],
                leading_colon: false,
            };
            if index
                .resolve_handler(&helper.crate_key, &helper.module, &target)
                .1
                != HandlerResolution::Unresolved
            {
                return false;
            }
        }
        if code_may_exit(index, helper, &[Stmt::Expr(call.args[0].clone(), None)]) {
            return false;
        }
        expected == "Err" || matches!(call.args.first(),Some(Expr::Tuple(t)) if t.elems.is_empty())
    }
    fn terminal(expr: &Expr) -> Option<&Block> {
        if let Expr::Block(b) = expr {
            Some(&b.block)
        } else {
            None
        }
    }
    let statements = &helper.function.block.stmts;
    let (gate, prefix, rejects_true) = match statements.last()? {
        Stmt::Expr(Expr::If(gate), None) => {
            let other = terminal(&gate.else_branch.as_ref()?.1)?;
            let rejects_true = if result_branch(index, helper, &gate.then_branch, "Err", false)
                && result_branch(index, helper, other, "Ok", false)
            {
                true
            } else if result_branch(index, helper, &gate.then_branch, "Ok", false)
                && result_branch(index, helper, other, "Err", false)
            {
                false
            } else {
                return None;
            };
            (gate, &statements[..statements.len() - 1], rejects_true)
        }
        Stmt::Expr(_, None)
            if statements.len() >= 2
                && result_branch(
                    index,
                    helper,
                    &syn::Block {
                        brace_token: Default::default(),
                        stmts: vec![statements.last()?.clone()],
                    },
                    "Ok",
                    false,
                ) =>
        {
            let Stmt::Expr(Expr::If(gate), _) = &statements[statements.len() - 2] else {
                return None;
            };
            if gate.else_branch.is_some()
                || !result_branch(index, helper, &gate.then_branch, "Err", true)
            {
                return None;
            }
            (gate, &statements[..statements.len() - 2], true)
        }
        _ => return None,
    };
    // Earlier fallible prechecks can reject additionally, but cannot bypass the
    // final gate. No ignored calls, mutable locals, branches or early success.
    if !prefix.iter().all(
        |s| matches!(s,Stmt::Expr(Expr::Try(t),Some(_)) if result_source(index,helper,&t.expr,0)),
    ) || code_may_exit(index, helper, prefix)
    {
        return None;
    }
    let (mut condition, negated) = match consumed_expression(&gate.cond) {
        Expr::Unary(u) if matches!(u.op, syn::UnOp::Not(_)) => (&*u.expr, true),
        e => (e, false),
    };
    let mut fields = Vec::new();
    loop {
        match consumed_expression(condition) {
            Expr::Field(f) => {
                let syn::Member::Named(n) = &f.member else {
                    return None;
                };
                fields.push(n.to_string());
                condition = &f.base;
            }
            Expr::Path(p) => {
                let root = p.path.get_ident()?;
                let arg=helper.function.sig.inputs.iter().find_map(|a|match a {FnArg::Typed(a) if matches!(&*a.pat,Pat::Ident(p) if p.ident==*root && p.mutability.is_none())=>Some(a),_=>None})?;
                if matches!(&*arg.ty,syn::Type::Reference(r) if r.mutability.is_some()) {
                    return None;
                }
                let owner = policy_drift::record_type(index, helper, &arg.ty)?;
                if fields.is_empty() {
                    return None;
                }
                fields.reverse();
                let mut current = owner.clone();
                for (position, name) in fields.iter().enumerate() {
                    let (ty, public) = index.record_fields.get(&current)?.get(name)?;
                    if !public
                        && !(helper.crate_key == current.0
                            && helper.module.starts_with(&current.1[..current.1.len() - 1]))
                    {
                        return None;
                    }
                    if position + 1 == fields.len() {
                        if !matches!(ty,syn::Type::Path(p) if p.path.is_ident("bool")) {
                            return None;
                        }
                    } else {
                        let c = HandlerDefinition {
                            crate_key: current.0.clone(),
                            module: current.1[..current.1.len() - 1].to_vec(),
                            owner: None,
                            ..helper.clone()
                        };
                        current = policy_drift::record_type(index, &c, ty)?;
                    }
                }
                let required = negated == rejects_true;
                return Some(format!(
                    "source predicate {}:{}.{} == {required}",
                    owner.0.display(),
                    owner.1.join("::"),
                    fields.join(".")
                ));
            }
            _ => return None,
        }
    }
}

fn unmodeled_field_rejection(handler: &HandlerDefinition) -> bool {
    #[derive(Default)]
    struct Gates(bool);
    impl<'ast> Visit<'ast> for Gates {
        fn visit_expr_if(&mut self, e: &'ast ExprIf) {
            #[derive(Default)]
            struct Fields(bool);
            impl<'ast> Visit<'ast> for Fields {
                fn visit_expr_field(&mut self, _: &'ast syn::ExprField) {
                    self.0 = true;
                }
                fn visit_expr_closure(&mut self, _: &'ast ExprClosure) {}
            }
            let mut fields = Fields::default();
            fields.visit_expr(&e.cond);
            let field = fields.0;
            self.0 |= field && e.then_branch.stmts.iter().any(|s|matches!(s,Stmt::Expr(Expr::Return(r),_) if r.expr.as_deref().is_some_and(|e|matches!(consumed_expression(e),Expr::Call(c) if matches!(&*c.func,Expr::Path(p) if p.path.is_ident("Err"))))));
            visit::visit_expr_if(self, e);
        }
        fn visit_expr_closure(&mut self, _: &'ast ExprClosure) {}
        fn visit_expr_async(&mut self, _: &'ast syn::ExprAsync) {}
        fn visit_item_fn(&mut self, _: &'ast ItemFn) {}
    }
    let mut gates = Gates::default();
    gates.visit_block(&handler.function.block);
    gates.0
}

fn code_may_exit(index: &HandlerIndex, handler: &HandlerDefinition, statements: &[Stmt]) -> bool {
    struct Escape<'a> {
        index: &'a HandlerIndex,
        handler: &'a HandlerDefinition,
        unknown: bool,
    }
    impl<'ast> Visit<'ast> for Escape<'_> {
        fn visit_stmt_macro(&mut self, _: &'ast syn::StmtMacro) {
            self.unknown = true;
        }
        fn visit_expr_return(&mut self, _: &'ast syn::ExprReturn) {
            self.unknown = true;
        }
        fn visit_expr_macro(&mut self, _: &'ast syn::ExprMacro) {
            self.unknown = true;
        }
        fn visit_expr_try(&mut self, t: &'ast syn::ExprTry) {
            self.unknown |= !result_source(self.index, self.handler, &t.expr, 0);
            visit::visit_expr_try(self, t);
        }
        fn visit_expr_closure(&mut self, _: &'ast ExprClosure) {}
        fn visit_expr_async(&mut self, _: &'ast syn::ExprAsync) {}
        fn visit_item_fn(&mut self, _: &'ast ItemFn) {}
    }
    let mut escape = Escape {
        index,
        handler,
        unknown: false,
    };
    for stmt in statements {
        escape.visit_stmt(stmt);
    }
    escape.unknown
}

fn mandatory_helper_call(index: &HandlerIndex, handler: &HandlerDefinition, symbol: &str) -> bool {
    for stmt in &handler.function.block.stmts {
        if code_may_exit(index, handler, std::slice::from_ref(stmt)) {
            return false;
        }
        match stmt {
            Stmt::Expr(Expr::Try(t), Some(_)) => {
                if !result_source(index, handler, &t.expr, 0) {
                    return false;
                }
                if call_path(consumed_expression(&t.expr))
                    .is_some_and(|p| p.to_token_stream().to_string().replace(' ', "") == symbol)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}
impl<'ast> Visit<'ast> for CallArguments<'_> {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if node.func.to_token_stream().to_string().replace(' ', "") == self.symbol {
            for arg in &node.args {
                if let Expr::Lit(ExprLit {
                    lit: Lit::Str(value),
                    ..
                }) = arg
                {
                    self.values.push(value.value());
                }
            }
        }
        visit::visit_expr_call(self, node);
    }
}

// Await consumes a future; parentheses and invisible groups preserve its value.
// Do not unwrap arbitrary calls, methods, closures or deferred async blocks.
fn consumed_expression(mut expr: &Expr) -> &Expr {
    loop {
        expr = match expr {
            Expr::Await(value) => &value.base,
            Expr::Paren(value) => &value.expr,
            Expr::Group(value) => &value.expr,
            _ => return expr,
        };
    }
}

// Inspect returned expressions, not every Err constructor anywhere in a body.
fn returned_calls(expr: &Expr, calls: &mut Vec<String>) -> bool {
    match consumed_expression(expr) {
        Expr::Call(call) => {
            if let Expr::Path(path) = &*call.func {
                let name = path.path.to_token_stream().to_string().replace(' ', "");
                if name == "Err" {
                    return true;
                }
                calls.push(name);
            }
            false
        }
        Expr::Return(r) => r.expr.as_deref().is_some_and(|e| returned_calls(e, calls)),
        Expr::Block(b) => returned_block(&b.block, calls),
        Expr::If(i) => {
            let a = returned_block(&i.then_branch, calls);
            let b = i
                .else_branch
                .as_ref()
                .is_some_and(|(_, e)| returned_calls(e, calls));
            a || b
        }
        Expr::Match(m) => m.arms.iter().fold(false, |rejects, arm| {
            returned_calls(&arm.body, calls) || rejects
        }),
        _ => false,
    }
}

fn returned_block(block: &Block, calls: &mut Vec<String>) -> bool {
    match block.stmts.last() {
        Some(Stmt::Expr(expr, None)) => returned_calls(expr, calls),
        _ => false,
    }
}

// Bounded local call summaries establish only a possible rejection path.
// They deliberately do not claim dominance or prove an arbitrary predicate.
fn helper_may_reject(
    index: &HandlerIndex,
    definition: &HandlerDefinition,
    depth: usize,
    visited: &mut HashSet<String>,
) -> bool {
    if depth >= 8
        || !visited.insert(format!(
            "{}:{}",
            definition.crate_key.display(),
            definition.rust_path()
        ))
    {
        return false;
    }
    struct Calls {
        names: Vec<String>,
        rejects: bool,
    }
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_return(&mut self, node: &'ast syn::ExprReturn) {
            self.rejects |= node
                .expr
                .as_deref()
                .is_some_and(|e| returned_calls(e, &mut self.names));
            visit::visit_expr_return(self, node);
        }
        fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
            self.rejects |= returned_calls(&node.expr, &mut self.names);
            visit::visit_expr_try(self, node);
        }
        fn visit_expr_closure(&mut self, _: &'ast ExprClosure) {}
        fn visit_item_fn(&mut self, _: &'ast ItemFn) {}
        fn visit_expr_async(&mut self, _: &'ast syn::ExprAsync) {}
    }
    let mut calls = Calls {
        names: Vec::new(),
        rejects: false,
    };
    calls.visit_block(&definition.function.block);
    calls.rejects |= returned_block(&definition.function.block, &mut calls.names);
    if calls.rejects {
        return true;
    }
    calls.names.into_iter().any(|name| {
        let target = HandlerTarget::Path {
            segments: name.split("::").map(str::to_owned).collect(),
            leading_colon: false,
        };
        let (helper, _) = index.resolve_handler(&definition.crate_key, &definition.module, &target);
        helper.is_some_and(|helper| helper_may_reject(index, helper, depth + 1, visited))
    })
}
