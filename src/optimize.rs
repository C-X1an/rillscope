//! Bounded pure rewrites and column pruning, always followed by independent verification.
use crate::error::{ErrorCode as E, Result};
use crate::plan::*;
use crate::types::{ExprKind, TypedExpr, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

fn refs(expr: &TypedExpr, out: &mut BTreeSet<usize>) {
    match &expr.kind {
        ExprKind::Column(i) => {
            out.insert(*i);
        }
        ExprKind::Literal(_) => {}
        ExprKind::Unary(_, a) => refs(a, out),
        ExprKind::Binary(_, a, b) => {
            refs(a, out);
            refs(b, out);
        }
    }
}
fn remap(expr: &TypedExpr, map: &BTreeMap<usize, usize>) -> Result<TypedExpr> {
    let kind = match &expr.kind {
        ExprKind::Column(i) => ExprKind::Column(*map.get(i).ok_or(E::Plan)?),
        ExprKind::Literal(v) => ExprKind::Literal(v.clone()),
        ExprKind::Unary(op, a) => ExprKind::Unary(*op, Box::new(remap(a, map)?)),
        ExprKind::Binary(op, a, b) => {
            ExprKind::Binary(*op, Box::new(remap(a, map)?), Box::new(remap(b, map)?))
        }
    };
    Ok(TypedExpr {
        kind,
        data_type: expr.data_type,
        nullable: expr.nullable,
    })
}
fn substitute(expr: &TypedExpr, columns: &Projection) -> Result<TypedExpr> {
    let kind = match &expr.kind {
        ExprKind::Column(i) => return Ok(columns.get(*i).ok_or(E::Plan)?.1.clone()),
        ExprKind::Literal(v) => ExprKind::Literal(v.clone()),
        ExprKind::Unary(op, a) => ExprKind::Unary(*op, Box::new(substitute(a, columns)?)),
        ExprKind::Binary(op, a, b) => ExprKind::Binary(
            *op,
            Box::new(substitute(a, columns)?),
            Box::new(substitute(b, columns)?),
        ),
    };
    Ok(TypedExpr {
        kind,
        data_type: expr.data_type,
        nullable: expr.nullable,
    })
}
fn expr_depth(expr: &TypedExpr) -> usize {
    1 + match &expr.kind {
        ExprKind::Unary(_, a) => expr_depth(a),
        ExprKind::Binary(_, a, b) => expr_depth(a).max(expr_depth(b)),
        _ => 0,
    }
}
// Predict expansion without constructing or cloning the expanded expression.
fn substitution_shape(expr: &TypedExpr, columns: &Projection) -> Option<(usize, usize)> {
    let shape = match &expr.kind {
        ExprKind::Column(i) => {
            let value = &columns.get(*i)?.1;
            (value.cost() as usize, expr_depth(value))
        }
        ExprKind::Literal(_) => (1, 1),
        ExprKind::Unary(_, a) => {
            let (n, d) = substitution_shape(a, columns)?;
            (n.checked_add(1)?, d.checked_add(1)?)
        }
        ExprKind::Binary(_, a, b) => {
            let (an, ad) = substitution_shape(a, columns)?;
            let (bn, bd) = substitution_shape(b, columns)?;
            (
                an.checked_add(bn)?.checked_add(1)?,
                ad.max(bd).checked_add(1)?,
            )
        }
    };
    (shape.0 <= 256 && shape.1 <= 32).then_some(shape)
}
fn plan_nodes(node: &Node) -> usize {
    1 + match &node.kind {
        NodeKind::PolicyScan { .. } => 0,
        NodeKind::Filter { input, predicate } => plan_nodes(input) + predicate.cost() as usize,
        NodeKind::Project { input, columns } => {
            plan_nodes(input)
                + columns
                    .iter()
                    .map(|(_, e)| e.cost() as usize)
                    .sum::<usize>()
        }
        NodeKind::Join { left, right, .. } => plan_nodes(left) + plan_nodes(right),
        NodeKind::Aggregate {
            input,
            keys,
            aggregates,
        } => {
            plan_nodes(input)
                + keys.iter().map(|(_, e)| e.cost() as usize).sum::<usize>()
                + aggregates
                    .iter()
                    .map(|(_, a)| match a {
                        Aggregate::CountAll => 0,
                        Aggregate::Count(e) | Aggregate::Sum(e) => e.cost() as usize,
                    })
                    .sum::<usize>()
        }
        NodeKind::Sort { input, keys } => {
            plan_nodes(input) + keys.iter().map(|k| k.expr.cost() as usize).sum::<usize>()
        }
        NodeKind::Limit { input, .. } => plan_nodes(input),
    }
}
fn rewrite(
    node: &mut Node,
    trace: &mut Vec<&'static str>,
    nodes: &mut usize,
    depth: usize,
) -> Result<()> {
    match &mut node.kind {
        NodeKind::PolicyScan { .. } => {}
        NodeKind::Join { left, right, .. } => {
            rewrite(left, trace, nodes, depth + 1)?;
            rewrite(right, trace, nodes, depth + 1)?;
        }
        NodeKind::Filter { input, .. }
        | NodeKind::Project { input, .. }
        | NodeKind::Aggregate { input, .. }
        | NodeKind::Sort { input, .. }
        | NodeKind::Limit { input, .. } => rewrite(input, trace, nodes, depth + 1)?,
    }
    let NodeKind::Filter { input, predicate } = &node.kind else {
        return Ok(());
    };
    if matches!(predicate.kind, ExprKind::Literal(Value::Bool(true))) {
        *node = *input.clone();
        *nodes = nodes.checked_sub(2).ok_or(E::Plan)?;
        trace.push("remove_true_filter");
        return Ok(());
    }
    if !predicate.total() {
        return Ok(());
    }
    let mut changed = false;
    match &input.kind {
        NodeKind::Project {
            input: base,
            columns,
        } if columns.iter().all(|(_, e)| e.total()) => {
            let Some((expanded_nodes, expanded_depth)) = substitution_shape(predicate, columns)
            else {
                return Ok(());
            };
            let available = 256usize
                .checked_sub(*nodes)
                .and_then(|n| n.checked_add(predicate.cost() as usize))
                .ok_or(E::Plan)?;
            if expanded_nodes > available || depth + 1 + expanded_depth > 32 {
                return Ok(());
            }
            *nodes = nodes
                .checked_sub(predicate.cost() as usize)
                .and_then(|n| n.checked_add(expanded_nodes))
                .ok_or(E::Plan)?;
            let predicate = substitute(predicate, columns)?;
            let filtered = Node {
                kind: NodeKind::Filter {
                    input: base.clone(),
                    predicate,
                },
                schema: base.schema.clone(),
            };
            node.kind = NodeKind::Project {
                input: Box::new(filtered),
                columns: columns.clone(),
            };
            trace.push("push_pure_filter_project");
            changed = true;
        }
        NodeKind::Join { left, right, on } => {
            if depth + 1 + expr_depth(predicate) > 32 {
                return Ok(());
            }
            let mut columns = BTreeSet::new();
            refs(predicate, &mut columns);
            let split = left.schema.len();
            if columns.iter().all(|i| *i < split) {
                let filtered = Node {
                    kind: NodeKind::Filter {
                        input: left.clone(),
                        predicate: predicate.clone(),
                    },
                    schema: left.schema.clone(),
                };
                node.kind = NodeKind::Join {
                    left: Box::new(filtered),
                    right: right.clone(),
                    on: on.clone(),
                };
                trace.push("push_pure_filter_join_left");
                changed = true;
            } else if columns.iter().all(|i| *i >= split) {
                let map = columns.iter().map(|i| (*i, *i - split)).collect();
                let filtered = Node {
                    kind: NodeKind::Filter {
                        input: right.clone(),
                        predicate: remap(predicate, &map)?,
                    },
                    schema: right.schema.clone(),
                };
                node.kind = NodeKind::Join {
                    left: left.clone(),
                    right: Box::new(filtered),
                    on: on.clone(),
                };
                trace.push("push_pure_filter_join_right");
                changed = true;
            }
        }
        _ => {}
    }
    if changed {
        rewrite(node, trace, nodes, depth)?;
    }
    Ok(())
}
fn identity(len: usize) -> BTreeMap<usize, usize> {
    (0..len).map(|i| (i, i)).collect()
}
fn mapped_projection(columns: &Projection, map: &BTreeMap<usize, usize>) -> Result<Projection> {
    columns
        .iter()
        .map(|(field, expr)| Ok((field.clone(), remap(expr, map)?)))
        .collect()
}
fn prune(node: &Node, required: &BTreeSet<usize>) -> Result<(Node, BTreeMap<usize, usize>)> {
    if required.iter().any(|i| *i >= node.schema.len()) {
        return Err(E::Plan.into());
    }
    let (kind, schema, map) = match &node.kind {
        NodeKind::PolicyScan {
            table,
            occurrence,
            alias,
            columns,
            grant,
        } => {
            let keep: Vec<_> = required.iter().copied().collect();
            let schema = keep
                .iter()
                .map(|i| node.schema.get(*i).cloned().ok_or(E::Plan.into()))
                .collect::<Result<_>>()?;
            let columns = keep
                .iter()
                .map(|i| columns.get(*i).copied().ok_or(E::Plan.into()))
                .collect::<Result<_>>()?;
            let map = keep
                .iter()
                .enumerate()
                .map(|(new, old)| (*old, new))
                .collect();
            (
                NodeKind::PolicyScan {
                    table: *table,
                    occurrence: *occurrence,
                    alias: alias.clone(),
                    columns,
                    grant: grant.clone(),
                },
                schema,
                map,
            )
        }
        NodeKind::Filter { input, predicate } => {
            let mut needed = required.clone();
            refs(predicate, &mut needed);
            let (input, map) = prune(input, &needed)?;
            let schema = input.schema.clone();
            (
                NodeKind::Filter {
                    input: Box::new(input),
                    predicate: remap(predicate, &map)?,
                },
                schema,
                map,
            )
        }
        NodeKind::Project { input, columns } => {
            let mut keep = required.clone();
            for (i, (_, expr)) in columns.iter().enumerate() {
                if !expr.total() {
                    keep.insert(i);
                }
            }
            let mut needed = BTreeSet::new();
            for i in &keep {
                refs(&columns.get(*i).ok_or(E::Plan)?.1, &mut needed);
            }
            let (input, map) = prune(input, &needed)?;
            let mut out = Vec::new();
            let mut mapping = BTreeMap::new();
            for i in keep {
                let (field, expr) = columns.get(i).ok_or(E::Plan)?;
                mapping.insert(i, out.len());
                out.push((field.clone(), remap(expr, &map)?));
            }
            let schema = out.iter().map(|(f, _)| f.clone()).collect();
            (
                NodeKind::Project {
                    input: Box::new(input),
                    columns: out,
                },
                schema,
                mapping,
            )
        }
        NodeKind::Join { left, right, on } => {
            let split = left.schema.len();
            let mut a: BTreeSet<_> = required.iter().filter(|i| **i < split).copied().collect();
            let mut b: BTreeSet<_> = required
                .iter()
                .filter(|i| **i >= split)
                .map(|i| *i - split)
                .collect();
            for (x, y) in on {
                a.insert(*x);
                b.insert(*y);
            }
            let (left, left_map) = prune(left, &a)?;
            let (right, right_map) = prune(right, &b)?;
            let pairs = on
                .iter()
                .map(|(a, b)| {
                    Ok((
                        *left_map.get(a).ok_or(E::Plan)?,
                        *right_map.get(b).ok_or(E::Plan)?,
                    ))
                })
                .collect::<Result<_>>()?;
            let mut map = left_map;
            for (old, new) in right_map {
                map.insert(old + split, new + left.schema.len());
            }
            let mut schema = left.schema.clone();
            schema.extend(right.schema.clone());
            (
                NodeKind::Join {
                    left: Box::new(left),
                    right: Box::new(right),
                    on: pairs,
                },
                schema,
                map,
            )
        }
        NodeKind::Aggregate {
            input,
            keys,
            aggregates,
        } => {
            // Group keys and SUM remain evaluated even when an ancestor ignores their outputs.
            let mut needed = BTreeSet::new();
            for (_, expr) in keys {
                refs(expr, &mut needed);
            }
            for (_, agg) in aggregates {
                match agg {
                    Aggregate::CountAll => {}
                    Aggregate::Count(e) | Aggregate::Sum(e) => refs(e, &mut needed),
                }
            }
            let (input, map) = prune(input, &needed)?;
            let keys = mapped_projection(keys, &map)?;
            let aggregates = aggregates
                .iter()
                .map(|(f, a)| {
                    Ok((
                        f.clone(),
                        match a {
                            Aggregate::CountAll => Aggregate::CountAll,
                            Aggregate::Count(e) => Aggregate::Count(remap(e, &map)?),
                            Aggregate::Sum(e) => Aggregate::Sum(remap(e, &map)?),
                        },
                    ))
                })
                .collect::<Result<_>>()?;
            (
                NodeKind::Aggregate {
                    input: Box::new(input),
                    keys,
                    aggregates,
                },
                node.schema.clone(),
                identity(node.schema.len()),
            )
        }
        NodeKind::Sort { input, keys } => {
            let mut needed = required.clone();
            for key in keys {
                refs(&key.expr, &mut needed);
            }
            let (input, map) = prune(input, &needed)?;
            let keys = keys
                .iter()
                .map(|k| {
                    Ok(OrderKey {
                        expr: remap(&k.expr, &map)?,
                        descending: k.descending,
                        nulls_first: k.nulls_first,
                    })
                })
                .collect::<Result<_>>()?;
            let schema = input.schema.clone();
            (
                NodeKind::Sort {
                    input: Box::new(input),
                    keys,
                },
                schema,
                map,
            )
        }
        NodeKind::Limit { input, count } => {
            let (input, map) = prune(input, required)?;
            let schema = input.schema.clone();
            (
                NodeKind::Limit {
                    input: Box::new(input),
                    count: *count,
                },
                schema,
                map,
            )
        }
    };
    Ok((Node { kind, schema }, map))
}
fn digest(node: &Node) -> Vec<u8> {
    Sha256::digest(format!("{node:?}").as_bytes()).to_vec()
}
pub(crate) fn optimize(mut plan: BoundPlan, enabled: bool) -> Result<BoundPlan> {
    if !enabled {
        plan.trace.push("optimization_disabled");
        return Ok(plan);
    }
    let mut seen = BTreeSet::new();
    let mut converged = false;
    for _ in 0..16 {
        let before = digest(&plan.root);
        if !seen.insert(before.clone()) {
            return Err(E::Plan.into());
        }
        let mut nodes = plan_nodes(&plan.root);
        if nodes > 256 {
            return Err(E::Plan.into());
        }
        rewrite(&mut plan.root, &mut plan.trace, &mut nodes, 1)?;
        if digest(&plan.root) == before {
            converged = true;
            break;
        }
    }
    if !converged {
        return Err(E::Plan.into());
    }
    let required = (0..plan.root.schema.len()).collect();
    let (root, _) = prune(&plan.root, &required)?;
    if root != plan.root {
        plan.trace.push("prune_unused_columns");
    }
    plan.root = root;
    Ok(plan)
}
