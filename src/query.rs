//! Closed unresolved query representation; this never carries authority.
use crate::decode::strict_json;
use crate::error::{ErrorCode as E, Result};
use crate::types::{BinaryOp, DataType, UnaryOp, Value, identifier};
use serde_json::{Map, Value as Json};
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Expr {
    Col(String),
    Lit(Value),
    Null,
    Unary(UnaryOp, Box<Expr>),
    Binary(BinaryOp, Box<Expr>, Box<Expr>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Named {
    pub name: String,
    pub expr: Expr,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Agg {
    CountAll,
    Count(Expr),
    Sum(Expr),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NamedAgg {
    pub name: String,
    pub agg: Agg,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SortKey {
    pub expr: Expr,
    pub descending: bool,
    pub nulls_first: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Plan {
    Scan {
        table: String,
        alias: String,
    },
    Filter {
        input: Box<Plan>,
        predicate: Expr,
    },
    Project {
        input: Box<Plan>,
        columns: Vec<Named>,
    },
    Join {
        left: Box<Plan>,
        right: Box<Plan>,
        on: Vec<(Expr, Expr)>,
    },
    Aggregate {
        input: Box<Plan>,
        keys: Vec<Named>,
        aggregates: Vec<NamedAgg>,
    },
    Sort {
        input: Box<Plan>,
        keys: Vec<SortKey>,
    },
    Limit {
        input: Box<Plan>,
        count: usize,
    },
}
#[derive(Clone, Debug)]
pub struct Query {
    pub(crate) plan: Plan,
}
struct Gate {
    nodes: usize,
    scans: usize,
}
impl Gate {
    fn bump(&mut self, depth: usize) -> Result<()> {
        self.nodes += 1;
        if depth > 32 || self.nodes > 256 {
            return Err(E::Limit.into());
        }
        Ok(())
    }
}
fn object(value: &Json) -> Result<&Map<String, Json>> {
    value.as_object().ok_or(E::Input.into())
}
fn fields(value: &Json, expected: &[&str]) -> Result<()> {
    let obj = object(value)?;
    if obj.len() != expected.len() || expected.iter().any(|k| !obj.contains_key(*k)) {
        return Err(E::Input.into());
    }
    Ok(())
}
fn get<'a>(value: &'a Json, key: &str) -> Result<&'a Json> {
    object(value)?.get(key).ok_or(E::Input.into())
}
fn string(value: &Json) -> Result<&str> {
    value.as_str().ok_or(E::Input.into())
}
fn name(value: &Json) -> Result<String> {
    let s = string(value)?;
    if !identifier(s) {
        return Err(E::Input.into());
    }
    Ok(s.to_owned())
}
fn array(value: &Json) -> Result<&[Json]> {
    value.as_array().map(Vec::as_slice).ok_or(E::Input.into())
}
fn expr(value: &Json, gate: &mut Gate, depth: usize) -> Result<Expr> {
    gate.bump(depth)?;
    let obj = object(value)?;
    if obj.contains_key("col") {
        fields(value, &["col"])?;
        let text = string(get(value, "col")?)?;
        let parts: Vec<_> = text.split('.').collect();
        if parts.is_empty() || parts.len() > 2 || parts.iter().any(|p| !identifier(p)) {
            return Err(E::Input.into());
        }
        return Ok(Expr::Col(text.to_owned()));
    }
    if obj.contains_key("lit") {
        let lit = get(value, "lit")?;
        if lit.is_null() {
            fields(value, &["lit", "type"])?;
            let dtype: DataType =
                serde_json::from_value(get(value, "type")?.clone()).map_err(|_| E::Input)?;
            return Ok(Expr::Lit(Value::Null(dtype)));
        }
        fields(value, &["lit"])?;
        let dtype = match lit {
            Json::Bool(_) => DataType::Bool,
            Json::Number(_) => DataType::I64,
            Json::String(_) => DataType::Text,
            _ => return Err(E::Input.into()),
        };
        return Ok(Expr::Lit(
            Value::from_json(lit, dtype, false).map_err(|_| E::Input)?,
        ));
    }
    let op = string(get(value, "op")?)?;
    if matches!(op, "not" | "is_null") {
        fields(value, &["op", "expr"])?;
        return Ok(Expr::Unary(
            if op == "not" {
                UnaryOp::Not
            } else {
                UnaryOp::IsNull
            },
            Box::new(expr(get(value, "expr")?, gate, depth + 1)?),
        ));
    }
    let op = match op {
        "eq" => BinaryOp::Eq,
        "ne" => BinaryOp::Ne,
        "lt" => BinaryOp::Lt,
        "le" => BinaryOp::Le,
        "gt" => BinaryOp::Gt,
        "ge" => BinaryOp::Ge,
        "and" => BinaryOp::And,
        "or" => BinaryOp::Or,
        "add" => BinaryOp::Add,
        "sub" => BinaryOp::Sub,
        _ => return Err(E::Unsupported.into()),
    };
    fields(value, &["op", "left", "right"])?;
    Ok(Expr::Binary(
        op,
        Box::new(expr(get(value, "left")?, gate, depth + 1)?),
        Box::new(expr(get(value, "right")?, gate, depth + 1)?),
    ))
}
fn named(value: &Json, gate: &mut Gate, depth: usize) -> Result<Vec<Named>> {
    let values = array(value)?;
    if values.len() > 64 {
        return Err(E::Limit.into());
    }
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for value in values {
        fields(value, &["name", "expr"])?;
        let name = name(get(value, "name")?)?;
        if !seen.insert(name.clone()) {
            return Err(E::Input.into());
        }
        out.push(Named {
            name,
            expr: expr(get(value, "expr")?, gate, depth)?,
        });
    }
    Ok(out)
}
fn plan(value: &Json, gate: &mut Gate, depth: usize) -> Result<Plan> {
    gate.bump(depth)?;
    match string(get(value, "op")?)? {
        "scan" => {
            fields(value, &["op", "table", "alias"])?;
            gate.scans += 1;
            if gate.scans > 4 {
                return Err(E::Limit.into());
            }
            Ok(Plan::Scan {
                table: name(get(value, "table")?)?,
                alias: name(get(value, "alias")?)?,
            })
        }
        "filter" => {
            fields(value, &["op", "input", "predicate"])?;
            Ok(Plan::Filter {
                input: Box::new(plan(get(value, "input")?, gate, depth + 1)?),
                predicate: expr(get(value, "predicate")?, gate, depth + 1)?,
            })
        }
        "project" => {
            fields(value, &["op", "input", "columns"])?;
            let input = Box::new(plan(get(value, "input")?, gate, depth + 1)?);
            let columns = named(get(value, "columns")?, gate, depth + 1)?;
            if columns.is_empty() {
                return Err(E::Input.into());
            }
            Ok(Plan::Project { input, columns })
        }
        "join" => {
            fields(value, &["op", "left", "right", "on"])?;
            let left = Box::new(plan(get(value, "left")?, gate, depth + 1)?);
            let right = Box::new(plan(get(value, "right")?, gate, depth + 1)?);
            let mut on = Vec::new();
            let pairs = array(get(value, "on")?)?;
            if pairs.is_empty() || pairs.len() > 64 {
                return Err(E::Input.into());
            }
            for pair in pairs {
                fields(pair, &["left", "right"])?;
                on.push((
                    expr(get(pair, "left")?, gate, depth + 1)?,
                    expr(get(pair, "right")?, gate, depth + 1)?,
                ));
            }
            Ok(Plan::Join { left, right, on })
        }
        "aggregate" => {
            fields(value, &["op", "input", "keys", "aggregates"])?;
            let input = Box::new(plan(get(value, "input")?, gate, depth + 1)?);
            let keys = named(get(value, "keys")?, gate, depth + 1)?;
            if keys.len() > 16 {
                return Err(E::Limit.into());
            }
            let values = array(get(value, "aggregates")?)?;
            if keys.len() + values.len() > 64 {
                return Err(E::Limit.into());
            }
            let mut seen: BTreeSet<_> = keys.iter().map(|k| k.name.clone()).collect();
            let mut aggregates = Vec::new();
            for value in values {
                let name = name(get(value, "name")?)?;
                if !seen.insert(name.clone()) {
                    return Err(E::Input.into());
                }
                let agg = match string(get(value, "kind")?)? {
                    "count_all" => {
                        fields(value, &["name", "kind"])?;
                        Agg::CountAll
                    }
                    "count" | "sum" => {
                        fields(value, &["name", "kind", "expr"])?;
                        let input = expr(get(value, "expr")?, gate, depth + 1)?;
                        if string(get(value, "kind")?)? == "count" {
                            Agg::Count(input)
                        } else {
                            Agg::Sum(input)
                        }
                    }
                    _ => return Err(E::Unsupported.into()),
                };
                aggregates.push(NamedAgg { name, agg });
            }
            if keys.is_empty() && aggregates.is_empty() {
                return Err(E::Input.into());
            }
            Ok(Plan::Aggregate {
                input,
                keys,
                aggregates,
            })
        }
        "sort" => {
            fields(value, &["op", "input", "keys"])?;
            let input = Box::new(plan(get(value, "input")?, gate, depth + 1)?);
            let values = array(get(value, "keys")?)?;
            if values.is_empty() || values.len() > 64 {
                return Err(E::Input.into());
            }
            let mut keys = Vec::new();
            for value in values {
                fields(value, &["expr", "direction", "nulls"])?;
                let descending = match string(get(value, "direction")?)? {
                    "asc" => false,
                    "desc" => true,
                    _ => return Err(E::Input.into()),
                };
                let nulls_first = match string(get(value, "nulls")?)? {
                    "first" => true,
                    "last" => false,
                    _ => return Err(E::Input.into()),
                };
                keys.push(SortKey {
                    expr: expr(get(value, "expr")?, gate, depth + 1)?,
                    descending,
                    nulls_first,
                });
            }
            Ok(Plan::Sort { input, keys })
        }
        "limit" => {
            fields(value, &["op", "input", "count"])?;
            let count = get(value, "count")?.as_u64().ok_or(E::Input)?;
            if count > 10000 {
                return Err(E::Limit.into());
            }
            Ok(Plan::Limit {
                input: Box::new(plan(get(value, "input")?, gate, depth + 1)?),
                count: count as usize,
            })
        }
        _ => Err(E::Unsupported.into()),
    }
}
impl Query {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let value = strict_json(bytes, 65536, 96)?;
        fields(&value, &["version", "plan"])?;
        if get(&value, "version")?.as_u64() != Some(1) {
            return Err(E::Unsupported.into());
        }
        Ok(Self {
            plan: plan(get(&value, "plan")?, &mut Gate { nodes: 0, scans: 0 }, 1)?,
        })
    }
    pub(crate) fn from_plan(plan: Plan) -> Result<Self> {
        fn expression(expr: &Expr, gate: &mut Gate, depth: usize) -> Result<()> {
            gate.bump(depth)?;
            match expr {
                Expr::Unary(_, a) => expression(a, gate, depth + 1),
                Expr::Binary(_, a, b) => {
                    expression(a, gate, depth + 1)?;
                    expression(b, gate, depth + 1)
                }
                _ => Ok(()),
            }
        }
        fn visit(plan: &Plan, gate: &mut Gate, depth: usize) -> Result<()> {
            gate.bump(depth)?;
            match plan {
                Plan::Scan { .. } => {
                    gate.scans += 1;
                    if gate.scans > 4 {
                        return Err(E::Limit.into());
                    }
                }
                Plan::Filter { input, predicate } => {
                    visit(input, gate, depth + 1)?;
                    expression(predicate, gate, depth + 1)?;
                }
                Plan::Project { input, columns } => {
                    visit(input, gate, depth + 1)?;
                    for c in columns {
                        expression(&c.expr, gate, depth + 1)?;
                    }
                }
                Plan::Join { left, right, on } => {
                    visit(left, gate, depth + 1)?;
                    visit(right, gate, depth + 1)?;
                    for (a, b) in on {
                        expression(a, gate, depth + 1)?;
                        expression(b, gate, depth + 1)?;
                    }
                }
                Plan::Aggregate {
                    input,
                    keys,
                    aggregates,
                } => {
                    visit(input, gate, depth + 1)?;
                    for k in keys {
                        expression(&k.expr, gate, depth + 1)?;
                    }
                    for a in aggregates {
                        match &a.agg {
                            Agg::CountAll => {}
                            Agg::Count(e) | Agg::Sum(e) => expression(e, gate, depth + 1)?,
                        }
                    }
                }
                Plan::Sort { input, keys } => {
                    visit(input, gate, depth + 1)?;
                    for k in keys {
                        expression(&k.expr, gate, depth + 1)?;
                    }
                }
                Plan::Limit { input, .. } => visit(input, gate, depth + 1)?,
            }
            Ok(())
        }
        visit(&plan, &mut Gate { nodes: 0, scans: 0 }, 1)?;
        Ok(Self { plan })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_shapes_before_binding() {
        for bad in [br#"{"version":1,"plan":{"op":"policy_scan"}}"#.as_slice(),br#"{"version":1,"plan":{"op":"scan","table":"t","alias":"a","tenant":"beta"}}"#,
            br#"{"version":1,"plan":{"op":"filter","input":{"op":"scan","table":"t","alias":"a"},"predicate":{"lit":null}}}"#] {
            assert!(Query::from_json(bad).is_err());
        }
    }
}
