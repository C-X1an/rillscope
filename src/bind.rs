//! Bind and authorize every expression position before any catalog scan.
use crate::catalog::{Catalog, Context};
use crate::error::{ErrorCode as E, Result};
use crate::plan::*;
use crate::query::{self, Agg, Expr, Plan, Query};
use crate::types::{
    BinaryOp, DataType, ExprKind, Field, TypedExpr, UnaryOp, Value, binary_type, unary_type,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

struct Binder {
    catalog: Arc<Catalog>,
    context: Arc<Context>,
    aliases: BTreeSet<String>,
    hidden: BTreeSet<String>,
    sources: BTreeMap<u32, usize>,
}
pub(crate) fn origins(expr: &TypedExpr, schema: &[BoundField]) -> Result<BTreeSet<Origin>> {
    match &expr.kind {
        ExprKind::Column(i) => Ok(schema.get(*i).ok_or(E::Plan)?.origins.clone()),
        ExprKind::Literal(_) => Ok(BTreeSet::new()),
        ExprKind::Unary(_, a) => origins(a, schema),
        ExprKind::Binary(_, a, b) => {
            let mut out = origins(a, schema)?;
            out.extend(origins(b, schema)?);
            Ok(out)
        }
    }
}
impl Binder {
    fn expr(&self, expr: &Expr, schema: &[BoundField]) -> Result<TypedExpr> {
        let (kind, data_type, nullable) = match expr {
            Expr::Col(name) => {
                let (qualifier, name_part) = name
                    .split_once('.')
                    .map_or((None, name.as_str()), |(q, n)| (Some(q), n));
                let indices: Vec<_> = schema
                    .iter()
                    .enumerate()
                    .filter(|(_, f)| {
                        f.field.name == name_part
                            && qualifier.is_none_or(|q| f.qualifier.as_deref() == Some(q))
                    })
                    .map(|(i, _)| i)
                    .collect();
                if indices.len() != 1 {
                    return Err(if indices.is_empty() && self.hidden.contains(name) {
                        E::Forbidden
                    } else {
                        E::Bind
                    }
                    .into());
                }
                let index = *indices.first().ok_or(E::Bind)?;
                let field = &schema.get(index).ok_or(E::Bind)?.field;
                (ExprKind::Column(index), field.data_type, field.nullable)
            }
            Expr::Lit(value) => (
                ExprKind::Literal(value.clone()),
                value.data_type(),
                value.is_null(),
            ),
            Expr::Null => (
                ExprKind::Literal(Value::Null(DataType::I64)),
                DataType::I64,
                true,
            ),
            Expr::Unary(op, a) => {
                let a = if *op == UnaryOp::Not && matches!(**a, Expr::Null) {
                    TypedExpr {
                        kind: ExprKind::Literal(Value::Null(DataType::Bool)),
                        data_type: DataType::Bool,
                        nullable: true,
                    }
                } else {
                    self.expr(a, schema)?
                };
                let (dtype, nullable) = unary_type(*op, (a.data_type, a.nullable))?;
                (ExprKind::Unary(*op, Box::new(a)), dtype, nullable)
            }
            Expr::Binary(op, a, b) => {
                let null = |dtype| TypedExpr {
                    kind: ExprKind::Literal(Value::Null(dtype)),
                    data_type: dtype,
                    nullable: true,
                };
                let (a, b) = match (matches!(**a, Expr::Null), matches!(**b, Expr::Null)) {
                    (true, true) => {
                        let dtype = if matches!(op, BinaryOp::And | BinaryOp::Or) {
                            DataType::Bool
                        } else {
                            DataType::I64
                        };
                        (null(dtype), null(dtype))
                    }
                    (true, false) => {
                        let b = self.expr(b, schema)?;
                        (null(b.data_type), b)
                    }
                    (false, true) => {
                        let a = self.expr(a, schema)?;
                        let b = null(a.data_type);
                        (a, b)
                    }
                    (false, false) => (self.expr(a, schema)?, self.expr(b, schema)?),
                };
                let (dtype, nullable) =
                    binary_type(*op, (a.data_type, a.nullable), (b.data_type, b.nullable))?;
                (
                    ExprKind::Binary(*op, Box::new(a), Box::new(b)),
                    dtype,
                    nullable,
                )
            }
        };
        Ok(TypedExpr {
            kind,
            data_type,
            nullable,
        })
    }
    fn projection(&self, named: &[query::Named], schema: &[BoundField]) -> Result<Projection> {
        named
            .iter()
            .map(|named| {
                let expr = self.expr(&named.expr, schema)?;
                let field = BoundField {
                    field: Field {
                        name: named.name.clone(),
                        data_type: expr.data_type,
                        nullable: expr.nullable,
                    },
                    qualifier: None,
                    origins: origins(&expr, schema)?,
                };
                Ok((field, expr))
            })
            .collect()
    }
    fn node(&mut self, plan: &Plan) -> Result<Node> {
        let (kind, schema) = match plan {
            Plan::Scan { table, alias } => {
                let table_id = self.catalog.table_index(table).ok_or(E::Forbidden)?;
                let grant = self
                    .context
                    .grants
                    .get(&table_id)
                    .cloned()
                    .ok_or(E::Forbidden)?;
                if !self.aliases.insert(alias.clone()) {
                    return Err(E::Bind.into());
                }
                let occurrence = self.sources.len() as u32;
                self.sources.insert(occurrence, table_id);
                let table = self.catalog.tables.get(table_id).ok_or(E::Catalog)?;
                for (i, col) in table.columns.iter().enumerate() {
                    if !grant.visible.contains(&i) {
                        self.hidden.insert(col.name.clone());
                        self.hidden.insert(format!("{alias}.{}", col.name));
                    }
                }
                let columns: Vec<_> = grant.visible.iter().copied().collect();
                let schema = columns
                    .iter()
                    .map(|i| {
                        Ok(BoundField {
                            field: table.columns.get(*i).ok_or(E::Context)?.clone(),
                            qualifier: Some(alias.clone()),
                            origins: BTreeSet::from([Origin {
                                occurrence,
                                table: table_id,
                                column: *i,
                            }]),
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                (
                    NodeKind::PolicyScan {
                        table: table_id,
                        occurrence,
                        alias: alias.clone(),
                        columns,
                        grant,
                    },
                    schema,
                )
            }
            Plan::Filter { input, predicate } => {
                let input = self.node(input)?;
                let predicate = if matches!(predicate, Expr::Null) {
                    TypedExpr {
                        kind: ExprKind::Literal(Value::Null(DataType::Bool)),
                        data_type: DataType::Bool,
                        nullable: true,
                    }
                } else {
                    self.expr(predicate, &input.schema)?
                };
                if predicate.data_type != DataType::Bool {
                    return Err(E::Type.into());
                }
                let schema = input.schema.clone();
                (
                    NodeKind::Filter {
                        input: Box::new(input),
                        predicate,
                    },
                    schema,
                )
            }
            Plan::Project { input, columns } => {
                let input = self.node(input)?;
                let columns = self.projection(columns, &input.schema)?;
                let schema = columns.iter().map(|(f, _)| f.clone()).collect();
                (
                    NodeKind::Project {
                        input: Box::new(input),
                        columns,
                    },
                    schema,
                )
            }
            Plan::Join { left, right, on } | Plan::SqlJoin { left, right, on } => {
                let sql = matches!(plan, Plan::SqlJoin { .. });
                let left = self.node(left)?;
                let right = self.node(right)?;
                let split = left.schema.len();
                let mut schema = left.schema.clone();
                schema.extend(right.schema.clone());
                let mut pairs = Vec::new();
                for (a, b) in on {
                    let a = self.expr(a, if sql { &schema } else { &left.schema })?;
                    let b = self.expr(b, if sql { &schema } else { &right.schema })?;
                    if a.data_type != b.data_type {
                        return Err(E::Type.into());
                    }
                    match (a.kind, b.kind) {
                        (ExprKind::Column(a), ExprKind::Column(b)) => {
                            let pair = if !sql {
                                (a, b)
                            } else if a < split && b >= split {
                                (a, b - split)
                            } else if b < split && a >= split {
                                (b, a - split)
                            } else {
                                return Err(E::Bind.into());
                            };
                            pairs.push(pair);
                        }
                        _ => return Err(E::Unsupported.into()),
                    }
                }
                if schema.len() > 256 {
                    return Err(E::Limit.into());
                }
                (
                    NodeKind::Join {
                        left: Box::new(left),
                        right: Box::new(right),
                        on: pairs,
                    },
                    schema,
                )
            }
            Plan::Aggregate {
                input,
                keys,
                aggregates,
            } => {
                let input = self.node(input)?;
                let keys = self.projection(keys, &input.schema)?;
                let mut out = Vec::new();
                for named in aggregates {
                    let (agg, nullable, origins) = match &named.agg {
                        Agg::CountAll => (Aggregate::CountAll, false, BTreeSet::new()),
                        Agg::Count(a) => {
                            let a = self.expr(a, &input.schema)?;
                            let o = origins(&a, &input.schema)?;
                            (Aggregate::Count(a), false, o)
                        }
                        Agg::Sum(a) => {
                            let a = self.expr(a, &input.schema)?;
                            if a.data_type != DataType::I64 {
                                return Err(E::Type.into());
                            }
                            let o = origins(&a, &input.schema)?;
                            (Aggregate::Sum(a), true, o)
                        }
                    };
                    out.push((
                        BoundField {
                            field: Field {
                                name: named.name.clone(),
                                data_type: DataType::I64,
                                nullable,
                            },
                            qualifier: None,
                            origins,
                        },
                        agg,
                    ));
                }
                let schema = keys
                    .iter()
                    .map(|(f, _)| f.clone())
                    .chain(out.iter().map(|(f, _)| f.clone()))
                    .collect();
                (
                    NodeKind::Aggregate {
                        input: Box::new(input),
                        keys,
                        aggregates: out,
                    },
                    schema,
                )
            }
            Plan::Sort { input, keys } => {
                let input = self.node(input)?;
                let keys = keys
                    .iter()
                    .map(|k| {
                        Ok(OrderKey {
                            expr: self.expr(&k.expr, &input.schema)?,
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
                )
            }
            Plan::Limit { input, count } => {
                let input = self.node(input)?;
                let schema = input.schema.clone();
                (
                    NodeKind::Limit {
                        input: Box::new(input),
                        count: *count,
                    },
                    schema,
                )
            }
        };
        Ok(Node { kind, schema })
    }
}
pub(crate) fn bind(
    query: &Query,
    catalog: Arc<Catalog>,
    context: Arc<Context>,
) -> Result<BoundPlan> {
    if !Arc::ptr_eq(&catalog, &context.catalog) {
        return Err(E::Context.into());
    }
    let mut binder = Binder {
        catalog: catalog.clone(),
        context: context.clone(),
        aliases: BTreeSet::new(),
        hidden: BTreeSet::new(),
        sources: BTreeMap::new(),
    };
    if let Some(checks) = &query.sql_group_checks {
        // Resolve original SELECT/GROUP references against the authorized pre-aggregate
        // schema, so lowering cannot erase ambiguity, a denial, or column identity.
        let input = binder.node(&checks.input)?;
        for column in &checks.columns {
            binder.expr(column, &input.schema)?;
        }
        for (selected, grouped) in &checks.matches {
            if binder.expr(selected, &input.schema)? != binder.expr(grouped, &input.schema)? {
                return Err(E::Bind.into());
            }
        }
        if checks.invalid_group {
            return Err(E::Bind.into());
        }
        binder.aliases.clear();
        binder.hidden.clear();
        binder.sources.clear();
    }
    let root = binder.node(&query.plan)?;
    if root.schema.len() > 64 {
        return Err(E::Limit.into());
    }
    Ok(BoundPlan::new(
        root,
        catalog,
        context,
        binder.sources,
        vec!["bind_all_references", "lower_policy_scans"],
    ))
}
