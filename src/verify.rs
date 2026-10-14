//! Independent traversal recomputes schema/provenance and all trusted leaves.
use crate::catalog::{Catalog, Context};
use crate::error::{ErrorCode as E, Result};
use crate::plan::*;
use crate::types::{DataType, ExprKind, Field, TypedExpr, binary_type, identifier, unary_type};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Only this module constructs this capability. It cannot be deserialized.
pub struct VerifiedPlan {
    root: Node,
    catalog: Arc<Catalog>,
    context: Arc<Context>,
    trace: Vec<&'static str>,
}
#[derive(Serialize)]
pub struct Explain {
    pub version: u32,
    pub status: &'static str,
    pub implementation: &'static str,
    pub rules: Vec<&'static str>,
    pub operators: Vec<&'static str>,
    pub schema: Vec<Field>,
}
impl VerifiedPlan {
    pub fn schema(&self) -> Vec<Field> {
        self.root.schema.iter().map(|f| f.field.clone()).collect()
    }
    pub(crate) fn root(&self) -> &Node {
        &self.root
    }
    pub(crate) fn catalog(&self) -> &Arc<Catalog> {
        &self.catalog
    }
    pub(crate) fn context(&self) -> &Arc<Context> {
        &self.context
    }
    pub fn check_identity(&self, catalog: &Arc<Catalog>, context: &Arc<Context>) -> Result<()> {
        if !Arc::ptr_eq(catalog, &self.catalog) || !Arc::ptr_eq(context, &self.context) {
            return Err(E::Plan.into());
        }
        Ok(())
    }
    pub fn explain(&self) -> Explain {
        fn visit(node: &Node, out: &mut Vec<&'static str>) {
            match &node.kind {
                NodeKind::PolicyScan { .. } => out.push("PolicyScan"),
                NodeKind::Filter { input, .. } => {
                    out.push("Filter");
                    visit(input, out)
                }
                NodeKind::Project { input, .. } => {
                    out.push("Project");
                    visit(input, out)
                }
                NodeKind::Join { left, right, .. } => {
                    out.push("InnerHashJoin");
                    visit(left, out);
                    visit(right, out)
                }
                NodeKind::Aggregate { input, .. } => {
                    out.push("Aggregate");
                    visit(input, out)
                }
                NodeKind::Sort { input, .. } => {
                    out.push("Sort");
                    visit(input, out)
                }
                NodeKind::Limit { input, .. } => {
                    out.push("Limit");
                    visit(input, out)
                }
            }
        }
        let mut operators = Vec::new();
        visit(&self.root, &mut operators);
        Explain {
            version: 1,
            status: "ok",
            implementation: "rust",
            rules: self.trace.clone(),
            operators,
            schema: self.schema(),
        }
    }
}
struct Checker<'a> {
    catalog: &'a Catalog,
    context: &'a Context,
    sources: BTreeMap<u32, usize>,
    aliases: BTreeSet<String>,
    nodes: usize,
}
impl Checker<'_> {
    fn tick(&mut self, depth: usize) -> Result<()> {
        self.nodes += 1;
        if depth > 32 || self.nodes > 256 {
            return Err(E::Plan.into());
        }
        Ok(())
    }
    fn expr(
        &mut self,
        expr: &TypedExpr,
        schema: &[BoundField],
        depth: usize,
    ) -> Result<(DataType, bool, BTreeSet<Origin>)> {
        self.tick(depth)?;
        let (dtype, nullable, origins) = match &expr.kind {
            ExprKind::Column(i) => {
                let field = schema.get(*i).ok_or(E::Plan)?;
                (
                    field.field.data_type,
                    field.field.nullable,
                    field.origins.clone(),
                )
            }
            ExprKind::Literal(value) => {
                if let crate::types::Value::Text(text) = value
                    && text.len() > 4096
                {
                    return Err(E::Plan.into());
                }
                (value.data_type(), value.is_null(), BTreeSet::new())
            }
            ExprKind::Unary(op, a) => {
                let (dtype, nullable, origins) = self.expr(a, schema, depth + 1)?;
                let (dtype, nullable) = unary_type(*op, (dtype, nullable)).map_err(|_| E::Plan)?;
                (dtype, nullable, origins)
            }
            ExprKind::Binary(op, a, b) => {
                let (at, an, mut origins) = self.expr(a, schema, depth + 1)?;
                let (bt, bn, other) = self.expr(b, schema, depth + 1)?;
                let (dtype, nullable) =
                    binary_type(*op, (at, an), (bt, bn)).map_err(|_| E::Plan)?;
                origins.extend(other);
                (dtype, nullable, origins)
            }
        };
        if expr.data_type != dtype || expr.nullable != nullable {
            return Err(E::Plan.into());
        }
        Ok((dtype, nullable, origins))
    }
    fn projection(
        &mut self,
        columns: &Projection,
        input: &[BoundField],
        depth: usize,
    ) -> Result<Vec<BoundField>> {
        let mut names = BTreeSet::new();
        let mut schema = Vec::new();
        for (field, expr) in columns {
            let (dtype, nullable, origins) = self.expr(expr, input, depth)?;
            if !identifier(&field.field.name) || !names.insert(field.field.name.clone()) {
                return Err(E::Plan.into());
            }
            let expected = BoundField {
                field: Field {
                    name: field.field.name.clone(),
                    data_type: dtype,
                    nullable,
                },
                qualifier: None,
                origins,
            };
            if *field != expected {
                return Err(E::Plan.into());
            }
            schema.push(expected);
        }
        Ok(schema)
    }
    fn node(&mut self, node: &Node, depth: usize) -> Result<Vec<BoundField>> {
        self.tick(depth)?;
        let schema = match &node.kind {
            NodeKind::PolicyScan {
                table,
                occurrence,
                alias,
                columns,
                grant,
            } => {
                if self.sources.insert(*occurrence, *table).is_some()
                    || self.sources.len() > 4
                    || !identifier(alias)
                    || !self.aliases.insert(alias.clone())
                {
                    return Err(E::Plan.into());
                }
                let trusted = self.context.grants.get(table).ok_or(E::Plan)?;
                if trusted != grant {
                    return Err(E::Plan.into());
                }
                let base = self.catalog.tables.get(*table).ok_or(E::Plan)?;
                let tenant = base.columns.get(grant.tenant_column).ok_or(E::Plan)?;
                if tenant.data_type != DataType::Text || tenant.nullable {
                    return Err(E::Plan.into());
                }
                let mut seen = BTreeSet::new();
                let mut schema = Vec::new();
                for col in columns {
                    if !grant.visible.contains(col) || !seen.insert(*col) {
                        return Err(E::Plan.into());
                    }
                    schema.push(BoundField {
                        field: base.columns.get(*col).ok_or(E::Plan)?.clone(),
                        qualifier: Some(alias.clone()),
                        origins: BTreeSet::from([Origin {
                            occurrence: *occurrence,
                            table: *table,
                            column: *col,
                        }]),
                    });
                }
                schema
            }
            NodeKind::Filter { input, predicate } => {
                let schema = self.node(input, depth + 1)?;
                if self.expr(predicate, &schema, depth + 1)?.0 != DataType::Bool {
                    return Err(E::Plan.into());
                }
                schema
            }
            NodeKind::Project { input, columns } => {
                let schema = self.node(input, depth + 1)?;
                self.projection(columns, &schema, depth + 1)?
            }
            NodeKind::Join { left, right, on } => {
                let mut schema = self.node(left, depth + 1)?;
                let right = self.node(right, depth + 1)?;
                if on.is_empty() || on.len() > 64 {
                    return Err(E::Plan.into());
                }
                for (a, b) in on {
                    if schema.get(*a).ok_or(E::Plan)?.field.data_type
                        != right.get(*b).ok_or(E::Plan)?.field.data_type
                    {
                        return Err(E::Plan.into());
                    }
                }
                schema.extend(right);
                schema
            }
            NodeKind::Aggregate {
                input,
                keys,
                aggregates,
            } => {
                let input = self.node(input, depth + 1)?;
                let mut schema = self.projection(keys, &input, depth + 1)?;
                if keys.len() > 16 || keys.is_empty() && aggregates.is_empty() {
                    return Err(E::Plan.into());
                }
                let mut names: BTreeSet<_> = schema.iter().map(|f| f.field.name.clone()).collect();
                for (field, agg) in aggregates {
                    if !identifier(&field.field.name) || !names.insert(field.field.name.clone()) {
                        return Err(E::Plan.into());
                    }
                    let (nullable, origins) = match agg {
                        Aggregate::CountAll => (false, BTreeSet::new()),
                        Aggregate::Count(a) => {
                            let (_, _, origins) = self.expr(a, &input, depth + 1)?;
                            (false, origins)
                        }
                        Aggregate::Sum(a) => {
                            let (dtype, _, origins) = self.expr(a, &input, depth + 1)?;
                            if dtype != DataType::I64 {
                                return Err(E::Plan.into());
                            }
                            (true, origins)
                        }
                    };
                    let expected = BoundField {
                        field: Field {
                            name: field.field.name.clone(),
                            data_type: DataType::I64,
                            nullable,
                        },
                        qualifier: None,
                        origins,
                    };
                    if *field != expected {
                        return Err(E::Plan.into());
                    }
                    schema.push(expected);
                }
                schema
            }
            NodeKind::Sort { input, keys } => {
                let schema = self.node(input, depth + 1)?;
                if keys.is_empty() || keys.len() > 64 {
                    return Err(E::Plan.into());
                }
                for key in keys {
                    self.expr(&key.expr, &schema, depth + 1)?;
                }
                schema
            }
            NodeKind::Limit { input, count } => {
                if *count > 10000 {
                    return Err(E::Plan.into());
                }
                self.node(input, depth + 1)?
            }
        };
        if schema.len() > 256 || schema != node.schema {
            return Err(E::Plan.into());
        }
        Ok(schema)
    }
}
pub(crate) fn verify(plan: BoundPlan) -> Result<VerifiedPlan> {
    if !plan.binding_identity_matches()
        || !Arc::ptr_eq(&plan.catalog, &plan.context.catalog)
        || plan.root.schema.len() > 64
    {
        return Err(E::Plan.into());
    }
    let mut checker = Checker {
        catalog: &plan.catalog,
        context: &plan.context,
        sources: BTreeMap::new(),
        aliases: BTreeSet::new(),
        nodes: 0,
    };
    checker.node(&plan.root, 1)?;
    if checker.sources.is_empty() || checker.sources != plan.sources {
        return Err(E::Plan.into());
    }
    let mut trace = plan.trace;
    trace.push("verify_authority_schema_provenance");
    Ok(VerifiedPlan {
        root: plan.root,
        catalog: plan.catalog,
        context: plan.context,
        trace,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bind::bind, query::Query};
    fn fixture() -> Result<BoundPlan> {
        let catalog=Catalog::from_bytes(br#"{"version":1,"snapshot":"test","tables":{"sales":{"columns":[{"name":"tenant","type":"text","nullable":false},{"name":"id","type":"i64","nullable":false},{"name":"amount","type":"i64","nullable":true},{"name":"salary","type":"i64","nullable":false}],"rows":[["alpha",1,20,100],["beta",2,999,9999]]}}}"#)?;
        let context =
            Context::from_bytes(catalog.clone(), include_bytes!("../examples/context.json"))?;
        let query =
            Query::from_json(br#"{"version":1,"plan":{"op":"scan","table":"sales","alias":"s"}}"#)?;
        bind(&query, catalog, context)
    }
    #[test]
    fn reject_forged_provenance_grant_source_and_snapshot() -> Result<()> {
        verify(fixture()?)?;
        let mut plan = fixture()?;
        plan.root.schema.first_mut().ok_or(E::Plan)?.origins.clear();
        assert_eq!(verify(plan).err().map(|e| e.code), Some(E::Plan));
        let mut plan = fixture()?;
        if let NodeKind::PolicyScan { grant, .. } = &mut plan.root.kind {
            grant.tenant_column = 999;
        }
        assert_eq!(verify(plan).err().map(|e| e.code), Some(E::Plan));
        let mut plan = fixture()?;
        plan.sources.clear();
        assert_eq!(verify(plan).err().map(|e| e.code), Some(E::Plan));
        let mut plan = fixture()?;
        plan.catalog = Catalog::from_bytes(include_bytes!("../examples/catalog.json"))?;
        assert_eq!(verify(plan).err().map(|e| e.code), Some(E::Plan));
        Ok(())
    }
    #[test]
    fn reject_other_context_even_same_label_and_content() -> Result<()> {
        let plan = verify(fixture()?)?;
        let context = Context::from_bytes(
            plan.catalog.clone(),
            include_bytes!("../examples/context.json"),
        )?;
        assert_eq!(
            plan.check_identity(&plan.catalog, &context)
                .map_err(|e| e.code),
            Err(E::Plan)
        );
        Ok(())
    }

    #[test]
    fn reject_context_and_snapshot_substitution_before_verification() -> Result<()> {
        let mut plan = fixture()?;
        let beta = Context::from_bytes(plan.catalog.clone(), br#"{"version":1,"tenant":"beta","policy_revision":"r2","tables":{"sales":{"tenant_column":"tenant","columns":["id","amount"]}}}"#)?;
        plan.context = beta;
        assert_eq!(verify(plan).err().map(|e| e.code), Some(E::Plan));
        let mut plan = fixture()?;
        let other = fixture()?;
        plan.catalog = other.catalog;
        plan.context = other.context;
        assert_eq!(verify(plan).err().map(|e| e.code), Some(E::Plan));
        Ok(())
    }
    #[test]
    fn denied_filter_is_bound_before_execution() -> Result<()> {
        let fixture = fixture()?;
        let query=Query::from_json(br#"{"version":1,"plan":{"op":"filter","input":{"op":"scan","table":"sales","alias":"s"},"predicate":{"op":"gt","left":{"col":"s.salary"},"right":{"lit":0}}}}"#)?;
        assert_eq!(
            bind(&query, fixture.catalog, fixture.context)
                .err()
                .map(|e| e.code),
            Some(E::Forbidden)
        );
        Ok(())
    }
}
