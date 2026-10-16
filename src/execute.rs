//! Execution accepts only an opaque verified plan and publishes complete results.
use crate::budget::{Budget, Metrics, Reservation};
use crate::catalog::{Catalog, Context};
use crate::error::{ErrorCode as E, Result};
use crate::operators::stream::{Rows, Stream};
use crate::plan::{Node, NodeKind};
use crate::types::{Field, Row};
use crate::verify::VerifiedPlan;
use serde::Serialize;
use std::io;
use std::sync::Arc;
use std::time::Instant;

#[derive(Serialize)]
pub struct QueryResult {
    version: u32,
    status: &'static str,
    schema: Vec<Field>,
    rows: Vec<Row>,
    metrics: Metrics,
    implementation: &'static str,
    #[serde(skip)]
    _reservation: Rows,
    #[serde(skip)]
    _schema_reservation: Reservation,
    #[serde(skip)]
    output_limit: usize,
    #[serde(skip)]
    execution_elapsed_ns: u128,
}
impl QueryResult {
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }
    pub fn schema(&self) -> &[Field] {
        &self.schema
    }
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }
    /// Trusted synthetic benchmark instrumentation; never included in ordinary JSON.
    pub fn execution_elapsed_ns(&self) -> u128 {
        self.execution_elapsed_ns
    }
    pub fn to_json_bytes(&mut self, budget: &Budget) -> Result<SerializedResult> {
        budget.checkpoint()?;
        let mut reservation = budget.reserve(0)?;
        let mut reserved = 0usize;
        let mut size = None;
        for _ in 0..4 {
            let mut count = Counter {
                bytes: 0,
                limit: self.output_limit,
            };
            serde_json::to_writer(&mut count, &*self).map_err(|_| E::OutputLimit)?;
            if count.bytes > reserved {
                reservation.grow(count.bytes - reserved)?;
                reserved = count.bytes;
            }
            let peak = budget.metrics().peak_reserved_bytes;
            if peak == self.metrics.peak_reserved_bytes {
                size = Some(count.bytes);
                break;
            }
            self.metrics.peak_reserved_bytes = peak;
        }
        let size = size.ok_or(E::Internal)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(|_| E::Budget)?;
        serde_json::to_writer(&mut bytes, &*self).map_err(|_| E::Internal)?;
        if bytes.len() != size {
            return Err(E::Internal.into());
        }
        budget.checkpoint()?;
        Ok(SerializedResult {
            bytes,
            _reservation: reservation,
        })
    }
}
pub struct SerializedResult {
    bytes: Vec<u8>,
    _reservation: Reservation,
}
impl SerializedResult {
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
struct Counter {
    bytes: usize,
    limit: usize,
}
impl io::Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("output limit"))?;
        if next > self.limit {
            return Err(io::Error::other("output limit"));
        }
        self.bytes = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn nodes(node: &Node) -> usize {
    1 + match &node.kind {
        NodeKind::PolicyScan { .. } => 0,
        NodeKind::Join { left, right, .. } => nodes(left) + nodes(right),
        NodeKind::Filter { input, .. }
        | NodeKind::Project { input, .. }
        | NodeKind::Aggregate { input, .. }
        | NodeKind::Sort { input, .. }
        | NodeKind::Limit { input, .. } => nodes(input),
    }
}
fn schema_bytes(node: &Node) -> Result<usize> {
    node.schema.iter().try_fold(
        std::mem::size_of::<Vec<Field>>(),
        |sum, field| -> Result<usize> {
            sum.checked_add(std::mem::size_of::<Field>())
                .and_then(|n| n.checked_add(field.field.name.len()))
                .ok_or(E::Budget.into())
        },
    )
}
fn execution_schema_bytes(node: &Node) -> Result<usize> {
    let children = match &node.kind {
        NodeKind::PolicyScan { .. } => 0,
        NodeKind::Join { left, right, .. } => execution_schema_bytes(left)?
            .checked_add(execution_schema_bytes(right)?)
            .ok_or(E::Budget)?,
        NodeKind::Filter { input, .. }
        | NodeKind::Project { input, .. }
        | NodeKind::Aggregate { input, .. }
        | NodeKind::Sort { input, .. }
        | NodeKind::Limit { input, .. } => execution_schema_bytes(input)?,
    };
    schema_bytes(node)?
        .checked_add(children)
        .ok_or(E::Budget.into())
}
pub fn execute(plan: &VerifiedPlan, budget: &mut Budget) -> Result<QueryResult> {
    execute_in(plan, plan.catalog(), plan.context(), budget)
}
pub fn execute_in(
    plan: &VerifiedPlan,
    catalog: &Arc<Catalog>,
    context: &Arc<Context>,
    budget: &mut Budget,
) -> Result<QueryResult> {
    plan.check_identity(catalog, context)?;
    budget.checkpoint()?;
    let started = Instant::now();
    let _operator_state = budget.reserve(
        nodes(plan.root())
            .checked_mul(512)
            .and_then(|n| n.checked_add(execution_schema_bytes(plan.root()).ok()?))
            .ok_or(E::Budget)?,
    )?;
    let schema_reservation = budget.reserve(schema_bytes(plan.root())?)?;
    let mut input = Stream::build(plan.root(), catalog, context, budget)?;
    let mut rows = Rows::new(budget)?;
    while let Some(frame) = input.next(budget)? {
        for i in 0..frame.batch.len() {
            if rows.data.len() >= budget.limits().max_output_rows {
                return Err(E::OutputLimit.into());
            }
            budget.charge(frame.batch.fields().len() as u64 + 1)?;
            rows.push_batch(&frame.batch, i)?;
        }
    }
    drop(input);
    budget.checkpoint()?;
    let execution_elapsed_ns = started.elapsed().as_nanos();
    let data = std::mem::take(&mut rows.data);
    let result = QueryResult {
        version: 1,
        status: "ok",
        schema: plan.schema(),
        rows: data,
        metrics: budget.metrics(),
        implementation: "rust",
        _reservation: rows,
        _schema_reservation: schema_reservation,
        output_limit: budget.limits().max_output_bytes,
        execution_elapsed_ns,
    };
    let mut count = Counter {
        bytes: 0,
        limit: budget.limits().max_output_bytes,
    };
    serde_json::to_writer(&mut count, &result).map_err(|_| E::OutputLimit)?;
    budget.observe("collect_before_publish")?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{budget::Limits, query::Query, types::Value};
    use std::sync::atomic::AtomicBool;
    fn fixture(query: serde_json::Value) -> Result<(VerifiedPlan, Budget)> {
        let catalog=Catalog::from_bytes(br#"{"version":1,"snapshot":"bags","tables":{"t":{"columns":[{"name":"tenant","type":"text","nullable":false},{"name":"id","type":"i64","nullable":true},{"name":"amount","type":"i64","nullable":true}],"rows":[["alpha",1,10],["beta",1,999],["alpha",1,20],["alpha",null,null]]}}}"#)?;
        let context=Context::from_bytes(catalog.clone(),br#"{"version":1,"tenant":"alpha","policy_revision":"r1","tables":{"t":{"tenant_column":"tenant","columns":["id","amount"]}}}"#)?;
        let query = Query::from_json(
            &serde_json::to_vec(&serde_json::json!({"version":1,"plan":query}))
                .map_err(|_| E::Internal)?,
        )?;
        let plan = crate::compile(&query, catalog, context)?;
        Ok((
            plan,
            Budget::new(Limits::default(), Arc::new(AtomicBool::new(false)), None)?,
        ))
    }
    #[test]
    fn duplicate_join_and_scalar_aggregate_are_exact() -> Result<()> {
        let join = serde_json::json!({"op":"join","left":{"op":"scan","table":"t","alias":"a"},"right":{"op":"scan","table":"t","alias":"b"},"on":[{"left":{"col":"a.id"},"right":{"col":"b.id"}}]});
        let (plan, mut budget) = fixture(
            serde_json::json!({"op":"aggregate","input":join,"keys":[],"aggregates":[{"name":"n","kind":"count_all"},{"name":"s","kind":"sum","expr":{"col":"a.amount"}}]}),
        )?;
        let result = execute(&plan, &mut budget)?;
        assert_eq!(result.rows(), &[vec![Value::I64(4), Value::I64(60)]]);
        drop(result);
        assert_eq!(budget.reserved_bytes(), 0);
        Ok(())
    }
    #[test]
    fn empty_scalar_null_and_count_are_exact() -> Result<()> {
        let (plan, mut budget) = fixture(
            serde_json::json!({"op":"aggregate","input":{"op":"filter","input":{"op":"scan","table":"t","alias":"a"},"predicate":{"lit":false}},"keys":[],"aggregates":[{"name":"n","kind":"count_all"},{"name":"s","kind":"sum","expr":{"col":"a.amount"}}]}),
        )?;
        assert_eq!(
            execute(&plan, &mut budget)?.rows(),
            &[vec![
                Value::I64(0),
                Value::Null(crate::types::DataType::I64)
            ]]
        );
        Ok(())
    }
    #[test]
    fn output_cancel_work_and_memory_fail_without_result() -> Result<()> {
        let (plan, _) = fixture(serde_json::json!({"op":"scan","table":"t","alias":"a"}))?;
        for (limits, expected) in [
            (
                Limits {
                    max_output_rows: 1,
                    ..Limits::default()
                },
                E::OutputLimit,
            ),
            (
                Limits {
                    max_output_bytes: 8,
                    ..Limits::default()
                },
                E::OutputLimit,
            ),
            (
                Limits {
                    max_work: 1,
                    ..Limits::default()
                },
                E::Budget,
            ),
            (
                Limits {
                    max_reserved_bytes: 10,
                    ..Limits::default()
                },
                E::Budget,
            ),
        ] {
            let mut budget = Budget::new(limits, Arc::new(AtomicBool::new(false)), None)?;
            assert_eq!(
                execute(&plan, &mut budget).err().map(|e| e.code),
                Some(expected)
            );
            assert_eq!(budget.reserved_bytes(), 0);
            assert!(budget.consumed_work() <= budget.limits().max_work);
        }
        let mut budget = Budget::new(Limits::default(), Arc::new(AtomicBool::new(true)), None)?;
        assert_eq!(
            execute(&plan, &mut budget).err().map(|e| e.code),
            Some(E::Cancelled)
        );
        assert_eq!(budget.executed_scans(), 0);
        Ok(())
    }

    #[test]
    fn cancellation_at_final_collection_never_returns_success() -> Result<()> {
        let (plan, _) = fixture(serde_json::json!({"op":"scan","table":"t","alias":"a"}))?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let observer_flag = cancelled.clone();
        let mut budget = Budget::new(Limits::default(), cancelled, None)?;
        budget.set_observer(move |stage| {
            if stage == "collect_before_publish" {
                observer_flag.store(true, std::sync::atomic::Ordering::Release);
            }
            Ok(())
        });
        assert_eq!(
            execute(&plan, &mut budget).err().map(|e| e.code),
            Some(E::Cancelled)
        );
        assert!(budget.executed_scans() > 0);
        assert_eq!(budget.reserved_bytes(), 0);
        Ok(())
    }

    #[test]
    fn expression_string_temporaries_reserve_before_allocation() -> Result<()> {
        let text = "x".repeat(4096);
        let expression = serde_json::json!({"op":"eq","left":{"lit":text},"right":{"lit":text}});
        let input = serde_json::json!({"op":"limit","input":{"op":"scan","table":"t","alias":"a"},"count":1});
        for plan in [
            serde_json::json!({"op":"project","input":input,"columns":[{"name":"same","expr":expression}]}),
            serde_json::json!({"op":"filter","input":input,"predicate":expression}),
            serde_json::json!({"op":"aggregate","input":input,"keys":[{"name":"same","expr":expression}],"aggregates":[{"name":"n","kind":"count_all"}]}),
            serde_json::json!({"op":"aggregate","input":input,"keys":[],"aggregates":[{"name":"n","kind":"count","expr":expression}]}),
            serde_json::json!({"op":"sort","input":input,"keys":[{"expr":expression,"direction":"asc","nulls":"last"}]}),
        ] {
            let (plan, _) = fixture(plan)?;
            let mut budget = Budget::new(
                Limits {
                    max_reserved_bytes: 4096,
                    ..Limits::default()
                },
                Arc::new(AtomicBool::new(false)),
                None,
            )?;
            assert_eq!(
                execute(&plan, &mut budget).err().map(|e| e.code),
                Some(E::Budget)
            );
            assert_eq!(budget.reserved_bytes(), 0);
        }
        Ok(())
    }

    #[test]
    fn exploding_join_stops_inside_the_charged_inner_loop() -> Result<()> {
        let rows: Vec<_> = (0..100)
            .map(|_| serde_json::json!(["alpha", 1, 1]))
            .collect();
        let catalog = Catalog::from_bytes(&serde_json::to_vec(&serde_json::json!({"version":1,"snapshot":"join-budget","tables":{"t":{"columns":[{"name":"tenant","type":"text","nullable":false},{"name":"id","type":"i64","nullable":false},{"name":"amount","type":"i64","nullable":false}],"rows":rows}}})).map_err(|_|E::Internal)?)?;
        let context = Context::from_bytes(catalog.clone(), br#"{"version":1,"tenant":"alpha","policy_revision":"r1","tables":{"t":{"tenant_column":"tenant","columns":["id","amount"]}}}"#)?;
        let query = Query::from_json(br#"{"version":1,"plan":{"op":"aggregate","input":{"op":"join","left":{"op":"scan","table":"t","alias":"a"},"right":{"op":"scan","table":"t","alias":"b"},"on":[{"left":{"col":"a.id"},"right":{"col":"b.id"}}]},"keys":[],"aggregates":[{"name":"n","kind":"count_all"}]}}"#)?;
        let plan = crate::compile(&query, catalog, context)?;
        let reached = Arc::new(AtomicBool::new(false));
        let observed = reached.clone();
        let mut budget = Budget::new(
            Limits {
                max_work: 3000,
                ..Limits::default()
            },
            Arc::new(AtomicBool::new(false)),
            None,
        )?;
        budget.set_observer(move |stage| {
            if stage == "join_inner" {
                observed.store(true, std::sync::atomic::Ordering::Release);
            }
            Ok(())
        });
        assert_eq!(
            execute(&plan, &mut budget).err().map(|e| e.code),
            Some(E::Budget)
        );
        assert!(reached.load(std::sync::atomic::Ordering::Acquire));
        assert!(budget.consumed_work() <= 3000);
        assert_eq!(budget.reserved_bytes(), 0);
        Ok(())
    }

    #[test]
    fn empty_result_schema_is_reserved_and_retained() -> Result<()> {
        let mut columns = vec![serde_json::json!({"name":"tenant","type":"text","nullable":false})];
        let mut names = Vec::new();
        for i in 0..63 {
            let name = format!("c{i}");
            names.push(name.clone());
            columns.push(serde_json::json!({"name":name,"type":"i64","nullable":false}));
        }
        let catalog = Catalog::from_bytes(&serde_json::to_vec(&serde_json::json!({"version":1,"snapshot":"empty-schema","tables":{"t":{"columns":columns,"rows":[]}}})).map_err(|_| E::Internal)?)?;
        let context = Context::from_bytes(catalog.clone(), &serde_json::to_vec(&serde_json::json!({"version":1,"tenant":"alpha","policy_revision":"r1","tables":{"t":{"tenant_column":"tenant","columns":names}}})).map_err(|_| E::Internal)?)?;
        let query =
            Query::from_json(br#"{"version":1,"plan":{"op":"scan","table":"t","alias":"a"}}"#)?;
        let plan = crate::compile(&query, catalog, context)?;
        let mut small = Budget::new(
            Limits {
                max_reserved_bytes: 512,
                ..Limits::default()
            },
            Arc::new(AtomicBool::new(false)),
            None,
        )?;
        assert_eq!(
            execute(&plan, &mut small).err().map(|e| e.code),
            Some(E::Budget)
        );
        assert_eq!(small.reserved_bytes(), 0);
        let mut budget = Budget::new(Limits::default(), Arc::new(AtomicBool::new(false)), None)?;
        let result = execute(&plan, &mut budget)?;
        assert_eq!(result.schema().len(), 63);
        assert!(budget.reserved_bytes() >= 63 * std::mem::size_of::<crate::types::Field>());
        drop(result);
        assert_eq!(budget.reserved_bytes(), 0);
        Ok(())
    }

    #[test]
    fn repeated_text_join_probe_keys_reserve_every_copy() -> Result<()> {
        let columns = serde_json::json!([
            {"name":"tenant","type":"text","nullable":false},
            {"name":"key","type":"text","nullable":false}
        ]);
        let catalog = Catalog::from_bytes(
            &serde_json::to_vec(&serde_json::json!({
                "version":1,"snapshot":"repeated-probe-keys","tables":{
                    "l":{"columns":columns,"rows":[["alpha","x".repeat(4096)]]},
                    "r":{"columns":columns,"rows":[]}
                }
            }))
            .map_err(|_| E::Internal)?,
        )?;
        let context = Context::from_bytes(catalog.clone(), br#"{"version":1,"tenant":"alpha","policy_revision":"r1","tables":{"l":{"tenant_column":"tenant","columns":["key"]},"r":{"tenant_column":"tenant","columns":["key"]}}}"#)?;
        let pairs: Vec<_> = (0..64)
            .map(|_| {
                serde_json::json!({
                    "left":{"col":"a.key"},"right":{"col":"b.key"}
                })
            })
            .collect();
        let query = Query::from_json(
            &serde_json::to_vec(&serde_json::json!({
                "version":1,"plan":{"op":"join",
                    "left":{"op":"scan","table":"l","alias":"a"},
                    "right":{"op":"scan","table":"r","alias":"b"},"on":pairs}
            }))
            .map_err(|_| E::Internal)?,
        )?;
        let plan = crate::compile(&query, catalog, context)?;
        let mut budget = Budget::new(
            Limits {
                max_reserved_bytes: 32768,
                ..Limits::default()
            },
            Arc::new(AtomicBool::new(false)),
            None,
        )?;
        assert_eq!(
            execute(&plan, &mut budget).err().map(|e| e.code),
            Some(E::Budget)
        );
        assert_eq!(budget.reserved_bytes(), 0);
        Ok(())
    }
}
