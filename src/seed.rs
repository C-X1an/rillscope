//! Development kernel, not the full query engine.
//!
//! Original nullable column storage, SQL-like Boolean semantics, checked
//! arithmetic, cooperative work limits, and host-bound scan authorization.
//! Query decoding, general physical verification, joins/aggregation, optimizer,
//! reservations and full CLI are not yet implemented. See IMPLEMENTATION_STATUS.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataType {
    I64,
    Bool,
    Text,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cell {
    Null(DataType),
    I64(i64),
    Bool(bool),
    Text(String),
}

impl Cell {
    pub fn data_type(&self) -> DataType {
        match self {
            Self::Null(t) => *t,
            Self::I64(_) => DataType::I64,
            Self::Bool(_) => DataType::Bool,
            Self::Text(_) => DataType::Text,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryError {
    Schema,
    Type,
    Forbidden,
    Context,
    Overflow,
    WorkBudget,
    Cancelled,
    OutputLimit,
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Schema => "invalid schema",
            Self::Type => "incompatible data type",
            Self::Forbidden => "column is not available in this scope",
            Self::Context => "invalid trusted context",
            Self::Overflow => "integer overflow",
            Self::WorkBudget => "work budget exceeded",
            Self::Cancelled => "query cancelled",
            Self::OutputLimit => "output limit exceeded",
        };
        f.write_str(message)
    }
}
impl Error for QueryError {}

pub type Result<T> = std::result::Result<T, QueryError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Column {
    I64(Vec<Option<i64>>),
    Bool(Vec<Option<bool>>),
    Text(Vec<Option<String>>),
}
impl Column {
    pub fn len(&self) -> usize {
        match self {
            Self::I64(v) => v.len(),
            Self::Bool(v) => v.len(),
            Self::Text(v) => v.len(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn data_type(&self) -> DataType {
        match self {
            Self::I64(_) => DataType::I64,
            Self::Bool(_) => DataType::Bool,
            Self::Text(_) => DataType::Text,
        }
    }
    pub fn cell(&self, index: usize) -> Result<Cell> {
        match self {
            Self::I64(v) => v
                .get(index)
                .map(|x| x.map_or(Cell::Null(DataType::I64), Cell::I64)),
            Self::Bool(v) => v
                .get(index)
                .map(|x| x.map_or(Cell::Null(DataType::Bool), Cell::Bool)),
            Self::Text(v) => v.get(index).map(|x| {
                x.as_ref()
                    .map_or(Cell::Null(DataType::Text), |s| Cell::Text(s.clone()))
            }),
        }
        .ok_or(QueryError::Schema)
    }
    fn has_null(&self) -> bool {
        match self {
            Self::I64(v) => v.iter().any(Option::is_none),
            Self::Bool(v) => v.iter().any(Option::is_none),
            Self::Text(v) => v.iter().any(Option::is_none),
        }
    }
    fn selected(&self, indices: &[usize]) -> Result<Self> {
        match self {
            Self::I64(v) => indices
                .iter()
                .map(|i| v.get(*i).copied().ok_or(QueryError::Schema))
                .collect::<Result<Vec<_>>>()
                .map(Self::I64),
            Self::Bool(v) => indices
                .iter()
                .map(|i| v.get(*i).copied().ok_or(QueryError::Schema))
                .collect::<Result<Vec<_>>>()
                .map(Self::Bool),
            Self::Text(v) => indices
                .iter()
                .map(|i| v.get(*i).cloned().ok_or(QueryError::Schema))
                .collect::<Result<Vec<_>>>()
                .map(Self::Text),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub data_type: DataType,
    pub nullable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    fields: Vec<Field>,
    columns: Vec<Column>,
    rows: usize,
}
impl Batch {
    pub fn new(fields: Vec<Field>, columns: Vec<Column>) -> Result<Self> {
        if fields.is_empty() || fields.len() != columns.len() || fields.len() > 64 {
            return Err(QueryError::Schema);
        }
        let rows = columns.first().ok_or(QueryError::Schema)?.len();
        let mut names = BTreeSet::new();
        for (field, column) in fields.iter().zip(&columns) {
            if field.name.is_empty() || !names.insert(field.name.clone()) || column.len() != rows {
                return Err(QueryError::Schema);
            }
            if field.data_type != column.data_type() || (!field.nullable && column.has_null()) {
                return Err(QueryError::Type);
            }
            if let Column::Text(values) = column
                && values.iter().flatten().any(|value| value.len() > 4096)
            {
                return Err(QueryError::Schema);
            }
        }
        Ok(Self {
            fields,
            columns,
            rows,
        })
    }
    pub fn rows(&self) -> usize {
        self.rows
    }
    pub fn fields(&self) -> &[Field] {
        &self.fields
    }
    pub fn column(&self, index: usize) -> Result<&Column> {
        self.columns.get(index).ok_or(QueryError::Schema)
    }
}

/// Trusted host-owned scope. No query JSON deserialization is provided.
#[derive(Clone, Debug)]
pub struct Context {
    tenant: String,
    visible: BTreeSet<String>,
    revision: String,
}
impl Context {
    pub fn new(tenant: String, visible: BTreeSet<String>, revision: String) -> Result<Self> {
        if tenant.len() > 4096 || revision.is_empty() || visible.is_empty() {
            return Err(QueryError::Context);
        }
        Ok(Self {
            tenant,
            visible,
            revision,
        })
    }
    pub fn revision(&self) -> &str {
        &self.revision
    }
}

#[derive(Debug)]
pub struct Table {
    batch: Batch,
    tenant_column: usize,
    snapshot: String,
}
impl Table {
    pub fn new(batch: Batch, tenant_column: usize, snapshot: String) -> Result<Self> {
        let field = batch.fields.get(tenant_column).ok_or(QueryError::Context)?;
        if field.data_type != DataType::Text || field.nullable || snapshot.is_empty() {
            return Err(QueryError::Context);
        }
        Ok(Self {
            batch,
            tenant_column,
            snapshot,
        })
    }
    pub fn snapshot(&self) -> &str {
        &self.snapshot
    }
}

/// Opaque scan capability borrows the exact immutable table and host context.
/// This checks scans only. It is NOT yet a general independent plan verifier.
#[derive(Debug)]
pub struct VerifiedScan<'a> {
    table: &'a Table,
    context: &'a Context,
    columns: Vec<usize>,
}

pub fn verify_scan<'a>(
    table: &'a Table,
    context: &'a Context,
    requested: &[String],
) -> Result<VerifiedScan<'a>> {
    if requested.is_empty() || requested.len() > 64 {
        return Err(QueryError::Schema);
    }
    let mut columns = Vec::new();
    let mut seen = BTreeSet::new();
    for name in requested {
        if !context.visible.contains(name) {
            return Err(QueryError::Forbidden);
        }
        if !seen.insert(name) {
            return Err(QueryError::Schema);
        }
        let index = table
            .batch
            .fields
            .iter()
            .position(|field| field.name == *name)
            .ok_or(QueryError::Forbidden)?;
        columns.push(index);
    }
    Ok(VerifiedScan {
        table,
        context,
        columns,
    })
}

/// A work meter, not a heap/RSS limit. Memory reservation is unfinished.
#[derive(Debug)]
pub struct WorkBudget<'a> {
    limit: u64,
    used: u64,
    cancelled: &'a AtomicBool,
}
impl<'a> WorkBudget<'a> {
    pub fn new(limit: u64, cancelled: &'a AtomicBool) -> Self {
        Self {
            limit,
            used: 0,
            cancelled,
        }
    }
    pub fn charge(&mut self, amount: u64) -> Result<()> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(QueryError::Cancelled);
        }
        let next = self
            .used
            .checked_add(amount)
            .ok_or(QueryError::WorkBudget)?;
        if next > self.limit {
            return Err(QueryError::WorkBudget);
        }
        self.used = next;
        Ok(())
    }
    pub fn used(&self) -> u64 {
        self.used
    }
}

pub fn execute_scan(
    scan: &VerifiedScan<'_>,
    budget: &mut WorkBudget<'_>,
    max_rows: usize,
) -> Result<Batch> {
    budget.charge(0)?;
    let mut selected = Vec::new();
    let tenant_column = scan.table.batch.column(scan.table.tenant_column)?;
    for row in 0..scan.table.batch.rows {
        budget.charge(1)?;
        let tenant = tenant_column.cell(row)?;
        if tenant == Cell::Text(scan.context.tenant.clone()) {
            if selected.len() >= max_rows {
                return Err(QueryError::OutputLimit);
            }
            budget.charge(scan.columns.len() as u64)?;
            selected.push(row);
        }
    }
    let fields = scan
        .columns
        .iter()
        .map(|i| {
            scan.table
                .batch
                .fields
                .get(*i)
                .cloned()
                .ok_or(QueryError::Schema)
        })
        .collect::<Result<Vec<_>>>()?;
    let mut columns = Vec::new();
    for index in &scan.columns {
        budget.charge(selected.len() as u64)?;
        columns.push(scan.table.batch.column(*index)?.selected(&selected)?);
    }
    Batch::new(fields, columns)
}

pub fn sql_and(left: Option<bool>, right: Option<bool>) -> Option<bool> {
    match (left, right) {
        (Some(false), _) | (_, Some(false)) => Some(false),
        (Some(true), Some(true)) => Some(true),
        _ => None,
    }
}
pub fn sql_or(left: Option<bool>, right: Option<bool>) -> Option<bool> {
    match (left, right) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), Some(false)) => Some(false),
        _ => None,
    }
}
pub fn sql_not(value: Option<bool>) -> Option<bool> {
    value.map(|v| !v)
}
pub fn checked_add(left: Option<i64>, right: Option<i64>) -> Result<Option<i64>> {
    match (left, right) {
        (Some(a), Some(b)) => a.checked_add(b).map(Some).ok_or(QueryError::Overflow),
        _ => Ok(None),
    }
}
pub fn checked_sum(values: &[Option<i64>]) -> Result<Option<i64>> {
    let mut result: Option<i64> = None;
    for value in values.iter().flatten() {
        result = Some(match result {
            None => *value,
            Some(total) => total.checked_add(*value).ok_or(QueryError::Overflow)?,
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Result<(Table, Context)> {
        let batch = Batch::new(
            vec![
                Field {
                    name: "tenant".into(),
                    data_type: DataType::Text,
                    nullable: false,
                },
                Field {
                    name: "id".into(),
                    data_type: DataType::I64,
                    nullable: false,
                },
                Field {
                    name: "amount".into(),
                    data_type: DataType::I64,
                    nullable: true,
                },
            ],
            vec![
                Column::Text(vec![
                    Some("alpha".into()),
                    Some("beta".into()),
                    Some("alpha".into()),
                ]),
                Column::I64(vec![Some(1), Some(2), Some(3)]),
                Column::I64(vec![Some(10), Some(i64::MAX), None]),
            ],
        )?;
        Ok((
            Table::new(batch, 0, "fixture-v1".into())?,
            Context::new(
                "alpha".into(),
                BTreeSet::from(["id".into(), "amount".into()]),
                "r1".into(),
            )?,
        ))
    }
    #[test]
    fn boolean_truth_tables() {
        let values = [Some(false), Some(true), None];
        let and = [
            [Some(false), Some(false), Some(false)],
            [Some(false), Some(true), None],
            [Some(false), None, None],
        ];
        let or = [
            [Some(false), Some(true), None],
            [Some(true), Some(true), Some(true)],
            [None, Some(true), None],
        ];
        for (i, a) in values.iter().enumerate() {
            for (j, b) in values.iter().enumerate() {
                assert_eq!(sql_and(*a, *b), and[i][j]);
                assert_eq!(sql_or(*a, *b), or[i][j]);
            }
        }
        assert_eq!(sql_not(None), None);
    }
    #[test]
    fn overflow_is_not_wraparound() {
        assert_eq!(
            checked_add(Some(i64::MAX), Some(1)),
            Err(QueryError::Overflow)
        );
        assert_eq!(checked_add(None, Some(1)), Ok(None));
        assert_eq!(checked_sum(&[]), Ok(None));
        assert_eq!(checked_sum(&[Some(1), None, Some(2)]), Ok(Some(3)));
        assert_eq!(
            checked_sum(&[Some(i64::MAX), Some(1)]),
            Err(QueryError::Overflow)
        );
    }
    #[test]
    fn scoped_scan() -> Result<()> {
        let (table, context) = fixture()?;
        let scan = verify_scan(&table, &context, &["id".into(), "amount".into()])?;
        let cancelled = AtomicBool::new(false);
        let out = execute_scan(&scan, &mut WorkBudget::new(100, &cancelled), 10)?;
        assert_eq!(out.rows(), 2);
        assert_eq!(out.column(0)?, &Column::I64(vec![Some(1), Some(3)]));
        assert_eq!(out.column(1)?, &Column::I64(vec![Some(10), None]));
        Ok(())
    }
    #[test]
    fn hidden_column_rejected() -> Result<()> {
        let (table, context) = fixture()?;
        assert!(matches!(
            verify_scan(&table, &context, &["tenant".into()]),
            Err(QueryError::Forbidden)
        ));
        Ok(())
    }
    #[test]
    fn duplicate_projection_rejected() -> Result<()> {
        let (table, context) = fixture()?;
        assert!(matches!(
            verify_scan(&table, &context, &["id".into(), "id".into()]),
            Err(QueryError::Schema)
        ));
        Ok(())
    }
    #[test]
    fn cancellation_and_exhaustion_no_result() -> Result<()> {
        let (table, context) = fixture()?;
        let scan = verify_scan(&table, &context, &["id".into()])?;
        let flag = AtomicBool::new(false);
        assert_eq!(
            execute_scan(&scan, &mut WorkBudget::new(1, &flag), 10),
            Err(QueryError::WorkBudget)
        );
        flag.store(true, Ordering::Relaxed);
        assert_eq!(
            execute_scan(&scan, &mut WorkBudget::new(100, &flag), 10),
            Err(QueryError::Cancelled)
        );
        Ok(())
    }
    #[test]
    fn output_limit_no_partial_batch() -> Result<()> {
        let (table, context) = fixture()?;
        let scan = verify_scan(&table, &context, &["id".into()])?;
        let flag = AtomicBool::new(false);
        assert_eq!(
            execute_scan(&scan, &mut WorkBudget::new(100, &flag), 1),
            Err(QueryError::OutputLimit)
        );
        Ok(())
    }
    #[test]
    fn batch_schema_invariants() {
        let field = Field {
            name: "x".into(),
            data_type: DataType::I64,
            nullable: false,
        };
        assert!(Batch::new(vec![field.clone()], vec![Column::Bool(vec![Some(true)])]).is_err());
        assert!(Batch::new(vec![field.clone()], vec![Column::I64(vec![None])]).is_err());
        assert!(
            Batch::new(
                vec![field.clone(), field],
                vec![Column::I64(vec![]), Column::I64(vec![])]
            )
            .is_err()
        );
    }
    #[test]
    fn bounds_are_errors() {
        assert_eq!(Column::I64(vec![]).cell(0), Err(QueryError::Schema));
    }
    #[test]
    fn meter_overflow_cannot_reset() {
        let flag = AtomicBool::new(false);
        let mut budget = WorkBudget::new(u64::MAX, &flag);
        assert_eq!(budget.charge(u64::MAX), Ok(()));
        assert_eq!(budget.charge(1), Err(QueryError::WorkBudget));
    }
}
