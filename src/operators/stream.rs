//! Pull-based column batches. User expressions see only authorized columns.
use super::blocking::{self, HashJoin};
use crate::budget::{Budget, Reservation};
use crate::catalog::{Catalog, Context};
use crate::error::{ErrorCode as E, Result};
use crate::plan::{Node, NodeKind, Projection};
use crate::types::{Batch, Field, Row, TypedExpr, Value};

pub(crate) struct Rows {
    pub data: Vec<Row>,
    reservation: Reservation,
    pub bytes: usize,
}
impl Rows {
    pub fn new(budget: &Budget) -> Result<Self> {
        Ok(Self {
            data: Vec::new(),
            reservation: budget.reserve(0)?,
            bytes: 0,
        })
    }
    pub fn push_with(&mut self, bytes: usize, make: impl FnOnce() -> Result<Row>) -> Result<()> {
        self.reservation.grow(bytes)?;
        self.bytes = self.bytes.checked_add(bytes).ok_or(E::Budget)?;
        self.data.try_reserve_exact(1).map_err(|_| E::Budget)?;
        self.data.push(make()?);
        Ok(())
    }
    pub fn push_batch(&mut self, batch: &Batch, row: usize) -> Result<()> {
        let bytes = batch.row_bytes(row)?;
        self.push_with(bytes, || batch.row(row))
    }
    pub fn frame(self, fields: &[Field], budget: &Budget) -> Result<Frame> {
        let bytes = self
            .bytes
            .checked_mul(2)
            .and_then(|x| x.checked_add(fields.len() * 128 + 256))
            .ok_or(E::Budget)?;
        let reservation = budget.reserve(bytes)?;
        let batch = Batch::from_rows(fields.to_vec(), &self.data)?;
        Ok(Frame {
            batch,
            _reservation: reservation,
        })
    }
    pub fn reorder(&mut self, order: &[usize], budget: &Budget) -> Result<()> {
        if order.len() != self.data.len() {
            return Err(E::Plan.into());
        }
        let _temporary = budget.reserve(order.len().checked_mul(64).ok_or(E::Budget)?)?;
        let old = std::mem::take(&mut self.data);
        let mut slots: Vec<Option<Row>> = old.into_iter().map(Some).collect();
        let mut out = Vec::new();
        out.try_reserve_exact(order.len()).map_err(|_| E::Budget)?;
        for i in order {
            out.push(slots.get_mut(*i).and_then(Option::take).ok_or(E::Plan)?);
        }
        self.data = out;
        Ok(())
    }
}
pub(crate) struct Frame {
    pub batch: Batch,
    _reservation: Reservation,
}
pub(crate) fn row_bytes(row: &[Value]) -> Result<usize> {
    row.iter().try_fold(std::mem::size_of::<Row>(), |size, v| {
        size.checked_add(v.logical_bytes()).ok_or(E::Budget.into())
    })
}
pub(crate) fn expr_bytes(expr: &TypedExpr, row: &[Value]) -> Result<usize> {
    match &expr.kind {
        crate::types::ExprKind::Column(i) => Ok(row.get(*i).ok_or(E::Plan)?.logical_bytes()),
        crate::types::ExprKind::Literal(v) => Ok(v.logical_bytes()),
        _ => Ok(std::mem::size_of::<Value>()),
    }
}
pub(crate) enum Stream<'a> {
    Empty,
    Scan {
        node: &'a Node,
        catalog: &'a Catalog,
        context: &'a Context,
        cursor: usize,
        started: bool,
    },
    Filter {
        node: &'a Node,
        input: Box<Stream<'a>>,
        predicate: &'a TypedExpr,
    },
    Project {
        node: &'a Node,
        input: Box<Stream<'a>>,
        columns: &'a Projection,
    },
    Limit {
        node: &'a Node,
        input: Box<Stream<'a>>,
        remaining: usize,
    },
    Materialized {
        node: &'a Node,
        rows: Rows,
        cursor: usize,
    },
    Join(Box<HashJoin<'a>>),
}
impl<'a> Stream<'a> {
    pub fn build(
        node: &'a Node,
        catalog: &'a Catalog,
        context: &'a Context,
        budget: &mut Budget,
    ) -> Result<Self> {
        budget.checkpoint()?;
        Ok(match &node.kind {
            NodeKind::PolicyScan { .. } => Self::Scan {
                node,
                catalog,
                context,
                cursor: 0,
                started: false,
            },
            NodeKind::Filter { input, predicate } => Self::Filter {
                node,
                input: Box::new(Self::build(input, catalog, context, budget)?),
                predicate,
            },
            NodeKind::Project { input, columns } => Self::Project {
                node,
                input: Box::new(Self::build(input, catalog, context, budget)?),
                columns,
            },
            NodeKind::Limit { input, count } => {
                if *count == 0 {
                    Self::Empty
                } else {
                    Self::Limit {
                        node,
                        input: Box::new(Self::build(input, catalog, context, budget)?),
                        remaining: *count,
                    }
                }
            }
            NodeKind::Join { left, right, on } => Self::Join(Box::new(HashJoin::build(
                node, left, right, on, catalog, context, budget,
            )?)),
            NodeKind::Aggregate {
                input,
                keys,
                aggregates,
            } => {
                let mut input = Self::build(input, catalog, context, budget)?;
                let rows = blocking::aggregate(&mut input, keys, aggregates, budget)?;
                Self::Materialized {
                    node,
                    rows,
                    cursor: 0,
                }
            }
            NodeKind::Sort { input, keys } => {
                let mut input = Self::build(input, catalog, context, budget)?;
                let rows = blocking::sort(&mut input, keys, budget)?;
                Self::Materialized {
                    node,
                    rows,
                    cursor: 0,
                }
            }
        })
    }
    pub fn next(&mut self, budget: &mut Budget) -> Result<Option<Frame>> {
        budget.checkpoint()?;
        match self {
            Self::Empty => Ok(None),
            Self::Scan {
                node,
                catalog,
                context,
                cursor,
                started,
            } => {
                if !*started {
                    budget.start_scan()?;
                    *started = true;
                }
                let NodeKind::PolicyScan {
                    table,
                    columns,
                    grant,
                    ..
                } = &node.kind
                else {
                    return Err(E::Plan.into());
                };
                let data = &catalog.tables.get(*table).ok_or(E::Plan)?.data;
                let fields: Vec<_> = node.schema.iter().map(|f| f.field.clone()).collect();
                let mut out = Rows::new(budget)?;
                while *cursor < data.len() && out.data.len() < budget.limits().batch_rows {
                    budget.charge_hidden(1)?;
                    let row = *cursor;
                    *cursor += 1;
                    if data.text_matches(row, grant.tenant_column, &context.tenant)? {
                        budget.charge(columns.len() as u64)?;
                        out.push_with(data.selected_bytes(row, columns)?, || {
                            columns.iter().map(|col| data.cell(row, *col)).collect()
                        })?;
                    }
                }
                if out.data.is_empty() {
                    return Ok(None);
                }
                Ok(Some(out.frame(&fields, budget)?))
            }
            Self::Filter {
                node,
                input,
                predicate,
            } => {
                let fields: Vec<_> = node.schema.iter().map(|f| f.field.clone()).collect();
                loop {
                    let Some(frame) = input.next(budget)? else {
                        return Ok(None);
                    };
                    let mut out = Rows::new(budget)?;
                    for i in 0..frame.batch.len() {
                        budget.charge(predicate.cost())?;
                        let _temporary = budget
                            .reserve(frame.batch.row_bytes(i)? + std::mem::size_of::<Value>())?;
                        let row = frame.batch.row(i)?;
                        if predicate.eval(&row)?.boolean()? == Some(true) {
                            out.push_with(row_bytes(&row)?, || Ok(row.clone()))?;
                        }
                    }
                    if !out.data.is_empty() {
                        return Ok(Some(out.frame(&fields, budget)?));
                    }
                }
            }
            Self::Project {
                node,
                input,
                columns,
            } => {
                let Some(frame) = input.next(budget)? else {
                    return Ok(None);
                };
                let mut out = Rows::new(budget)?;
                for i in 0..frame.batch.len() {
                    let _temporary = budget.reserve(frame.batch.row_bytes(i)?)?;
                    let row = frame.batch.row(i)?;
                    let bytes = columns.iter().try_fold(
                        std::mem::size_of::<Row>(),
                        |sum, (_, e)| -> Result<usize> {
                            sum.checked_add(expr_bytes(e, &row)?)
                                .ok_or(E::Budget.into())
                        },
                    )?;
                    let cost = columns.iter().map(|(_, e)| e.cost()).sum();
                    budget.charge(cost)?;
                    out.push_with(bytes, || {
                        columns.iter().map(|(_, expr)| expr.eval(&row)).collect()
                    })?;
                }
                let fields: Vec<_> = node.schema.iter().map(|f| f.field.clone()).collect();
                Ok(Some(out.frame(&fields, budget)?))
            }
            Self::Limit {
                node,
                input,
                remaining,
            } => {
                if *remaining == 0 {
                    return Ok(None);
                }
                let Some(frame) = input.next(budget)? else {
                    return Ok(None);
                };
                let count = (*remaining).min(frame.batch.len());
                *remaining -= count;
                if count == frame.batch.len() {
                    return Ok(Some(frame));
                }
                let mut out = Rows::new(budget)?;
                for i in 0..count {
                    budget.charge(1)?;
                    out.push_batch(&frame.batch, i)?;
                }
                let fields: Vec<_> = node.schema.iter().map(|f| f.field.clone()).collect();
                Ok(Some(out.frame(&fields, budget)?))
            }
            Self::Materialized { node, rows, cursor } => {
                if *cursor >= rows.data.len() {
                    return Ok(None);
                }
                let end = cursor
                    .saturating_add(budget.limits().batch_rows)
                    .min(rows.data.len());
                let mut out = Rows::new(budget)?;
                for row in rows.data.get(*cursor..end).ok_or(E::Plan)? {
                    budget.charge(row.len() as u64)?;
                    out.push_with(row_bytes(row)?, || Ok(row.clone()))?;
                }
                *cursor = end;
                let fields: Vec<_> = node.schema.iter().map(|f| f.field.clone()).collect();
                Ok(Some(out.frame(&fields, budget)?))
            }
            Self::Join(join) => join.next(budget),
        }
    }
}
