//! Duplicate-preserving hash join, nullable aggregation, and fallible stable sort.
use super::stream::{Frame, Rows, Stream, expr_bytes, expr_temporary_bytes, row_bytes};
use crate::budget::{Budget, Reservation};
use crate::catalog::{Catalog, Context};
use crate::error::{ErrorCode as E, Result};
use crate::plan::{Aggregate, BoundField, Node, OrderKey, Projection};
use crate::types::{DataType, Value};
use std::cmp::Ordering;
use std::collections::HashMap;

fn collect(input: &mut Stream<'_>, budget: &mut Budget) -> Result<Rows> {
    let mut rows = Rows::new(budget)?;
    while let Some(frame) = input.next(budget)? {
        for i in 0..frame.batch.len() {
            budget.charge(1)?;
            rows.push_batch(&frame.batch, i)?;
        }
    }
    Ok(rows)
}
pub(crate) struct HashJoin<'a> {
    node: &'a Node,
    left: Stream<'a>,
    right: Rows,
    on: &'a [(usize, usize)],
    hash: HashMap<Vec<Value>, Vec<usize>>,
    _hash_reservation: Reservation,
    frame: Option<Frame>,
    left_row: usize,
    match_row: usize,
}
impl<'a> HashJoin<'a> {
    pub fn build(
        node: &'a Node,
        left: &'a Node,
        right: &'a Node,
        on: &'a [(usize, usize)],
        catalog: &'a Catalog,
        context: &'a Context,
        budget: &mut Budget,
    ) -> Result<Self> {
        let mut right_stream = Stream::build(right, catalog, context, budget)?;
        let right = collect(&mut right_stream, budget)?;
        let mut hash: HashMap<Vec<Value>, Vec<usize>> = HashMap::new();
        let mut reservation = budget.reserve(0)?;
        for (i, row) in right.data.iter().enumerate() {
            budget.charge(on.len() as u64 + 1)?;
            let key_bytes = on.iter().try_fold(64usize, |sum, (_, col)| {
                sum.checked_add(row.get(*col).ok_or(E::Plan)?.logical_bytes())
                    .ok_or(E::Budget)
            })?;
            let _temporary = budget.reserve(key_bytes)?;
            let key: Vec<_> = on
                .iter()
                .map(|(_, col)| row.get(*col).cloned().ok_or(E::Plan.into()))
                .collect::<Result<_>>()?;
            if key.iter().any(Value::is_null) {
                continue;
            }
            if let Some(indices) = hash.get_mut(&key) {
                reservation.grow(8)?;
                indices.try_reserve_exact(1).map_err(|_| E::Budget)?;
                indices.push(i);
            } else {
                reservation.grow(key_bytes + 128)?;
                hash.try_reserve(1).map_err(|_| E::Budget)?;
                hash.insert(key, vec![i]);
            }
        }
        Ok(Self {
            node,
            left: Stream::build(left, catalog, context, budget)?,
            right,
            on,
            hash,
            _hash_reservation: reservation,
            frame: None,
            left_row: 0,
            match_row: 0,
        })
    }
    pub fn next(&mut self, budget: &mut Budget) -> Result<Option<Frame>> {
        let mut out = Rows::new(budget)?;
        while out.data.len() < budget.limits().batch_rows {
            if self
                .frame
                .as_ref()
                .is_none_or(|f| self.left_row >= f.batch.len())
            {
                self.frame = self.left.next(budget)?;
                self.left_row = 0;
                self.match_row = 0;
                if self.frame.is_none() {
                    break;
                }
            }
            let frame = self.frame.as_ref().ok_or(E::Plan)?;
            let _temporary = budget.reserve(frame.batch.row_bytes(self.left_row)?)?;
            let left = frame.batch.row(self.left_row)?;
            budget.charge(self.on.len() as u64 + 1)?;
            // A bound key may repeat a column. Account for each owned copy,
            // independently of the complete row's width, before cloning it.
            let key_bytes = self.on.iter().try_fold(64usize, |sum, (col, _)| {
                sum.checked_add(left.get(*col).ok_or(E::Plan)?.logical_bytes())
                    .ok_or(E::Budget)
            })?;
            let _key_temporary = budget.reserve(key_bytes)?;
            let key: Vec<_> = self
                .on
                .iter()
                .map(|(col, _)| left.get(*col).cloned().ok_or(E::Plan.into()))
                .collect::<Result<_>>()?;
            let matches = if key.iter().any(Value::is_null) {
                None
            } else {
                self.hash.get(&key)
            };
            if let Some(indices) = matches
                && let Some(index) = indices.get(self.match_row)
            {
                budget.observe("join_inner")?;
                budget.charge(1)?;
                let right = self.right.data.get(*index).ok_or(E::Plan)?;
                let bytes = row_bytes(&left)?
                    .checked_add(row_bytes(right)?)
                    .ok_or(E::Budget)?;
                out.push_with(bytes, || {
                    let mut row = left.clone();
                    row.try_reserve_exact(right.len()).map_err(|_| E::Budget)?;
                    row.extend(right.iter().cloned());
                    Ok(row)
                })?;
                self.match_row += 1;
            } else {
                self.left_row += 1;
                self.match_row = 0;
            }
        }
        if out.data.is_empty() {
            return Ok(None);
        }
        let fields: Vec<_> = self.node.schema.iter().map(|f| f.field.clone()).collect();
        Ok(Some(out.frame(&fields, budget)?))
    }
}

pub(crate) fn aggregate(
    input: &mut Stream<'_>,
    keys: &Projection,
    aggregates: &[(BoundField, Aggregate)],
    budget: &mut Budget,
) -> Result<Rows> {
    let mut index: HashMap<Vec<Value>, usize> = HashMap::new();
    let mut groups: Vec<(Vec<Value>, Vec<Value>)> = Vec::new();
    let mut reservation = budget.reserve(0)?;
    let initial = || {
        aggregates
            .iter()
            .map(|(_, agg)| match agg {
                Aggregate::Sum(_) => Value::Null(DataType::I64),
                _ => Value::I64(0),
            })
            .collect::<Vec<_>>()
    };
    if keys.is_empty() {
        reservation.grow(128 + aggregates.len() * std::mem::size_of::<Value>())?;
        groups.push((vec![], initial()));
        index.insert(vec![], 0);
    }
    while let Some(frame) = input.next(budget)? {
        for i in 0..frame.batch.len() {
            let _row_reservation = budget.reserve(frame.batch.row_bytes(i)?)?;
            let row = frame.batch.row(i)?;
            let key_bytes = keys
                .iter()
                .try_fold(24usize, |sum, (_, e)| -> Result<usize> {
                    sum.checked_add(expr_bytes(e, &row)?)
                        .ok_or(E::Budget.into())
                })?;
            let aggregate_bytes = aggregates
                .iter()
                .map(|(_, a)| match a {
                    Aggregate::CountAll => Ok(0),
                    Aggregate::Count(e) | Aggregate::Sum(e) => expr_temporary_bytes(e, &row),
                })
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .max()
                .unwrap_or(0);
            let key_temporary_bytes = keys
                .iter()
                .try_fold(0usize, |peak, (_, e)| -> Result<usize> {
                    Ok(peak.max(expr_temporary_bytes(e, &row)?))
                })?;
            let _temporary = budget.reserve(
                key_bytes
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(aggregate_bytes.max(key_temporary_bytes) + 256))
                    .ok_or(E::Budget)?,
            )?;
            let cost = keys.iter().map(|(_, e)| e.cost()).sum::<u64>();
            budget.charge(cost + 1)?;
            let key: Vec<_> = keys
                .iter()
                .map(|(_, expr)| expr.eval(&row))
                .collect::<Result<_>>()?;
            let group = if let Some(group) = index.get(&key) {
                *group
            } else {
                let bytes = row_bytes(&key)?
                    .checked_mul(2)
                    .and_then(|x| {
                        x.checked_add(192 + aggregates.len() * std::mem::size_of::<Value>())
                    })
                    .ok_or(E::Budget)?;
                reservation.grow(bytes)?;
                index.try_reserve(1).map_err(|_| E::Budget)?;
                groups.try_reserve_exact(1).map_err(|_| E::Budget)?;
                let group = groups.len();
                index.insert(key.clone(), group);
                groups.push((key, initial()));
                group
            };
            let values = &mut groups.get_mut(group).ok_or(E::Plan)?.1;
            for (j, (_, agg)) in aggregates.iter().enumerate() {
                let state = values.get_mut(j).ok_or(E::Plan)?;
                let value = match agg {
                    Aggregate::CountAll => {
                        budget.charge(1)?;
                        Some(1)
                    }
                    Aggregate::Count(expr) => {
                        budget.charge(expr.cost())?;
                        if expr.eval(&row)?.is_null() {
                            None
                        } else {
                            Some(1)
                        }
                    }
                    Aggregate::Sum(expr) => {
                        budget.charge(expr.cost())?;
                        match expr.eval(&row)? {
                            Value::I64(n) => Some(n),
                            Value::Null(DataType::I64) => None,
                            _ => return Err(E::Plan.into()),
                        }
                    }
                };
                if let Some(n) = value {
                    let total = match state {
                        Value::I64(v) => *v,
                        Value::Null(DataType::I64) => 0,
                        _ => return Err(E::Plan.into()),
                    };
                    *state = Value::I64(total.checked_add(n).ok_or(E::Overflow)?);
                }
            }
        }
    }
    let mut output = Rows::new(budget)?;
    for (key, values) in &groups {
        budget.charge((key.len() + values.len()) as u64)?;
        let bytes = row_bytes(key)?
            .checked_add(row_bytes(values)?)
            .ok_or(E::Budget)?;
        output.push_with(bytes, || Ok(key.iter().chain(values).cloned().collect()))?;
    }
    Ok(output)
}

fn compare(a: &[Value], b: &[Value], keys: &[OrderKey]) -> Result<Ordering> {
    for (i, key) in keys.iter().enumerate() {
        let a = a.get(i).ok_or(E::Plan)?;
        let b = b.get(i).ok_or(E::Plan)?;
        let order = match (a.is_null(), b.is_null()) {
            (true, true) => Ordering::Equal,
            (true, false) => {
                if key.nulls_first {
                    Ordering::Less
                } else {
                    Ordering::Greater
                }
            }
            (false, true) => {
                if key.nulls_first {
                    Ordering::Greater
                } else {
                    Ordering::Less
                }
            }
            (false, false) => {
                let order = a.compare(b)?;
                if key.descending {
                    order.reverse()
                } else {
                    order
                }
            }
        };
        if !order.is_eq() {
            return Ok(order);
        }
    }
    Ok(Ordering::Equal)
}
pub(crate) fn sort(input: &mut Stream<'_>, keys: &[OrderKey], budget: &mut Budget) -> Result<Rows> {
    let mut rows = collect(input, budget)?;
    let mut values: Vec<Vec<Value>> = Vec::new();
    let mut reservation = budget.reserve(rows.data.len().checked_mul(40).ok_or(E::Budget)?)?;
    for row in &rows.data {
        let expression_bytes = keys.iter().try_fold(0usize, |peak, key| -> Result<usize> {
            Ok(peak.max(expr_temporary_bytes(&key.expr, row)?))
        })?;
        let _expression = budget.reserve(expression_bytes)?;
        let bytes = keys.iter().try_fold(24usize, |sum, key| -> Result<usize> {
            sum.checked_add(expr_bytes(&key.expr, row)?)
                .ok_or(E::Budget.into())
        })?;
        reservation.grow(bytes)?;
        budget.charge(keys.iter().map(|k| k.expr.cost()).sum())?;
        values.try_reserve_exact(1).map_err(|_| E::Budget)?;
        values.push(
            keys.iter()
                .map(|key| key.expr.eval(row))
                .collect::<Result<_>>()?,
        );
    }
    let len = rows.data.len();
    let mut order: Vec<_> = (0..len).collect();
    let mut scratch = vec![0usize; len];
    let mut width = 1usize;
    while width < len {
        let mut start = 0usize;
        while start < len {
            let mid = start.saturating_add(width).min(len);
            let end = mid.saturating_add(width).min(len);
            let (mut a, mut b, mut dest) = (start, mid, start);
            while a < mid || b < end {
                budget.charge(1)?;
                let take_left = if b == end {
                    true
                } else if a == mid {
                    false
                } else {
                    compare(
                        values.get(*order.get(a).ok_or(E::Plan)?).ok_or(E::Plan)?,
                        values.get(*order.get(b).ok_or(E::Plan)?).ok_or(E::Plan)?,
                        keys,
                    )? != Ordering::Greater
                };
                *scratch.get_mut(dest).ok_or(E::Plan)? = if take_left {
                    let i = *order.get(a).ok_or(E::Plan)?;
                    a += 1;
                    i
                } else {
                    let i = *order.get(b).ok_or(E::Plan)?;
                    b += 1;
                    i
                };
                dest += 1;
            }
            start = end;
        }
        std::mem::swap(&mut order, &mut scratch);
        width = width.checked_mul(2).ok_or(E::Budget)?;
    }
    rows.reorder(&order, budget)?;
    Ok(rows)
}
