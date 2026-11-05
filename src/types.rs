//! Exact types, three-valued expressions, and owned columns with validity bitmaps.
use crate::error::{ErrorCode as E, Result};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::cmp::Ordering;

#[path = "catalog_rows.rs"]
mod catalog_rows;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DataType {
    I64,
    Bool,
    Text,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Value {
    Null(DataType),
    I64(i64),
    Bool(bool),
    Text(String),
}
impl Value {
    pub fn data_type(&self) -> DataType {
        match self {
            Self::Null(t) => *t,
            Self::I64(_) => DataType::I64,
            Self::Bool(_) => DataType::Bool,
            Self::Text(_) => DataType::Text,
        }
    }
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null(_))
    }
    pub fn logical_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + match self {
                Self::Text(s) => s.len(),
                _ => 0,
            }
    }
    pub fn json(&self) -> serde_json::Value {
        match self {
            Self::Null(_) => serde_json::Value::Null,
            Self::I64(n) => (*n).into(),
            Self::Bool(b) => (*b).into(),
            Self::Text(s) => s.clone().into(),
        }
    }
    pub fn boolean(&self) -> Result<Option<bool>> {
        match self {
            Self::Bool(b) => Ok(Some(*b)),
            Self::Null(DataType::Bool) => Ok(None),
            _ => Err(E::Type.into()),
        }
    }
    pub fn from_json(value: &serde_json::Value, dtype: DataType, nullable: bool) -> Result<Self> {
        match (value, dtype) {
            (serde_json::Value::Null, _) if nullable => Ok(Self::Null(dtype)),
            (serde_json::Value::Bool(b), DataType::Bool) => Ok(Self::Bool(*b)),
            (serde_json::Value::Number(n), DataType::I64) => {
                n.as_i64().map(Self::I64).ok_or(E::Type.into())
            }
            (serde_json::Value::String(s), DataType::Text) if s.len() <= 4096 => {
                Ok(Self::Text(s.clone()))
            }
            _ => Err(E::Type.into()),
        }
    }
    pub fn compare(&self, other: &Self) -> Result<Ordering> {
        match (self, other) {
            (Self::I64(a), Self::I64(b)) => Ok(a.cmp(b)),
            (Self::Bool(a), Self::Bool(b)) => Ok(a.cmp(b)),
            (Self::Text(a), Self::Text(b)) => Ok(a.as_bytes().cmp(b.as_bytes())),
            _ => Err(E::Type.into()),
        }
    }
}
pub type Row = Vec<Value>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub name: String,
    #[serde(rename = "type")]
    pub data_type: DataType,
    pub nullable: bool,
}

pub fn identifier(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnaryOp {
    Not,
    IsNull,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BinaryOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    Add,
    Sub,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ExprKind {
    Column(usize),
    Literal(Value),
    Unary(UnaryOp, Box<TypedExpr>),
    Binary(BinaryOp, Box<TypedExpr>, Box<TypedExpr>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TypedExpr {
    pub kind: ExprKind,
    pub data_type: DataType,
    pub nullable: bool,
}
pub(crate) fn unary_type(op: UnaryOp, input: (DataType, bool)) -> Result<(DataType, bool)> {
    match op {
        UnaryOp::IsNull => Ok((DataType::Bool, false)),
        UnaryOp::Not if input.0 == DataType::Bool => Ok(input),
        _ => Err(E::Type.into()),
    }
}
pub(crate) fn binary_type(
    op: BinaryOp,
    a: (DataType, bool),
    b: (DataType, bool),
) -> Result<(DataType, bool)> {
    if a.0 != b.0 {
        return Err(E::Type.into());
    }
    let nullable = a.1 || b.1;
    match op {
        BinaryOp::Add | BinaryOp::Sub if a.0 == DataType::I64 => Ok((DataType::I64, nullable)),
        BinaryOp::And | BinaryOp::Or if a.0 == DataType::Bool => Ok((DataType::Bool, nullable)),
        BinaryOp::Eq | BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
            Ok((DataType::Bool, nullable))
        }
        _ => Err(E::Type.into()),
    }
}
impl TypedExpr {
    pub fn cost(&self) -> u64 {
        match &self.kind {
            ExprKind::Column(_) | ExprKind::Literal(_) => 1,
            ExprKind::Unary(_, a) => 1 + a.cost(),
            ExprKind::Binary(_, a, b) => 1 + a.cost() + b.cost(),
        }
    }
    pub fn total(&self) -> bool {
        match &self.kind {
            ExprKind::Binary(BinaryOp::Add | BinaryOp::Sub, _, _) => false,
            ExprKind::Unary(_, a) => a.total(),
            ExprKind::Binary(_, a, b) => a.total() && b.total(),
            _ => true,
        }
    }
    pub fn eval(&self, row: &[Value]) -> Result<Value> {
        match &self.kind {
            ExprKind::Column(i) => row.get(*i).cloned().ok_or(E::Plan.into()),
            ExprKind::Literal(v) => Ok(v.clone()),
            ExprKind::Unary(op, a) => {
                let value = a.eval(row)?;
                match op {
                    UnaryOp::IsNull => Ok(Value::Bool(value.is_null())),
                    UnaryOp::Not => Ok(value
                        .boolean()?
                        .map_or(Value::Null(DataType::Bool), |b| Value::Bool(!b))),
                }
            }
            ExprKind::Binary(op, a, b) => {
                let left = a.eval(row)?;
                let right = b.eval(row)?;
                if matches!(op, BinaryOp::And | BinaryOp::Or) {
                    let (a, b) = (left.boolean()?, right.boolean()?);
                    let value = match op {
                        BinaryOp::And => sql_and(a, b),
                        _ => sql_or(a, b),
                    };
                    return Ok(value.map_or(Value::Null(DataType::Bool), Value::Bool));
                }
                if left.is_null() || right.is_null() {
                    return Ok(Value::Null(self.data_type));
                }
                if matches!(op, BinaryOp::Add | BinaryOp::Sub) {
                    if let (Value::I64(a), Value::I64(b)) = (left, right) {
                        return match op {
                            BinaryOp::Add => a.checked_add(b),
                            _ => a.checked_sub(b),
                        }
                        .map(Value::I64)
                        .ok_or(E::Overflow.into());
                    }
                    return Err(E::Type.into());
                }
                let order = left.compare(&right)?;
                let value = match op {
                    BinaryOp::Eq => order.is_eq(),
                    BinaryOp::Ne => !order.is_eq(),
                    BinaryOp::Lt => order.is_lt(),
                    BinaryOp::Le => !order.is_gt(),
                    BinaryOp::Gt => order.is_gt(),
                    BinaryOp::Ge => !order.is_lt(),
                    _ => return Err(E::Plan.into()),
                };
                Ok(Value::Bool(value))
            }
        }
    }
}
pub fn sql_and(a: Option<bool>, b: Option<bool>) -> Option<bool> {
    match (a, b) {
        (Some(false), _) | (_, Some(false)) => Some(false),
        (Some(true), Some(true)) => Some(true),
        _ => None,
    }
}
pub fn sql_or(a: Option<bool>, b: Option<bool>) -> Option<bool> {
    match (a, b) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (Some(false), Some(false)) => Some(false),
        _ => None,
    }
}

#[derive(Clone, Debug)]
struct Validity {
    bits: Vec<u64>,
    len: usize,
}
impl Validity {
    fn new(len: usize) -> Result<Self> {
        let mut bits = Vec::new();
        bits.try_reserve_exact(len.div_ceil(64))
            .map_err(|_| E::Budget)?;
        bits.resize(len.div_ceil(64), 0);
        Ok(Self { bits, len })
    }
    fn set(&mut self, i: usize) -> Result<()> {
        if i >= self.len {
            return Err(E::Plan.into());
        }
        let slot = self.bits.get_mut(i / 64).ok_or(E::Plan)?;
        *slot |= 1u64 << (i % 64);
        Ok(())
    }
    fn valid(&self, i: usize) -> Result<bool> {
        if i >= self.len {
            return Err(E::Plan.into());
        }
        Ok(self.bits.get(i / 64).ok_or(E::Plan)? & (1u64 << (i % 64)) != 0)
    }
}
#[derive(Clone, Debug)]
enum ColumnData {
    I64(Vec<i64>),
    Bool(Vec<bool>),
    Text { offsets: Vec<usize>, bytes: Vec<u8> },
}
#[derive(Clone, Debug)]
pub struct Column {
    data: ColumnData,
    validity: Validity,
    data_type: DataType,
}
impl Column {
    pub fn from_values(dtype: DataType, values: &[Value]) -> Result<Self> {
        Self::from_values_checked(dtype, values, &mut || Ok(()))
    }
    fn from_values_checked(
        dtype: DataType,
        values: &[Value],
        checkpoint: &mut impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        Self::from_value_iter_checked(
            dtype,
            values.iter().map(|value| Ok(Cow::Borrowed(value))),
            checkpoint,
        )
    }
    fn from_value_iter_checked<'a>(
        dtype: DataType,
        values: impl ExactSizeIterator<Item = Result<Cow<'a, Value>>>,
        checkpoint: &mut impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        let len = values.len();
        let mut validity = Validity::new(len)?;
        let mut ints = Vec::new();
        let mut bools = Vec::new();
        let mut offsets = Vec::new();
        let mut bytes = Vec::new();
        match dtype {
            DataType::I64 => ints.try_reserve_exact(len),
            DataType::Bool => bools.try_reserve_exact(len),
            DataType::Text => offsets.try_reserve_exact(len + 1),
        }
        .map_err(|_| E::Budget)?;
        if dtype == DataType::Text {
            offsets.push(0);
        }
        for (i, value) in values.enumerate() {
            checkpoint()?;
            let value = value?;
            let value = value.as_ref();
            if value.data_type() != dtype {
                return Err(E::Type.into());
            }
            if !value.is_null() {
                validity.set(i)?;
            }
            match (dtype, value) {
                (DataType::I64, Value::I64(n)) => ints.push(*n),
                (DataType::I64, _) => ints.push(0),
                (DataType::Bool, Value::Bool(b)) => bools.push(*b),
                (DataType::Bool, _) => bools.push(false),
                (DataType::Text, _) => {
                    if let Value::Text(s) = value {
                        if s.len() > 4096 {
                            return Err(E::Limit.into());
                        }
                        bytes.try_reserve(s.len()).map_err(|_| E::Budget)?;
                        bytes.extend_from_slice(s.as_bytes());
                    }
                    offsets.push(bytes.len());
                }
            }
        }
        let data = match dtype {
            DataType::I64 => ColumnData::I64(ints),
            DataType::Bool => ColumnData::Bool(bools),
            DataType::Text => ColumnData::Text { offsets, bytes },
        };
        Ok(Self {
            data,
            validity,
            data_type: dtype,
        })
    }
    pub fn len(&self) -> usize {
        self.validity.len
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn cell(&self, i: usize) -> Result<Value> {
        if !self.validity.valid(i)? {
            return Ok(Value::Null(self.data_type));
        }
        match &self.data {
            ColumnData::I64(v) => v.get(i).copied().map(Value::I64).ok_or(E::Plan.into()),
            ColumnData::Bool(v) => v.get(i).copied().map(Value::Bool).ok_or(E::Plan.into()),
            ColumnData::Text { offsets, bytes } => {
                let start = *offsets.get(i).ok_or(E::Plan)?;
                let end = *offsets.get(i + 1).ok_or(E::Plan)?;
                let text = std::str::from_utf8(bytes.get(start..end).ok_or(E::Plan)?)
                    .map_err(|_| E::Plan)?;
                Ok(Value::Text(text.to_owned()))
            }
        }
    }
    pub(crate) fn value_bytes(&self, i: usize) -> Result<usize> {
        self.validity.valid(i)?;
        match &self.data {
            ColumnData::Text { offsets, .. } => {
                let start = *offsets.get(i).ok_or(E::Plan)?;
                let end = *offsets.get(i + 1).ok_or(E::Plan)?;
                Ok(std::mem::size_of::<Value>() + end.checked_sub(start).ok_or(E::Plan)?)
            }
            _ => Ok(std::mem::size_of::<Value>()),
        }
    }
    pub(crate) fn text_matches(&self, i: usize, text: &str) -> Result<bool> {
        if !self.validity.valid(i)? {
            return Ok(false);
        }
        match &self.data {
            ColumnData::Text { offsets, bytes } => {
                let start = *offsets.get(i).ok_or(E::Plan)?;
                let end = *offsets.get(i + 1).ok_or(E::Plan)?;
                Ok(bytes.get(start..end).ok_or(E::Plan)? == text.as_bytes())
            }
            _ => Err(E::Plan.into()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Batch {
    fields: Vec<Field>,
    columns: Vec<Column>,
    len: usize,
}
impl Batch {
    pub fn from_rows(fields: Vec<Field>, rows: &[Row]) -> Result<Self> {
        Self::from_rows_checked(fields, rows, &mut || Ok(()))
    }
    pub(crate) fn from_rows_checked(
        fields: Vec<Field>,
        rows: &[Row],
        checkpoint: &mut impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        // Internal joins/group lowering can carry four bounded scan schemas.
        // The binder and verifier separately enforce the public 64-column result cap.
        if fields.len() > 256 {
            return Err(E::Plan.into());
        }
        for row in rows {
            checkpoint()?;
            if row.len() != fields.len() {
                return Err(E::Plan.into());
            }
        }
        let mut columns = Vec::new();
        columns
            .try_reserve_exact(fields.len())
            .map_err(|_| E::Budget)?;
        for (i, field) in fields.iter().enumerate() {
            checkpoint()?;
            for row in rows {
                checkpoint()?;
                let value = row.get(i).ok_or(E::Plan)?;
                if !field.nullable && value.is_null() {
                    return Err(E::Type.into());
                }
            }
            columns.push(Column::from_value_iter_checked(
                field.data_type,
                rows.iter()
                    .map(|row| row.get(i).map(Cow::Borrowed).ok_or_else(|| E::Plan.into())),
                checkpoint,
            )?);
        }
        Ok(Self {
            fields,
            columns,
            len: rows.len(),
        })
    }
    // Materialized-row comparison oracle retained with the original tests.
    #[cfg(test)]
    pub(crate) fn from_json_rows(
        fields: Vec<Field>,
        rows: &[Vec<serde_json::Value>],
    ) -> Result<Self> {
        if fields.len() > 256 || rows.iter().any(|row| row.len() != fields.len()) {
            return Err(E::Plan.into());
        }
        let mut columns = Vec::new();
        columns
            .try_reserve_exact(fields.len())
            .map_err(|_| E::Budget)?;
        for (i, field) in fields.iter().enumerate() {
            let values = rows.iter().map(|row| {
                let value = row.get(i).ok_or(E::Plan)?;
                Value::from_json(value, field.data_type, field.nullable).map(Cow::Owned)
            });
            columns.push(Column::from_value_iter_checked(
                field.data_type,
                values,
                &mut || Ok(()),
            )?);
        }
        Ok(Self {
            fields,
            columns,
            len: rows.len(),
        })
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn fields(&self) -> &[Field] {
        &self.fields
    }
    pub fn cell(&self, row: usize, col: usize) -> Result<Value> {
        self.columns.get(col).ok_or(E::Plan)?.cell(row)
    }
    pub fn row(&self, i: usize) -> Result<Row> {
        if i >= self.len {
            return Err(E::Plan.into());
        }
        self.columns.iter().map(|c| c.cell(i)).collect()
    }
    pub(crate) fn row_bytes(&self, i: usize) -> Result<usize> {
        if i >= self.len {
            return Err(E::Plan.into());
        }
        self.columns.iter().try_fold(24usize, |total, c| {
            total.checked_add(c.value_bytes(i)?).ok_or(E::Budget.into())
        })
    }
    pub(crate) fn selected_bytes(&self, i: usize, indices: &[usize]) -> Result<usize> {
        indices.iter().try_fold(24usize, |total, col| {
            total
                .checked_add(self.columns.get(*col).ok_or(E::Plan)?.value_bytes(i)?)
                .ok_or(E::Budget.into())
        })
    }
    pub(crate) fn text_matches(&self, row: usize, col: usize, text: &str) -> Result<bool> {
        self.columns
            .get(col)
            .ok_or(E::Plan)?
            .text_matches(row, text)
    }
}

impl Serialize for Value {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Null(_) => serializer.serialize_none(),
            Self::I64(n) => serializer.serialize_i64(*n),
            Self::Bool(b) => serializer.serialize_bool(*b),
            Self::Text(s) => serializer.serialize_str(s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_three_valued_truth_table() {
        let v = [Some(false), Some(true), None];
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
        for i in 0..3 {
            for j in 0..3 {
                assert_eq!(sql_and(v[i], v[j]), and[i][j]);
                assert_eq!(sql_or(v[i], v[j]), or[i][j]);
            }
        }
    }
    #[test]
    fn typed_columns_preserve_null_and_utf8() -> Result<()> {
        let input = [
            Value::Text("é".into()),
            Value::Null(DataType::Text),
            Value::Text("".into()),
        ];
        let col = Column::from_values(DataType::Text, &input)?;
        for (i, v) in input.iter().enumerate() {
            assert_eq!(&col.cell(i)?, v);
        }
        assert_eq!(col.cell(3).map_err(|e| e.code), Err(E::Plan));
        Ok(())
    }
    fn ingestion_fields() -> Vec<Field> {
        [
            ("n", DataType::I64),
            ("b", DataType::Bool),
            ("s", DataType::Text),
        ]
        .into_iter()
        .map(|(name, data_type)| Field {
            name: name.into(),
            data_type,
            nullable: true,
        })
        .collect()
    }
    #[test]
    fn json_ingestion_preserves_exact_values_typed_nulls_and_duplicate_rows() -> Result<()> {
        let rows = vec![
            vec![serde_json::json!(i64::MIN), true.into(), "é\0🙂".into()],
            vec![serde_json::Value::Null; 3],
            vec![serde_json::json!(i64::MAX), false.into(), "".into()],
            vec![serde_json::json!(i64::MIN), true.into(), "é\0🙂".into()],
        ];
        let expected = [
            vec![
                Value::I64(i64::MIN),
                Value::Bool(true),
                Value::Text("é\0🙂".into()),
            ],
            vec![
                Value::Null(DataType::I64),
                Value::Null(DataType::Bool),
                Value::Null(DataType::Text),
            ],
            vec![
                Value::I64(i64::MAX),
                Value::Bool(false),
                Value::Text("".into()),
            ],
            vec![
                Value::I64(i64::MIN),
                Value::Bool(true),
                Value::Text("é\0🙂".into()),
            ],
        ];
        let fields = ingestion_fields();
        let batch = Batch::from_json_rows(fields.clone(), &rows)?;
        assert_eq!(batch.fields(), &fields);
        assert_eq!(batch.len(), 4);
        for (i, row) in expected.iter().enumerate() {
            assert_eq!(&batch.row(i)?, row);
        }
        let ordinary = Batch::from_rows(fields, &expected)?;
        for (i, row) in expected.iter().enumerate() {
            assert_eq!(&ordinary.row(i)?, row);
        }
        Ok(())
    }
    #[test]
    fn json_ingestion_rejects_shape_coercions_and_nullable_violation() {
        let field = |data_type, nullable| Field {
            name: "x".into(),
            data_type,
            nullable,
        };
        for (data_type, value) in [
            (DataType::I64, serde_json::json!(true)),
            (DataType::I64, serde_json::json!(1.0)),
            (DataType::I64, serde_json::json!(1u64 << 63)),
            (DataType::Bool, serde_json::json!(1)),
            (DataType::Text, serde_json::json!("x".repeat(4097))),
        ] {
            assert_eq!(
                Batch::from_json_rows(vec![field(data_type, true)], &[vec![value]])
                    .err()
                    .map(|error| error.code),
                Some(E::Type)
            );
        }
        assert_eq!(
            Batch::from_json_rows(
                vec![field(DataType::I64, false)],
                &[vec![serde_json::Value::Null]]
            )
            .err()
            .map(|error| error.code),
            Some(E::Type)
        );
        assert_eq!(
            Batch::from_json_rows(vec![field(DataType::I64, true)], &[vec![]])
                .err()
                .map(|error| error.code),
            Some(E::Plan)
        );
        assert_eq!(
            Batch::from_json_rows(
                vec![field(DataType::I64, true)],
                &[vec![1.into(), 2.into()]]
            )
            .err()
            .map(|error| error.code),
            Some(E::Plan)
        );
        assert_eq!(
            Batch::from_json_rows(vec![field(DataType::I64, true); 257], &[])
                .err()
                .map(|error| error.code),
            Some(E::Plan)
        );
    }
    #[test]
    fn json_ingestion_keeps_empty_schema_columns_and_text_byte_limit() -> Result<()> {
        let fields = ingestion_fields();
        let empty = Batch::from_json_rows(fields.clone(), &[])?;
        assert_eq!(empty.fields(), &fields);
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.cell(0, 0).map_err(|error| error.code), Err(E::Plan));
        let exact = "é".repeat(2048);
        let batch =
            Batch::from_json_rows(fields, &[vec![1.into(), true.into(), exact.clone().into()]])?;
        assert_eq!(batch.cell(0, 2)?, Value::Text(exact));
        Ok(())
    }
    #[test]
    fn arithmetic_overflow_and_typed_null() {
        let lit = |n| TypedExpr {
            kind: ExprKind::Literal(n),
            data_type: DataType::I64,
            nullable: false,
        };
        let expr = TypedExpr {
            kind: ExprKind::Binary(
                BinaryOp::Add,
                Box::new(lit(Value::I64(i64::MAX))),
                Box::new(lit(Value::I64(1))),
            ),
            data_type: DataType::I64,
            nullable: false,
        };
        assert_eq!(expr.eval(&[]).map_err(|e| e.code), Err(E::Overflow));
        assert!(
            binary_type(
                BinaryOp::Eq,
                (DataType::I64, false),
                (DataType::Text, false)
            )
            .is_err()
        );
        assert!(Value::from_json(&true.into(), DataType::I64, false).is_err());
    }
}
