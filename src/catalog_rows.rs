//! Schema-directed catalog ingestion without an intermediate JSON/row tree.
use super::{Batch, Column, ColumnData, DataType, Field, Validity};
use crate::error::{ErrorCode as E, Result};
use serde::Deserializer;
use serde::de::{self, DeserializeSeed, SeqAccess, Visitor};
use serde_json::value::RawValue;
use std::fmt;

enum Scalar<'a> {
    Null,
    I64(i64),
    Bool(bool),
    Text(&'a str),
}

impl Column {
    fn empty_catalog(data_type: DataType) -> Result<Self> {
        let data = match data_type {
            DataType::I64 => ColumnData::I64(Vec::new()),
            DataType::Bool => ColumnData::Bool(Vec::new()),
            DataType::Text => {
                let mut offsets = Vec::new();
                offsets.try_reserve_exact(1).map_err(|_| E::Budget)?;
                offsets.push(0);
                ColumnData::Text {
                    offsets,
                    bytes: Vec::new(),
                }
            }
        };
        Ok(Self {
            data,
            validity: Validity::new(0)?,
            data_type,
        })
    }

    fn push_catalog(&mut self, scalar: Scalar<'_>, nullable: bool) -> Result<()> {
        let valid = !matches!(scalar, Scalar::Null);
        match (&scalar, self.data_type) {
            (Scalar::Null, _) if nullable => {}
            (Scalar::I64(_), DataType::I64) | (Scalar::Bool(_), DataType::Bool) => {}
            (Scalar::Text(text), DataType::Text) if text.len() <= 4096 => {}
            _ => return Err(E::Type.into()),
        }
        // Every growth is fallible. A rejected cell discards the unpublished
        // whole catalog; no partially appended column is exposed to a caller.
        let index = self.validity.len;
        let next = index.checked_add(1).ok_or(E::Budget)?;
        if index.is_multiple_of(64) {
            self.validity.bits.try_reserve(1).map_err(|_| E::Budget)?;
        }
        match &mut self.data {
            ColumnData::I64(values) => {
                values.try_reserve(1).map_err(|_| E::Budget)?;
                values.push(match scalar {
                    Scalar::I64(value) => value,
                    _ => 0,
                });
            }
            ColumnData::Bool(values) => {
                values.try_reserve(1).map_err(|_| E::Budget)?;
                values.push(match scalar {
                    Scalar::Bool(value) => value,
                    _ => false,
                });
            }
            ColumnData::Text { offsets, bytes } => {
                offsets.try_reserve(1).map_err(|_| E::Budget)?;
                if let Scalar::Text(text) = scalar {
                    bytes.try_reserve(text.len()).map_err(|_| E::Budget)?;
                    bytes.extend_from_slice(text.as_bytes());
                }
                offsets.push(bytes.len());
            }
        }
        if index.is_multiple_of(64) {
            self.validity.bits.push(0);
        }
        self.validity.len = next;
        if valid {
            self.validity.set(index)?;
        }
        Ok(())
    }
}

struct Cell<'a> {
    column: &'a mut Column,
    nullable: bool,
}
impl Cell<'_> {
    fn append<X: de::Error>(self, scalar: Scalar<'_>) -> std::result::Result<(), X> {
        self.column
            .push_catalog(scalar, self.nullable)
            .map_err(|_| X::custom("invalid catalog cell"))
    }
}
impl<'de> DeserializeSeed<'de> for Cell<'_> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Cell<'_> {
    type Value = ();
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an exact catalog scalar")
    }
    fn visit_unit<X: de::Error>(self) -> std::result::Result<(), X> {
        self.append(Scalar::Null)
    }
    fn visit_i64<X: de::Error>(self, value: i64) -> std::result::Result<(), X> {
        self.append(Scalar::I64(value))
    }
    fn visit_u64<X: de::Error>(self, value: u64) -> std::result::Result<(), X> {
        let value = i64::try_from(value).map_err(|_| X::custom("catalog integer range"))?;
        self.append(Scalar::I64(value))
    }
    fn visit_bool<X: de::Error>(self, value: bool) -> std::result::Result<(), X> {
        self.append(Scalar::Bool(value))
    }
    fn visit_str<X: de::Error>(self, value: &str) -> std::result::Result<(), X> {
        self.append(Scalar::Text(value))
    }
    fn visit_string<X: de::Error>(self, value: String) -> std::result::Result<(), X> {
        self.append(Scalar::Text(&value))
    }
}

struct Row<'a>(&'a mut Batch);
impl<'de> DeserializeSeed<'de> for Row<'_> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<(), D::Error> {
        if self.0.len >= 1_000_000 {
            return Err(de::Error::custom("catalog row limit"));
        }
        deserializer.deserialize_seq(self)
    }
}
impl<'de> Visitor<'de> for Row<'_> {
    type Value = ();
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("one schema-width catalog row")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<(), A::Error> {
        for (field, column) in self.0.fields.iter().zip(&mut self.0.columns) {
            seq.next_element_seed(Cell {
                column,
                nullable: field.nullable,
            })?
            .ok_or_else(|| de::Error::custom("catalog row width"))?;
        }
        // deserialize_seq also requires the next token to end this row; any
        // additional scalar is rejected rather than dropped or coerced.
        self.0.len = self
            .0
            .len
            .checked_add(1)
            .ok_or_else(|| de::Error::custom("catalog row limit"))?;
        Ok(())
    }
}

struct Rows<'a>(&'a mut Batch);
impl<'de> DeserializeSeed<'de> for Rows<'_> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<(), D::Error> {
        deserializer.deserialize_seq(self)
    }
}
impl<'de> Visitor<'de> for Rows<'_> {
    type Value = ();
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded catalog rows")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<(), A::Error> {
        while seq.next_element_seed(Row(&mut *self.0))?.is_some() {}
        Ok(())
    }
}

impl Batch {
    pub(crate) fn from_catalog_rows(fields: Vec<Field>, rows: &RawValue) -> Result<Self> {
        // Catalog metadata has already enforced the public64-column schema,
        // and the caller preflighted the complete256MiB/depth64 input.
        if fields.is_empty() || fields.len() > 64 {
            return Err(E::Catalog.into());
        }
        let mut columns = Vec::new();
        columns
            .try_reserve_exact(fields.len())
            .map_err(|_| E::Budget)?;
        for field in &fields {
            columns.push(Column::empty_catalog(field.data_type)?);
        }
        let mut result = Self {
            fields,
            columns,
            len: 0,
        };
        let mut deserializer = serde_json::Deserializer::from_str(rows.get());
        Rows(&mut result)
            .deserialize(&mut deserializer)
            .map_err(|_| E::Catalog)?;
        deserializer.end().map_err(|_| E::Catalog)?;
        Ok(result)
    }
}
