//! Validated immutable operator inputs; no query-accessible path or mutation API.
use crate::decode::{preflight, strict_json};
use crate::error::{ErrorCode as E, Result};
use crate::types::{Batch, DataType, Field, identifier};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

pub const MAX_CATALOG_BYTES: usize = 256 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogInput<'a> {
    version: u32,
    snapshot: String,
    #[serde(borrow)]
    tables: &'a RawValue,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TableInput<'a> {
    #[serde(deserialize_with = "catalog_columns")]
    columns: Vec<Field>,
    #[serde(borrow)]
    rows: &'a RawValue,
}

// Only metadata is materialized here. Borrowing rows allows either JSON member
// order; their scalars are validated once the authoritative schema is known.
fn catalog_columns<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Vec<Field>, D::Error> {
    struct Columns;
    struct NextField(usize);
    impl<'de> DeserializeSeed<'de> for NextField {
        type Value = Field;
        fn deserialize<X: Deserializer<'de>>(
            self,
            deserializer: X,
        ) -> std::result::Result<Field, X::Error> {
            if self.0 >= 64 {
                return Err(de::Error::custom("catalog column limit"));
            }
            Field::deserialize(deserializer)
        }
    }
    impl<'de> Visitor<'de> for Columns {
        type Value = Vec<Field>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("bounded catalog columns")
        }
        fn visit_seq<A: SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut fields: Vec<Field> = Vec::new();
            while let Some(field) = seq.next_element_seed(NextField(fields.len()))? {
                if !identifier(&field.name) || fields.iter().any(|prior| prior.name == field.name) {
                    return Err(de::Error::custom("invalid catalog column"));
                }
                fields
                    .try_reserve(1)
                    .map_err(|_| de::Error::custom("catalog allocation limit"))?;
                fields.push(field);
            }
            if fields.is_empty() {
                return Err(de::Error::custom("empty catalog schema"));
            }
            Ok(fields)
        }
    }
    deserializer.deserialize_seq(Columns)
}

#[derive(Debug)]
pub(crate) struct Table {
    pub name: String,
    pub columns: Vec<Field>,
    pub data: Batch,
}

struct CatalogTables(Vec<Table>);
impl<'de> Deserialize<'de> for CatalogTables {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct Tables;
        impl<'de> Visitor<'de> for Tables {
            type Value = CatalogTables;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("bounded unique catalog tables")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut tables: Vec<Table> = Vec::new();
                while let Some(name) = map.next_key::<String>()? {
                    if tables.len() >= 256
                        || !identifier(&name)
                        || tables.iter().any(|prior| prior.name == name)
                    {
                        return Err(de::Error::custom("invalid or duplicate catalog table"));
                    }
                    let input: TableInput<'de> = map.next_value()?;
                    let data = Batch::from_catalog_rows(input.columns.clone(), input.rows)
                        .map_err(|_| de::Error::custom("invalid catalog rows"))?;
                    tables
                        .try_reserve(1)
                        .map_err(|_| de::Error::custom("catalog allocation limit"))?;
                    tables.push(Table {
                        name,
                        columns: input.columns,
                        data,
                    });
                }
                // Preserve the previous BTreeMap table identity ordering.
                tables.sort_by(|left, right| left.name.cmp(&right.name));
                Ok(CatalogTables(tables))
            }
        }
        deserializer.deserialize_map(Tables)
    }
}

#[derive(Debug)]
pub struct Catalog {
    pub(crate) tables: Vec<Table>,
    digest: String,
    snapshot: String,
}
impl Catalog {
    pub fn from_bytes(bytes: &[u8]) -> Result<Arc<Self>> {
        preflight(bytes, MAX_CATALOG_BYTES, 64).map_err(|_| E::Catalog)?;
        let input: CatalogInput<'_> = serde_json::from_slice(bytes).map_err(|_| E::Catalog)?;
        if input.version != 1 || input.snapshot.is_empty() || input.snapshot.len() > 128 {
            return Err(E::Catalog.into());
        }
        let CatalogTables(tables) =
            serde_json::from_str(input.tables.get()).map_err(|_| E::Catalog)?;
        Ok(Arc::new(Self {
            tables,
            digest: format!("{:x}", Sha256::digest(bytes)),
            snapshot: input.snapshot,
        }))
    }
    pub fn content_digest(&self) -> &str {
        &self.digest
    }
    pub fn snapshot(&self) -> &str {
        &self.snapshot
    }
    pub(crate) fn table_index(&self, name: &str) -> Option<usize> {
        self.tables.iter().position(|t| t.name == name)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextInput {
    version: u32,
    policy_revision: String,
    tenant: String,
    tables: BTreeMap<String, GrantInput>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantInput {
    tenant_column: String,
    columns: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Grant {
    pub tenant_column: usize,
    pub visible: BTreeSet<usize>,
}
#[derive(Debug)]
pub struct Context {
    pub(crate) catalog: Arc<Catalog>,
    pub(crate) tenant: String,
    pub(crate) grants: BTreeMap<usize, Grant>,
    revision: String,
    digest: String,
}
impl Context {
    pub fn from_bytes(catalog: Arc<Catalog>, bytes: &[u8]) -> Result<Arc<Self>> {
        let value = strict_json(bytes, 1024 * 1024, 32).map_err(|_| E::Context)?;
        let input: ContextInput = serde_json::from_value(value).map_err(|_| E::Context)?;
        if input.version != 1
            || input.tenant.is_empty()
            || input.tenant.len() > 128
            || input.policy_revision.is_empty()
            || input.policy_revision.len() > 128
            || input.tables.len() > 256
        {
            return Err(E::Context.into());
        }
        let mut grants = BTreeMap::new();
        for (name, grant) in input.tables {
            let table_id = catalog.table_index(&name).ok_or(E::Context)?;
            let table = catalog.tables.get(table_id).ok_or(E::Context)?;
            let tenant_column = table
                .columns
                .iter()
                .position(|c| c.name == grant.tenant_column)
                .ok_or(E::Context)?;
            let tenant_field = table.columns.get(tenant_column).ok_or(E::Context)?;
            if tenant_field.data_type != DataType::Text
                || tenant_field.nullable
                || grant.columns.len() > 64
            {
                return Err(E::Context.into());
            }
            let mut visible = BTreeSet::new();
            for name in grant.columns {
                let col = table
                    .columns
                    .iter()
                    .position(|c| c.name == name)
                    .ok_or(E::Context)?;
                if !visible.insert(col) {
                    return Err(E::Context.into());
                }
            }
            grants.insert(
                table_id,
                Grant {
                    tenant_column,
                    visible,
                },
            );
        }
        Ok(Arc::new(Self {
            catalog,
            tenant: input.tenant,
            grants,
            revision: input.policy_revision,
            digest: format!("{:x}", Sha256::digest(bytes)),
        }))
    }
    pub fn policy_revision(&self) -> &str {
        &self.revision
    }
    pub fn content_digest(&self) -> &str {
        &self.digest
    }
}

#[cfg(test)]
#[path = "catalog_ingestion_tests.rs"]
mod ingestion_tests;

#[cfg(test)]
mod tests {
    use super::*;
    const CATALOG:&[u8] = br#"{"version":1,"snapshot":"t","tables":{"t":{"columns":[{"name":"tenant","type":"text","nullable":false},{"name":"id","type":"i64","nullable":false}],"rows":[["alpha",1],["beta",2]]}}}"#;
    #[test]
    fn catalog_type_lengths_names_and_duplicate_keys_fail() {
        let input = std::str::from_utf8(CATALOG).unwrap_or("");
        for bad in [
            input.replace("[\"alpha\",1]", "[\"alpha\"]"),
            input.replace("[\"alpha\",1]", "[\"alpha\",true]"),
            input.replace("\"name\":\"id\"", "\"name\":\"tenant\""),
            input.replace("\"version\":1", "\"version\":1,\"version\":1"),
        ] {
            assert_eq!(
                Catalog::from_bytes(bad.as_bytes()).err().map(|e| e.code),
                Some(E::Catalog)
            );
        }
    }
    #[test]
    fn column_ingestion_keeps_catalog_structure_and_scalar_rejections() {
        let input = std::str::from_utf8(CATALOG).unwrap_or("");
        for bad in [
            input.replace("\"rows\":", "\"extra\":0,\"rows\":"),
            input.replace("\"type\":\"text\"", "\"type\":\"text\",\"type\":\"text\""),
            input.replace("[\"alpha\",1]", "[null,1]"),
            input.replace("[\"alpha\",1]", "[\"alpha\",1.0]"),
            input.replace("[\"alpha\",1]", "[\"alpha\",9223372036854775808]"),
            input.replace("[\"alpha\",1]", "[\"alpha\",1,2]"),
        ] {
            assert_eq!(
                Catalog::from_bytes(bad.as_bytes())
                    .err()
                    .map(|error| error.code),
                Some(E::Catalog)
            );
        }
    }
    #[test]
    fn context_rejects_invalid_grants() -> Result<()> {
        let catalog = Catalog::from_bytes(CATALOG)?;
        let good = br#"{"version":1,"tenant":"alpha","policy_revision":"r1","tables":{"t":{"tenant_column":"tenant","columns":["id"]}}}"#;
        let context = Context::from_bytes(catalog.clone(), good)?;
        assert_eq!(context.policy_revision(), "r1");
        let bad = std::str::from_utf8(good)
            .map_err(|_| E::Internal)?
            .replace("[\"id\"]", "[\"id\",\"id\"]");
        assert_eq!(
            Context::from_bytes(catalog, bad.as_bytes())
                .err()
                .map(|e| e.code),
            Some(E::Context)
        );
        Ok(())
    }
}
