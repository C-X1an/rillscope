//! Validated immutable operator inputs; no query-accessible path or mutation API.
use crate::decode::strict_json;
use crate::error::{ErrorCode as E, Result};
use crate::types::{Batch, DataType, Field, Row, Value, identifier};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub const MAX_CATALOG_BYTES: usize = 256 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogInput {
    version: u32,
    snapshot: String,
    tables: BTreeMap<String, TableInput>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TableInput {
    columns: Vec<Field>,
    rows: Vec<Vec<serde_json::Value>>,
}

#[derive(Debug)]
pub(crate) struct Table {
    pub name: String,
    pub columns: Vec<Field>,
    pub data: Batch,
}
#[derive(Debug)]
pub struct Catalog {
    pub(crate) tables: Vec<Table>,
    digest: String,
    snapshot: String,
}
impl Catalog {
    pub fn from_bytes(bytes: &[u8]) -> Result<Arc<Self>> {
        let json = strict_json(bytes, MAX_CATALOG_BYTES, 64).map_err(|_| E::Catalog)?;
        let input: CatalogInput = serde_json::from_value(json).map_err(|_| E::Catalog)?;
        if input.version != 1
            || input.snapshot.is_empty()
            || input.snapshot.len() > 128
            || input.tables.len() > 256
        {
            return Err(E::Catalog.into());
        }
        let mut tables = Vec::new();
        tables
            .try_reserve_exact(input.tables.len())
            .map_err(|_| E::Catalog)?;
        for (name, table) in input.tables {
            if !identifier(&name)
                || table.columns.is_empty()
                || table.columns.len() > 64
                || table.rows.len() > 1_000_000
            {
                return Err(E::Catalog.into());
            }
            let mut names = BTreeSet::new();
            for field in &table.columns {
                if !identifier(&field.name) || !names.insert(field.name.clone()) {
                    return Err(E::Catalog.into());
                }
            }
            let mut rows: Vec<Row> = Vec::new();
            rows.try_reserve_exact(table.rows.len())
                .map_err(|_| E::Catalog)?;
            for row in table.rows {
                if row.len() != table.columns.len() {
                    return Err(E::Catalog.into());
                }
                rows.push(
                    row.iter()
                        .zip(&table.columns)
                        .map(|(v, f)| {
                            Value::from_json(v, f.data_type, f.nullable)
                                .map_err(|_| E::Catalog.into())
                        })
                        .collect::<Result<_>>()?,
                );
            }
            let data = Batch::from_rows(table.columns.clone(), &rows).map_err(|_| E::Catalog)?;
            tables.push(Table {
                name,
                columns: table.columns,
                data,
            });
        }
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
