//! Bound, private physical representation. No executable ordinary Scan exists.
use crate::catalog::{Catalog, Context, Grant};
use crate::types::{Field, TypedExpr};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Origin {
    pub occurrence: u32,
    pub table: usize,
    pub column: usize,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BoundField {
    pub field: Field,
    pub qualifier: Option<String>,
    pub origins: BTreeSet<Origin>,
}
pub(crate) type Projection = Vec<(BoundField, TypedExpr)>;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Aggregate {
    CountAll,
    Count(TypedExpr),
    Sum(TypedExpr),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OrderKey {
    pub expr: TypedExpr,
    pub descending: bool,
    pub nulls_first: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NodeKind {
    PolicyScan {
        table: usize,
        occurrence: u32,
        alias: String,
        columns: Vec<usize>,
        grant: Grant,
    },
    Filter {
        input: Box<Node>,
        predicate: TypedExpr,
    },
    Project {
        input: Box<Node>,
        columns: Projection,
    },
    Join {
        left: Box<Node>,
        right: Box<Node>,
        on: Vec<(usize, usize)>,
    },
    Aggregate {
        input: Box<Node>,
        keys: Projection,
        aggregates: Vec<(BoundField, Aggregate)>,
    },
    Sort {
        input: Box<Node>,
        keys: Vec<OrderKey>,
    },
    Limit {
        input: Box<Node>,
        count: usize,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Node {
    pub kind: NodeKind,
    pub schema: Vec<BoundField>,
}
pub(crate) struct BoundPlan {
    pub root: Node,
    pub catalog: Arc<Catalog>,
    pub context: Arc<Context>,
    pub sources: BTreeMap<u32, usize>,
    pub trace: Vec<&'static str>,
    trusted_catalog: Arc<Catalog>,
    trusted_context: Arc<Context>,
}
impl BoundPlan {
    pub fn new(
        root: Node,
        catalog: Arc<Catalog>,
        context: Arc<Context>,
        sources: BTreeMap<u32, usize>,
        trace: Vec<&'static str>,
    ) -> Self {
        Self {
            root,
            trusted_catalog: catalog.clone(),
            trusted_context: context.clone(),
            catalog,
            context,
            sources,
            trace,
        }
    }
    pub fn binding_identity_matches(&self) -> bool {
        Arc::ptr_eq(&self.catalog, &self.trusted_catalog)
            && Arc::ptr_eq(&self.context, &self.trusted_context)
    }
}
