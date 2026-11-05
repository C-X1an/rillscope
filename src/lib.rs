//! Original restricted query compiler and bounded analytical executor.
#![forbid(unsafe_code)]
mod bind;
pub mod budget;
pub mod catalog;
mod decode;
pub mod error;
pub mod execute;
mod operators;
mod optimize;
mod plan;
pub mod query;
#[cfg(test)]
#[expect(
    dead_code,
    reason = "Historical prototype helpers are retained only with their original tests; they are excluded from the production query API."
)]
mod seed;
pub mod sql;
pub mod types;
pub mod verify;

pub fn compile(
    query: &query::Query,
    catalog: std::sync::Arc<catalog::Catalog>,
    context: std::sync::Arc<catalog::Context>,
) -> error::Result<verify::VerifiedPlan> {
    compile_with_options(query, catalog, context, CompileOptions::default())
}

#[derive(Clone, Copy, Debug)]
pub struct CompileOptions {
    pub optimize: bool,
}
impl Default for CompileOptions {
    fn default() -> Self {
        Self { optimize: true }
    }
}
pub fn compile_with_options(
    query: &query::Query,
    catalog: std::sync::Arc<catalog::Catalog>,
    context: std::sync::Arc<catalog::Context>,
    options: CompileOptions,
) -> error::Result<verify::VerifiedPlan> {
    verify::verify(optimize::optimize(
        bind::bind(query, catalog, context)?,
        options.optimize,
    )?)
}
