//! Trusted synthetic benchmark instrumentation, separate from the ordinary query CLI.
#![forbid(unsafe_code)]
use rillscope::budget::{Budget, Limits};
use rillscope::catalog::{Catalog, Context, MAX_CATALOG_BYTES};
use rillscope::error::{ErrorCode as E, QueryError, Result};
use rillscope::query::Query;
use rillscope::{CompileOptions, compile_with_options};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::process::ExitCode;
use std::sync::{Arc, atomic::AtomicBool};
use std::time::Instant;

fn read(path: &str, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(limit.min(65536) + 1)
        .map_err(|_| E::Budget)?;
    File::open(path)
        .map_err(|_| E::Input)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| E::Input)?;
    if bytes.len() > limit {
        return Err(E::Limit.into());
    }
    Ok(bytes)
}
#[derive(Serialize)]
struct Measurement {
    implementation: &'static str,
    synthetic_only: bool,
    optimize: bool,
    batch_rows: usize,
    load_ns: u128,
    compile_ns: u128,
    execution_only_ns: Option<u128>,
    execution_call_wall_ns: u128,
    serialization_ns: Option<u128>,
    error: Option<QueryError>,
    prepublication_ns: u128,
    consumed_work: u64,
    visible_work: u64,
    peak_reserved_bytes: usize,
    collected_rows: Option<usize>,
    catalog_sha256: String,
    context_sha256: String,
    query_sha256: String,
    result_sha256: Option<String>,
}
fn run() -> Result<Vec<u8>> {
    let mut arguments = Vec::new();
    for value in std::env::args_os().skip(1) {
        if arguments.len() >= 17 {
            return Err(E::Input.into());
        }
        let value = value.into_string().map_err(|_| E::Input)?;
        if value.len() > 4096 {
            return Err(E::Input.into());
        }
        arguments.push(value);
    }
    if arguments.first().map(String::as_str) != Some("--synthetic") || arguments.len() % 2 != 1 {
        return Err(E::Input.into());
    }
    let mut fields = BTreeMap::new();
    for pair in arguments.get(1..).ok_or(E::Input)?.as_chunks::<2>().0 {
        let key = pair[0].as_str();
        if !matches!(
            key,
            "--catalog"
                | "--context"
                | "--query"
                | "--format"
                | "--optimize"
                | "--batch-rows"
                | "--max-work"
                | "--measurement"
        ) || fields.insert(key, pair[1].clone()).is_some()
        {
            return Err(E::Input.into());
        }
    }
    let started = Instant::now();
    let catalog_bytes = read(
        &fields.remove("--catalog").ok_or(E::Input)?,
        MAX_CATALOG_BYTES,
    )?;
    let catalog = Catalog::from_bytes(&catalog_bytes)?;
    if !catalog.snapshot().starts_with("synthetic-") {
        return Err(E::Context.into());
    }
    let context_bytes = read(&fields.remove("--context").ok_or(E::Input)?, 1024 * 1024)?;
    let context = Context::from_bytes(catalog.clone(), &context_bytes)?;
    let query_bytes = read(&fields.remove("--query").ok_or(E::Input)?, 65536)?;
    let format = fields.remove("--format").unwrap_or_else(|| "json".into());
    let query = match format.as_str() {
        "json" => Query::from_json(&query_bytes)?,
        "sql" => Query::from_sql(&query_bytes)?,
        _ => return Err(E::Input.into()),
    };
    let optimize = match fields.remove("--optimize").as_deref().unwrap_or("on") {
        "on" => true,
        "off" => false,
        _ => return Err(E::Input.into()),
    };
    let batch_rows = fields
        .remove("--batch-rows")
        .map(|value| value.parse().map_err(|_| E::Input))
        .transpose()?
        .unwrap_or(1024);
    let measurement_path = fields.remove("--measurement").ok_or(E::Input)?;
    let max_work = fields
        .remove("--max-work")
        .map(|value| value.parse().map_err(|_| E::Input))
        .transpose()?
        .unwrap_or(10_000_000);
    let load_ns = started.elapsed().as_nanos();
    let compile_started = Instant::now();
    let plan = compile_with_options(&query, catalog, context, CompileOptions { optimize })?;
    let compile_ns = compile_started.elapsed().as_nanos();
    let mut budget = Budget::new(
        Limits {
            batch_rows,
            max_work,
            ..Limits::default()
        },
        Arc::new(AtomicBool::new(false)),
        None,
    )?;
    let execution_started = Instant::now();
    let executed = rillscope::execute::execute(&plan, &mut budget);
    let execution_call_wall_ns = execution_started.elapsed().as_nanos();
    let (execution_only_ns, collected_rows, serialization_ns, output) = match executed {
        Ok(mut result) => {
            let elapsed = result.execution_elapsed_ns();
            let rows = result.rows().len();
            let serialize_started = Instant::now();
            let output = result
                .to_json_bytes(&budget)
                .map(|value| value.into_bytes());
            (
                Some(elapsed),
                Some(rows),
                Some(serialize_started.elapsed().as_nanos()),
                output,
            )
        }
        Err(error) => (None, None, None, Err(error)),
    };
    let measurement = Measurement {
        implementation: "rust-benchmark",
        synthetic_only: true,
        optimize,
        batch_rows,
        load_ns,
        compile_ns,
        execution_only_ns,
        execution_call_wall_ns,
        serialization_ns,
        error: output.as_ref().err().copied(),
        prepublication_ns: started.elapsed().as_nanos(),
        consumed_work: budget.consumed_work(),
        visible_work: budget.metrics().work_units,
        peak_reserved_bytes: budget.metrics().peak_reserved_bytes,
        collected_rows,
        catalog_sha256: format!("{:x}", Sha256::digest(&catalog_bytes)),
        context_sha256: format!("{:x}", Sha256::digest(&context_bytes)),
        query_sha256: format!("{:x}", Sha256::digest(&query_bytes)),
        result_sha256: output
            .as_ref()
            .ok()
            .map(|bytes| format!("{:x}", Sha256::digest(bytes))),
    };
    let data = serde_json::to_vec(&measurement).map_err(|_| E::Internal)?;
    File::options()
        .write(true)
        .create_new(true)
        .open(measurement_path)
        .map_err(|_| E::Input)?
        .write_all(&data)
        .map_err(|_| E::Internal)?;
    budget.checkpoint()?;
    output
}
#[derive(Serialize)]
struct Failure {
    version: u32,
    status: &'static str,
    error: QueryError,
    implementation: &'static str,
}
fn main() -> ExitCode {
    let (bytes, code) = match run() {
        Ok(bytes) => (bytes, 0),
        Err(error) => match serde_json::to_vec(&Failure {
            version: 1,
            status: "error",
            error,
            implementation: "rust-benchmark",
        }) {
            Ok(bytes) => (bytes, error.exit_code()),
            Err(_) => return ExitCode::from(6),
        },
    };
    if io::stdout()
        .lock()
        .write_all(&bytes)
        .and_then(|()| io::stdout().lock().write_all(b"\n"))
        .is_err()
    {
        return ExitCode::from(6);
    }
    ExitCode::from(code)
}
