//! Operator-controlled files and one terminal value-free JSON envelope.
#![forbid(unsafe_code)]
use rillscope::budget::{Budget, Limits};
use rillscope::catalog::{Catalog, Context, MAX_CATALOG_BYTES};
use rillscope::error::{ErrorCode as E, QueryError, Result};
use rillscope::query::Query;
use rillscope::{CompileOptions, compile_with_options};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::process::ExitCode;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

struct Arguments {
    command: String,
    catalog: String,
    context: String,
    query: String,
    sql: bool,
    optimize: bool,
}
fn arguments(args: &[String]) -> Result<Arguments> {
    let command = args.first().ok_or(E::Input)?.clone();
    if !matches!(command.as_str(), "run" | "explain") {
        return Err(E::Input.into());
    }
    if args.len() > 13 || args.len() % 2 != 1 {
        return Err(E::Input.into());
    }
    let mut flags = BTreeMap::new();
    for pair in args.get(1..).ok_or(E::Input)?.as_chunks::<2>().0 {
        let key = pair.first().ok_or(E::Input)?.as_str();
        let value = pair.get(1).ok_or(E::Input)?;
        if !matches!(
            key,
            "--catalog" | "--context" | "--query" | "--format" | "--optimize"
        ) || flags.insert(key, value.clone()).is_some()
        {
            return Err(E::Input.into());
        }
    }
    let catalog = flags.remove("--catalog").ok_or(E::Input)?;
    let context = flags.remove("--context").ok_or(E::Input)?;
    let query = flags.remove("--query").ok_or(E::Input)?;
    let sql = match flags.remove("--format").as_deref().unwrap_or("json") {
        "json" => false,
        "sql" => true,
        _ => return Err(E::Input.into()),
    };
    let optimize = match flags.remove("--optimize").as_deref().unwrap_or("on") {
        "on" => true,
        "off" => false,
        _ => return Err(E::Input.into()),
    };
    if [&catalog, &context, &query]
        .iter()
        .any(|s| s.is_empty() || s.len() > 4096)
    {
        return Err(E::Input.into());
    }
    Ok(Arguments {
        command,
        catalog,
        context,
        query,
        sql,
        optimize,
    })
}
fn read(path: &str, max: usize, code: E, stdin: bool) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(max.min(65536) + 1)
        .map_err(|_| code)?;
    if path == "-" && stdin {
        io::stdin()
            .lock()
            .take(max as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| code)?;
    } else {
        File::open(path)
            .map_err(|_| code)?
            .take(max as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| code)?;
    }
    if bytes.len() > max {
        return Err(if stdin { E::Limit } else { code }.into());
    }
    Ok(bytes)
}
fn cancellation() -> Result<Arc<AtomicBool>> {
    let flag = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    {
        signal_hook::flag::register(signal_hook::consts::SIGTERM, flag.clone())
            .map_err(|_| E::Internal)?;
        signal_hook::flag::register(signal_hook::consts::SIGINT, flag.clone())
            .map_err(|_| E::Internal)?;
    }
    Ok(flag)
}
fn run(args: Arguments, cancelled: Arc<AtomicBool>) -> Result<Vec<u8>> {
    let catalog = Catalog::from_bytes(&read(&args.catalog, MAX_CATALOG_BYTES, E::Catalog, false)?)?;
    let synthetic = catalog.snapshot().starts_with("synthetic-");
    let scan_counter_file = synthetic
        .then(|| std::env::var_os("RILLSCOPE_TEST_SCAN_COUNTER_FILE"))
        .flatten();
    if let Some(path) = &scan_counter_file {
        File::create(path)
            .and_then(|mut file| file.write_all(b"0\n"))
            .map_err(|_| E::Internal)?;
    }
    let context = Context::from_bytes(
        catalog.clone(),
        &read(&args.context, 1024 * 1024, E::Context, false)?,
    )?;
    let bytes = read(&args.query, 65536, E::Input, true)?;
    let query = if args.sql {
        Query::from_sql(&bytes)?
    } else {
        Query::from_json(&bytes)?
    };
    let plan = compile_with_options(
        &query,
        catalog,
        context,
        CompileOptions {
            optimize: args.optimize,
        },
    )?;
    if args.command == "explain" {
        return serde_json::to_vec(&plan.explain()).map_err(|_| E::Internal.into());
    }
    let mut budget = Budget::new(Limits::default(), cancelled.clone(), None)?;
    if synthetic {
        let phase_file = std::env::var_os("RILLSCOPE_TEST_PHASE_FILE");
        let cancel_before_publish = std::env::var_os("RILLSCOPE_TEST_CANCEL_BEFORE_PUBLISH")
            .is_some_and(|value| value == "1");
        let mut sent = false;
        let mut scans = 0u32;
        budget.set_observer(move |stage| {
            if stage == "scan_open"
                && let Some(path) = &scan_counter_file
            {
                scans = scans.checked_add(1).ok_or(E::Internal)?;
                File::create(path)
                    .and_then(|mut file| writeln!(file, "{scans}"))
                    .map_err(|_| E::Internal)?;
            }
            if stage == "join_inner"
                && !sent
                && let Some(path) = &phase_file
            {
                File::create(path)
                    .and_then(|mut file| file.write_all(b"join_inner\n"))
                    .map_err(|_| E::Internal)?;
                sent = true;
            }
            if stage == "collect_before_publish" && cancel_before_publish {
                cancelled.store(true, Ordering::Release);
            }
            Ok(())
        });
    }
    let mut result = rillscope::execute::execute(&plan, &mut budget)?;
    let serialized = result.to_json_bytes(&budget)?;
    budget.checkpoint()?;
    Ok(serialized.into_bytes())
}
#[derive(Serialize)]
struct Failure {
    version: u32,
    status: &'static str,
    error: QueryError,
    implementation: &'static str,
}
fn argument_strings(args: impl IntoIterator<Item = std::ffi::OsString>) -> Result<Vec<String>> {
    let mut out = Vec::new();
    out.try_reserve_exact(13).map_err(|_| E::Input)?;
    for arg in args {
        if out.len() >= 13 || arg.len() > 16384 {
            return Err(E::Input.into());
        }
        let arg = arg.into_string().map_err(|_| E::Input)?;
        if arg.len() > 4096 {
            return Err(E::Input.into());
        }
        out.push(arg);
    }
    Ok(out)
}
fn main() -> ExitCode {
    let args = argument_strings(std::env::args_os().skip(1));
    if args.as_ref().is_ok_and(|args| args == &["--version"]) {
        return if io::stdout()
            .lock()
            .write_all(b"rillscope 0.1.0-dev\n")
            .is_ok()
        {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(6)
        };
    }
    let flag = cancellation();
    let outcome = args.and_then(|args| {
        flag.and_then(|flag| {
            arguments(&args)
                .and_then(|args| run(args, flag.clone()))
                .and_then(|bytes| {
                    if flag.load(Ordering::Acquire) {
                        Err(E::Cancelled.into())
                    } else {
                        Ok(bytes)
                    }
                })
        })
    });
    let (bytes, code) = match outcome {
        Ok(bytes) => (bytes, 0),
        Err(error) => {
            let failure = Failure {
                version: 1,
                status: "error",
                error,
                implementation: "rust",
            };
            match serde_json::to_vec(&failure) {
                Ok(bytes) => (bytes, error.exit_code()),
                Err(_) => return ExitCode::from(6),
            }
        }
    };
    let mut stdout = io::stdout().lock();
    if stdout
        .write_all(&bytes)
        .and_then(|()| stdout.write_all(b"\n"))
        .is_err()
    {
        return ExitCode::from(6);
    }
    ExitCode::from(code)
}

#[cfg(test)]
mod review_tests {
    use super::*;
    #[test]
    fn malformed_os_argument_is_a_value_free_input_error() {
        #[cfg(unix)]
        let invalid = {
            use std::os::unix::ffi::OsStringExt;
            std::ffi::OsString::from_vec(b"PATH_CANARY_\xff".to_vec())
        };
        #[cfg(windows)]
        let invalid = {
            use std::os::windows::ffi::OsStringExt;
            std::ffi::OsString::from_wide(&[0x0050, 0x0041, 0xd800])
        };
        let error = argument_strings([invalid]).err();
        assert_eq!(error.map(|e| e.code), Some(E::Input));
        assert_eq!(
            argument_strings((0..14).map(|_| std::ffi::OsString::from("x")))
                .err()
                .map(|e| e.code),
            Some(E::Input)
        );
    }
}
