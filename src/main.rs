//! This binary reports seed status. It does not pretend to implement the full CLI.
use std::process::ExitCode;
fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["seed-status"] {
        println!("{{\"implementation\":\"rust-kernel-seed\",\"product_complete\":false}}");
        ExitCode::SUCCESS
    } else {
        eprintln!("RillScope kernel seed: the full query CLI is not implemented. See IMPLEMENTATION_STATUS.md.");
        ExitCode::from(2)
    }
}
