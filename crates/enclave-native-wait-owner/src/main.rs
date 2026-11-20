//! Dedicated binary boundary proposed for strict child wait custody.
//!
//! Admission/lifetime/transport are deliberately unsupplied. This executable
//! accepts no command, argv, environment-selected tool, stdin protocol or root
//! operation and cannot construct a production wait scope. It refuses startup
//! before command construction. This is isolation groundwork, not a PF service.

#[cfg(unix)]
mod strict_command;

fn main() -> std::process::ExitCode {
    eprintln!("WAIT_OWNER_START_REFUSED admission=UNSUPPLIED discipline=UNQUALIFIED");
    std::process::ExitCode::from(78)
}
