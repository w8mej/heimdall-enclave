//! Restricted privileged publisher; one fixed root-only deployment inspection.
fn main() {
    let arguments:Vec<_>=std::env::args_os().collect();
    let result=if arguments.len()==2&&arguments[1]=="--check-idle" {enclave_swarm_syncd::snapshot_broker::check_idle()} else if arguments.len()==2&&arguments[1]=="--quiesce-idle" {enclave_swarm_syncd::snapshot_broker::quiesce_idle()} else {enclave_swarm_syncd::snapshot_broker::run()};
    if let Err(error)=result{eprintln!("{error}");std::process::exit(1);}
}
