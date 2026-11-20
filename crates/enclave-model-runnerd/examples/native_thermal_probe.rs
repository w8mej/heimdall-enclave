//! Disposable native telemetry probe; never installed as a daemon or test hook.
#[cfg(target_os = "macos")]
fn main() {
    use enclave_model_runnerd::classes::speculative::{DarwinThermal, ThermalProvider, ThermalState};
    let mode = std::env::args().nth(1).expect("mode: real/registration/query/eof/readerror");
    let expected = match mode.as_str() {
        "real" => 0,
        "registration" => 1,
        "query" => 2,
        "eof" => 3,
        "readerror" => 4,
        _ => panic!("invalid thermal probe mode"),
    };
    let snapshot: Option<unsafe extern "C" fn() -> u64> = if expected == 0 {
        None
    } else {
        // A fault must prove its interposer loaded and the intended path ran.
        let sym = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"mcpmac_thermal_fault_snapshot".as_ptr()) };
        assert!(!sym.is_null(), "BLOCKED: thermal fault interposer did not load");
        Some(unsafe { std::mem::transmute(sym) })
    };
    if let Some(read) = snapshot {
        assert_eq!(unsafe { read() } & 0xff, expected, "wrong fault library");
    }
    let thermal = DarwinThermal::new();
    if let Some(read) = snapshot {
        // Bits: register path observed, query path observed, cancel observed,
        // initial-query write completed (entry to read), or injected read error. EOF uses an actual closed pipe writer and real
        // read(2); cancel proves Rust passed through its failed-read cleanup.
        let required = match expected { 1 => 1, 2 => 11, 3 => 7, 4 => 15, _ => unreachable!() };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let flags = unsafe { read() } >> 8;
            if flags & required == required { break; }
            assert!(std::time::Instant::now() < deadline, "fault path not exercised: mode={mode} flags={flags}");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // Cleanup records cancel just before the worker stores Critical.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while thermal.sample().0 != ThermalState::Critical {
            assert!(std::time::Instant::now() < deadline, "fault did not fail closed");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        println!("mode={mode} sample={:?} injection_snapshot={:#x}", thermal.sample(), unsafe { read() });
    } else {
        std::thread::sleep(std::time::Duration::from_millis(500));
        println!("mode=real sample={:?}; actual sample observation only; subscription success unproven; no forced thermal transition", thermal.sample());
    }
}
#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("NOT RUN: native thermal probe requires macOS");
    std::process::exit(77);
}
