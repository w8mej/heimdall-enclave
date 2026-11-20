//! Explicit nonproduction host-config test input set, never used by production fallback.
use std::path::{Path, PathBuf};
pub fn host_inputs(base: &Path) -> PathBuf {
    let root = base.join("test-inputs");
    let corpus = enclave_model_runnerd::zoo::calibrated_corpus();
    for (name, bytes) in [
        (
            "schemas/enclave.lock.toml",
            include_bytes!("../../../../schemas/enclave.lock.toml").as_slice(),
        ),
        (
            "packaging/fido-mds/yubico.json",
            include_bytes!("../../../../packaging/fido-mds/yubico.json").as_slice(),
        ),
        ("assets/calibration.corpus", corpus.as_slice()),
    ] {
        let p = root.join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }
    root
}
