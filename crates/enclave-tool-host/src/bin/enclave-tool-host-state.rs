//! Explicit first-install provisioning of durable tool replay state; never run by startup.

fn main() {
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let args: Vec<String> = std::env::args().collect();
        if args.len() != 5 || args[1] != "init" {
            return Err("usage: enclave-tool-host-state init ABSOLUTE_REPLAY_PATH ISSUER_PUBLIC_KEY_HEX CAPACITY".into());
        }
        let bytes: [u8; 32] = hex::decode(&args[3])?.try_into()
            .map_err(|_| "issuer key must be 32 bytes")?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)?;
        let _host = enclave_tool_host::DurableToolHost::provision(
            std::path::Path::new(&args[2]), key, args[4].parse()?)?;
        println!("provisioned; normal startup must reopen this exact issuer/state pair");
        Ok(())
    })();
    if let Err(e) = result {
        eprintln!("tool host provisioning refused: {e}");
        std::process::exit(1);
    }
}
