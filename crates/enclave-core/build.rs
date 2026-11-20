fn main() {
    for source in [
        "native/holders.c",
        "native/holder_maps.c",
        "native/holder_policy.c",
        "native/holder_policy.h",
        "native/resource.c",
    ] {
        println!("cargo:rerun-if-changed={source}");
    }
    // Compile the identical decision engine on every supported test host.
    // Keep it in the same archive as its Darwin sampler to avoid link-order
    // dependencies between separate native libraries.
    let mut native = cc::Build::new();
    native.file("native/holder_policy.c").warnings(true);
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        native
            .file("native/holders.c")
            .file("native/holder_maps.c")
            .file("native/resource.c");
    }
    native.compile("mcpmac_holders");
}
