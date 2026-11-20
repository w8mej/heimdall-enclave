fn main() {
    println!("cargo:rerun-if-changed=native/l3_socket.c");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("native/l3_socket.c")
            .warnings(true)
            .compile("depot_l3_socket");
        println!("cargo:rerun-if-changed=native/seed_conditions.m");
        cc::Build::new()
            .file("native/seed_conditions.m")
            .flag("-fobjc-arc")
            .flag("-fblocks")
            .warnings(true)
            .compile("depot_seed_conditions");
        for framework in ["Foundation", "Network", "IOKit"] {
            println!("cargo:rustc-link-lib=framework={framework}");
        }
    }
}
