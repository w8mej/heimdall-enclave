fn main() {
    for path in [
        "src/backends/mlx/mlx_shim.cpp",
        "src/backends/mlx/mlx_shim.h",
        "src/backends/coreml/mil_inspector.cpp",
        "src/backends/coreml/mil_inspector.h",
        "src/arena_metal.m",
        "src/backends/coreml/runtime.m",
        "src/backends/coreml/bert.m",
        "src/backends/coreml/model_data_owner.h",
        "src/owned_browser.m",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    println!("cargo:rerun-if-env-changed=MLX_C_LIB_DIR");
    if std::env::var_os("CARGO_FEATURE_MLX_NATIVE").is_some() && target_os == "macos" {
        // Only the native worker binary links libmlxc (#[link] on its FFI).
        let dir = std::env::var("MLX_C_LIB_DIR").unwrap_or_else(|_| "/opt/homebrew/lib".into());
        println!("cargo:rustc-link-search=native={dir}");
    }

    let mut cpp_build = cc::Build::new();
    cpp_build
        .cpp(true)
        .std("c++17")
        .file("src/backends/mlx/mlx_shim.cpp")
        .file("src/backends/coreml/mil_inspector.cpp");

    cpp_build.compile("enclave_model_runnerd_cpp");

    if target_os == "macos" {
        let mut objc_build = cc::Build::new();
        objc_build.file("src/arena_metal.m").file("src/backends/coreml/runtime.m")
            .file("src/backends/coreml/bert.m")
            .file("src/owned_browser.m").flag("-fobjc-arc").flag("-fblocks");
        // The dedicated trained experiment is also disabled at its C entry
        // points in release; Rust independently refuses before native I/O.
        if std::env::var("PROFILE").as_deref() == Ok("debug") {
            objc_build.define("MCPMAC_COREML_BERT_DEVELOPMENT", None);
            // Native ownership regression hook; absent from release symbols.
            objc_build.define("MCPMAC_OWNED_BROWSER_TESTING", None);
        }
        objc_build.compile("enclave_model_runnerd_metal");

        println!("cargo:rustc-link-lib=framework=Metal");
        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=CoreML");
        println!("cargo:rustc-link-lib=framework=WebKit");
        println!("cargo:rustc-link-lib=framework=AppKit");
    }
}
