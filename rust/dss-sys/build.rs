// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! Generates bindings from the header that `native-image --shared` wrote next to the library, and links it.
//!
//! Library location: `DSS_NATIVE_LIB_DIR`, or by default the repository's
//! `build/native/<os>-<arch>/` produced by `scripts/build-native.sh`.

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo::rerun-if-env-changed=DSS_NATIVE_LIB_DIR");
    let dir = lib_dir();
    let header = dir.join("libdssnative.h");
    if !header.is_file() {
        panic!(
            "{} not found. Build the native library with scripts/build-native.sh, \
             or point DSS_NATIVE_LIB_DIR at a directory containing libdssnative and its headers.",
            header.display()
        );
    }
    println!("cargo::rerun-if-changed={}", header.display());
    println!("cargo::rerun-if-changed={}", dir.join("graal_isolate.h").display());

    println!("cargo::rustc-link-search=native={}", dir.display());
    println!("cargo::rustc-link-lib=dylib=dssnative");
    // This crate's own test binaries find the library without installing it. Dependents set their own rpath.
    println!("cargo::rustc-link-arg=-Wl,-rpath,{}", dir.display());
    println!("cargo::metadata=lib_dir={}", dir.display());

    let bindings = bindgen::Builder::default()
        .header(header.to_string_lossy())
        .clang_arg(format!("-I{}", dir.display()))
        .allowlist_function("dss_.*")
        .allowlist_function("graal_.*")
        .allowlist_type("graal_.*")
        .allowlist_item("__graal_create_isolate_params_version")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("bindgen failed on libdssnative.h");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out.join("bindings.rs"))
        .expect("cannot write bindings");
}

fn lib_dir() -> PathBuf {
    if let Ok(dir) = env::var("DSS_NATIVE_LIB_DIR") {
        return PathBuf::from(dir);
    }
    let os = match env::var("CARGO_CFG_TARGET_OS").unwrap().as_str() {
        "macos" => "macos".to_string(),
        other => other.to_string(),
    };
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "x86_64" => "x64".to_string(),
        other => other.to_string(),
    };
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../../build/native")
        .join(format!("{os}-{arch}"))
}
