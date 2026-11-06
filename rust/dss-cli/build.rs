// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! rpath for the CLI: next to the executable ($ORIGIN / @executable_path) and ../lib, as in the release package,
//! plus, for `cargo run` in the repository, the directory dss-sys linked against. Release packages are built with
//! DSS_RELEASE_RPATH_ONLY=1 so no build-machine path ends up in the binary.

fn main() {
    println!("cargo::rerun-if-env-changed=DSS_RELEASE_RPATH_ONLY");
    let origin = if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        "@executable_path"
    } else {
        "$ORIGIN"
    };
    println!("cargo::rustc-link-arg-bins=-Wl,-rpath,{origin}");
    println!("cargo::rustc-link-arg-bins=-Wl,-rpath,{origin}/../lib");
    let release_only = std::env::var("DSS_RELEASE_RPATH_ONLY").is_ok_and(|v| v == "1");
    if let (false, Ok(dir)) = (release_only, std::env::var("DEP_DSSNATIVE_LIB_DIR")) {
        println!("cargo::rustc-link-arg-bins=-Wl,-rpath,{dir}");
    }
}
