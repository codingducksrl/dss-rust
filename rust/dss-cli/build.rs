// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! rpath for the CLI: next to the executable ($ORIGIN / @executable_path) and ../lib, as in the release package,
//! plus, for `cargo run` in the repository, the directory dss-sys linked against. Release packages are built with
//! DSS_RELEASE_RPATH_ONLY=1 so no build-machine path ends up in the binary.
//!
//! For the same development builds, the absolute path of the repository's OJ keystore (trust/oj-keystore.p12):
//! the CLI's last fallback when no keystore is given or packaged, so that `cargo run` works from anywhere without
//! ever looking up the root of trust in the current directory. Release builds get no such fallback.

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
    let keystore = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../trust/oj-keystore.p12");
    println!("cargo::rerun-if-changed={}", keystore.display());
    if let (false, Ok(keystore)) = (release_only, keystore.canonicalize())
        && let Some(path) = keystore.to_str()
    {
        println!("cargo::rustc-env=DSS_CLI_DEV_OJ_KEYSTORE={path}");
    }
}
