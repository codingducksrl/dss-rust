// SPDX-FileCopyrightText: 2026 Coding Duck
// SPDX-License-Identifier: LGPL-2.1-or-later

//! Test and example binaries of this crate find libdssnative through an rpath to the directory dss-sys linked
//! against. Applications set their own rpath (see docs/native-library.md).

fn main() {
    if let Ok(dir) = std::env::var("DEP_DSSNATIVE_LIB_DIR") {
        println!("cargo::rustc-link-arg=-Wl,-rpath,{dir}");
    }
}
