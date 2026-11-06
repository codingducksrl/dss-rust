# Licensing

Copyright (C) 2026 Coding Duck

dss-native is free software: you can redistribute it and/or modify it under the terms of the **GNU Lesser General
Public License, version 2.1 or (at your option) any later version** (`LGPL-2.1-or-later`), as published by the
Free Software Foundation. The full text is in [`LICENSE`](LICENSE).

The licence covers everything in this repository except the files listed under
[Files under other licences](#files-under-other-licences). Source files carry it in an SPDX header:

```
SPDX-FileCopyrightText: 2026 Coding Duck
SPDX-License-Identifier: LGPL-2.1-or-later
```

dss-native is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
more details.

## Files under other licences

| Files | Licence | Origin |
|---|---|---|
| `java/mvnw`, `java/mvnw.cmd` | Apache-2.0 | Apache Maven Wrapper 3.3.4, © The Apache Software Foundation |
| `trust/oj-keystore.p12` | LGPL-2.1-or-later | DSS demonstrations 6.5.1, © European Commission. Public X.509 certificates only; see [`trust/README.md`](trust/README.md) |
| `third-party/*.txt` | the licence each file reproduces | Notices of components compiled into the library, shipped in release packages |

## Why LGPL, and how replaceability works

The EU Digital Signature Service (DSS) is LGPL-2.1-or-later. Normally an application keeps LGPL code
"replaceable" by loading it as a separate library (a separate jar or `.so`) that users can swap.

GraalVM Native Image breaks that model. It compiles DSS, its dependencies, the wrapper and a minimal runtime
(Substrate VM) into **one** shared library (`libdssnative.so` / `.dylib`). There is no separate DSS file to
replace.

dss-native meets LGPL-2.1 §6 by giving users everything needed to **rebuild the native library against a
modified DSS**:

1. The complete source of the wrapper and all build scripts are published in this repository, under the
   LGPL, so they can be combined with DSS on the same terms.
2. The DSS version is a single Maven property (`dss.version` in `java/pom.xml`). A modified DSS can be
   installed into a local Maven repository (`mvn install` in a DSS checkout) and picked up by changing that
   property, or by adding the modified modules as dependencies.
3. `scripts/build-native.sh` rebuilds the shared library from source with GraalVM Community Edition, which
   is free.
4. The Rust crates only talk to the library through its C ABI (`dss_*` functions in `libdssnative.h`). A
   rebuilt library with the same ABI can be dropped in without rebuilding the Rust application. Applications
   that link the library dynamically keep that ability for their users. The library is built with a relocatable
   install name / soname for this.

Applications that embed dss-native must give their users the same ability: ship the native library as a
separate file, not statically linked, and point to this repository's source and build instructions, or ship
them. They must also pass on the notices of the components below, which release packages collect in
`licenses/` (see [Release packages](#release-packages)).

## Components compiled into the native library

| Component | Licence |
|---|---|
| EU DSS 6.5.1 (`eu.europa.ec.joinup.sd-dss:*`, 35 modules), © European Commission; source: <https://github.com/esig/dss>, tag `6.5.1` | LGPL-2.1-or-later |
| Bouncy Castle 1.86 (`bcprov`, `bcpkix`, `bcutil`) | MIT (Bouncy Castle Licence) |
| Apache PDFBox 3.0.8, FontBox, pdfbox-io | Apache-2.0; the resources PDFBox bundles are listed in its `LICENSE` |
| Apache Santuario xmlsec 3.0.6 | Apache-2.0 |
| Apache HttpClient 5.6.5, HttpCore 5.4.4 (`httpcore5`, `httpcore5-h2`) | Apache-2.0 |
| Apache Commons Lang 3.21.0, Collections 4.6.0, Codec 1.18.0, IO 2.22.0, Logging 1.4.0 | Apache-2.0 |
| Woodstox 6.5.1 | Apache-2.0 |
| Stax2 API 4.2.1 | BSD-2-Clause |
| Jakarta XML Binding API 3.0.1, Jakarta Activation 2.0.1, Eclipse JAXB runtime 3.0.2 (`jaxb-runtime`, `jaxb-core`, `txw2`), istack-commons-runtime 4.0.1 | BSD-3-Clause (Eclipse Distribution License 1.0) |
| SLF4J 2.0.20 (`slf4j-api`, `slf4j-simple`) | MIT |
| GraalVM Community Edition 25.4.4.1.1 runtime (Substrate VM, JDK 25 class library); source: the release `graal-25.4.4.1.1` of <https://github.com/graalvm/graalvm-ce-builds>, component commits in its `release` file | GPL-2.0-only WITH Classpath-exception-2.0 |

All of them are free/open-source. Oracle GraalVM (GFTC) is not used. The Classpath Exception means that linking
the GraalVM runtime into the library does not extend the GPL to the rest of the library.

### Fonts

| Font | Where from | Licence |
|---|---|---|
| PT Serif Regular, © 2010 ParaType Ltd. | the `dss-pades` jar (`fonts/PTSerifRegular.ttf`) | OFL-1.1 |
| Liberation Sans Regular | the PDFBox jar (PDFBox's fallback font; the tests also use it as a caller's font) | OFL-1.1 |

PT Serif is compiled into the library as the default font of visible signatures, and a subset of it is embedded
in each PDF signed with that default. The OFL allows both. Its copyright notice and licence text, which the OFL
asks redistributions of the font to carry, are in `third-party/pt-serif.txt` (`licenses/pt-serif.txt` in a
package); Liberation Sans's are in PDFBox's `LICENSE`. The OFL does not apply to documents created with the
fonts, so signed PDFs carry no obligation.

## Rust crates in `dss-cli` and `dss-server`

The `dss`, `dss-sys`, `dss-cli` and `dss-server` crates are part of dss-native. The `dss-cli` and `dss-server`
executables also contain the Rust standard library and the crates from `rust/Cargo.lock` that they use at run
time, all under permissive licences: MIT, Apache-2.0, BSD-3-Clause or the Unlicense, most of them offering a
choice of MIT or Apache-2.0. Build-time dependencies (bindgen, libclang bindings, procedural macros) are not part
of the executables.

`scripts/collect-rust-licenses.py` copies the licence files of each of those crates, and the standard library's
copyright notice, into a package's `licenses/rust/`, with an index in `crates.tsv`. It fails if a crate ships no
licence file.

## Release packages

A release package (`scripts/package.sh`), and the Docker image built from it under `/opt/dss-native`, carries
the licences of everything it contains:

| Path | Contents |
|---|---|
| `LICENSE` | LGPL-2.1: dss-native and DSS |
| `LICENSING.md` | this file |
| `SOURCE` | the repository and commit the package was built from, the DSS source, the GraalVM CE release |
| `licenses/LGPL-2.1.txt`, `licenses/dss.txt` | the LGPL again, and DSS's copyright notice |
| `licenses/pt-serif.txt` | PT Serif's copyright notice and the OFL-1.1 |
| `licenses/java/<artifact>-<version>/` | the `LICENSE` and `NOTICE` files of each third-party jar compiled into the library, as the jar ships them; Stax2 API's full licence from `third-party/stax2-api.txt` |
| `licenses/graalvm/` | GraalVM CE's `LICENSE.txt` and `THIRD_PARTY_LICENSE.txt`, the JDK's `legal/` notices, and the `release` file with the source commit of each GraalVM component |
| `licenses/rust/` | the licence files of the crates in `dss-cli` and `dss-server`, and the Rust standard library's `COPYRIGHT-library.html` |

`scripts/build-native.sh` writes the same `licenses/`, without `rust/`, next to the library in
`build/native/<os>-<arch>/`, so an application that ships only the library takes its notices from there.

The Docker image's Debian base keeps the licences of its own packages in `/usr/share/doc/*/copyright`.

## Data files

- `trust/oj-keystore.p12` is copied unchanged from the DSS demonstrations 6.5.1
  (`dss-demo-webapp/src/main/resources/keystore.p12`). It contains only **public** X.509 certificates of the EU
  LOTL signers, as announced in the Official Journal of the EU. See [`trust/README.md`](trust/README.md).
- `testdata/fixtures/` is entirely synthetic, produced by `scripts/generate-fixtures.sh` from a throw-away test
  PKI with fictitious names. It contains no personal data. Real signed documents belong in the gitignored
  `testdata/private/`.
- The seed trusted-list cache attached to each release holds the EU List of Trusted Lists and the national
  trusted lists exactly as the European Commission and the Member States publish them under Regulation (EU)
  No 910/2014 (eIDAS).
