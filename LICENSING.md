# Licensing

Copyright (C) 2026 Coding Duck

dss-native is an independent project by Coding Duck. It is not affiliated with, endorsed by or supported by the
European Commission or the DSS project; it uses DSS, unmodified, under DSS's licence.

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

`REUSE.toml` records the licence of every file that cannot carry an SPDX header (manifests, lock
files, documentation, fixtures, the files above). The repository's `LICENSES/` directory holds the text of
every licence those headers and annotations name, as the [REUSE specification](https://reuse.software)
requires (`LICENSES/LGPL-2.1-or-later.txt` is a copy of `LICENSE`; release packages carry the third-party
texts in `licenses/` instead). CI fails when a file has neither a header nor an
annotation, or when a licence text is missing or unused (`scripts/ci/check-repo.py`, and `reuse lint` itself).

## Why LGPL, and how replaceability works

The EU Digital Signature Service (DSS) is LGPL-2.1-or-later. Normally an application keeps LGPL code
"replaceable" by loading it as a separate library (a separate jar or `.so`) that users can swap.

GraalVM Native Image breaks that model. It compiles DSS, its dependencies, the wrapper and a minimal runtime
(Substrate VM) into **one** shared library (`libdssnative.so` / `.dylib`). There is no separate DSS file to
replace.

The library is therefore DSS itself, in object code, together with the wrapper (a work based on DSS). Its
distribution falls under **LGPL-2.1 §4** (object code of the Library), which requires the **complete
corresponding source** to accompany it, or equivalent access to it from the same place. dss-native meets that,
and gives users everything needed to **rebuild the native library against a modified DSS**:

1. The complete source of the wrapper and all build scripts are published in this repository, under the
   LGPL, so they can be combined with DSS on the same terms. Every GitHub release carries, next to its packages,
   the source of this repository at the release tag and the DSS source at the tag the release was built with
   (see [Source of the release packages](#source-of-the-release-packages)).
2. The DSS version is a single Maven property (`dss.version` in `java/pom.xml`). A modified DSS can be
   installed into a local Maven repository (`mvn install` in a DSS checkout) and picked up by changing that
   property, or by adding the modified modules as dependencies.
3. `scripts/build-native.sh` rebuilds the shared library from source with GraalVM Community Edition, which
   is free.
4. The Rust crates only talk to the library through its C ABI (`dss_*` functions in `libdssnative.h`). A
   rebuilt library with the same ABI can be dropped in without rebuilding the Rust application. Applications
   that link the library dynamically keep that ability for their users. The library is built with a relocatable
   install name / soname for this.

Applications that embed dss-native redistribute that object code, so the same duties pass to them:

- **Ship the native library as a separate file**, not statically linked, so users can replace it.
- **Accompany it with the corresponding source** (LGPL-2.1 §4 and §6): the release's `dss-native-<version>-source`
  and `dss-<version>-source` archives, or equivalent access to them from the place the application is
  distributed; a link to this repository alone is not enough. GraalVM CE's runtime inside the library is GPL
  code with the Classpath Exception, whose source must be offered the same way (GPLv2 §3): the release's
  `graal-*` and `labs-openjdk-*` source archives.
- **Pass on the notices** of the components below, which release packages collect in `licenses/` (see
  [Release packages](#release-packages)).

**Rust applications.** The `dss` and `dss-sys` crates are LGPL-2.1-or-later as well, and Cargo compiles them
statically into the application, unlike the native library. Under LGPL-2.1 §6 an application that links them
must also let its users relink it with a modified version of those crates: ship the application's own object
files (or its source) with what is needed to link them again, or the crates' source together with a way to
rebuild the application against a modified copy, and say that the crates are used and under which licence.
Linking only `libdssnative` through its C ABI (from C, or through your own bindings) avoids this second duty.

## Components compiled into the native library

| Component | Licence |
|---|---|
| EU DSS 6.5.1 (`eu.europa.ec.joinup.sd-dss:*`, 35 modules), © European Commission; source: <https://github.com/esig/dss>, tag `6.5.1` | LGPL-2.1-or-later |
| Bouncy Castle 1.86 (`bcprov`, `bcpkix`, `bcutil`) | MIT (Bouncy Castle Licence) |
| Apache PDFBox 3.0.8, FontBox, pdfbox-io | Apache-2.0; the resources PDFBox bundles are listed in its `LICENSE` |
| Apache Santuario xmlsec 3.0.6 | Apache-2.0 |
| Apache HttpClient 5.6.5, HttpCore 5.4.4 (`httpcore5`, `httpcore5-h2`) | Apache-2.0 |
| Public Suffix List (`org/publicsuffix/list/effective_tld_names.dat`, a data file inside HttpClient), © Mozilla Foundation and contributors; source: <https://publicsuffix.org/list/> | MPL-2.0 |
| Apache Commons Lang 3.21.0, Collections 4.6.0, Codec 1.18.0, IO 2.22.0, Logging 1.4.0 | Apache-2.0 |
| Woodstox 6.5.1, © Tatu Saloranta | Apache-2.0 |
| Stax2 API 4.2.1 | BSD-2-Clause |
| XML Signature schema (`xsd/xmldsig-core-schema.xsd` in DSS's `specs-xmldsig`), © 2001 The Internet Society and W3C | W3C Software License (W3C-19980720) |
| Jakarta XML Binding API 3.0.1, Jakarta Activation 2.0.1, Eclipse JAXB runtime 3.0.2 (`jaxb-runtime`, `jaxb-core`, `txw2`), istack-commons-runtime 4.0.1 | BSD-3-Clause (Eclipse Distribution License 1.0) |
| SLF4J 2.0.20 (`slf4j-api`, `slf4j-simple`) | MIT |
| GraalVM Community Edition 25.5.5.0.3 runtime (Substrate VM, JDK 25 class library); binaries: the release `graal-25.5.5.0.3` of <https://github.com/graalvm/graalvm-ce-builds>; source: <https://github.com/oracle/graal> and <https://github.com/graalvm/labs-openjdk> at the commit and tag its `release` file names, attached to each dss-native release | GPL-2.0-only WITH Classpath-exception-2.0 |
| GraalVM SDK modules `org.graalvm.nativeimage`, `org.graalvm.word`, `org.graalvm.collections` 25.5.5.0.3, © Oracle and/or its affiliates | UPL-1.0 |

All of them are free/open-source. Oracle GraalVM (GFTC) is not used: `scripts/build-native.sh` refuses any other
JDK than GraalVM Community Edition (`scripts/ci/check-graalvm.sh`). The Classpath Exception means that linking
the GraalVM runtime into the library does not extend the GPL to the rest of the library.

The ETSI schemas DSS compiles in (`specs-xades`, `specs-trusted-list`, `specs-validation-report`) carry no
licence or copyright notice to reproduce.

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
| `SOURCE` | the canonical repository URL and the commit the package was built from, and the source archives of DSS and GraalVM CE attached to the same release |
| `README.md`, `docs/`, `trust/README.md`, `php/`, `docker/` | the documentation, in the repository's layout so its links work |
| `licenses/LGPL-2.1.txt`, `licenses/dss.txt` | the LGPL again, and DSS's copyright notice |
| `licenses/pt-serif.txt` | PT Serif's copyright notice with its Reserved Font Names, and the OFL-1.1 |
| `licenses/xmldsig-core-schema.txt` | the XML Signature schema's notice and the W3C Software License |
| `licenses/java/<artifact>-<version>/` | the `LICENSE` and `NOTICE` files of each third-party jar compiled into the library, as the jar ships them; full notices from `third-party/` for Stax2 API, Woodstox (whose jars only point to their licence) and, in `httpclient5-*`, the Public Suffix List with the MPL-2.0 |
| `licenses/graalvm/` | GraalVM CE's `LICENSE.txt` and `THIRD_PARTY_LICENSE.txt`, the JDK's `legal/` notices, the GraalVM SDK's UPL-1.0 (`graalvm-sdk.txt`), and the `release` file with the source commit of each GraalVM component |
| `licenses/rust/` | the licence files of the crates in `dss-cli` and `dss-server`, and the Rust standard library's `COPYRIGHT-library.html` |
| `sbom/java.cdx.json`, `sbom/rust.cdx.json` | CycloneDX SBOMs: the jars compiled into the library, the crates in `dss-cli` and `dss-server` |

`scripts/build-native.sh` writes the same `licenses/`, without `rust/`, and `sbom/java.cdx.json` next to the
library in `build/native/<os>-<arch>/`, so an application that ships only the library takes its notices from
there. It regenerates them on every build, so a bumped dependency leaves no stale notice behind.

### Source of the release packages

Each GitHub release (made by `.github/workflows/ci.yml` from a `v<version>` tag) carries, next to the packages,
the corresponding source of what they contain, so that it is available from the same place as the object code:

| Asset | Contents |
|---|---|
| `dss-native-<version>-source.tar.gz` | this repository at the release tag (wrapper, Rust crates, build scripts) |
| `dss-<dss.version>-source.tar.gz` | EU DSS at the tag `java/pom.xml` builds against (<https://github.com/esig/dss>) |
| `graal-<commit>-source.tar.gz` | GraalVM CE's own components (Substrate VM, SDK, compiler) at the commit in the build's `release` file (<https://github.com/oracle/graal>) |
| `labs-openjdk-jvmci-<tag>-source.tar.gz` | the JDK class library GraalVM CE is built from, at the `jvmci` tag of its `JAVA_RUNTIME_VERSION` (<https://github.com/graalvm/labs-openjdk>) |
| `SHA256SUMS` | the SHA-256 of every asset, the loose `oj-keystore.p12` included; with a public repository also signed build provenance (`gh attestation verify <file> --repo codingducksrl/dss-rust`) |

`scripts/ci/fetch-sources.sh` downloads the third-party archives. A package's `SOURCE` file names them.

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
