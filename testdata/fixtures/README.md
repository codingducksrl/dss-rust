# testdata/fixtures

Synthetic, committed test documents. Every file is produced by
[`scripts/generate-fixtures.sh`](../../scripts/generate-fixtures.sh)
(`java/src/test/java/.../testsupport/FixtureGenerator.java`) from the throw-away PKI in `pki/`. All names
("Mario Rossi (TEST)", "Giulia Bianchi (TEST)") and URLs (`*.dss-native.test`) are fictitious. Nothing
here is personal data.

Each signed payload contains the marker `DSS-NATIVE-SYNTHETIC-CONTENT`. In every file under `tampered/` the first
letter of that marker is changed to `X`, inside the signed bytes.

| File | What it is | Expected (trusted via synthetic IT TL) |
|---|---|---|
| `cades/attached-der.p7m` | CAdES-B enveloping, DER | TOTAL_PASSED |
| `cades/attached-ber.p7m` | Same signature, outer layers re-encoded BER indefinite-length, content chunked | TOTAL_PASSED |
| `cades/attached-base64.p7m` | `attached-der.p7m` as base64 text (CRLF, 76 columns) | TOTAL_PASSED, `transformations: ["base64"]` |
| `cades/nested.p7m.p7m` | EC signer's CAdES envelope around `attached-der.p7m` | TOTAL_PASSED, and `nested[0]` TOTAL_PASSED |
| `cades/multi-signer.p7m` | Two parallel signers (RSA + EC) over the same content | 2 × TOTAL_PASSED |
| `cades/detached.txt.p7s` | CAdES-B detached over `content/document.txt` | with content: TOTAL_PASSED; without: INDETERMINATE / SIGNED_DATA_NOT_FOUND |
| `pades/b-b.pdf` | PAdES-BASELINE-B | TOTAL_PASSED (needs revocation: online CRL) |
| `pades/b-t.pdf` | PAdES-BASELINE-T (test TSA) | TOTAL_PASSED (needs revocation: online CRL) |
| `pades/b-lt.pdf` | PAdES-BASELINE-LT (CRL in DSS dictionary) | TOTAL_PASSED, also with `revocation: "offline"` |
| `pades/b-lta.pdf` | PAdES-BASELINE-LTA (+ document timestamp) | TOTAL_PASSED, also with `revocation: "offline"` |
| `tampered/cades/*`, `tampered/pades/*` | One byte of signed content changed | TOTAL_FAILED / HASH_FAILURE (nested: at both levels) |
| `tampered/content/document.txt` | Altered detached content | with `detached.txt.p7s`: TOTAL_FAILED / HASH_FAILURE |
| `content/document.pdf`, `content/document.txt` | Unsigned originals | n/a |
| `content/form.pdf` | Form with an empty signature field `Firma1` and a text field `Nome` | n/a (visible signatures) |
| `content/rotated.pdf` | A page turned by `/Rotate 90` | n/a (visible signatures) |
| `content/protected.pdf` | `document.pdf` protected with an owner password | n/a (visible signatures) |
| `content/stamp.jpg` | JPEG image for visible signatures (made with ImageIO, which the native tests cannot use) | n/a |
| `pki/test-pki.p12` | Test PKI (password `dss-native-test`), valid 2026–2045 | n/a |
| `pki/root-ca.pem` | Test root, for `extra_trusted_certificates` | n/a |
| `signing/<case>.json`, `signing/<case>.sig` | External signing: `options_json` with a fixed signing time, and what an external signer returned for the digest `dss_sign_prepare` gives (`pades-cms`, `cades-cms`: a BER CMS with a signature timestamp; `pades-signature-value`, `cades-signature-value`: an RSA signature value; `pades-visible-cms`: a visible signature in a new box with text and a PNG, CMS without timestamp; `pades-visible-field-signature-value`: a visible signature in `form.pdf`'s `Firma1` field, with `stamp.jpg` behind the text, RSA signature value) | `dss_sign_complete` succeeds: PAdES/CAdES-BASELINE-T for `pades-cms` and `cades-cms` (their CMS carries a timestamp), -B for the others. It needs the same digest again, so it also checks that preparing is deterministic (for the visible cases: that the appearance is drawn byte for byte the same natively) |

Expectations are asserted in `FixtureValidationTest` (the `signing/` cases in the Rust tests and the C smoke
test). Regenerate them with

```bash
scripts/generate-fixtures.sh [--new-pki] [--signing-only] [--out=<dir>] [--time=<ISO-8601 instant>]
```

- `--new-pki` also replaces the PKI in `pki/`;
- `--signing-only` rewrites only `signing/` (it also writes the `content/` files the signing cases need,
  `form.pdf`, `rotated.pdf`, `protected.pdf` and `stamp.jpg`, when they are missing);
- `--out=<dir>` writes into another directory (a relative one is taken from the current directory) and copies the
  committed PKI and `content/stamp.jpg` there first when it has none;
- `--time=<instant>` moves the fixture clock (default `2026-11-01T09:00:00Z`).

The script runs `FixtureGenerator` in a JVM of its own, `$JAVA_HOME/bin/java` (else `java` on `PATH`, JDK 21 or
later), started with `-XX:+UnlockExperimentalVMOptions -XX:hashCode=2`.

**Regeneration is reproducible.** `FixtureGenerator` signs at a fixed fixture time (`2026-11-01T09:00:00Z`, or
`--time`); each timestamp, CRL and PDF file identifier takes the next minute of a clock started there. ECDSA nonces
and the encrypted PDF's IVs come from a seeded generator. `--new-pki` derives every key, serial number and
certificate from per-entity seeds and a fixed validity (from 2026-01-01, 20 × 365 days), so it rebuilds the same
PKI; only the salts of the `test-pki.p12` container change. `content/stamp.jpg` is drawn with AWT only when it is
missing, because font rendering differs between machines: delete it to redraw it. The JVM flag above matters: DSS
orders the certificates of a PAdES DSS dictionary by identity hash codes, and without it `pades/b-lt.pdf` and
`b-lta.pdf` (and their tampered twins) can differ between runs; the generator warns when the flag is missing.

With the same PKI, time, JDK and dependency versions, a regeneration is byte-identical. To check one:

```bash
scripts/generate-fixtures.sh --out=/abs/path/check && diff -r -x README.md testdata/fixtures /abs/path/check
```

`FixtureReproducibilityTest` checks this in two JVMs. The files committed here still come from the earlier,
time-based generator and have not been regenerated since generation became reproducible: the first regeneration
replaces every signed file, and the PDFs under `content/`, once. Review that one as a replacement (do the
expectations above still hold?), with the signing cases regenerated together with the documents they were
prepared from. After it, any difference is a real change.
