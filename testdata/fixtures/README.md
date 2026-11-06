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
| `pki/test-pki.p12` | Test PKI (password `dss-native-test`), valid 2026–2045 | n/a |
| `pki/root-ca.pem` | Test root, for `extra_trusted_certificates` | n/a |
| `signing/<case>.json`, `signing/<case>.sig` | External signing: `options_json` with a fixed signing time, and what an external signer returned for the digest `dss_sign_prepare` gives (`pades-cms`, `cades-cms`: a BER CMS with a signature timestamp; `pades-signature-value`, `cades-signature-value`: an RSA signature value) | `dss_sign_complete` succeeds: PAdES/CAdES-BASELINE-T for the CMS cases, -B for the others. It needs the same digest again, so it also checks that preparing is deterministic |

Expectations are asserted in `FixtureValidationTest` (the `signing/` cases in the Rust tests and the C smoke
test). Regenerate the documents with `scripts/generate-fixtures.sh`, with `--new-pki` to also replace the PKI, or
with `--signing-only` to rewrite only `signing/`.
