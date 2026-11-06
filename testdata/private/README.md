# testdata/private

Put real signed documents here (`.p7m`, `.pdf`, …) to include them in local and
differential test runs. Everything in this folder except this README is gitignored:
real documents usually carry personal data and must never be committed.

Detached signatures: name the content file the same as the signature without the
`.p7s` extension (e.g. `contract.pdf` + `contract.pdf.p7s`).

`scripts/diff-vs-jvm.sh` compares every document here between plain DSS on the JVM and the native library. By
default it uses the real EU LOTL (cached in `build/diff/real-cache`, filled online on first use) with online
revocation. Put a `config.json` (same format as `config_json`, see README.md) here to use another
configuration.
