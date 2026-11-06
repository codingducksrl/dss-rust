# trust/

## `oj-keystore.p12`: LOTL signing certificates

The EU List of Trusted Lists (LOTL) is signed by the European Commission. The certificates allowed to sign it
are announced in the **Official Journal of the EU** (OJ). DSS verifies the LOTL signature against this keystore
(`LOTLSource.setCertificateSource`) and checks that the LOTL's `SchemeInformationURI` points to the current OJ
publication (`oj_url`).

| | |
|---|---|
| Source | `esig/dss-demonstrations`, tag `6.5.1`, `dss-demo-webapp/src/main/resources/keystore.p12` |
| Licence | LGPL-2.1-or-later, © European Commission, as DSS (public certificates only) |
| Type / password | PKCS#12 / `dss-password` (the password protects nothing secret) |
| SHA-256 | `98a76fbcd726e3553ecdf8dec59eef1b015b0579e7514d8c26f7c6124ce382e6` |
| Matching OJ URL | `https://eur-lex.europa.eu/eli/C/2026/1944/oj` (DSS 6.5.1 demo `current.oj.url`; the `oj_url` default) |
| Entries | 6 certificates (EC "DigitalSign Qualified CA G1" signers, validity up to 2029) |
| Verified | Real-LOTL integration test on 2026-10-28: LOTL signature `TOTAL_PASSED` |

List the entries:

```bash
keytool -list -v -keystore trust/oj-keystore.p12 -storetype PKCS12 -storepass dss-password
```

## When to update it

The engine's TL status contains an `oj_url_changed` alert when the LOTL starts announcing a new OJ publication.
LOTL validation also stops returning `TOTAL_PASSED` once the EC signs with a certificate that is not in the
keystore. Pivot LOTLs bridge most rotations automatically, but not a new OJ publication.

To update:

1. Take `keystore.p12` and `current.oj.url` from the latest `esig/dss-demonstrations` release
   (`dss-demo-webapp/src/main/resources/`). Or build the keystore yourself from the certificates printed in
   the new OJ notice ("List of the Member States' trusted lists" notice in the C series):

   ```bash
   keytool -importcert -noprompt -storetype PKCS12 -keystore oj-keystore.p12 -storepass dss-password -alias <name> -file cert.pem
   ```

2. Update `EngineConfig.DEFAULT_OJ_URL`, this README and the SHA-256 above.
3. Run the online suite: `cd java && ./mvnw test -Pintegration`.

Applications can also ship their own keystore and pass `oj_keystore.path` / `oj_url` in `config_json`
without rebuilding the library.
