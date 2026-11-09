/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.engine;

import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.tsp.TSPException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.ExtendedKeyUsage;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.TimestampBinary;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.extension.ExtendedKeyUsages;
import eu.europa.esig.dss.spi.CertificateExtensionsUtils;
import eu.europa.esig.dss.spi.x509.ListCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;

/**
 * A {@link TSPSource} that checks every token the configured TSA returns before DSS writes it into a document.
 * DSS's {@code OnlineTSPSource} only checks the response against the request (status, nonce, policy, imprint);
 * the token's own signature, the certificate behind it and its time are not looked at until someone validates the
 * document, by which time a bad token has been paid for and embedded. Here a token is refused ({@link
 * DssError.Code#TSA_FAILED}) when:
 *
 * <ul>
 *   <li>it cannot be parsed, or its message imprint is not the digest that was sent;</li>
 *   <li>it does not carry the certificate of the key that signed it, or that signature does not verify;</li>
 *   <li>that certificate was not valid at the token's time, or lacks the {@code id-kp-timeStamping} extended key
 *       usage (RFC 3161 §2.3);</li>
 *   <li>the token is signed with MD2, MD5 or SHA-1, or with an RSA key shorter than 2048 bits;</li>
 *   <li>its time is further than {@code tsa.max_clock_skew_ms} from this host's clock;</li>
 *   <li>with {@code tsa.require_trusted} (the default), its certificate does not chain to a trusted certificate
 *       (the trusted lists or {@code extra_trusted_certificates}). The check is skipped, with a warning, when
 *       the engine has no trust anchors at all, so that T-level signing keeps working without trusted lists.
 *       That includes an engine with {@code require_trusted_lists} whose cache is still empty: extending refuses
 *       there ({@code TRUSTED_LISTS_NOT_LOADED}), but signing at T needs no lists, so until the first refresh
 *       succeeds a token from any TSA is embedded unchecked (the warning is the only signal; a later validation of
 *       the document reports the timestamp as untrusted). Operators who need the check from the first call should
 *       seed the cache or list the TSA's chain in {@code extra_trusted_certificates}.</li>
 * </ul>
 *
 * <p>A TSA that cannot be reached, answers an HTTP error or returns a response DSS cannot use is also reported as
 * {@code TSA_FAILED}, so that callers can tell a TSA outage (retry later) from a refusal of their document.
 */
final class CheckedTspSource implements TSPSource {

    private static final long serialVersionUID = 1L;
    private static final Logger LOG = LoggerFactory.getLogger(CheckedTspSource.class);
    private static final Set<DigestAlgorithm> WEAK_DIGESTS = Set.of(DigestAlgorithm.MD2, DigestAlgorithm.MD5,
            DigestAlgorithm.SHA1);
    private static final int MIN_RSA_BITS = 2048;
    private static final int MAX_CHAIN_LENGTH = 16;

    /** What is checked, from {@code config_json "tsa"}. */
    record Settings(long maxClockSkewMs, boolean requireTrusted) {
        Settings {
            if (maxClockSkewMs < 0) {
                throw new IllegalArgumentException("maxClockSkewMs must not be negative");
            }
        }
    }

    private final TSPSource delegate;
    private final String url;
    private final Settings settings;
    private final transient ListCertificateSource trusted;

    /**
     * @param trusted the trust anchors the token's certificate must chain to (the verifier's trusted sources)
     */
    CheckedTspSource(TSPSource delegate, String url, Settings settings, ListCertificateSource trusted) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.url = url;
        this.settings = Objects.requireNonNull(settings, "settings");
        this.trusted = Objects.requireNonNull(trusted, "trusted");
    }

    @Override
    public TimestampBinary getTimeStampResponse(DigestAlgorithm digestAlgorithm, byte[] digest) {
        TimestampBinary binary;
        try {
            binary = delegate.getTimeStampResponse(digestAlgorithm, digest);
        } catch (DssError e) {
            throw e;
        } catch (DSSException e) {
            throw failed("the TSA at " + url + " could not be used: " + e.getMessage(), e);
        }
        if (binary == null || binary.getBytes() == null) {
            throw failed("the TSA at " + url + " returned no token");
        }
        check(binary.getBytes(), digest);
        return binary;
    }

    /** The checks listed in the class comment, on a DER token; package-private for tests. */
    void check(byte[] encoded, byte[] digest) {
        TimestampToken token;
        try {
            token = new TimestampToken(encoded, TimestampType.SIGNATURE_TIMESTAMP);
        } catch (TSPException | IOException | CMSException | RuntimeException e) {
            throw failed("the token returned by the TSA at " + url + " cannot be parsed: " + e.getMessage(), e);
        }
        if (digest != null && !token.matchData(digest, true)) {
            throw failed("the token returned by the TSA at " + url + " is not over the digest that was sent");
        }
        Date genTime = token.getGenerationTime();
        if (genTime == null) {
            throw failed("the token returned by the TSA at " + url + " has no time");
        }
        long skewMs = Math.abs(genTime.getTime() - System.currentTimeMillis());
        if (skewMs > settings.maxClockSkewMs) {
            throw failed("the token returned by the TSA at " + url + " is dated " + genTime.toInstant() + ", "
                    + (skewMs / 1000) + " s away from this host's clock (tsa.max_clock_skew_ms is "
                    + settings.maxClockSkewMs + "): one of the two clocks is wrong");
        }

        CertificateToken signer = null;
        for (CertificateToken candidate : token.getCertificates()) {
            if (token.isSignedBy(candidate)) {
                signer = candidate;
                break;
            }
        }
        if (signer == null) {
            throw failed("the token returned by the TSA at " + url + " does not carry the certificate of the key "
                    + "that signed it, or its signature does not verify");
        }
        String subject = signer.getSubject().getRFC2253();
        if (!signer.isValidOn(genTime)) {
            throw failed("the TSA certificate (" + subject + ") behind the token from " + url + " was not valid at "
                    + "the token's time " + genTime.toInstant() + ": it is valid from "
                    + signer.getNotBefore().toInstant() + " to " + signer.getNotAfter().toInstant());
        }
        ExtendedKeyUsages extended = CertificateExtensionsUtils.getExtendedKeyUsage(signer);
        List<String> purposes = extended != null && extended.getOids() != null ? extended.getOids() : List.of();
        if (!purposes.contains(ExtendedKeyUsage.TIMESTAMPING.getOid())) {
            throw failed("the TSA certificate (" + subject + ") behind the token from " + url + " lacks the "
                    + "id-kp-timeStamping extended key usage: it is not a timestamping certificate");
        }
        SignatureAlgorithm algorithm = token.getSignatureAlgorithm();
        DigestAlgorithm tokenDigest = algorithm == null ? null : algorithm.getDigestAlgorithm();
        if (tokenDigest != null && WEAK_DIGESTS.contains(tokenDigest)) {
            throw failed("the token returned by the TSA at " + url + " is signed with " + algorithm.getName()
                    + ", which is too weak for a timestamp");
        }
        if (signer.getPublicKey() instanceof RSAPublicKey rsa && rsa.getModulus().bitLength() < MIN_RSA_BITS) {
            throw failed("the TSA certificate (" + subject + ") behind the token from " + url + " has a "
                    + rsa.getModulus().bitLength() + "-bit RSA key, shorter than the " + MIN_RSA_BITS
                    + " bits a timestamp needs");
        }
        if (settings.requireTrusted) {
            if (trusted.getNumberOfCertificates() == 0) {
                LOG.warn("Accepting the timestamp from {} without a trust check: the engine has no trust anchors "
                        + "(no trusted lists loaded and no extra_trusted_certificates)", url);
            } else if (!chainsToTrustAnchor(token, signer)) {
                throw failed("the TSA certificate (" + subject + ") behind the token from " + url + " does not chain "
                        + "to a trusted certificate (the trusted lists or extra_trusted_certificates); set "
                        + "tsa.require_trusted to false to accept it anyway");
            }
        }
    }

    /** Walks issuers through the token's certificates and the trust anchors until one anchor is reached. */
    private boolean chainsToTrustAnchor(TimestampToken token, CertificateToken signer) {
        Set<String> seen = new HashSet<>();
        CertificateToken current = signer;
        for (int i = 0; i < MAX_CHAIN_LENGTH; i++) {
            if (trusted.isTrusted(current)) {
                return true;
            }
            seen.add(current.getDSSIdAsString());
            if (current.isSelfSigned()) {
                return false;
            }
            Set<CertificateToken> candidates = new LinkedHashSet<>(trusted.getBySubject(current.getIssuer()));
            for (CertificateToken c : token.getCertificates()) {
                if (c.getSubject().getPrincipal().equals(current.getIssuerX500Principal())) {
                    candidates.add(c);
                }
            }
            CertificateToken issuer = null;
            for (CertificateToken c : candidates) {
                if (!seen.contains(c.getDSSIdAsString()) && current.isSignedBy(c)) {
                    issuer = c;
                    break;
                }
            }
            if (issuer == null) {
                return false;
            }
            current = issuer;
        }
        return false;
    }

    private static DssError failed(String message) {
        return new DssError(DssError.Code.TSA_FAILED, message);
    }

    private static DssError failed(String message, Throwable cause) {
        return new DssError(DssError.Code.TSA_FAILED, message, cause);
    }
}
