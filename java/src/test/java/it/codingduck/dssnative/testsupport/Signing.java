/*
 * dss-native
 * SPDX-FileCopyrightText: 2026 Coding Duck
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
package it.codingduck.dssnative.testsupport;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.DSSSecurityProvider;

/** Signs DSS's data-to-be-signed with a JCA key, so tests need no token module. */
public final class Signing {

    private Signing() {
    }

    public static SignatureValue sign(ToBeSigned tbs, DigestAlgorithm digest, PrivateKey key) {
        return sign(tbs, SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.forKey(key), digest), key);
    }

    /** Through BouncyCastle, which knows DSS's JCE names for every scheme (e.g. RSASSA-PSS with MGF1). */
    public static SignatureValue sign(ToBeSigned tbs, SignatureAlgorithm algorithm, PrivateKey key) {
        try {
            Signature jca = Signature.getInstance(algorithm.getJCEId(), DSSSecurityProvider.getSecurityProvider());
            jca.initSign(key);
            jca.update(tbs.getBytes());
            return new SignatureValue(algorithm, jca.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
