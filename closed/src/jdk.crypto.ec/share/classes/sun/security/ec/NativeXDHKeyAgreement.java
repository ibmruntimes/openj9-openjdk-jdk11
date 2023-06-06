/*
 * Copyright (c) 2009, 2021, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2023, 2023 All Rights Reserved
 * ===========================================================================
 */

package sun.security.ec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;

import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import jdk.crypto.jniprovider.NativeCrypto;

import sun.security.x509.X509Key;

public class NativeXDHKeyAgreement extends KeyAgreementSpi {
    private static NativeCrypto nativeCrypto;
    private static final boolean nativeCryptTrace = NativeCrypto.isTraceEnabled();

    private XECPrivateKey xecPrivateKey;
    private byte[] privateKey;
    private byte[] secret;
    private XECOperations ops;
    private final XECParameters lockedParams;

    private XDHKeyAgreement javaImplementation;

    public NativeXDHKeyAgreement() {
        lockedParams = null;
    }

    public NativeXDHKeyAgreement(AlgorithmParameterSpec paramSpec) {
        lockedParams = XECParameters.get(ProviderException::new, paramSpec);
    }

    @Override
    protected void engineInit(Key key, SecureRandom random)
            throws InvalidKeyException {

        initImpl(key);
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params,
                              SecureRandom random) throws InvalidKeyException,
        InvalidAlgorithmParameterException {

        initImpl(key);

        // The private key parameters must match params, if present.
        if (params != null) {
            XECParameters xecParams = XECParameters.get(
                InvalidAlgorithmParameterException::new, params);
            if (!xecParams.oidEquals(ops.getParameters())) {
                throw new InvalidKeyException("Incorrect private key parameters");
            }
        }
    }

    private void initImpl(Key key) throws InvalidKeyException {

        if (!(key instanceof XECPrivateKey)) {
            throw new InvalidKeyException("Unsupported key type");
        }
        xecPrivateKey = (XECPrivateKey) key;
        XECParameters xecParams = XECParameters.get(
            InvalidKeyException::new, xecPrivateKey.getParams());

        if ((lockedParams != null) && (lockedParams != xecParams)) {
            throw new InvalidKeyException("Parameters must be " + lockedParams.getName());
        }

        ops = new XECOperations(xecParams);
        privateKey = xecPrivateKey.getScalar()
                .orElseThrow(() -> new InvalidKeyException("No private key value"));
        secret = null;

        if (!NativeCrypto.isAllowedAndLoaded()) {
            if (nativeCryptTrace) {
                System.err.println("OpenSSL library not loaded." +
                    " Using Java crypto implementation to generate secret.");
            }
            initializeJavaImplementation();
        } else {
            /* Assign ID used by OpenSSL for different curves. */
            int curveType;
            if (isX25519(ops.getParameters())) {
                curveType = NativeCrypto.X25519;
            } else {
                curveType = NativeCrypto.X448;
            }

            if ((curveType == NativeCrypto.X448)
                && (NativeCrypto.getVersionIfAvailable() < NativeCrypto.OPENSSL_VERSION_3_0_0)
            ) {
                if (nativeCryptTrace) {
                    System.err.println("OpenSSL version too old for X448 key agreement (<3.x)," +
                        " using Java crypto implementation.");
                }
                initializeJavaImplementation();
            }
        }
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase)
            throws InvalidKeyException, IllegalStateException {
        byte[] computedSecret;
        if (javaImplementation != null) {
            computedSecret = javaImplComputeSecret(key, lastPhase);
        } else {
            if (privateKey == null) {
                throw new IllegalStateException("Not initialized");
            }
            if (secret != null) {
                throw new IllegalStateException("Phase already executed");
            }
            if (!lastPhase) {
                throw new IllegalStateException(
                    "Only two party agreement supported, lastPhase must be true");
            }

            if (!(key instanceof XDHPublicKeyImpl)) {
                throw new InvalidKeyException("Unsupported key type");
            }

            XDHPublicKeyImpl publicKey = (XDHPublicKeyImpl) key;

            // Ensure public key parameters are compatible with private key.
            XECParameters xecParams = XECParameters.get(InvalidKeyException::new,
                publicKey.getParams());
            if (!ops.getParameters().oidEquals(xecParams)) {
                throw new InvalidKeyException(
                    "Public key parameters are not compatible with private key.");
            }

            /* Assign ID used by OpenSSL for different curves. */
            int curveType;
            if (isX25519(ops.getParameters())) {
                curveType = NativeCrypto.X25519;
            } else {
                curveType = NativeCrypto.X448;
            }

            byte[] publicKeyArray = publicKey.getKeyAsByteArray();
            computedSecret = new byte[ops.getParameters().getBytes()];

            if (nativeCrypto == null) {
                nativeCrypto = NativeCrypto.getNativeCrypto();
            }
            int result = nativeCrypto.XDHGenerateSecret(privateKey, privateKey.length,
                                                        publicKeyArray, publicKeyArray.length,
                                                        computedSecret, computedSecret.length,
                                                        curveType);

            if (result == -1) {
                if (nativeCryptTrace) {
                    System.err.println("Shared secret generation by OpenSSL failed," +
                        " using Java crypto implementation.");
                }
                computedSecret = javaImplComputeSecret(key, lastPhase);
            }
        }

        // Test for contributory behavior.
        if (allZero(computedSecret)) {
            throw new InvalidKeyException("Point has small order");
        }

        secret = computedSecret;
        return null;
    }

    /*
     * Constant-time check for an all-zero array.
     */
    private static boolean allZero(byte[] arr) {
        byte orValue = (byte) 0;
        for (int i = 0; i < arr.length; i++) {
            orValue |= arr[i];
        }

        return orValue == (byte) 0;
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        byte[] result = secret;
        if (result == null) {
            throw new IllegalStateException("Not initialized correctly");
        }
        secret = null;
        return result;
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset)
        throws IllegalStateException, ShortBufferException {

        if (secret == null) {
            throw new IllegalStateException("Not initialized correctly");
        }
        int secretLen = secret.length;
        if (secretLen > sharedSecret.length - offset) {
            throw new ShortBufferException("Need " + secretLen
                + " bytes, only " + (sharedSecret.length - offset)
                + " available");
        }

        System.arraycopy(secret, 0, sharedSecret, offset, secretLen);
        secret = null;
        return secretLen;
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm)
            throws IllegalStateException, NoSuchAlgorithmException,
            InvalidKeyException {

        if (algorithm == null) {
            throw new NoSuchAlgorithmException("Algorithm must not be null");
        }

        if (!(algorithm.equals("TlsPremasterSecret"))) {
            throw new NoSuchAlgorithmException("Only supported for algorithm TlsPremasterSecret");
        }
        return new SecretKeySpec(engineGenerateSecret(), algorithm);
    }

    /*
     * Initializes the java implementation.
     *
     * Already set parameters are used to specify the curve type
     * and previously set private key is used to initialize the
     * engine.
     */
    private void initializeJavaImplementation() throws InvalidKeyException {
        synchronized (this) {
            if (lockedParams == null) {
                javaImplementation = new XDHKeyAgreement();
            } else {
                if (isX25519(lockedParams)) {
                    javaImplementation = new XDHKeyAgreement.X25519();
                } else {
                    javaImplementation = new XDHKeyAgreement.X448();
                }
            }
            javaImplementation.engineInit(xecPrivateKey, null);
        }
    }

    /**
     * Utilizes the java implementation to compute the shared secret.
     *
     * @param key the public key
     * @param lastPhase value indicating whether this is the last phase
     */
    private byte[] javaImplComputeSecret(Key key, boolean lastPhase) throws InvalidKeyException {
        if (javaImplementation == null) {
            initializeJavaImplementation();
        }
        javaImplementation.engineDoPhase(key, lastPhase);
        return javaImplementation.engineGenerateSecret();
    }

    private static boolean isX25519(XECParameters parameters) {
        return "X25519".equals(parameters.getName());
    }

    static final class X25519 extends NativeXDHKeyAgreement {
        public X25519() {
            super(NamedParameterSpec.X25519);
        }
    }

    static final class X448 extends NativeXDHKeyAgreement {
        public X448() {
            super(NamedParameterSpec.X448);
        }
    }
}
