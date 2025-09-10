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
 * (c) Copyright IBM Corp. 2023, 2025 All Rights Reserved
 * ===========================================================================
 */

package sun.security.ec;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;

import jdk.crypto.jniprovider.NativeCrypto;

import sun.security.jca.JCAUtil;
import sun.security.provider.Sun;
import sun.security.util.BitArray;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X509Key;

public class NativeXDHKeyPairGenerator extends KeyPairGeneratorSpi {
    private static NativeCrypto nativeCrypto;
    private static final boolean nativeCryptTrace = NativeCrypto.isTraceEnabled();

    private SecureRandom random;
    private XECOperations ops;
    private final XECParameters lockedParams;

    private final XDHKeyPairGenerator javaImplementation;
    private boolean useJavaImpl;

    public NativeXDHKeyPairGenerator() {
        javaImplementation = new XDHKeyPairGenerator();
        tryInitialize(NamedParameterSpec.X25519);
        lockedParams = null;
    }

    private NativeXDHKeyPairGenerator(NamedParameterSpec paramSpec) {
        if (paramSpec == NamedParameterSpec.X25519) {
            javaImplementation = new XDHKeyPairGenerator.X25519();
        } else {
            javaImplementation = new XDHKeyPairGenerator.X448();
        }
        tryInitialize(paramSpec);
        lockedParams = ops.getParameters();
    }

    private void tryInitialize(NamedParameterSpec paramSpec) {
        try {
            initialize(paramSpec, null);
        } catch (InvalidAlgorithmParameterException ex) {
            String name = paramSpec.getName();
            throw new ProviderException(name + " not supported");
        }
    }

    @Override
    public void initialize(int keySize, SecureRandom random) {
        XECParameters params = XECParameters.getBySize(
            InvalidParameterException::new, keySize);

        initializeImpl(params, random);
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {

        XECParameters xecParams = XECParameters.get(
            InvalidAlgorithmParameterException::new, params);

        initializeImpl(xecParams, random);
    }

    private void initializeImpl(XECParameters params, SecureRandom random) {

        if ((lockedParams != null) && (lockedParams != params)) {
            throw new InvalidParameterException(
                "Parameters must be " + lockedParams.getName());
        }

        ops = new XECOperations(params);
        this.random = (random != null) ? random : JCAUtil.getSecureRandom();

        useJavaImpl = false;
        javaImplementation.initialize(ops.getParameters().getBits(), this.random);
        if (random == null) {
            if (nativeCryptTrace) {
                System.err.println("No SecureRandom implementation was provided during"
                        + " initialization. Using OpenSSL.");
            }
        } else if ((random.getProvider() instanceof Sun)
            && ("NativePRNG".equals(random.getAlgorithm()) || "DRBG".equals(random.getAlgorithm()))
        ) {
            if (nativeCryptTrace) {
                System.err.println("Default SecureRandom implementation was provided during"
                        + " initialization. Using OpenSSL.");
            }
        } else {
            if (nativeCryptTrace) {
                System.err.println("SecureRandom implementation was provided during"
                        + " initialization. Using Java implementation instead of OpenSSL.");
            }
            useJavaImpl = true;
        }
    }

    @Override
    public KeyPair generateKeyPair() {
        /*
         * When the keypair generator is initialized with
         * anything other than the default SecureRandom
         * implementation, use the Java implementation
         * to generate the keypair.
         */
        if (useJavaImpl) {
            return javaImplementation.generateKeyPair();
        }

        /* If library isn't loaded, use Java implementation. */
        if (!NativeCrypto.isAllowedAndLoaded()) {
            if (nativeCryptTrace) {
                System.err.println("OpenSSL library not loaded. Using Java crypto implementation to generate KeyPair.");
            }
            return javaImplementation.generateKeyPair();
        }

        XECParameters params;
        if (lockedParams != null) {
            params = lockedParams;
        } else {
            params = ops.getParameters();
        }

        /* Find ID used by OpenSSL for different curves. */
        int curveType;
        if (isX25519(params)) {
            curveType = NativeCrypto.X25519;
        } else {
            curveType = NativeCrypto.X448;
        }

        /* Create empty byte arrays for private and public keys. */
        byte[] privateKey = new byte[params.getBytes()];
        byte[] publicKey = new byte[params.getBytes()];

        if (nativeCrypto == null) {
            nativeCrypto = NativeCrypto.getNativeCrypto();
        }

        /* Compute private and public keys. */
        int result = nativeCrypto.XDHCreateKeys(privateKey, privateKey.length, publicKey, publicKey.length, curveType);

        /* If OpenSSL method fails, revert to Java implementation. */
        if (result == -1) {
            if (nativeCryptTrace) {
                System.err.println("KeyPair generation by OpenSSL failed, using Java crypto implementation.");
            }
            return javaImplementation.generateKeyPair();
        }
        try {
            reverse(publicKey);

            // Clear the extra bits.
            int bitsMod8 = params.getBits() % 8;
            if (bitsMod8 != 0) {
                int mask = (1 << bitsMod8) - 1;
                publicKey[0] &= (byte) mask;
            }

            BigInteger u = new BigInteger(1, publicKey);

            return new KeyPair(
                new XDHPublicKeyImpl(params, u),
                new XDHPrivateKeyImpl(params, privateKey)
            );
        } catch (InvalidKeyException ex) {
            throw new ProviderException(ex);
        }
    }

    private static void swap(byte[] arr, int i, int j) {
        byte tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }

    private static void reverse(byte[] arr) {
        int i = 0;
        int j = arr.length - 1;

        while (i < j) {
            swap(arr, i, j);
            i++;
            j--;
        }
    }

    private static boolean isX25519(XECParameters parameters) {
        return "X25519".equals(parameters.getName());
    }

    static final class X25519 extends NativeXDHKeyPairGenerator {
        public X25519() {
            super(NamedParameterSpec.X25519);
        }
    }

    static final class X448 extends NativeXDHKeyPairGenerator {
        public X448() {
            super(NamedParameterSpec.X448);
        }
    }
}
