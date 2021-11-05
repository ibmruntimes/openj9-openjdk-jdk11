/*
 * Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
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
 * (c) Copyright IBM Corp. 2018, 2021 All Rights Reserved
 * ===========================================================================
 */
package com.sun.crypto.provider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.VarHandle;
import java.lang.ref.Cleaner;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.*;
import sun.security.util.DerValue;

import jdk.crypto.jniprovider.NativeCrypto;
import jdk.internal.ref.CleanerFactory;

/**
 * Implementation of the ChaCha20 cipher, as described in RFC 7539.
 *
 * @since 11
 */
abstract class NativeChaCha20Cipher extends CipherSpi {
    // Mode constants
    private static final int MODE_NONE = 0;
    private static final int MODE_AEAD = 1;

    private static final int CIPHERBUF_BASE = 1024;

    // The initialization state of the cipher
    private boolean initialized;

    // The mode of operation for this object
    protected int mode;

    // The direction (encrypt vs. decrypt) for the data flow
    private int direction;

    // Has all AAD data been provided (i.e. have we called our first update)
    private boolean aadDone = false;

    // The key's encoding in bytes for this object
    private byte[] keyBytes;

    // The nonce used for this object
    private byte[] nonce;

    // The counter
    private long counter;

    // AEAD-related fields and constants
    private static final int TAG_LENGTH = 16;
    private long aadLen;

    // The underlying engine for doing the ChaCha20/Poly1305 work
    private ChaChaEngine engine;

    private static final NativeCrypto nativeCrypto;
    private static final Cleaner contextCleaner;
    private final long context;

    private final ByteArrayOutputStream aadBuf;

    static {
        nativeCrypto = NativeCrypto.getNativeCrypto();
        contextCleaner = CleanerFactory.cleaner();
    }

    private static final class ChaCha20CleanerRunnable implements Runnable {
        private final long context;

        public ChaCha20CleanerRunnable(long context) {
            this.context = context;
        }

        @Override
        public void run() {
            /*
             * Release the ChaCha20 context.
             */
            nativeCrypto.DestroyContext(context);
        }
    }

    /**
     * Default constructor.
     */
    protected NativeChaCha20Cipher() {
        context = nativeCrypto.CreateContext();

        if (context == -1) {
            throw new ProviderException("Error in NativeChaCha20Cipher - CreateContext");
        }
        contextCleaner.register(this, new ChaCha20CleanerRunnable(this.context));

        aadBuf = new ByteArrayOutputStream();
    }

    private NativeChaCha20Cipher(int mode) {
        this();
        this.mode = mode;
    }

    /**
     * Set the mode of operation.  Since this is a stream cipher, there
     * is no mode of operation in the block-cipher sense of things.  The
     * protected {@code mode} field will only accept a value of {@code None}
     * (case-insensitive).
     *
     * @param mode The mode value
     *
     * @throws NoSuchAlgorithmException if a mode of operation besides
     *      {@code None} is provided.
     */
    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (mode.equalsIgnoreCase("None") == false) {
            throw new NoSuchAlgorithmException("Mode must be None");
        }
    }

    /**
     * Set the padding scheme.  Padding schemes do not make sense with stream
     * ciphers, but allow {@code NoPadding}.  See JCE spec.
     *
     * @param padding The padding type.  The only allowed value is
     *      {@code NoPadding} case insensitive).
     *
     * @throws NoSuchPaddingException if a padding scheme besides
     *      {@code NoPadding} is provided.
     */
    @Override
    protected void engineSetPadding(String padding)
            throws NoSuchPaddingException {
        if (padding.equalsIgnoreCase("NoPadding") == false) {
            throw new NoSuchPaddingException("Padding must be NoPadding");
        }
    }

    /**
     * Returns the block size.  For a stream cipher like ChaCha20, this
     * value will always be zero.
     *
     * @return This method always returns 0.  See the JCE Specification.
     */
    @Override
    protected int engineGetBlockSize() {
        return 0;
    }

    /**
     * Get the output size based on an input length.  In simple stream-cipher
     * mode, the output size will equal the input size.  For ChaCha20-Poly1305
     * for encryption the output size will be the sum of the input length
     * and tag length.  For decryption, the output size will be the sum of
     * 1. The input length less the tag length or zero, whichever is larger.
     * 2. The unprocessed input length.
     *
     * @param inputLen the length in bytes of the input.
     *
     * @return the output length in bytes.
     */
    @Override
    protected int engineGetOutputSize(int inputLen) {
        int outLen = 0;

        if (mode == MODE_NONE) {
            outLen = inputLen;
        } else if (mode == MODE_AEAD) {
            if (direction == Cipher.ENCRYPT_MODE) {
                outLen = Math.addExact(inputLen, TAG_LENGTH);
            } else {
                outLen = Integer.max(inputLen, TAG_LENGTH) - TAG_LENGTH;
                outLen = Math.addExact(outLen, engine.getCipherBufferLength());
            }
        }

        return outLen;
    }

    /**
     * Get the nonce value used.
     *
     * @return the nonce bytes.  For ChaCha20 this will be a 12-byte value.
     */
    @Override
    protected byte[] engineGetIV() {
        return (nonce != null) ? nonce.clone() : null;
    }

    /**
     * Get the algorithm parameters for this cipher.  For the ChaCha20
     * cipher, this will always return {@code null} as there currently is
     * no {@code AlgorithmParameters} implementation for ChaCha20.  For
     * ChaCha20-Poly1305, a {@code ChaCha20Poly1305Parameters} object will be
     * created and initialized with the configured nonce value and returned
     * to the caller.
     *
     * @return a {@code null} value if the ChaCha20 cipher is used (mode is
     * MODE_NONE), or a {@code ChaCha20Poly1305Parameters} object containing
     * the nonce if the mode is MODE_AEAD.
     */
    @Override
    protected AlgorithmParameters engineGetParameters() {
        AlgorithmParameters params = null;
        byte[] nonceData = (nonce != null) ? nonce : createRandomNonce(null);
        if (mode == MODE_AEAD) {
            try {
                // Force the 12-byte nonce into a DER-encoded OCTET_STRING
                byte[] derNonce = new byte[nonceData.length + 2];
                derNonce[0] = 0x04;                 // OCTET_STRING tag
                derNonce[1] = (byte)nonceData.length;   // 12-byte length;
                System.arraycopy(nonceData, 0, derNonce, 2, nonceData.length);
                params = AlgorithmParameters.getInstance("ChaCha20-Poly1305");
                params.init(derNonce);
            } catch (NoSuchAlgorithmException | IOException exc) {
                throw new RuntimeException(exc);
            }
        }
        return params;
    }

    /**
     * Initialize the engine using a key and secure random implementation.  If
     * a SecureRandom object is provided it will be used to create a random
     * nonce value.  If the {@code random} parameter is null an internal
     * secure random source will be used to create the random nonce.
     * The counter value will be set to 1.
     *
     * @param opmode the type of operation to do.  This value may not be
     *      {@code Cipher.DECRYPT_MODE} or {@code Cipher.UNWRAP_MODE} mode
     *      because it must generate random parameters like the nonce.
     * @param key a 256-bit key suitable for ChaCha20
     * @param random a {@code SecureRandom} implementation used to create the
     *      random nonce.  If {@code null} is used for the random object,
     *      then an internal secure random source will be used to create the
     *      nonce.
     *
     * @throws UnsupportedOperationException if the mode of operation
     *      is {@code Cipher.WRAP_MODE} or {@code Cipher.UNWRAP_MODE}
     *      (currently unsupported).
     * @throws InvalidKeyException if the key is of the wrong type or is
     *      not 256-bits in length.  This will also be thrown if the opmode
     *      parameter is {@code Cipher.DECRYPT_MODE}.
     *      {@code Cipher.UNWRAP_MODE} would normally be disallowed in this
     *      context but it is preempted by the UOE case above.
     */
    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random)
            throws InvalidKeyException {
        if (opmode != Cipher.DECRYPT_MODE) {
            byte[] newNonce = createRandomNonce(random);
            counter = 1;
            init(opmode, key, newNonce);
        } else {
            throw new InvalidKeyException("Default parameter generation " +
                "disallowed in DECRYPT and UNWRAP modes");
        }
    }

    /**
     * Initialize the engine using a key and secure random implementation.
     *
     * @param opmode the type of operation to do.  This value must be either
     *      {@code Cipher.ENCRYPT_MODE} or {@code Cipher.DECRYPT_MODE}
     * @param key a 256-bit key suitable for ChaCha20
     * @param params a {@code ChaCha20ParameterSpec} that will provide
     *      the nonce and initial block counter value.
     * @param random a {@code SecureRandom} implementation, this parameter
     *      is not used in this form of the initializer.
     *
     * @throws UnsupportedOperationException if the mode of operation
     *      is {@code Cipher.WRAP_MODE} or {@code Cipher.UNWRAP_MODE}
     *      (currently unsupported).
     * @throws InvalidKeyException if the key is of the wrong type or is
     *      not 256-bits in length.  This will also be thrown if the opmode
     *      parameter is not {@code Cipher.ENCRYPT_MODE} or
     *      {@code Cipher.DECRYPT_MODE} (excepting the UOE case above).
     * @throws InvalidAlgorithmParameterException if {@code params} is
     *      not a {@code ChaCha20ParameterSpec}
     */
    @Override
    protected void engineInit(int opmode, Key key,
            AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {

        // If AlgorithmParameterSpec is null, then treat this like an init
        // of the form (int, Key, SecureRandom)
        if (params == null) {
            engineInit(opmode, key, random);
            return;
        }

        // We will ignore the secure random implementation and use the nonce
        // from the AlgorithmParameterSpec instead.
        byte[] newNonce = null;
        switch (mode) {
            case MODE_NONE:
                if (!(params instanceof ChaCha20ParameterSpec)) {
                    throw new InvalidAlgorithmParameterException(
                        "ChaCha20 algorithm requires ChaCha20ParameterSpec");
                }
                ChaCha20ParameterSpec chaParams = (ChaCha20ParameterSpec)params;
                newNonce = chaParams.getNonce();
                // first 32 bits of counter is always 0
                counter = ((long)chaParams.getCounter()) & 0x00000000FFFFFFFFL;
                break;
            case MODE_AEAD:
                if (!(params instanceof IvParameterSpec)) {
                    throw new InvalidAlgorithmParameterException(
                        "ChaCha20-Poly1305 requires IvParameterSpec");
                }
                IvParameterSpec ivParams = (IvParameterSpec)params;
                newNonce = ivParams.getIV();
                if (newNonce.length != 12) {
                    throw new InvalidAlgorithmParameterException(
                        "ChaCha20-Poly1305 nonce must be 12 bytes in length");
                }
                break;
            default:
                // Should never happen
                throw new RuntimeException("ChaCha20 in unsupported mode");
        }
        init(opmode, key, newNonce);
    }

    /**
     * Initialize the engine using the {@code AlgorithmParameter} initialization
     * format.  This cipher does supports initialization with
     * {@code AlgorithmParameter} objects for ChaCha20-Poly1305 but not for
     * ChaCha20 as a simple stream cipher.  In the latter case, it will throw
     * an {@code InvalidAlgorithmParameterException} if the value is non-null.
     * If a null value is supplied for the {@code params} field
     * the cipher will be initialized with the counter value set to 1 and
     * a random nonce.  If {@code null} is used for the random object,
     * then an internal secure random source will be used to create the
     * nonce.
     *
     * @param opmode the type of operation to do.  This value must be either
     *      {@code Cipher.ENCRYPT_MODE} or {@code Cipher.DECRYPT_MODE}
     * @param key a 256-bit key suitable for ChaCha20
     * @param params a {@code null} value if the algorithm is ChaCha20, or
     *      the appropriate {@code AlgorithmParameters} object containing the
     *      nonce information if the algorithm is ChaCha20-Poly1305.
     * @param random a {@code SecureRandom} implementation, may be {@code null}.
     *
     * @throws UnsupportedOperationException if the mode of operation
     *      is {@code Cipher.WRAP_MODE} or {@code Cipher.UNWRAP_MODE}
     *      (currently unsupported).
     * @throws InvalidKeyException if the key is of the wrong type or is
     *      not 256-bits in length.  This will also be thrown if the opmode
     *      parameter is not {@code Cipher.ENCRYPT_MODE} or
     *      {@code Cipher.DECRYPT_MODE} (excepting the UOE case above).
     * @throws InvalidAlgorithmParameterException if {@code params} is
     *      non-null and the algorithm is ChaCha20.  This exception will be
     *      also thrown if the algorithm is ChaCha20-Poly1305 and an incorrect
     *      {@code AlgorithmParameters} object is supplied.
     */
    @Override
    protected void engineInit(int opmode, Key key,
            AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {

        // If AlgorithmParameters is null, then treat this like an init
        // of the form (int, Key, SecureRandom)
        if (params == null) {
            engineInit(opmode, key, random);
            return;
        }

        byte[] newNonce = null;
        switch (mode) {
            case MODE_NONE:
                throw new InvalidAlgorithmParameterException(
                        "AlgorithmParameters not supported");
            case MODE_AEAD:
                String paramAlg = params.getAlgorithm();
                if (!paramAlg.equalsIgnoreCase("ChaCha20-Poly1305")) {
                    throw new InvalidAlgorithmParameterException(
                            "Invalid parameter type: " + paramAlg);
                }
                try {
                    DerValue dv = new DerValue(params.getEncoded());
                    newNonce = dv.getOctetString();
                    if (newNonce.length != 12) {
                        throw new InvalidAlgorithmParameterException(
                                "ChaCha20-Poly1305 nonce must be " +
                                "12 bytes in length");
                    }
                } catch (IOException ioe) {
                    throw new InvalidAlgorithmParameterException(ioe);
                }
                break;
            default:
                throw new RuntimeException("Invalid mode: " + mode);
        }

        // Continue with initialization
        init(opmode, key, newNonce);
    }

    /**
     * Update additional authenticated data (AAD).
     *
     * @param src the byte array containing the authentication data.
     * @param offset the starting offset in the buffer to update.
     * @param len the amount of authentication data to update.
     *
     * @throws IllegalStateException if the cipher has not been initialized,
     *      {@code engineUpdate} has been called, or the cipher is running
     *      in a non-AEAD mode of operation.  It will also throw this
     *      exception if the submitted AAD would overflow a 64-bit length
     *      counter.
     */
    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        if (!initialized) {
            // We know that the cipher has not been initialized if the key
            // is still null.
            throw new IllegalStateException(
                    "Attempted to update AAD on uninitialized Cipher");
        } else if (aadDone) {
            // No AAD updates allowed after the PT/CT update method is called
            throw new IllegalStateException("Attempted to update AAD on " +
                    "Cipher after plaintext/ciphertext update");
        } else if (mode != MODE_AEAD) {
            throw new IllegalStateException(
                    "Cipher is running in non-AEAD mode");
        } else {
            try {
                aadLen = Math.addExact(aadLen, len);
                // Cache all the aad data in aadBuf
                aadBuf.write(src, offset, len);
            } catch (ArithmeticException ae) {
                throw new IllegalStateException("AAD overflow", ae);
            }
        }
    }

    /**
     * Update additional authenticated data (AAD).
     *
     * @param src the ByteBuffer containing the authentication data.
     *
     * @throws IllegalStateException if the cipher has not been initialized,
     *      {@code engineUpdate} has been called, or the cipher is running
     *      in a non-AEAD mode of operation.  It will also throw this
     *      exception if the submitted AAD would overflow a 64-bit length
     *      counter.
     */
    @Override
    protected void engineUpdateAAD(ByteBuffer src) {
        if (!initialized) {
            // We know that the cipher has not been initialized if the key
            // is still null.
            throw new IllegalStateException(
                    "Attempted to update AAD on uninitialized Cipher");
        } else if (aadDone) {
            // No AAD updates allowed after the PT/CT update method  is called
            throw new IllegalStateException("Attempted to update AAD on " +
                    "Cipher after plaintext/ciphertext update");
        } else if (mode != MODE_AEAD) {
            throw new IllegalStateException(
                    "Cipher is running in non-AEAD mode");
        } else {
            try {
                aadLen = Math.addExact(aadLen, src.remaining());

                // convert ByteBuffer to Array and put into aadBuf
                byte[] temp_arr = new byte[src.remaining()];
                src.get(temp_arr);
                // Cache all the aad data in aadBuf
                aadBuf.write(temp_arr, 0, temp_arr.length);

            } catch (ArithmeticException ae) {
                throw new IllegalStateException("AAD overflow", ae);
            }
        }
    }

    /**
     * Create a random 12-byte nonce.
     *
     * @param random a {@code SecureRandom} object.  If {@code null} is
     * provided a new {@code SecureRandom} object will be instantiated.
     *
     * @return a 12-byte array containing the random nonce.
     */
    private byte[] createRandomNonce(SecureRandom random) {
        byte[] newNonce = new byte[12];
        SecureRandom rand = (random != null) ? random : new SecureRandom();
        rand.nextBytes(newNonce);
        return newNonce;
    }

    /**
     * Perform additional initialization actions based on the key and operation
     * type.
     *
     * @param opmode the type of operation to do.  This value must be either
     *      {@code Cipher.ENCRYPT_MODE} or {@code Cipher.DECRYPT_MODE}
     * @param key a 256-bit key suitable for ChaCha20
     * @param newNonce the new nonce value for this initialization.
     *
     * @throws UnsupportedOperationException if the {@code opmode} parameter
     *      is {@code Cipher.WRAP_MODE} or {@code Cipher.UNWRAP_MODE}
     *      (currently unsupported).
     * @throws InvalidKeyException if the {@code opmode} parameter is not
     *      {@code Cipher.ENCRYPT_MODE} or {@code Cipher.DECRYPT_MODE}, or
     *      if the key format is not {@code RAW}.
     */
    private void init(int opmode, Key key, byte[] newNonce)
            throws InvalidKeyException {

        if ((opmode == Cipher.WRAP_MODE) || (opmode == Cipher.UNWRAP_MODE)) {
            throw new UnsupportedOperationException(
                    "WRAP_MODE and UNWRAP_MODE are not currently supported");
        } else if ((opmode != Cipher.ENCRYPT_MODE) &&
                (opmode != Cipher.DECRYPT_MODE)) {
            throw new InvalidKeyException("Unknown opmode: " + opmode);
        }

        // Make sure that the provided key and nonce are unique before
        // assigning them to the object.
        byte[] newKeyBytes = getEncodedKey(key);
        checkKeyAndNonce(newKeyBytes, newNonce);
        this.keyBytes = newKeyBytes;
        nonce = newNonce;

        // ossl_mode:
        // 0 : ChaCha20-Poly1305 decrypt
        // 1 : ChaCha20-Poly1305 encrypt
        // 2 : ChaCha20 streaming
        int ossl_mode = -1;

        // openssl_iv is only used by OpenSSL, here is the format:
        // Streaming mode: 16 bytes
        //                 first 4 bytes is the block counter (little-endian unsigned 32 bit int)
        //                 the last 12 bytes is the nonce
        // Poly1305 mode:  12 bytes nonce
        byte[] openssl_iv = null;

        if (mode == MODE_NONE) {
            engine = new EngineStreamOnly();
            ossl_mode = 2;
            byte[] counter_byte = intToLittleEndian(counter);

            openssl_iv = new byte[16];
            System.arraycopy(counter_byte, 0, openssl_iv, 0, counter_byte.length /* 4 */);
            System.arraycopy(nonce, 0, openssl_iv, 4, nonce.length /* 12 */);

        } else if (mode == MODE_AEAD) {
            openssl_iv = nonce;
            if (opmode == Cipher.ENCRYPT_MODE) {
                engine = new EngineAEADEnc();
                ossl_mode = 1;
            } else if (opmode == Cipher.DECRYPT_MODE) {
                engine = new EngineAEADDec();
                ossl_mode = 0;
            } else {
                throw new InvalidKeyException("Not encrypt or decrypt mode");
            }
        }

        direction = opmode;
        aadDone = false;
        initialized = true;

        int ret = nativeCrypto.ChaCha20Init(context, ossl_mode, openssl_iv, openssl_iv.length, keyBytes, keyBytes.length);
    }

    /**
     * Check the key and nonce bytes to make sure that they do not repeat
     * across reinitialization.
     *
     * @param newKeyBytes the byte encoding for the newly provided key
     * @param newNonce the new nonce to be used with this initialization
     *
     * @throws InvalidKeyException if both the key and nonce match the
     *      previous initialization.
     *
     */
    private void checkKeyAndNonce(byte[] newKeyBytes, byte[] newNonce)
            throws InvalidKeyException {
        // A new initialization must have either a different key or nonce
        // so the starting state for each block is not the same as the
        // previous initialization.
        if (MessageDigest.isEqual(newKeyBytes, keyBytes) &&
                MessageDigest.isEqual(newNonce, nonce)) {
            throw new InvalidKeyException(
                    "Matching key and nonce from previous initialization");
        }
    }

    /**
     * Return the encoded key as a byte array
     *
     * @param key the {@code Key} object used for this {@code Cipher}
     *
     * @return the key bytes
     *
     * @throws InvalidKeyException if the key is of the wrong type or length,
     *      or if the key encoding format is not {@code RAW}.
     */
    private static byte[] getEncodedKey(Key key) throws InvalidKeyException {
        if ("RAW".equals(key.getFormat()) == false) {
            throw new InvalidKeyException("Key encoding format must be RAW");
        }
        byte[] encodedKey = key.getEncoded();
        if (encodedKey == null || encodedKey.length != 32) {
            throw new InvalidKeyException("Key length must be 256 bits");
        }
        return encodedKey;
    }

    /**
     * Update the currently running operation with additional data
     *
     * @param in the plaintext or ciphertext input bytes (depending on the
     *      operation type).
     * @param inOfs the offset into the input array
     * @param inLen the length of the data to use for the update operation.
     *
     * @return the resulting plaintext or ciphertext bytes (depending on
     *      the operation type)
     */
    @Override
    protected byte[] engineUpdate(byte[] in, int inOfs, int inLen) {
        byte[] out = new byte[inLen];
        try {
            int size = engine.doUpdate(in, inOfs, inLen, out, 0);
            // Special case for EngineAEADDec, doUpdate only buffers the input
            // So the output array must be empty since no encryption happened yet
            if (size == 0) {
                return new byte[0];
            }
        } catch (ShortBufferException | KeyException exc) {
            throw new RuntimeException(exc);
        }

        return out;
    }

    /**
     * Update the currently running operation with additional data
     *
     * @param in the plaintext or ciphertext input bytes (depending on the
     *      operation type).
     * @param inOfs the offset into the input array
     * @param inLen the length of the data to use for the update operation.
     * @param out the byte array that will hold the resulting data.  The array
     *      must be large enough to hold the resulting data.
     * @param outOfs the offset for the {@code out} buffer to begin writing
     *      the resulting data.
     *
     * @return the length in bytes of the data written into the {@code out}
     *      buffer.
     *
     * @throws ShortBufferException if the buffer {@code out} does not have
     *      enough space to hold the resulting data.
     */
    @Override
    protected int engineUpdate(byte[] in, int inOfs, int inLen,
            byte[] out, int outOfs) throws ShortBufferException {
        int bytesUpdated = 0;
        try {
            bytesUpdated = engine.doUpdate(in, inOfs, inLen, out, outOfs);
        } catch (KeyException ke) {
            throw new RuntimeException(ke);
        }
        return bytesUpdated;
    }

    /**
     * Complete the currently running operation using any final
     * data provided by the caller.
     *
     * @param in the plaintext or ciphertext input bytes (depending on the
     *      operation type).
     * @param inOfs the offset into the input array
     * @param inLen the length of the data to use for the update operation.
     *
     * @return the resulting plaintext or ciphertext bytes (depending on
     *      the operation type)
     *
     * @throws AEADBadTagException if, during decryption, the provided tag
     *      does not match the calculated tag.
     */
    @Override
    protected byte[] engineDoFinal(byte[] in, int inOfs, int inLen)
            throws AEADBadTagException {
        byte[] output = new byte[engineGetOutputSize(inLen)];
        try {
            engine.doFinal(in, inOfs, inLen, output, 0);
        } catch (ShortBufferException | KeyException exc) {
            throw new RuntimeException(exc);
        } finally {
            // Regardless of what happens, the cipher cannot be used for
            // further processing until it has been freshly initialized.
            initialized = false;
        }
        return output;
    }

    /**
     * Complete the currently running operation using any final
     * data provided by the caller.
     *
     * @param in the plaintext or ciphertext input bytes (depending on the
     *      operation type).
     * @param inOfs the offset into the input array
     * @param inLen the length of the data to use for the update operation.
     * @param out the byte array that will hold the resulting data.  The array
     *      must be large enough to hold the resulting data.
     * @param outOfs the offset for the {@code out} buffer to begin writing
     *      the resulting data.
     *
     * @return the length in bytes of the data written into the {@code out}
     *      buffer.
     *
     * @throws ShortBufferException if the buffer {@code out} does not have
     *      enough space to hold the resulting data.
     * @throws AEADBadTagException if, during decryption, the provided tag
     *      does not match the calculated tag.
     */
    @Override
    protected int engineDoFinal(byte[] in, int inOfs, int inLen, byte[] out,
            int outOfs) throws ShortBufferException, AEADBadTagException {

        int bytesUpdated = 0;
        try {
            bytesUpdated = engine.doFinal(in, inOfs, inLen, out, outOfs);
        } catch (KeyException ke) {
            throw new RuntimeException(ke);
        } finally {
            // Regardless of what happens, the cipher cannot be used for
            // further processing until it has been freshly initialized.
            initialized = false;
        }
        return bytesUpdated;
    }

    /**
     * Wrap a {@code Key} using this Cipher's current encryption parameters.
     *
     * @param key the key to wrap.  The data that will be encrypted will
     *      be the provided {@code Key} in its encoded form.
     *
     * @return a byte array consisting of the wrapped key.
     *
     * @throws UnsupportedOperationException this will (currently) always
     *      be thrown, as this method is not currently supported.
     */
    @Override
    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException,
            InvalidKeyException {
        throw new UnsupportedOperationException(
                "Wrap operations are not supported");
    }

    /**
     * Unwrap a {@code Key} using this Cipher's current encryption parameters.
     *
     * @param wrappedKey the key to unwrap.
     * @param algorithm the algorithm associated with the wrapped key
     * @param type the type of the wrapped key. This is one of
     *      {@code SECRET_KEY}, {@code PRIVATE_KEY}, or {@code PUBLIC_KEY}.
     *
     * @return the unwrapped key as a {@code Key} object.
     *
     * @throws UnsupportedOperationException this will (currently) always
     *      be thrown, as this method is not currently supported.
     */
    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String algorithm,
            int type) throws InvalidKeyException, NoSuchAlgorithmException {
        throw new UnsupportedOperationException(
                "Unwrap operations are not supported");
    }

    /**
     * Get the length of a provided key in bits.
     *
     * @param key the key to be evaluated
     *
     * @return the length of the key in bits
     *
     * @throws InvalidKeyException if the key is invalid or does not
     *      have an encoded form.
     */
    @Override
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        byte[] encodedKey = getEncodedKey(key);
        return encodedKey.length << 3;
    }

    /**
     * Convert positive 32 bit integer to unsigned little-Endian byte array.
     *
     * If the number is larger than 32 bits, then the extra
     * bits will be ignored
     */
    private static byte[] intToLittleEndian (long i) {
        byte[] ret = new byte[4];
        ret[0] = (byte) (i & 0xFF);
        ret[1] = (byte) ((i >> 8) & 0xFF);
        ret[2] = (byte) ((i >> 16) & 0xFF);
        ret[3] = (byte) ((i >> 24) & 0xFF);
        return ret;
    }

    /**
     * Interface for the underlying processing engines for ChaCha20
     */
    interface ChaChaEngine {
        /**
         * Perform a multi-part update for ChaCha20.
         *
         * @param in the input data.
         * @param inOff the offset into the input.
         * @param inLen the length of the data to process.
         * @param out the output buffer.
         * @param outOff the offset at which to write the output data.
         *
         * @return the number of output bytes written.
         *
         * @throws ShortBufferException if the output buffer does not
         *      provide enough space.
         * @throws KeyException if the counter value has been exhausted.
         */
        int doUpdate(byte[] in, int inOff, int inLen, byte[] out, int outOff)
                throws ShortBufferException, KeyException;

        /**
         * Finalize a multi-part or single-part ChaCha20 operation.
         *
         * @param in the input data.
         * @param inOff the offset into the input.
         * @param inLen the length of the data to process.
         * @param out the output buffer.
         * @param outOff the offset at which to write the output data.
         *
         * @return the number of output bytes written.
         *
         * @throws ShortBufferException if the output buffer does not
         *      provide enough space.
         * @throws AEADBadTagException if in decryption mode the provided
         *      tag and calculated tag do not match.
         * @throws KeyException if the counter value has been exhausted.
         */
        int doFinal(byte[] in, int inOff, int inLen, byte[] out, int outOff)
                throws ShortBufferException, AEADBadTagException, KeyException;

        /**
        * Returns the length of the unprocessed input.
        * Only used in EngineAEADDec since AEADDec does not process input in doUpdate().
        * In other engines, the function should return zero.
        *
        * @return the number of unprocessed bytes left.
        */
        int getCipherBufferLength();
    }

    private final class EngineStreamOnly implements ChaChaEngine {

        EngineStreamOnly() { }

        @Override
        public synchronized int doUpdate(byte[] in, int inOff, int inLen, byte[] out,
                int outOff) throws ShortBufferException, KeyException {
            if (initialized) {
               try {
                    if (out != null) {
                        Objects.checkFromIndexSize(outOff, inLen, out.length);
                    } else {
                        throw new ShortBufferException(
                                "Output buffer too small");
                    }
                } catch (IndexOutOfBoundsException iobe) {
                    throw new ShortBufferException("Output buffer too small");
                }

                Objects.checkFromIndexSize(inOff, inLen, in.length);
                int ret = nativeCrypto.ChaCha20Update(context, in, inOff, inLen, out, outOff, /*aadArray*/ null, /*aadArray.length*/ 0);
                if (ret == -1) {
                    throw new ProviderException("Error in Native ChaCha20Cipher");
                }
                return inLen;
            } else {
                throw new IllegalStateException(
                        "Must use either a different key or iv");
            }
        }

        @Override
        public int doFinal(byte[] in, int inOff, int inLen, byte[] out,
                int outOff) throws ShortBufferException, KeyException {
            if (in != null) {
                return doUpdate(in, inOff, inLen, out, outOff);
            } else {
                return inLen;
            }
        }

        @Override
        public int getCipherBufferLength() {
            return 0;
        }
    }

    private final class EngineAEADEnc implements ChaChaEngine {

        EngineAEADEnc() throws InvalidKeyException {
            counter = 1;
        }

        @Override
        public synchronized int doUpdate(byte[] in, int inOff, int inLen, byte[] out,
                int outOff) throws ShortBufferException, KeyException {
            if (initialized) {
                // If this is the first update since AAD updates, signal that
                // we're done processing AAD info
                if (!aadDone) {
                    aadDone = true;
                }
                try {
                    if (out != null) {
                        Objects.checkFromIndexSize(outOff, inLen, out.length);
                    } else {
                        throw new ShortBufferException(
                                "Output buffer too small");
                    }
                } catch (IndexOutOfBoundsException iobe) {
                    throw new ShortBufferException("Output buffer too small");
                }

                Objects.checkFromIndexSize(inOff, inLen, in.length);

                byte aadArray[] = aadBuf.toByteArray();
                aadBuf.reset();
                int ret = nativeCrypto.ChaCha20Update(context, in, inOff, inLen, out, outOff, aadArray, aadArray.length);
                if (ret == -1) {
                    throw new ProviderException("Error in Native CipherBlockChaining");
                }

                return inLen;
            } else {
                throw new IllegalStateException(
                        "Must use either a different key or iv");
            }
        }

        @Override
        public synchronized int doFinal(byte[] in, int inOff, int inLen, byte[] out,
                int outOff) throws ShortBufferException, KeyException {
            // Make sure we have enough room for the remaining data (if any)
            // and the tag.
            if ((inLen + TAG_LENGTH) > (out.length - outOff)) {
                throw new ShortBufferException("Output buffer too small");
            }

            if (in != null) {
                doUpdate(in, inOff, inLen, out, outOff);
            }

            int ret = nativeCrypto.ChaCha20FinalEncrypt(context, out, outOff + inLen , TAG_LENGTH);
            if (ret == -1) {
                throw new ProviderException("Error in Native ChaCha20Cipher");
            }
            aadDone = false;
            return Math.addExact(inLen, TAG_LENGTH);
        }

        @Override
        public int getCipherBufferLength() {
            return 0;
        }
    }

    private final class EngineAEADDec implements ChaChaEngine {

        private final ByteArrayOutputStream cipherBuf;
        private final byte[] tag;

        EngineAEADDec() {
            counter = 1;
            cipherBuf = new ByteArrayOutputStream(CIPHERBUF_BASE);
            tag = new byte[TAG_LENGTH];
        }

        @Override
        public int doUpdate(byte[] in, int inOff, int inLen, byte[] out,
                int outOff) {
            if (initialized) {
                // If this is the first update since AAD updates, signal that
                // we're done processing AAD info and pad the AAD to a multiple
                // of 16 bytes.
                if (!aadDone) {
                    aadDone = true;
                }

                if (in != null) {
                    Objects.checkFromIndexSize(inOff, inLen, in.length);
                    // Write doUpdate data to the buffer
                    // No computation done yet
                    cipherBuf.write(in, inOff, inLen);
                }
            } else {
                throw new IllegalStateException(
                        "Must use either a different key or iv");
            }
            return 0;
        }

        @Override
        public synchronized int doFinal(byte[] in, int inOff, int inLen, byte[] out,
                int outOff) throws ShortBufferException, AEADBadTagException,
                KeyException {

            byte[] ctPlusTag;
            int ctPlusTagLen;
            if (cipherBuf.size() == 0 && inOff == 0) {
                // No previous data has been seen before doFinal, so we do
                // not need to hold any ciphertext in a buffer.  We can
                // process it directly from the "in" parameter.
                doUpdate(null, inOff, inLen, out, outOff);
                ctPlusTag = in;
                ctPlusTagLen = inLen;
            } else {
                doUpdate(in, inOff, inLen, out, outOff);
                ctPlusTag = cipherBuf.toByteArray();
                ctPlusTagLen = ctPlusTag.length;
            }
            cipherBuf.reset();

            // ctPlusTag now contains all the data

            // There must at least be a tag length's worth of ciphertext
            // data in the buffered input.
            if (ctPlusTagLen < TAG_LENGTH) {
                throw new AEADBadTagException("Input too short - need tag");
            }

            //cipher text length
            int ctLen = ctPlusTagLen - TAG_LENGTH;

            // Make sure we will have enough room for the output buffer
            try {
                Objects.checkFromIndexSize(outOff, ctLen, out.length);
            } catch (IndexOutOfBoundsException ioobe) {
                throw new ShortBufferException("Output buffer too small");
            }

            byte aadArray[] = aadBuf.toByteArray();
            aadBuf.reset();

            // inOff of ctPlusTag is always 0
            int ret = nativeCrypto.ChaCha20FinalDecrypt(context, ctPlusTag, 0, ctPlusTagLen, out,
                                             outOff, aadArray, aadArray.length , TAG_LENGTH);
            aadDone = false;

            if (ret == -2) {
                throw new AEADBadTagException("Tag mismatch");
            } else if (ret == -1) {
                throw new ProviderException("Error in Native ChaCha20Cipher");
            }

            return ctLen;
        }

        @Override
        public int getCipherBufferLength() {
            return cipherBuf.size();
        }
    }

    public static final class ChaCha20Only extends NativeChaCha20Cipher {
        public ChaCha20Only() {
            super(MODE_NONE);
        }
    }

    public static final class ChaCha20Poly1305 extends NativeChaCha20Cipher {
        public ChaCha20Poly1305() {
            super(MODE_AEAD);
        }
    }
}
