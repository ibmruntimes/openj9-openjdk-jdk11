/*
 * Copyright (c) 2013, 2018, Oracle and/or its affiliates. All rights reserved.
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
 * (c) Copyright IBM Corp. 2018, 2019 All Rights Reserved
 * ===========================================================================
 */

package com.sun.crypto.provider;

import java.util.Arrays;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import static com.sun.crypto.provider.AESConstants.AES_BLOCK_SIZE;
import com.sun.crypto.provider.AESCrypt;

import jdk.crypto.jniprovider.NativeCrypto;

/**
 * This class represents ciphers in GaloisCounter (GCM) mode.
 *
 * <p>This mode currently should only be used w/ AES cipher.
 * Although no checking is done, caller should only pass AES
 * Cipher to the constructor.
 *
 * <p>NOTE: Unlike other modes, when used for decryption, this class
 * will buffer all processed outputs internally and won't return them
 * until the tag has been successfully verified.
 *
 * @since 1.8
 */
final class NativeGaloisCounterMode extends FeedbackCipher {

    private byte[] key;
    private boolean decrypting;
    private static final byte[] emptyAAD = new byte[0];

    static int DEFAULT_TAG_LEN = AES_BLOCK_SIZE;
    static int DEFAULT_IV_LEN = 12; // in bytes

    // In NIST SP 800-38D, GCM input size is limited to be no longer
    // than (2^36 - 32) bytes. Otherwise, the counter will wrap
    // around and lead to a leak of plaintext.
    // However, given the current GCM spec requirement that recovered
    // text can only be returned after successful tag verification,
    // we are bound by limiting the data size to the size limit of
    // java byte array, e.g. Integer.MAX_VALUE, since all data
    // can only be returned by the doFinal(...) call.
    private static final int MAX_BUF_SIZE = Integer.MAX_VALUE;

    // buffer for AAD data; if null, meaning update has been called
    private ByteArrayOutputStream aadBuffer = new ByteArrayOutputStream();

    // buffer for storing input in decryption, not used for encryption
    private ByteArrayOutputStream ibuffer = null;
    // buffer for storing input in encryption not used for decryption
    private ByteArrayOutputStream ibuffer_enc = null;

    // in bytes; need to convert to bits (default value 128) when needed
    private int tagLenBytes = DEFAULT_TAG_LEN;

    // these following 2 fields can only be initialized after init() is
    // called, e.g. after cipher key k is set, and STAY UNCHANGED
    private byte[] subkeyH = null;
    private byte[] preCounterBlock = null;

    // additional variables for save/restore calls
    private byte[] aadBufferSave = null;
    private byte[] ibufferSave = null;
    private byte[] ibufferSave_enc = null;

    private static NativeCrypto nativeCrypto;

    static {
        nativeCrypto = NativeCrypto.getNativeCrypto();
    }

    private static void checkDataLength(int processed, int len) {
        if (processed > MAX_BUF_SIZE - len) {
            throw new ProviderException("SunJCE provider only supports " +
                "input size up to " + MAX_BUF_SIZE + " bytes");
        }
    }

    /*
     * Constructor
     */
    NativeGaloisCounterMode(SymmetricCipher embeddedCipher) {
        super(embeddedCipher);
        aadBuffer = new ByteArrayOutputStream();
    }

    /**
     * Gets the name of the feedback mechanism
     *
     * @return the name of the feedback mechanism
     */
    String getFeedback() {

        return "GCM";
    }

    /**
     * Resets the cipher object to its original state.
     * This is used when doFinal is called in the Cipher class, so that the
     * cipher can be reused (with its original key and iv).
     */
    void reset() {
        if (aadBuffer == null) {
            aadBuffer = new ByteArrayOutputStream();
        } else {
            aadBuffer.reset();
        }

        if (ibuffer != null) {
            ibuffer.reset();
        }

        if (ibuffer_enc != null) {
            ibuffer_enc.reset();
        }
    }

    /**
     * Save the current content of this cipher.
     */
    void save() {
        aadBufferSave =
            ((aadBuffer == null || aadBuffer.size() == 0)?
             null : aadBuffer.toByteArray());

        if (ibuffer != null) {
            ibufferSave = ibuffer.toByteArray();
        }

        if (ibuffer_enc != null) {
            ibufferSave_enc = ibuffer_enc.toByteArray();
        }
    }

    /**
     * Restores the content of this cipher to the previous saved one.
     */
    void restore() {
        if (aadBuffer != null) {
            aadBuffer.reset();

            if (aadBufferSave != null) {
                aadBuffer.write(aadBufferSave, 0, aadBufferSave.length);
            }
        }

        if (ibuffer != null && ibufferSave != null) {
            ibuffer.reset();
            ibuffer.write(ibufferSave, 0, ibufferSave.length);
        }

        if (ibuffer_enc != null && ibufferSave_enc != null) {
            ibuffer_enc.reset();
            ibuffer_enc.write(ibufferSave_enc, 0, ibufferSave_enc.length);
        }
    }

    /**
     * Initializes the cipher in the specified mode with the given key
     * and iv.
     *
     * @param decrypting flag indicating encryption or decryption
     * @param algorithm the algorithm name
     * @param key the key
     * @param iv the iv
     * @param tagLenBytes the length of tag in bytes
     *
     * @exception InvalidKeyException if the given key is inappropriate for
     * initializing this cipher
     */
    void init(boolean decrypting, String algorithm, byte[] key, byte[] iv)
            throws InvalidKeyException {
        init(decrypting, algorithm, key, iv, DEFAULT_TAG_LEN);
    }

    /**
     * Initializes the cipher in the specified mode with the given key
     * and iv.
     *
     * @param decrypting flag indicating encryption or decryption
     * @param algorithm the algorithm name
     * @param key the key
     * @param iv the iv
     * @param tagLenBytes the length of tag in bytes
     *
     * @exception InvalidKeyException if the given key is inappropriate for
     * initializing this cipher
     */
    void init(boolean decrypting, String algorithm, byte[] keyValue,
              byte[] ivValue, int tagLenBytes)
              throws InvalidKeyException {
        if (keyValue == null || ivValue == null) {
            throw new InvalidKeyException("Internal error");
        }

        if (!AESCrypt.isKeySizeValid(keyValue.length)) {
            throw new InvalidKeyException("Invalid AES key length: " +
                keyValue.length + " bytes");
        }

        this.key = keyValue.clone();
        this.iv = ivValue.clone();
        this.tagLenBytes = tagLenBytes;
        this.decrypting = decrypting;

        if (aadBuffer == null) {
            aadBuffer = new ByteArrayOutputStream();
        } else {
            aadBuffer.reset();
        }
 
        if (decrypting) {
            ibuffer = new ByteArrayOutputStream();
        }

        if (!decrypting) {
            ibuffer_enc = new ByteArrayOutputStream();
        }
    }

    /**
     * Continues a multi-part update of the Additional Authentication
     * Data (AAD), using a subset of the provided buffer. If this
     * cipher is operating in either GCM or CCM mode, all AAD must be
     * supplied before beginning operations on the ciphertext (via the
     * {@code update} and {@code doFinal} methods).
     * <p>
     * NOTE: Given most modes do not accept AAD, default impl for this
     * method throws IllegalStateException.
     *
     * @param src the buffer containing the AAD
     * @param offset the offset in {@code src} where the AAD input starts
     * @param len the number of AAD bytes
     *
     * @throws IllegalStateException if this cipher is in a wrong state
     * (e.g., has not been initialized), does not accept AAD, or if
     * operating in either GCM or CCM mode and one of the {@code update}
     * methods has already been called for the active
     * encryption/decryption operation
     * @throws UnsupportedOperationException if this method
     * has not been overridden by an implementation
     *
     * @since 1.8
     */
    void updateAAD(byte[] src, int offset, int len) {
        if (aadBuffer != null) {
            aadBuffer.write(src, offset, len);
        } else {
            // update has already been called
            throw new IllegalStateException
                ("Update has been called; no more AAD data");
        }
    }

    /**
     * Performs encryption operation.
     *
     * <p>The input plain text <code>in</code>, starting at <code>inOff</code>
     * and ending at <code>(inOff + len - 1)</code>, is encrypted. The result
     * is stored in <code>out</code>, starting at <code>outOfs</code>.
     *
     * @param in the buffer with the input data to be encrypted
     * @param inOfs the offset in <code>in</code>
     * @param len the length of the input data
     * @param out the buffer for the result
     * @param outOfs the offset in <code>out</code>
     * @exception ProviderException if <code>len</code> is not
     * a multiple of the block size
     * @return the number of bytes placed into the <code>out</code> buffer
     */
    int encrypt(byte[] in, int inOfs, int len, byte[] out, int outOfs) {
        if ((len % blockSize) != 0) {
            throw new ProviderException("Internal error in input buffering");
       }

        checkDataLength(ibuffer_enc.size(), len);

        if (len > 0) {
            // store internally until encryptFinal is called because
            // spec mentioned that only return recovered data after tag
            // is successfully verified
            ibuffer_enc.write(in, inOfs, len);
        }

        return 0;
    }

    /**
     * Performs encryption operation for the last time.
     *
     * @param in the input buffer with the data to be encrypted
     * @param inOfs the offset in <code>in</code>
     * @param len the length of the input data
     * @param out the buffer for the encryption result
     * @param outOfs the offset in <code>out</code>
     * @return the number of bytes placed into the <code>out</code> buffer
     */
    int encryptFinal(byte[] in, int inOfs, int len, byte[] out, int outOfs)
        throws IllegalBlockSizeException, ShortBufferException {

        if (len > MAX_BUF_SIZE - tagLenBytes) {
            throw new ShortBufferException
                ("Can't fit both data and tag into one buffer");
        }

        if (out.length - outOfs < (len + tagLenBytes)) {
            throw new ShortBufferException("Output buffer too small");
        }

        checkDataLength(ibuffer_enc.size(), len);

        if (len > 0) {
            ibuffer_enc.write(in, inOfs, len);
        }

        // refresh 'in' to all buffered-up bytes
        in = ibuffer_enc.toByteArray();
        inOfs = 0;
        len = in.length;
        ibuffer_enc.reset();

        byte[] aad = ((aadBuffer == null || aadBuffer.size() == 0) ? emptyAAD : aadBuffer.toByteArray());

        int ret = nativeCrypto.GCMEncrypt(key, key.length,
                iv, iv.length,
                in, inOfs, len,
                out, outOfs,
                aad, aad.length, tagLenBytes);
        if (ret == -1) {
            throw new ProviderException("Error in Native GaloisCounterMode");
        }

        return (len + tagLenBytes);
    }

    /**
     * Performs decryption operation.
     *
     * <p>The input cipher text <code>in</code>, starting at
     * <code>inOfs</code> and ending at <code>(inOfs + len - 1)</code>,
     * is decrypted. The result is stored in <code>out</code>, starting at
     * <code>outOfs</code>.
     *
     * @param in the buffer with the input data to be decrypted
     * @param inOfs the offset in <code>in</code>
     * @param len the length of the input data
     * @param out the buffer for the result
     * @param outOfs the offset in <code>out</code>
     * @exception ProviderException if <code>len</code> is not
     * a multiple of the block size
     * @return the number of bytes placed into the <code>out</code> buffer
     */
    int decrypt(byte[] in, int inOfs, int len, byte[] out, int outOfs) {
        if ((len % blockSize) != 0) {
            throw new ProviderException("Internal error in input buffering");
       }

        checkDataLength(ibuffer.size(), len);

        if (len > 0) {
            // store internally until decryptFinal is called because
            // spec mentioned that only return recovered data after tag
            // is successfully verified
            ibuffer.write(in, inOfs, len);
        }

        return 0;
    }

    /**
     * Performs decryption operation for the last time.
     *
     * <p>NOTE: For cipher feedback modes which does not perform
     * special handling for the last few blocks, this is essentially
     * the same as <code>encrypt(...)</code>. Given most modes do
     * not do special handling, the default impl for this method is
     * to simply call <code>decrypt(...)</code>.
     *
     * @param in the input buffer with the data to be decrypted
     * @param inOfs the offset in <code>cipher</code>
     * @param len the length of the input data
     * @param out the buffer for the decryption result
     * @param outOfs the offset in <code>plain</code>
     * @return the number of bytes placed into the <code>out</code> buffer
     */
    int decryptFinal(byte[] in, int inOfs, int len,
                     byte[] out, int outOfs)
        throws IllegalBlockSizeException, AEADBadTagException,
        ShortBufferException {
        if (len < tagLenBytes) {
            throw new AEADBadTagException("Input too short - need tag");
        }

        // do this check here can also catch the potential integer overflow
        // scenario for the subsequent output buffer capacity check.
        checkDataLength(ibuffer.size(), (len - tagLenBytes));


        if (out.length - outOfs < ((ibuffer.size() + len) - tagLenBytes)) {
            throw new ShortBufferException("Output buffer too small");
        }

        byte[] aad = ((aadBuffer == null || aadBuffer.size() == 0) ?
                       emptyAAD : aadBuffer.toByteArray());

        aadBuffer = null;

        if (len > 0) {
            ibuffer.write(in, inOfs, len);
        }

        // refresh 'in' to all buffered-up bytes
        in = ibuffer.toByteArray();
        inOfs = 0;
        len = in.length;
        ibuffer.reset();

        int ret = nativeCrypto.GCMDecrypt(key, key.length,
                iv, iv.length,
                in, inOfs, len,
                out, outOfs,
                aad, aad.length, tagLenBytes);

        if (ret == -2) {
            throw new AEADBadTagException("Tag mismatch!");
        } else if (ret == -1) {
            throw new ProviderException("Error in Native GaloisCounterMode");
        }


        return ret;
    }

    // return tag length in bytes
    int getTagLen() {

        return this.tagLenBytes;
    }

    int getBufferedLength() {
        if (ibuffer != null && decrypting) {
            return ibuffer.size();
        }

        if (ibuffer_enc != null && !decrypting) {
            return ibuffer_enc.size();
        }

        return 0;
    }
}
