/*[INCLUDE-IF CRIU_SUPPORT]*/
/*
 * Copyright (c) 1998, 2014, Oracle and/or its affiliates. All rights reserved.
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
 * (c) Copyright IBM Corp. 2022, 2022 All Rights Reserved
 * ===========================================================================
 */

package openj9.internal.criu;

import java.io.InputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

/**
 * <p>This class provides a crytpographically strong pseudo-random number
 * generator based on the SHA-1 hash algorithm.
 *
 * <p>Seed must be provided externally.
 *
 * <p>Also note that when a random object is deserialized,
 * <a href="#engineNextBytes(byte[])">engineNextBytes</a> invoked on the
 * restored random object will yield the exact same (random) bytes as the
 * original object.  If this behaviour is not desired, the restored random
 * object should be seeded, using
 * <a href="#engineSetSeed(byte[])">engineSetSeed</a>.
 *
 * @author Benjamin Renaud
 * @author Josh Bloch
 * @author Gadi Guy
 */

public final class SHA1PRNG implements java.io.Serializable {

    private static final long serialVersionUID = 3581829991155417889L;

    // SHA-1 Digest yields 160-bit hashes which require 20 bytes of space.
    private static final int DIGEST_SIZE = 20;
    private transient MessageDigest digest;
    private byte[] state;
    private byte[] remainder;
    private int remCount;

    // This class is a modified version of the SHA1PRNG SecureRandom implementation
    // that is found at sun.security.provider.SecureRandom.
    // It was modified to be used by CRIUSEC NativePRNG as a mixing data source.
    // Auto-seeding was removed, it is always seeded by NativePRNG from a
    // blocking entropy source.

    private SHA1PRNG(byte[] seed) {
        init(seed);
    }

    static SHA1PRNG seedFrom(InputStream in) throws IOException {
        byte[] seed = new byte[DIGEST_SIZE];
        if (in.readNBytes(seed, 0, DIGEST_SIZE) != DIGEST_SIZE) {
            throw new IOException("Could not read seed");
        }
        return new SHA1PRNG(seed);
    }

    /**
     * This call, used by the constructor, instantiates the SHA digest
     * and sets the seed.
     */
    private void init(byte[] seed) {
        if (seed == null) {
            throw new InternalError("internal error: no seed available.");
        }

        try {
            digest = MessageDigest.getInstance("SHA-1", "CRIUSEC");
        } catch (NoSuchProviderException | NoSuchAlgorithmException e) {
            throw new InternalError("internal error: SHA-1 not available.", e);
        }

        engineSetSeed(seed);
    }


    /**
     * Reseeds this random object. The given seed supplements, rather than
     * replaces, the existing seed. Thus, repeated calls are guaranteed
     * never to reduce randomness.
     *
     * @param seed the seed.
     */
    public synchronized void engineSetSeed(byte[] seed) {
        if (state != null) {
            digest.update(state);
            for (int i = 0; i < state.length; i++) {
                state[i] = 0;
            }
        }
        state = digest.digest(seed);
        remCount = 0;
    }

    private static void updateState(byte[] state, byte[] output) {
        int carry = 1;
        boolean collision = true;

        // state(n + 1) = (state(n) + output(n) + 1) % 2^160;
        for (int i = 0; i < state.length; i++) {
            // Add two bytes.
            int stateCalc = (state[i] & 0xFF) + (output[i] & 0xFF) + carry;
            // Result is lower 8 bits.
            byte newState = (byte)stateCalc;
            // Store result. Check for state collision.
            collision &= (state[i] == newState);
            state[i] = newState;
            // High 8 bits are carry. Store for next iteration.
            carry = stateCalc >>> 8;
        }

        // Make sure at least one bit changes.
        if (collision) {
           state[0]++;
        }
    }


    /**
     * Generates a user-specified number of random bytes.
     *
     * @param result the array to be filled in with random bytes.
     */
    public synchronized void engineNextBytes(byte[] result) {
        int index = 0;
        byte[] output = remainder;

        // Use remainder from last time.
        int r = remCount;
        if (r > 0) {
            // Compute how many bytes to be copied.
            int todo = Math.min(result.length - index, DIGEST_SIZE - r);
            // Copy the bytes, zero the buffer.
            for (int i = 0; i < todo; i++) {
                result[i] = output[r];
                output[r++] = 0;
            }
            remCount += todo;
            index += todo;
        }

        // If we need more bytes, make them.
        while (index < result.length) {
            // Step the state.
            digest.update(state);
            output = digest.digest();
            updateState(state, output);

            // Compute how many bytes to be copied.
            int todo = Math.min(result.length - index, DIGEST_SIZE);
            // Copy the bytes, zero the buffer.
            for (int i = 0; i < todo; i++) {
                result[index++] = output[i];
                output[i] = 0;
            }
            remCount += todo;
        }

        // Store remainder for next time.
        remainder = output;
        remCount %= DIGEST_SIZE;
    }

    void clearState() {
        Arrays.fill(state, (byte) 0x00);
        Arrays.fill(remainder, (byte) 0x00);
        remCount = 0;
    }
}
