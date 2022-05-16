/*[INCLUDE-IF CRIU_SUPPORT]*/
/*
 * Copyright (c) 2003, 2016, Oracle and/or its affiliates. All rights reserved.
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

import java.io.*;
import java.lang.reflect.Method;
import java.net.*;
import java.security.*;
import java.util.Arrays;

import sun.security.util.Debug;

/**
 * Native PRNG implementation for Solaris/Linux/MacOS.
 * This class was modified from the OpenJDK implementation. Code was removed
 * to eliminate any buffering, so we trade off performance and allow only
 * for reading directly from /dev/random when the app needs random bytes.
 * <p>
 * It obtains seed and random numbers by reading /dev/random and /dev/urandom.
 * <p>
 * On some Unix platforms, /dev/random may block until enough entropy is
 * available, but that may negatively impact the perceived startup
 * time.  By selecting these sources, this implementation tries to
 * strike a balance between performance and security.
 * <p>
 * generateSeed()/nextBytes() and setSeed() attempt to directly read/write to the seed
 * source. However, this file may only be writable by root in many
 * configurations.
 * <p>
 * Finally, note that we use a singleton for the actual work (RandomIO)
 * to avoid having to open and close /dev/random constantly. However,
 * there may be many NativePRNG instances created by the JCA framework.
 *
 * @since   1.5
 * @author  Andreas Sterbenz
 */
public final class NativePRNG extends SecureRandomSpi {

    private static final long serialVersionUID = -6599091113397072932L;

    private static final Debug debug = Debug.getInstance("provider");

    // name of the pure random file (also used for setSeed())
    private static final String NAME_RANDOM = "/dev/random";

    // singleton instance or null if not available
    private static final RandomIO INSTANCE = initIO();

    /**
     * Create a RandomIO object for all I/O of this Variant type.
     */
    private static RandomIO initIO() {
        return AccessController.doPrivileged(
            new PrivilegedAction<>() {
                @Override
                public RandomIO run() {
                    File seedFile = new File(NAME_RANDOM);
                    File nextFile = new File(NAME_RANDOM);

                    if (debug != null) {
                        debug.println("NativePRNG." +
                            " seedFile: " + seedFile +
                            " nextFile: " + nextFile);
                    }

                    if (!seedFile.canRead() || !nextFile.canRead()) {
                        if (debug != null) {
                            debug.println("NativePRNG." +
                                " Couldn't read Files.");
                        }
                        return null;
                    }

                    try {
                        return new RandomIO(seedFile, nextFile);
                    } catch (Exception e) {
                        return null;
                    }
                }
        });
    }

    // return whether the NativePRNG is available
    static boolean isAvailable() {
        return INSTANCE != null;
    }

    // constructor, called by the JCA framework
    public NativePRNG() {
        super();
        if (INSTANCE == null) {
            throw new AssertionError("NativePRNG not available");
        }
    }

    // set the seed
    @Override
    protected void engineSetSeed(byte[] seed) {
        INSTANCE.implSetSeed(seed);
    }

    // get pseudo random bytes
    @Override
    protected void engineNextBytes(byte[] bytes) {
        INSTANCE.implNextBytes(bytes);
    }

    // get true random bytes
    @Override
    protected byte[] engineGenerateSeed(int numBytes) {
        return INSTANCE.implGenerateSeed(numBytes);
    }

    static void clearRNGBuffers() {
        INSTANCE.clearRNGBuffers();
    }

    /**
     * Nested class doing the actual work. Singleton, see INSTANCE above.
     */
    private static final class RandomIO {

        // we buffer data we read from the "next" file for efficiency,
        // but we limit the lifetime to avoid using stale bits
        // lifetime in ms, currently 100 ms (0.1 s)
        private static final long MAX_BUFFER_TIME = 100;

        // size of the "next" buffer
        private static final int MAX_BUFFER_SIZE = 65536;
        private static final int MIN_BUFFER_SIZE = 32;
        private int bufferSize = 256;

        // Holder for the seedFile.  Used if we ever add seed material.
        private File seedFile;

        // In/OutputStream for "seed" and "next".
        private final InputStream seedIn, nextIn;
        private OutputStream seedOut;

        // flag indicating if we have tried to open seedOut yet
        private boolean seedOutInitialized;

        // SHA1PRNG instance for mixing
        // initialized lazily on demand to avoid problems during startup
        private volatile sun.security.provider.SecureRandom mixRandom;

        // buffer for next bits
        private byte[] nextBuffer;

        // number of bytes left in nextBuffer
        private int buffered;

        // time we read the data into the nextBuffer
        private long lastRead;

        // Count for the number of buffer size changes requests
        // Positive value in increase size, negative to lower it.
        private int change_buffer = 0;

        // Request limit to trigger an increase in nextBuffer size
        private static final int REQ_LIMIT_INC = 1000;

        // Request limit to trigger a decrease in nextBuffer size
        private static final int REQ_LIMIT_DEC = -100;

        // mutex lock for nextBytes()
        private final Object LOCK_GET_BYTES = new Object();

        // mutex lock for generateSeed()
        private final Object LOCK_GET_SEED = new Object();

        // mutex lock for setSeed()
        private final Object LOCK_SET_SEED = new Object();

        // constructor, called only once from initIO()
        private RandomIO(File seedFile, File nextFile) throws IOException {
            this.seedFile = seedFile;
            InputStream seedStream = null, nextStream = null;
            try {
                // Invoke the getInputStream method from the FileInputStreamPool class.
                Class<?> runnable = Class.forName("sun.security.provider.FileInputStreamPool",
                        true, ClassLoader.getSystemClassLoader());
                Method getStream = runnable.getDeclaredMethod("getInputStream", File.class);
                getStream.setAccessible(true);
                seedStream = (InputStream) getStream.invoke(null, seedFile);
                nextStream = (InputStream) getStream.invoke(null, nextFile);
            } catch (Exception e) {
                System.out.println(e.toString());
            }
            this.seedIn = seedStream;
            this.nextIn = nextStream;
            this.nextBuffer = new byte[bufferSize];
        }

        // get the SHA1PRNG for mixing
        // initialize if not yet created
        private sun.security.provider.SecureRandom getMixRandom() {
            sun.security.provider.SecureRandom r = mixRandom;
            if (r == null) {
                synchronized (LOCK_GET_BYTES) {
                    r = mixRandom;
                    if (r == null) {
                        r = new sun.security.provider.SecureRandom();
                        try {
                            byte[] b = new byte[20];
                            readFully(nextIn, b);
                            r.engineSetSeed(b);
                        } catch (IOException e) {
                            throw new ProviderException("init failed", e);
                        }
                        mixRandom = r;
                    }
                }
            }
            return r;
        }

        // Read data.length bytes from in.
        // These are not normal files, so we need to loop the read.
        // Just keep trying as long as we are making progress.
        private static void readFully(InputStream in, byte[] data)
                throws IOException {
            int len = data.length;
            int ofs = 0;
            while (len > 0) {
                int k = in.read(data, ofs, len);
                if (k <= 0) {
                    throw new EOFException("File(s) closed?");
                }
                ofs += k;
                len -= k;
            }
            if (len > 0) {
                throw new IOException("Could not read from file(s)");
            }
        }

        // get true random bytes, just read from "seed"
        private byte[] implGenerateSeed(int numBytes) {
            synchronized (LOCK_GET_SEED) {
                try {
                    byte[] b = new byte[numBytes];
                    readFully(seedIn, b);
                    return b;
                } catch (IOException e) {
                    throw new ProviderException("generateSeed() failed", e);
                }
            }
        }

        // supply random bytes to the OS
        // write to "seed" if possible
        // always add the seed to our mixing random
        private void implSetSeed(byte[] seed) {
            synchronized (LOCK_SET_SEED) {
                if (seedOutInitialized == false) {
                    seedOutInitialized = true;
                    seedOut = AccessController.doPrivileged(
                            new PrivilegedAction<>() {
                        @Override
                        public OutputStream run() {
                            try {
                                return new FileOutputStream(seedFile, true);
                            } catch (Exception e) {
                                return null;
                            }
                        }
                    });
                }
                if (seedOut != null) {
                    try {
                        seedOut.write(seed);
                    } catch (IOException e) {
                        // Ignored. On Mac OS X, /dev/urandom can be opened
                        // for write, but actual write is not permitted.
                    }
                }
                getMixRandom().engineSetSeed(seed);
            }
        }

        // ensure that there is at least one valid byte in the buffer
        // if not, read new bytes
        private void ensureBufferValid() throws IOException {
            long time = System.currentTimeMillis();
            int new_buffer_size = 0;

            // Check if buffer has bytes available that are not too old
            if (buffered > 0) {
                if (time - lastRead < MAX_BUFFER_TIME) {
                    return;
                } else {
                    // byte is old, so subtract from counter to shrink buffer
                    change_buffer--;
                }
            } else {
                // No bytes available, so add to count to increase buffer
                change_buffer++;
            }

            // If counter has it a limit, increase or decrease size
            if (change_buffer > REQ_LIMIT_INC) {
                new_buffer_size = nextBuffer.length * 2;
            } else if (change_buffer < REQ_LIMIT_DEC) {
                new_buffer_size = nextBuffer.length / 2;
            }

            // If buffer size is to be changed, replace nextBuffer.
            if (new_buffer_size > 0) {
                if (new_buffer_size <= MAX_BUFFER_SIZE &&
                        new_buffer_size >= MIN_BUFFER_SIZE) {
                    nextBuffer = new byte[new_buffer_size];
                    if (debug != null) {
                        debug.println("Buffer size changed to " +
                                new_buffer_size);
                    }
                } else {
                    if (debug != null) {
                        debug.println("Buffer reached limit: " +
                                nextBuffer.length);
                    }
                }
                change_buffer = 0;
            }

            // Load fresh random bytes into nextBuffer
            lastRead = time;
            readFully(nextIn, nextBuffer);
            buffered = nextBuffer.length;
        }

        // get pseudo random bytes
        // read from "next" and XOR with bytes generated by the
        // mixing SHA1PRNG
        private void implNextBytes(byte[] data) {
            try {
                getMixRandom().engineNextBytes(data);
                int data_len = data.length;
                int ofs = 0;
                int len;
                int buf_pos;
                int localofs;
                byte[] localBuffer;

                while (data_len > 0) {
                    synchronized (LOCK_GET_BYTES) {
                        ensureBufferValid();
                        buf_pos = nextBuffer.length - buffered;
                        if (data_len > buffered) {
                            len = buffered;
                            buffered = 0;
                        } else {
                            len = data_len;
                            buffered -= len;
                        }
                        localBuffer = Arrays.copyOfRange(nextBuffer, buf_pos,
                                buf_pos + len);
                    }
                    localofs = 0;
                    while (len > localofs) {
                        data[ofs] ^= localBuffer[localofs];
                        ofs++;
                        localofs++;
                    }
                data_len -= len;
                }
            } catch (IOException e){
                throw new ProviderException("nextBytes() failed", e);
            }
        }

        // clear the RNG buffer
        private void clearRNGBuffers() {
            if (this.nextBuffer != null) {
                Arrays.fill(this.nextBuffer, (byte) 0x00);
                this.nextBuffer = null;
            }
        }
    }
}
