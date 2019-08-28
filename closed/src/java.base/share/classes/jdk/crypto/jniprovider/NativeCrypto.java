/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2018, 2019 All Rights Reserved
 * ===========================================================================
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * IBM designates this particular file as subject to the "Classpath" exception
 * as provided by IBM in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, see <http://www.gnu.org/licenses/>.
 *
 * ===========================================================================
 */
package jdk.crypto.jniprovider;

import java.security.*;

import com.ibm.oti.vm.VM;

import jdk.internal.misc.Unsafe;
import jdk.internal.reflect.Reflection;
import jdk.internal.reflect.CallerSensitive;

public class NativeCrypto {

    //ossl_ver:
    // -1 : library load failed
    //  0 : openssl 1.0.x
    //  1 : openssl 1.1.x
    private static final int ossl_ver = AccessController.doPrivileged(
            (PrivilegedAction<Integer>) () -> {
                int ossl_ver = -1;
                try {
                    System.loadLibrary("jncrypto"); // check for native library
                    // load OpenSSL crypto library dynamically.
                    ossl_ver = loadCrypto();
                } catch (UnsatisfiedLinkError usle) {
                    // Return that ossl_ver is -1 (default set above)
                }

                return ossl_ver;
            });

    private static final boolean loaded = ossl_ver != -1;

    public static final boolean isLoaded() {
        return loaded;
    }

    public static final int getVersion() {
        return ossl_ver;
    }

    private NativeCrypto() {
        //empty
    }

    @CallerSensitive
    public static NativeCrypto getNativeCrypto() {
        ClassLoader callerClassLoader = Reflection.getCallerClass().getClassLoader();

        if ((callerClassLoader == null) || (callerClassLoader == VM.getVMLangAccess().getExtClassLoader())) {
			return new NativeCrypto();
		}

        throw new SecurityException("NativeCrypto");
    }

    /* Native digest interfaces */
    static final native int loadCrypto();

    public final native long DigestCreateContext(long nativeBuffer,
                                                 int algoIndex);

    public final native int DigestDestroyContext(long context);

    public final native int DigestUpdate(long context,
                                         byte[] message,
                                         int messageOffset,
                                         int messageLen);

    public final native int DigestComputeAndReset(long context,
                                                  byte[] message,
                                                  int messageOffset,
                                                  int messageLen,
                                                  byte[] digest,
                                                  int digestOffset,
                                                  int digestLen);

    public final native void DigestReset(long context);

    /* Native interfaces shared by CBC and ChaCha20 */
    public final native long CreateContext();

    public final native int DestroyContext(long context);

    /* Native CBC interfaces */

    public final native int CBCInit(long context,
                                    int mode,
                                    byte[] iv,
                                    int ivlen,
                                    byte[] key,
                                    int keylen);

    public final native int  CBCUpdate(long context,
                                       byte[] input,
                                       int inputOffset,
                                       int inputLen,
                                       byte[] output,
                                       int outputOffset);

    public final native int  CBCFinalEncrypt(long context,
                                             byte[] input,
                                             int inputOffset,
                                             int inputLen,
                                             byte[] output,
                                             int outputOffset);

    /* Native GCM interfaces */
    public final native int GCMEncrypt(byte[] key,
                                       int keylen,
                                       byte[] iv,
                                       int ivlen,
                                       byte[] input,
                                       int inOffset,
                                       int inLen,
                                       byte[] output,
                                       int outOffset,
                                       byte[] aad,
                                       int aadLen,
                                       int tagLen);

    public final native int GCMDecrypt(byte[] key,
                                       int keylen,
                                       byte[] iv,
                                       int ivlen,
                                       byte[] input,
                                       int inOffset,
                                       int inLen,
                                       byte[] output,
                                       int outOffset,
                                       byte[] aad,
                                       int aadLen,
                                       int tagLen);

    /* Native RSA interfaces */
    public final native long createRSAPublicKey(byte[] n,
                                                int nLen,
                                                byte[] e,
                                                int eLen);

    public final native long createRSAPrivateCrtKey(byte[] n,
                                                    int nLen,
                                                    byte[] d,
                                                    int dLen,
                                                    byte[] e,
                                                    int eLen,
                                                    byte[] p,
                                                    int pLen,
                                                    byte[] q,
                                                    int qLen,
                                                    byte[] dp,
                                                    int dpLen,
                                                    byte[] dq,
                                                    int dqLen,
                                                    byte[] qinv,
                                                    int qinvLen);

    public final native void destroyRSAKey(long key);

    public final native int RSADP(byte[] k,
                                  int kLen,
                                  byte[] m,
                                  int verify,
                                  long RSAPrivateCrtKey);

    public final native int RSAEP(byte[] k,
                                  int kLen,
                                  byte[] m,
                                  long RSAPublicKey);

    /* Native ChaCha20 interfaces */

    public final native int ChaCha20Init(long context,
                                    int mode,
                                    byte[] iv,
                                    int ivlen,
                                    byte[] key,
                                    int keylen);

    public final native int ChaCha20Update(long context,
                                       byte[] input,
                                       int inputOffset,
                                       int inputLen,
                                       byte[] output,
                                       int outputOffset,
                                       byte[] aad,
                                       int aadLen);

    public final native int ChaCha20FinalEncrypt(long context,
                                             byte[] output,
                                             int outputOffset,
                                             int tagLen);

    public final native int ChaCha20FinalDecrypt(long context,
                                       byte[] input,
                                       int inOffset,
                                       int inputLen,
                                       byte[] output,
                                       int outOffset,
                                       byte[] aad,
                                       int aadLen,
                                       int tagLen);

}
