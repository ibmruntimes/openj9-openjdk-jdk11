/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2018, 2024 All Rights Reserved
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

import java.lang.ref.Cleaner;
import java.security.*;

import com.ibm.oti.vm.VM;

import jdk.internal.misc.Unsafe;
import jdk.internal.ref.CleanerFactory;
import jdk.internal.reflect.Reflection;
import jdk.internal.reflect.CallerSensitive;

import sun.security.action.GetPropertyAction;

/*[IF CRIU_SUPPORT]*/
import openj9.internal.criu.InternalCRIUSupport;
/*[ENDIF] CRIU_SUPPORT */

public class NativeCrypto {

    /* Define constants for the native digest algorithm indices. */
    public static final int SHA1_160 = 0;
    public static final int SHA2_224 = 1;
    public static final int SHA2_256 = 2;
    public static final int SHA5_384 = 3;
    public static final int SHA5_512 = 4;
    public static final int MD5 = 5;

    /* Define constants for the EC field types. */
    public static final int ECField_Fp = 0;
    public static final int ECField_F2m = 1;

    /* Define XDH curve constants used by OpenSSL. */
    public static final int X25519 = 1034;
    public static final int X448 = 1035;

    public static final long OPENSSL_VERSION_1_0_0 = 0x1_00_00_000L;
    public static final long OPENSSL_VERSION_1_1_0 = 0x1_01_00_000L;
    public static final long OPENSSL_VERSION_1_1_1 = 0x1_01_01_000L;
    public static final long OPENSSL_VERSION_3_0_0 = 0x3_00_00_000L;

    private static final Cleaner ECKeyCleaner = CleanerFactory.cleaner();

    private static final boolean useNativeCrypto = Boolean.parseBoolean(
            GetPropertyAction.privilegedGetProperty("jdk.nativeCrypto", "true"));

    private static final boolean traceEnabled = Boolean.parseBoolean(
            GetPropertyAction.privilegedGetProperty("jdk.nativeCryptoTrace", "false"));

    private static final class InstanceHolder {
        private static final NativeCrypto instance = new NativeCrypto();
    }

    //ossl_vers will be either:
    // -1 : library load failed
    // or one of the OPENSSL_VERSION_x_x_x constants
    private final long ossl_ver;

    private static long loadCryptoLibraries() {
        long osslVersion;

        try {
            // load jncrypto JNI library
            System.loadLibrary("jncrypto");
            // load OpenSSL crypto library dynamically
            osslVersion = loadCrypto(traceEnabled);
            if (traceEnabled && (osslVersion != -1)) {
                System.err.println("Native crypto library load succeeded - using native crypto library.");
            }
        } catch (UnsatisfiedLinkError usle) {
            if (traceEnabled) {
                System.err.println("UnsatisfiedLinkError: Failure attempting to load jncrypto JNI library");
                System.err.println("Warning: Native crypto library load failed." +
                        " Using Java crypto implementation.");
            }
            // signal load failure
            osslVersion = -1;
        }
        return osslVersion;
    }

    @SuppressWarnings("removal")
    private NativeCrypto() {
        ossl_ver = AccessController.doPrivileged((PrivilegedAction<Long>) () -> loadCryptoLibraries()).longValue();
    }

    /**
     * Check whether the native crypto libraries are loaded successfully.
     * If CRIU is enabled and a checkpoint is allowed, the library loading
     * is disallowed, and this returns false.
     *
     * @return whether the native crypto libraries have been loaded successfully
     */
    public static final boolean isAllowedAndLoaded() {
        return getVersionIfAvailable() >= 0;
    }

    /**
     * Return the OpenSSL version.
     * -1 is returned if CRIU is enabled and checkpoints are allowed
     * unless -XX:-CRIUSecProvider is specified.
     * The libraries are to be loaded for the first reference of InstanceHolder.instance.
     *
     * @return the OpenSSL library version if it is available
     */
    public static final long getVersionIfAvailable() {
/*[IF CRIU_SUPPORT]*/
        if (InternalCRIUSupport.isCheckpointAllowed() && InternalCRIUSupport.enableCRIUSecProvider()) {
            return -1;
        }
/*[ENDIF] CRIU_SUPPORT */
        return InstanceHolder.instance.ossl_ver;
    }

    /**
     * Check whether native crypto is enabled. Note that, by default, native
     * crypto is enabled (the native crypto library implementation is used).
     *
     * The property 'jdk.nativeCrypto' is used to control enablement of all
     * native cryptos (Digest, CBC, GCM, RSA, ChaCha20, EC, and PBE), while
     * the given property should be used to control enablement of the given
     * native crypto algorithm.
     *
     * @param property the property used to control enablement of the given
     *                 algorithm
     * @param name the name of the class or the algorithm
     * @return whether the given native crypto algorithm is enabled
     */
    public static final boolean isAlgorithmEnabled(String property, String name) {
        boolean useNativeAlgorithm = false;
        if (useNativeCrypto) {
            useNativeAlgorithm = Boolean.parseBoolean(
                    GetPropertyAction.privilegedGetProperty(property, "true"));
        }
        /*
         * User wants to use the native crypto implementation. Ensure that the native crypto library is enabled.
         * Otherwise, issue a warning message.
         */
        if (traceEnabled) {
            if (useNativeAlgorithm) {
                System.err.println(name + " native crypto implementation enabled.");
            } else {
                System.err.println(name + " native crypto implementation disabled." +
                        " Using Java crypto implementation.");
            }
        }
        return useNativeAlgorithm;
    }

    public static final boolean isEnabled() {
        return useNativeCrypto;
    }

    public static final boolean isTraceEnabled() {
        return traceEnabled;
    }

    @CallerSensitive
    public static NativeCrypto getNativeCrypto() {
        ClassLoader callerClassLoader = Reflection.getCallerClass().getClassLoader();

        if ((callerClassLoader == null) || (callerClassLoader == VM.getVMLangAccess().getExtClassLoader())) {
            return InstanceHolder.instance;
        }

        throw new SecurityException("NativeCrypto");
    }

    public void createECKeyCleaner(Object owner, long key) {
        ECKeyCleaner.register(owner, new Runnable() {
            @Override
            public void run() {
                NativeCrypto.this.ECDestroyKey(key);
            }
        });
    }

    /* Native digest interfaces */

    private static final native long loadCrypto(boolean trace);

    public static final native boolean isMD5Available();

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

    public final native int DigestReset(long context);

    /* Native interfaces shared by CBC, ChaCha20 and GCM. */

    public final native long CreateContext();

    public final native int DestroyContext(long context);

    /* Native CBC interfaces */

    public final native int CBCInit(long context,
                                    int mode,
                                    byte[] iv,
                                    int ivlen,
                                    byte[] key,
                                    int keylen,
                                    boolean doReset);

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

    public final native int GCMEncrypt(long context,
                                       byte[] key,
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
                                       int tagLen,
                                       boolean newIVLen,
                                       boolean newKeyLen);

    public final native int GCMDecrypt(long context,
                                       byte[] key,
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
                                       int tagLen,
                                       boolean newIVLen,
                                       boolean newKeyLen);

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
                                    int keylen,
                                    boolean doReset);

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

    /* Native EC interfaces */
    public final native int ECGenerateKeyPair(long key,
                                              byte[] x,
                                              int xLen,
                                              byte[] y,
                                              int yLen,
                                              byte[] s,
                                              int sLen,
                                              int fieldType);

    public final native int ECCreatePublicKey(long key,
                                              byte[] x,
                                              int xLen,
                                              byte[] y,
                                              int yLen,
                                              int field);

    public final native int ECCreatePrivateKey(long key,
                                               byte[] s,
                                               int sLen);

    public final native long ECEncodeGF(int fieldType,
                                        byte[] a,
                                        int aLen,
                                        byte[] b,
                                        int bLen,
                                        byte[] p,
                                        int pLen,
                                        byte[] x,
                                        int xLen,
                                        byte[] y,
                                        int yLen,
                                        byte[] n,
                                        int nLen,
                                        byte[] h,
                                        int hLen);

    public final native int ECDestroyKey(long key);

    public final native int ECDeriveKey(long publicKey,
                                        long privateKey,
                                        byte[] secret,
                                        int secretOffset,
                                        int secretLen);

    public final native boolean ECNativeGF2m();

    public final native int PBEDerive(byte[] password,
                                      int passwordLength,
                                      byte[] salt,
                                      int saltLength,
                                      byte[] key,
                                      int iterations,
                                      int n,
                                      int id,
                                      int hashAlgorithm);

    /* Native XDH (X25519, X448) interfaces. */
    public final native int XDHCreateKeys(byte[] privateKey,
                                          int privateKeyLength,
                                          byte[] publicKey,
                                          int publicKeyLength,
                                          int curveType);

    public final native int XDHGenerateSecret(byte[] privateKey,
                                              int privateKeyLength,
                                              byte[] publicKey,
                                              int publicKeyLength,
                                              byte[] computedSecret,
                                              int computedSecretLength,
                                              int curveType);
}
