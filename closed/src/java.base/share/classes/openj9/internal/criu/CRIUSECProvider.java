/*[INCLUDE-IF CRIU_SUPPORT]*/
/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2022, 2023 All Rights Reserved
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

package openj9.internal.criu;

import java.security.Provider;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.function.Consumer;

/**
 * The CRIUSECProvider is a security provider that is used as follows when CRIU
 * is enabled. During the checkpoint phase, all other security providers are
 * removed, except CRIUSECProvider, and the digests are cleared, to ensure that
 * no state is saved during checkpoint that is then restored during the restore
 * phase. During the resore phase, CRIUSECProvider is removed and the other
 * security providers are added back.
 */
public final class CRIUSECProvider extends Provider {

    private static final long serialVersionUID = -3240458633432287743L;

    private static final Map<Object, Consumer<Object>> actions = new WeakHashMap<>();

    @SuppressWarnings("unchecked")
    public static <T> void doOnRestart(T object, Consumer<T> action) {
        if (InternalCRIUSupport.isCheckpointAllowed()) {
            synchronized (actions) {
                // This unchecked cast is safe because the action
                // is only applied the supplied object.
                actions.put(object, (Consumer<Object>) action);
            }
        }
    }

    public CRIUSECProvider() {
        super("CRIUSEC", "1", "CRIUSEC Provider");

        String[] aliases = new String[] { "SHA",
                                          "SHA1",
                                          "OID.1.3.14.3.2.26",
                                          "1.3.14.3.2.26" };

        // SHA1PRNG is the default name needed by the jdk, but SHA1 is not used, rather it reads directly from /dev/random.
        putService(new Service(this, "MessageDigest", "SHA-1", "sun.security.provider.SHA", java.util.Arrays.asList(aliases), null));
        putService(new Service(this, "MessageDigest", "SHA-256", "sun.security.provider.SHA2$SHA256", null, null));
        putService(new Service(this, "MessageDigest", "MD5", "sun.security.provider.MD5", null, null));
        putService(new Service(this, "Mac", "HmacSHA256", "com.sun.crypto.provider.HmacCore$HmacSHA256", null, null));
        putService(new Service(this, "SecureRandom", "SHA1PRNG", "sun.security.provider.NativePRNG$CRIUNativePRNG", null, null));
    }

    /**
     * Reset security algorithms.
     */
    public static void resetCRIUSEC() {
        synchronized (actions) {
            for (Map.Entry<Object, Consumer<Object>> entry : actions.entrySet()) {
                Object object = entry.getKey();

                if (object != null) {
                    entry.getValue().accept(object);
                }
            }
        }
    }
}
