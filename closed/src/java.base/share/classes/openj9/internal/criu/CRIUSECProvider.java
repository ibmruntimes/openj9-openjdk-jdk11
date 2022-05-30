/*[INCLUDE-IF CRIU_SUPPORT]*/
/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2022, 2022 All Rights Reserved
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

    public CRIUSECProvider() {
        super("CRIUSEC", "1", "CRIUSEC Provider");

        String packageName = CRIUSECProvider.class.getPackage().getName() + ".";

        String[] aliases = new String[] { "SHA",
                                          "SHA1",
                                          "OID.1.3.14.3.2.26",
                                          "1.3.14.3.2.26" };

        // SHA1PRNG is the default name needed by the jdk, but SHA1 is not used, rather it reads directly from /dev/random.
        putService(new Service(this, "MessageDigest", "SHA-1", packageName + "SHA", java.util.Arrays.asList(aliases), null));
        putService(new Service(this, "SecureRandom", "SHA1PRNG", packageName + "NativePRNG", null, null));
    }

    /**
     * Resets the security digests.
     */
    public static void resetCRIUSEC() {
        NativePRNG.clearRNGState();
        DigestBase.resetDigests();
    }
}
