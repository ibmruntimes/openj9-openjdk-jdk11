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

package java.security;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import sun.security.action.GetPropertyAction;
import sun.security.jca.ProviderList;
import sun.security.jca.Providers;

/**
 * Configures the security providers when in CRIU mode.
 */
public final class CRIUConfigurator {
    private static Properties systemProps;
    /** Stores the old security providers (position, name). */
    private static final HashMap<String, String> oldProviders = new HashMap<>();
    /** Tracing for CRIUSEC. */
    private static final boolean debug = Boolean.parseBoolean(GetPropertyAction.privilegedGetProperty
            ("enable.j9internal.checkpoint.security.api.debug", "false"));

    /**
     * Removes the usual security providers and adds the CRIU security provider.
     *
     * @param props the system properties
     */
    public static void setCRIUSecMode(Properties props) {
        systemProps = props;

        for (Map.Entry<Object, Object> entry : props.entrySet()) {
            String key = (String) entry.getKey();
            if (key.startsWith("security.provider.")) {
                oldProviders.put(key, (String) entry.getValue());
            }
        }
        for (String provider : oldProviders.keySet()) {
            props.remove(provider);
        }
        props.put("security.provider.1", "openj9.internal.criu.CRIUSECProvider");

        if (debug) {
            System.out.println("CRIUSEC added and all other security providers removed.");
        }
    }

    /**
     * Removes the CRIU security provider and adds the usual security providers back.
     */
    public static void setCRIURestoreMode() {
        Security.removeProvider("CRIUSEC");
        // Note that CRIUSEC was set as security.provider.1 in the method setCRIUSecMode,
        // which is called before this method.
        systemProps.remove("security.provider.1");
        if (debug) {
            System.out.println("CRIUSEC removed.");
        }

        for (Map.Entry<String, String> entry : oldProviders.entrySet()) {
            systemProps.put(entry.getKey(), entry.getValue());
        }
        try {
            // Invoke the fromSecurityProperties method from the ProviderList class.
            Class<?> runnable = Class.forName("sun.security.jca.ProviderList", true, ClassLoader.getSystemClassLoader());
            Method readProperties = runnable.getDeclaredMethod("fromSecurityProperties");
            readProperties.setAccessible(true);
            ProviderList providerList = (ProviderList) readProperties.invoke(null);
            Providers.setProviderList(providerList);
        } catch (Exception e) {
            System.out.println(e.toString());
        }
        if (debug) {
            for (String provider : oldProviders.values()) {
                System.out.println(provider + " restored.");
            }
        }
    }
}
