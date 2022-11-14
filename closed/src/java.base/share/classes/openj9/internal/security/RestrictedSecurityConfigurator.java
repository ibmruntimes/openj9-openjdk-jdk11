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
package openj9.internal.security;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

import sun.security.util.Debug;

/*[IF CRIU_SUPPORT]*/
import openj9.internal.criu.InternalCRIUSupport;
/*[ENDIF] CRIU_SUPPORT*/

/**
 * Configures the security providers when in restricted security mode.
 */
public final class RestrictedSecurityConfigurator {

    private static final Debug debug = Debug.getInstance("semerufips");

    // Restricted security mode enable check, only supported on Linux x64.
    private static final boolean userEnabledFIPS;
    private static final boolean userEnabledSecurity;
    private static final boolean isSecuritySupported;
    private static final boolean shouldEnableSecurity;
    private static final String userSecuritySetting;

    private static boolean securityEnabled = false;

    private static int userSecurityNum = 0;
    private static boolean userSecurityTrace;
    private static boolean userSecurityAudit;
    private static boolean userSecurityHelp;

    private static final List<String> supportPlatforms = List.of("amd64");

    static {
        String[] props = AccessController.doPrivileged(
                new PrivilegedAction<>() {
                    @Override
                    public String[] run() {
                        return new String[] { System.getProperty("semeru.fips"),
                                System.getProperty("semeru.restrictedsecurity"),
                                System.getProperty("os.name"),
                                System.getProperty("os.arch") };
                    }
                });
        userEnabledFIPS = Boolean.parseBoolean(props[0]);
        String securitySetting = props[1];
        // If semeru.fips is true, then ignore semeru.restrictedsecurity, use userSecurityNum 1.
        if (Boolean.parseBoolean(props[0])) {
            securitySetting = "1";
        }
 /*[IF CRIU_SUPPORT]*/
        // If CRIU checkpoint mode is enabled, use the 2nd restricted security policy.
        if (InternalCRIUSupport.isCheckpointAllowed()) {
            securitySetting = "2";
        }
 /*[ENDIF] CRIU_SUPPORT*/
        userSecuritySetting = securitySetting;
        userEnabledSecurity = !isNullOrBlank(userSecuritySetting);
        isSecuritySupported = "Linux".equalsIgnoreCase(props[2])
                && supportPlatforms.contains(props[3]);
        shouldEnableSecurity = (userEnabledFIPS || userEnabledSecurity) && isSecuritySupported;
    }

    private RestrictedSecurityConfigurator() {
        super();
    }

    /**
     * Restricted security mode will be enabled only if the semeru.fips system
     * property is true (default as false), or semeru.restrictedsecurity is set,
     * or CRIU checkpoint mode is enabled.
     *
     * @return true if restricted security is enabled
     */
    public static boolean isEnabled() {
        return securityEnabled;
    }

/*[IF CRIU_SUPPORT]*/
    /**
     * Disables the restricted security mode.
     */
    public static void disable() {
        securityEnabled = false;
    }
/*[ENDIF] CRIU_SUPPORT*/

    /**
     * Remove the security providers and only add the restricted security providers.
     *
     * @param props the java.security properties
     * @return true if the restricted security properties loaded successfully
     */
    public static boolean configure(Properties props) {

        // Check if restricted security is supported on this platform.
        if ((userEnabledFIPS || userEnabledSecurity) && !isSecuritySupported) {
            new RuntimeException("Restricted security mode is not supported on this platform.")
                    .printStackTrace();
            System.exit(1);
        }

        try {
            if (shouldEnableSecurity) {
                if (debug != null) {
                    debug.println("Restricted security mode detected, loading...");
                }

                // Read and set user restricted security settings.
                initUserSetting();

                // Initialize the restricted security properties from java.security file.
                RestrictedSecurityProperties restricts = RestrictedSecurityProperties.createInstance(userSecurityNum,
                        props, userSecurityTrace, userSecurityAudit, userSecurityHelp);
                restricts.init();

                // Check if the SunsetDate expired.
                if (isPolicySunset(restricts.getDescSunsetDate())) {
                    new RuntimeException("Restricted security policy expired.").printStackTrace();
                    System.exit(1);
                }

                // Check secure random settings.
                if (isNullOrBlank(restricts.getJdkSecureRandomProvider())
                        || isNullOrBlank(restricts.getJdkSecureRandomAlgorithm())) {
                    new RuntimeException("Restricted security mode secure random is null.")
                            .printStackTrace();
                    System.exit(1);
                }

                // Remove all security providers.
                Iterator<Entry<Object, Object>> i = props.entrySet().iterator();
                while (i.hasNext()) {
                    Entry<Object, Object> e = i.next();
                    if (((String) e.getKey()).startsWith("security.provider")) {
                        if (debug != null) {
                            debug.println("Removing provider: " + e);
                        }
                        i.remove();
                    }
                }

                // Add restricted security providers.
                setProviders(props, restricts.getProviders());

                // Add restricted security Properties.
                setProperties(props, restricts);

                if (debug != null) {
                    debug.println("Restricted security mode loaded.");
                    debug.println("Restricted security mode properties: " + props.toString());
                }

                securityEnabled = true;
            }

        } catch (Exception e) {
            if (debug != null) {
                debug.println("Unable to load restricted security mode configurations.");
            }
            e.printStackTrace();
        }
        return securityEnabled;
    }

    /**
     * Load user restricted security settings from system property.
     */
    private static void initUserSetting() {

        if (debug != null) {
            debug.println("Loading user restricted security settings.");
        }

        String[] inputs = userSecuritySetting.split(",");

        // For input ",,"
        if (inputs.length == 0) {
            new RuntimeException("user restricted security setting " + userSecuritySetting + " incorrect.")
                    .printStackTrace();
            System.exit(1);
        }

        for (String input : inputs) {
            String in = input.trim();
            if (in.equalsIgnoreCase("audit")) {
                userSecurityAudit = true;
            } else if (in.equalsIgnoreCase("help")) {
                userSecurityHelp = true;
            } else if (in.equalsIgnoreCase("trace")) {
                userSecurityTrace = true;
            } else {
                try {
                    userSecurityNum = Integer.parseInt(in);
                } catch (NumberFormatException e) {
                    new RuntimeException("user restricted security setting " + userSecuritySetting + " incorrect.")
                            .printStackTrace();
                    System.exit(1);
                }
            }
        }

        if (debug != null) {
            debug.println("Loaded user restricted security settings, with userSecurityNum: "
                    + String.valueOf(userSecurityNum) + " userSecurityTrace: " + userSecurityTrace
                    + " userSecurityAudit: " + userSecurityAudit + " userSecurityHelp: " + userSecurityHelp);
        }
    }

    /**
     * Add restricted security providers.
     *
     * @param providers the provider name array
     */
    private static void setProviders(Properties props, ArrayList<String> providers) {

        if (debug != null) {
            debug.println("Adding restricted security provider.");
        }

        int pNum = 1;
        for (String provider : providers) {
            props.setProperty("security.provider." + pNum, provider);
            pNum ++;
            if (debug != null) {
                debug.println("Added restricted security provider: " + provider);
            }
        }
    }

    /**
     * Add restricted security properties.
     *
     * @param props the java.security properties
     */
    private static void setProperties(Properties props, RestrictedSecurityProperties properties) {

        if (debug != null) {
            debug.println("Adding restricted security properties.");
        }

        Map<String, String> propsMapping = new HashMap<>();

        // JDK properties name as Key, restricted security properties vaule as value.
        propsMapping.put("jdk.tls.disabledNamedCurves", properties.getJdkTlsDisabledNamedCurves());
        propsMapping.put("jdk.tls.disabledAlgorithms", properties.getJdkTlsDisabledAlgorithms());
        propsMapping.put("jdk.tls.ephemeralDHKeySize", properties.getJdkTlsDphemeralDHKeySize());
        propsMapping.put("jdk.tls.legacyAlgorithms", properties.getJdkTlsLegacyAlgorithms());
        propsMapping.put("jdk.certpath.disabledAlgorithms", properties.getJdkCertpathDisabledAlgorithms());
        propsMapping.put("jdk.security.legacyAlgorithm", properties.getJdkSecurityLegacyAlgorithm());

        for (Map.Entry<String, String> entry : propsMapping.entrySet()) {
            String jdkPropsName = entry.getKey();
            String propsNewValue = entry.getValue();

            String propsOldValue = !isNullOrBlank(props.getProperty(jdkPropsName)) ? props.getProperty(jdkPropsName) : "";

            if (!isNullOrBlank(propsNewValue)) {
                String values = !isNullOrBlank(propsOldValue) ? propsOldValue + ", " + propsNewValue : propsNewValue;
                props.setProperty(jdkPropsName, values);
                if (debug != null) {
                    debug.println("Added restricted security properties, with property: " + jdkPropsName + " values: "
                            + values);
                }
            }
        }

        // For keyStore and keystore.type, old value not needed, just set the new value.
        if (!isNullOrBlank(properties.getKeyStoreType())) {
            props.setProperty("keystore.type", properties.getKeyStoreType());
        }
        if (!isNullOrBlank(properties.getKeyStore())) {
            System.setProperty("javax.net.ssl.keyStore", properties.getKeyStore());
        }
    }

    /**
     * Check if restricted security policy sunset.
     *
     * @param descSunsetDate the sun set date from java.security
     * @return true if the restricted security policy sunset
     */
    private static boolean isPolicySunset(String descSunsetDate) {

        boolean isSunset = false;
        try {
            isSunset = LocalDate.parse(descSunsetDate, DateTimeFormatter.ofPattern("yyyy-MM-dd"))
                    .isBefore(LocalDate.now());
        } catch (Exception except) {
            new RuntimeException(
                    "Restricted security policy sunset date is inccorect, the correct format is yyyy-MM-dd.")
                    .printStackTrace();
            System.exit(1);
        }

        if (debug != null) {
            debug.println("Restricted security policy is sunset: " + isSunset);
        }
        return isSunset;
    }

    /**
     * Check if the input string is null and empty.
     *
     * @param string the input string
     * @return true if the input string is null and emtpy
     */
    private static boolean isNullOrBlank(String string) {
        return (string == null) || string.isBlank();
    }
}
