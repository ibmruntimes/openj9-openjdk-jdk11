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

import java.security.Provider.Service;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Properties;

import sun.security.util.Debug;

public final class RestrictedSecurityProperties {

    private static final Debug debug = Debug.getInstance("semerufips");

    private static RestrictedSecurityProperties instance;

    private static String descName;
    private static String descNumber;
    private static String descPolicy;
    private static String descSunsetDate;

    // Security properties.
    private static String jdkTlsDisabledNamedCurves;
    private static String jdkTlsDisabledAlgorithms;
    private static String jdkTlsDphemeralDHKeySize;
    private static String jdkTlsLegacyAlgorithms;
    private static String jdkCertpathDisabledAlgorithms;
    private static String jdkSecurityLegacyAlgorithm;
    private static String keyStoreType;
    private static String keyStore;

    // For Secure Random.
    private static String jdkSecureRandomProvider;
    private static String jdkSecureRandomAlgorithm;

    // Provider with argument (provider name + optional argument).
    private static ArrayList<String> providers = new ArrayList<String>();;
    // Provider without argument.
    private static ArrayList<String> providersSN = new ArrayList<String>();;
    // Constraints for each provider. Key is the Provider Name, Value is the Constraints.
    private static Map<String, String[][]> providerConstraints = new HashMap<String, String[][]>();

    private final int userSecurityNum;
    private final boolean userSecurityTrace;
    private final boolean userSecurityAudit;
    private final boolean userSecurityHelp;

    private final String propsPrefix;

    // The java.security properties.
    private final Properties securityProps;

    /**
     *
     * @param num   the restricted security setting number
     * @param props the java.security properties
     * @param trace the user security trace
     * @param audit the user security audit
     * @param help  the user security help
     */
    private RestrictedSecurityProperties(int num, Properties props, boolean trace, boolean audit, boolean help) {

        userSecurityNum = num;
        userSecurityTrace = trace;
        userSecurityAudit = audit;
        userSecurityHelp = help;
        securityProps = props;

        propsPrefix = "RestrictedSecurity" + String.valueOf(userSecurityNum);
    }

    /**
     * Get instance of RestrictedSecurityProperties.
     *
     * @param num   the restricted security setting number
     * @param props the java.security properties
     * @param trace the user security trace
     * @param audit the user security audit
     * @param help  the user security help
     * @return the created RestrictedSecurityProperties instance
     */
    public static RestrictedSecurityProperties createInstance(int num, Properties props, boolean trace,
            boolean audit, boolean help) {
        if (instance != null) {
            throw new RuntimeException(
                    "Restricted security mode is already initialized. Can't be initialized twice.");
        }
        instance = new RestrictedSecurityProperties(num, props, trace, audit, help);
        return instance;
    }

    /**
     * Get instance of RestrictedSecurityProperties.
     *
     * @return the created RestrictedSecurityProperties instance
     */
    public static RestrictedSecurityProperties getInstance() {
        if (instance == null) {
            throw new RuntimeException(
                    "Restricted security mode initialization error, call createInstance() first.");
        }
        return instance;
    }

    /**
     * Initialize the restricted security properties.
     */
    public void init() {
        if (debug != null) {
            debug.println("Initializing restricted security mode.");
        }

        if (securityProps == null) {
            throw new RuntimeException(
                    "Restricted security mode initialization error, call getInstance with variables first.");
        }

        try {

            // Print out the Help and Audit info.
            if (userSecurityHelp) {
                printHelp();
                if (userSecurityNum == 0) {
                    if (debug != null) {
                        debug.println("Print out the help info and exit.");
                    }
                    System.exit(0);
                }
            }
            if (userSecurityAudit) {
                listAudit();
                if (userSecurityNum == 0) {
                    if (debug != null) {
                        debug.println("Print out the audit info and exit.");
                    }
                    System.exit(0);
                }
            }

            // Load the restricted security providers from java.security properties.
            initProviders();
            // Load the restricted security properties from java.security properties.
            initProperties();
            // Load the restricted security provider constraints from java.security properties.
            initConstraints();

            // Print out the Trace info.
            if (userSecurityTrace) {
                listTrace();
            }

            if (debug != null) {
                debug.println("Initialized restricted security mode.");
            }
        } catch (Exception e) {
            if (debug != null) {
                debug.println("Unable to initialize restricted security mode.");
            }
            e.printStackTrace();
        }
    }

    /**
     * Load restricted security provider.
     */
    private void initProviders() {

        if (debug != null) {
            debug.println("Loading restricted security providers.");
        }

        for (int pNum = 1;; ++pNum) {
            String providerInfo = securityProps
                    .getProperty(propsPrefix + ".jce.provider." + pNum);

            if (providerInfo == null || providerInfo.trim().isEmpty()) {
                break;
            }

            if (!areBracketsBalanced(providerInfo)) {
                new RuntimeException("Restricted security provider format is inccorect: " + providerInfo)
                        .printStackTrace();
                System.exit(1);
            }

            int pos = providerInfo.indexOf('[');
            String providerName = (pos < 0) ? providerInfo.trim() : providerInfo.substring(0, pos).trim();
            // Provider with argument (provider name + optional argument).
            providers.add(pNum - 1, providerName);

            pos = providerName.indexOf(' ');
            providerName = (pos < 0) ? providerName.trim() : providerName.substring(0, pos).trim();
            // Provider without argument.
            providersSN.add(pNum - 1, providerName);

            if (debug != null) {
                debug.println("Loaded restricted security provider: " + providers.get(pNum - 1) + " with short name: "
                        + providersSN.get(pNum - 1));
            }
        }

        if (providers.isEmpty()) {
            new RuntimeException("Restricted security mode provider list empty, "
                    + "or no such restricted security policy in java.security file.").printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Load restricted security properties.
     */
    private void initProperties() {

        if (debug != null) {
            debug.println("Loading restricted security properties.");
        }

        descName = securityProps.getProperty(propsPrefix + ".desc.name");
        descNumber = securityProps.getProperty(propsPrefix + ".desc.number");
        descPolicy = securityProps.getProperty(propsPrefix + ".desc.policy");
        descSunsetDate = securityProps.getProperty(propsPrefix + ".desc.sunsetDate");

        jdkTlsDisabledNamedCurves = securityProps
                .getProperty(propsPrefix + ".tls.disabledNamedCurves");
        jdkTlsDisabledAlgorithms = securityProps
                .getProperty(propsPrefix + ".tls.disabledAlgorithms");
        jdkTlsDphemeralDHKeySize = securityProps
                .getProperty(propsPrefix + ".tls.ephemeralDHKeySize");
        jdkTlsLegacyAlgorithms = securityProps
                .getProperty(propsPrefix + ".tls.legacyAlgorithms");
        jdkCertpathDisabledAlgorithms = securityProps
                .getProperty(propsPrefix + ".jce.certpath.disabledAlgorithms");
        jdkSecurityLegacyAlgorithm = securityProps
                .getProperty(propsPrefix + ".jce.legacyAlgorithms");
        keyStoreType = securityProps.getProperty(propsPrefix + ".keystore.type");
        keyStore = securityProps.getProperty(propsPrefix + ".javax.net.ssl.keyStore");

        jdkSecureRandomProvider = securityProps
                .getProperty(propsPrefix + ".securerandom.provider");
        jdkSecureRandomAlgorithm = securityProps
                .getProperty(propsPrefix + ".securerandom.algorithm");

        if (debug != null) {
            debug.println("Loaded restricted security properties.");
        }
    }

    /**
     * Load security constraints with type, algorithm, attributes.
     *
     * Example:
     * RestrictedSecurity1.jce.provider.1 = SUN [{CertPathBuilder, PKIX, *}, {Policy,
     * JavaPolicy, *}, {CertPathValidator, *, *}].
     */
    private void initConstraints() {

        for (int pNum = 1; pNum <= providersSN.size(); pNum++) {

            String providerName = providersSN.get(pNum - 1);
            String providerInfo = securityProps
                    .getProperty(propsPrefix + ".jce.provider." + pNum);

            if (debug != null) {
                debug.println("Loading constraints for security provider: " + providerName);
            }

            // Remove all the space.
            providerInfo = providerInfo.trim().replaceAll(" ", "");

            // Provider with constraints.
            if (providerInfo.indexOf("[{") > 0) {
                String[] inputArray = providerInfo.substring(providerInfo.indexOf("[{") + 2, providerInfo.length() - 2)
                        .split("\\},\\{");

                // Column is type, algorithm and attributes.
                String[][] constraints = new String[inputArray.length][3];

                int cNum = 0;
                for (String input : inputArray) {
                    String[] inConstraint = input.trim().split(",");

                    int dNum = 0;
                    for (String inConsDetail : inConstraint) {
                        constraints[cNum][dNum] = !isNullOrBlank(inConsDetail) ? inConsDetail.trim() : "*";
                        dNum ++;
                    }
                    // If each input constraint doesn't have exactly three parts,
                    // set the "*" to those missing parts
                    for (int i = dNum; i < 3; i ++) {
                        constraints[cNum][i] = "*";
                    }

                    if (debug != null) {
                        debug.println("Loading constraints for provider " + providerName + " with constraints type: "
                                + constraints[cNum][0] + " algorithm: " + constraints[cNum][1] + " attributes: "
                                + constraints[cNum][2]);
                    }
                    cNum++;
                }
                providerConstraints.put(providerName, constraints);
                if (debug != null) {
                    debug.println("Loaded constraints for security provider: " + providerName);
                }
            }
        }
    }

    /**
     * Check if the Service is allowed in restricted security mode.
     *
     * @param service the Service to check
     * @return true if the Service is allowed
     */
    public boolean isServiceAllowed(Service service) {

        String providerName = service.getProvider().getName();
        String type = service.getType();
        String algorithm = service.getAlgorithm();

        // Provider with argument, remove argument.
        // e.g. SunPKCS11-NSS-FIPS, remove argument -NSS-FIPS.
        int pos = providerName.indexOf('-');
        providerName = (pos > 0) ? providerName.substring(0, pos) : providerName;

        String[][] constraints = providerConstraints.get(providerName);

        // Go into the security provider constraints check if there are.
        if (constraints != null && constraints.length > 0) {

            for (int cNum = 0; cNum < constraints.length; cNum++) {

                boolean cTypePut = "*".equals(constraints[cNum][0]) || type.equals(constraints[cNum][0]);
                boolean cAlgorithmPut = "*".equals(constraints[cNum][1]) || algorithm.equals(constraints[cNum][1]);
                boolean cAttributePut = "*".equals(constraints[cNum][2]);

                if (cTypePut && cAlgorithmPut && cAttributePut) {
                    if (debug != null) {
                        debug.println("Security constraints check, service type " + type + " algorithm " + algorithm
                                + " is allowed in provider " + providerName);
                    }
                    return true;
                }

                if (cTypePut && cAlgorithmPut) {
                    String[] cAttributes = constraints[cNum][2].split(":");

                    for (String cAttribute : cAttributes) {
                        String[] input = cAttribute.trim().split("=");
                        cAttributePut = true;

                        try {
                            String cName = input[0];
                            String cValue = input[1];
                            String sValue = service.getAttribute(cName);
                            cAttributePut &= (sValue != null) && cValue.equalsIgnoreCase(sValue);
                        } catch (ArrayIndexOutOfBoundsException ex) {
                            cAttributePut = false;
                            new RuntimeException(
                                    "Security constraints attribute for provider " + providerName + " is incorrect")
                                    .printStackTrace();
                        }
                    }

                    if (cAttributePut) {
                        if (debug != null) {
                            debug.println(
                                    "Security constraints check, service type " + type + " algorithm " + algorithm
                                    + " attribute " + constraints[cNum][2] + " is allowed in provider "
                                    + providerName);
                        }
                        return true;
                    }
                }
            }
            if (debug != null) {
                debug.println("Security constraints check, service type " + type + " algorithm " + algorithm
                        + " is NOT allowed in provider " + providerName);
            }
            return false;
        }
        return true;
    }

    /**
     * Check if the provider is allowed in restricted security mode.
     *
     * @param providerName the provider to check
     * @return true if the provider is allowed
     */
    public boolean isProviderAllowed(String providerName) {

        if (debug != null) {
            debug.println("Checking the provider " + providerName + " in the restricted security mode.");
        }

        // Remove the provider class package name if there is.
        int pos = providerName.lastIndexOf('.');
        providerName = (pos > 0) ? providerName.substring(pos + 1, providerName.length()) : providerName;

        // Remove argument, e.g. -NSS-FIPS, if there is.
        pos = providerName.indexOf('-');
        providerName = (pos > 0) ? providerName.substring(0, pos) : providerName;

        // Check if the provider is in the restricted security provider list.
        // If not, the provider won't be registered.
        if (providersSN.contains(providerName)) {
            if (debug != null) {
                debug.println("The provider " + providerName + " is allowed in the restricted security mode.");
            }
            return true;
        }

        if (debug != null) {
            debug.println("The provider " + providerName + " is not allowed in the restricted security mode.");

            System.out.println("Stack trace:");
            StackTraceElement[] elements = Thread.currentThread().getStackTrace();
            for (int i = 1; i < elements.length; i++) {
                StackTraceElement stack = elements[i];
                System.out.println("\tat " + stack.getClassName() + "." + stack.getMethodName() + "("
                        + stack.getFileName() + ":" + stack.getLineNumber() + ")");
            }
        }
        return false;
    }

    /**
     * Check if the provider is allowed in restricted security mode.
     *
     * @param providerClazz the provider class to check
     * @return true if the provider is allowed
     */
    public boolean isProviderAllowed(Class<?> providerClazz) {

        String providerName = providerClazz.getName();

        // Check if the specified class extends java.security.Provider
        if (!java.security.Provider.class.isAssignableFrom(providerClazz)) {
            if (debug != null) {
                debug.println("The provider class " + providerName + " does not extend java.security.Provider.");
            }
            // For class doesn't extend java.security.Provider, no need to
            // check allowed or not allowed, always return true to load it.
            return true;
        }
        return isProviderAllowed(providerName);
    }

    /**
     * List Audit info if userSecurityAudit is ture, default as false.
     */
    protected void listAudit() {

        System.out.println();
        System.out.println("Restricted Security Audit Info:");
        System.out.println("===============================");

        for (int num = 1;; ++num) {
            String desc = securityProps.getProperty("RestrictedSecurity" + num + ".desc.name");
            if (desc == null || desc.trim().isEmpty()) {
                break;
            }
            System.out.println("RestrictedSecurity" + num + ".desc.name: "
                    + securityProps.getProperty("RestrictedSecurity" + num + ".desc.name"));
            System.out.println("RestrictedSecurity" + num + ".desc.number: "
                    + securityProps.getProperty("RestrictedSecurity" + num + ".desc.number"));
            System.out.println("RestrictedSecurity" + num + ".desc.policy: "
                    + securityProps.getProperty("RestrictedSecurity" + num + ".desc.policy"));
            System.out.println("RestrictedSecurity" + num + ".desc.sunsetDate: "
                    + securityProps.getProperty("RestrictedSecurity" + num + ".desc.sunsetDate"));
            System.out.println();
        }
    }

    /**
     * List Trace info if userSecurityTrace is true, default as false.
     */
    protected void listTrace() {

        System.out.println();
        System.out.println("Restricted Security Trace Info:");
        System.out.println("===============================");
        System.out.println(propsPrefix + ".desc.name: " + descName);
        System.out.println(propsPrefix + ".desc.number: " + descNumber);
        System.out.println(propsPrefix + ".desc.policy: " + descPolicy);
        System.out.println(propsPrefix + ".desc.sunsetDate: " + descSunsetDate);
        System.out.println();

        // List only restrictions.
        System.out.println(propsPrefix + ".tls.disabledNamedCurves: "
                + jdkTlsDisabledNamedCurves);
        System.out.println(propsPrefix + ".tls.disabledAlgorithms: "
                + jdkTlsDisabledAlgorithms);
        System.out.println(propsPrefix + ".tls.ephemeralDHKeySize: "
                + jdkTlsDphemeralDHKeySize);
        System.out.println(propsPrefix + ".tls.legacyAlgorithms: "
                + jdkTlsLegacyAlgorithms);
        System.out.println(propsPrefix + ".jce.certpath.disabledAlgorithms: "
                + jdkCertpathDisabledAlgorithms);
        System.out.println(propsPrefix + ".jce.legacyAlgorithms: "
                + jdkSecurityLegacyAlgorithm);
        System.out.println();

        System.out.println(propsPrefix + ".keystore.type: "
                + keyStoreType);
        System.out.println(propsPrefix + ".javax.net.ssl.keyStore: "
                + keyStore);
        System.out.println(propsPrefix + ".securerandom.provider: "
                + jdkSecureRandomProvider);
        System.out.println(propsPrefix + ".securerandom.algorithm: "
                + jdkSecureRandomAlgorithm);

        // List providers.
        System.out.println();
        for (int pNum = 1; pNum <= providers.size(); pNum++) {
            System.out.println(propsPrefix + ".jce.provider." + pNum + ": "
                    + providers.get(pNum - 1));
        }

        System.out.println();
    }

    /**
     * Print help info if userSecurityHelp is ture, default as false.
     */
    protected void printHelp() {

        System.out.println();
        System.out.println("Restricted Security Mode Usage:");
        System.out.println("===============================");

        System.out.println(
                "-Dsemeru.restrictedsecurity=<n>  This flag will select the settings for the user " +
                "specified restricted security policy.");
        System.out.println(
                "-Dsemeru.restrictedsecurity=audit  This flag will list the name and number of all " +
                "configured restricted security policies. it will NOT cause the jvm to terminate " +
                "after printing the restricted security policies.");
        System.out.println(
                "-Dsemeru.restrictedsecurity=trace  This flag will list all properties relevant to " +
                "the restricted security mode, including the existing default properties and the " +
                "restricted security restrictions.");
        System.out.println("-Dsemeru.restrictedsecurity=help  This flag will print help message.");

        System.out.println();
        System.out.println("e.g.");
        System.out.println("    -Dsemeru.restrictedsecurity=1,trace,audit,help");
        System.out.println("    -Dsemeru.restrictedsecurity=help");

        System.out.println();
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

    /**
     * Function to check if brackets are balanced.
     *
     * @param string Input string for checking
     * @return true if the brackets are balanced
     */
    private boolean areBracketsBalanced(String string) {

        Deque<Character> stack = new ArrayDeque<Character>();

        for (int i = 0; i < string.length(); i++) {
            char x = string.charAt(i);

            if (x == '(' || x == '[' || x == '{') {
                stack.push(x);
                continue;
            }

            char check;
            try {
                switch (x) {
                    case ')':
                        check = stack.pop();
                        if (check == '{' || check == '[') {
                            return false;
                        }
                        break;
                    case '}':
                        check = stack.pop();
                        if (check == '(' || check == '[') {
                            return false;
                        }
                        break;
                    case ']':
                        check = stack.pop();
                        if (check == '(' || check == '{') {
                            return false;
                        }
                        break;
                }
            } catch (NoSuchElementException ex) {
                return false;
            }
        }
        // Check Empty Stack.
        return stack.isEmpty();
    }

    public String getDescName() {
        return descName;
    }

    public String getDescNumber() {
        return descNumber;
    }

    public String getDescPolicy() {
        return descPolicy;
    }

    public String getDescSunsetDate() {
        return descSunsetDate;
    }

    public String getJdkTlsDisabledNamedCurves() {
        return jdkTlsDisabledNamedCurves;
    }

    public String getJdkTlsDisabledAlgorithms() {
        return jdkTlsDisabledAlgorithms;
    }

    public String getJdkTlsDphemeralDHKeySize() {
        return jdkTlsDphemeralDHKeySize;
    }

    public String getJdkTlsLegacyAlgorithms() {
        return jdkTlsLegacyAlgorithms;
    }

    public String getJdkCertpathDisabledAlgorithms() {
        return jdkCertpathDisabledAlgorithms;
    }

    public String getJdkSecurityLegacyAlgorithm() {
        return jdkSecurityLegacyAlgorithm;
    }

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public String getKeyStore() {
        return keyStore;
    }

    public ArrayList<String> getProviders() {
        return providers;
    }

    public String getJdkSecureRandomProvider() {
        return jdkSecureRandomProvider;
    }

    public String getJdkSecureRandomAlgorithm() {
        return jdkSecureRandomAlgorithm;
    }
}
