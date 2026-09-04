/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2026, 2026 All Rights Reserved
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

/*
 * @test
 * @summary Test OpenJCEPlusSemeruDefaults provider loading in Semeru build
 * @library /test/lib
 * @run junit TestOpenJCEPlusSemeruDefaults
 */

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import jdk.test.lib.process.OutputAnalyzer;
import jdk.test.lib.process.ProcessTools;

public class TestOpenJCEPlusSemeruDefaults {

    /**
     * Check if this is a Semeru build by looking for IBM vendor and Semeru runtime.
     */
    private static boolean isSemeruBuild() {
        String vendor = System.getProperty("java.vendor");
        String runtimeName = System.getProperty("java.runtime.name");
        String version = System.getProperty("java.version");
        System.out.println("Java Vendor: " + vendor);
        System.out.println("Java Runtime Name: " + runtimeName);
        System.out.println("Java Version: " + version);

        return (vendor != null) && (runtimeName != null)
                && vendor.contains("IBM")
                && runtimeName.contains("Semeru");
    }

    /**
     * Check if the OpenJCEPlusSemeruDefaults provider is loaded.
     */
    private static void checkProviderLoad() throws Exception {
        if (!isSemeruBuild()) {
            System.out.println("Not a Semeru build. Skipping OpenJCEPlusSemeruDefaults provider test.");
            return;
        }

        System.out.println("This is a Semeru build. Loading for OpenJCEPlusSemeruDefaults provider...");

        // Note: Provider name includes a random suffix like "OpenJCEPlusSemeruDefaults-3EF205".
        Provider OpenJCEPlusSemeruDefaults = null;
        for (Provider provider : Security.getProviders()) {
            if (provider.getName().startsWith("OpenJCEPlusSemeruDefaults")) {
                OpenJCEPlusSemeruDefaults = provider;
                break;
            }
        }

        if (OpenJCEPlusSemeruDefaults != null) {
            System.out.println("SUCCESS: OpenJCEPlusSemeruDefaults provider is loaded.");
            System.out.println("Provider Name: " + OpenJCEPlusSemeruDefaults.getName());
            System.out.println("Provider Version: " + OpenJCEPlusSemeruDefaults.getVersionStr());
            System.out.println("Provider Info: " + OpenJCEPlusSemeruDefaults.getInfo());
        } else {
            System.out.println("FAILURE: OpenJCEPlusSemeruDefaults provider is not loaded in the security providers list.");
            System.out.println("Available providers:");
            for (Provider provider : Security.getProviders()) {
                System.out.println("  - " + provider.getName() + " (Version: " + provider.getVersionStr() + ")");
            }
            throw new RuntimeException("OpenJCEPlusSemeruDefaults provider is not available in this Semeru build");
        }
    }

    /**
     * Test PBE algorithm from OpenJCEPlusSemeruDefaults provider.
     */
    private static void testPBEAlgorithm() throws Exception {
        if (!isSemeruBuild()) {
            System.out.println("Not a Semeru build. Skipping PBE algorithm test.");
            return;
        }

        System.out.println("This is a Semeru build. Testing PBEWithHmacSHA256AndAES_128 algorithm...");

        char[] password = "testPassword123".toCharArray();

        try {
            byte[] salt = new byte[8];
            for (int i = 0; i < salt.length; i++) {
                salt[i] = (byte) i;
            }

            int iterationCount = 1000;
            PBEKeySpec keySpec = new PBEKeySpec(password);

            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");

            String keyFactoryProvider = keyFactory.getProvider().getName();
            System.out.println("SecretKeyFactory provider: " + keyFactoryProvider);

            if (!keyFactoryProvider.startsWith("OpenJCEPlusSemeruDefaults")) {
                throw new RuntimeException(
                        "FAILURE: SecretKeyFactory is not using OpenJCEPlusSemeruDefaults provider. Using: "
                                + keyFactoryProvider);
            }

            SecretKey secretKey = keyFactory.generateSecret(keySpec);

            PBEParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);

            Cipher cipher = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");

            String cipherProvider = cipher.getProvider().getName();
            System.out.println("Cipher provider: " + cipherProvider);

            if (!cipherProvider.startsWith("OpenJCEPlusSemeruDefaults")) {
                throw new RuntimeException(
                        "FAILURE: Cipher is not using OpenJCEPlusSemeruDefaults provider. Using: "
                                + cipherProvider);
            }

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);

            AlgorithmParameters params = cipher.getParameters();
            if (params == null) {
                throw new RuntimeException("FAILURE: Cipher parameters are null after encryption");
            }

            String plaintext = "Hello, OpenJCEPlusSemeruDefaults!";
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            System.out.println("Encryption successful. Encrypted length: "
                    + encrypted.length + " bytes");

            cipher.init(Cipher.DECRYPT_MODE, secretKey, params);

            byte[] decrypted = cipher.doFinal(encrypted);
            String decryptedText = new String(decrypted, StandardCharsets.UTF_8);

            if (!plaintext.equals(decryptedText)) {
                throw new RuntimeException(
                        "FAILURE: Algorithm test failed - Decrypted text does not match original. "
                                + "Expected: '" + plaintext + "', Got: '" + decryptedText + "'");
            }

            System.out.println("SUCCESS: Algorithm test passed. Decrypted text matches original.");
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    @Test
    public void testOpenJCEPlusSemeruDefaultsProviderLoad() throws Exception {
        OutputAnalyzer outputAnalyzer = ProcessTools.executeTestJava(
                "TestOpenJCEPlusSemeruDefaults",
                "providerLoad"
        );
        outputAnalyzer.reportDiagnosticSummary();

        // Check if it's a Semeru build first.
        if (outputAnalyzer.getOutput().contains("Not a Semeru build")) {
            System.out.println("Test skipped: Not running on a Semeru build");
            outputAnalyzer.shouldHaveExitValue(0);
        } else {
            // For Semeru builds, verify the provider was loaded successfully.
            outputAnalyzer.shouldContain("This is a Semeru build");
            outputAnalyzer.shouldContain("SUCCESS: OpenJCEPlusSemeruDefaults provider is loaded");
            outputAnalyzer.shouldHaveExitValue(0);
        }
    }

    @Test
    public void testOpenJCEPlusSemeruDefaultsProviderPBEAlgorithms() throws Exception {
        OutputAnalyzer outputAnalyzer = ProcessTools.executeTestJava(
                "TestOpenJCEPlusSemeruDefaults",
                "pbeAlgorithm"
        );
        outputAnalyzer.reportDiagnosticSummary();

        // Check if it's a Semeru build first.
        if (outputAnalyzer.getOutput().contains("Not a Semeru build")) {
            System.out.println("Test skipped: Not running on a Semeru build");
            outputAnalyzer.shouldHaveExitValue(0);
        } else {
            // For Semeru builds, verify the provider was loaded and algorithm test passed.
            outputAnalyzer.shouldContain("This is a Semeru build");
            outputAnalyzer.shouldContain("Testing PBEWithHmacSHA256AndAES_128 algorithm");
            outputAnalyzer.shouldMatch("SecretKeyFactory provider: OpenJCEPlusSemeruDefaults(-[A-F0-9]+)?");
            outputAnalyzer.shouldMatch("Cipher provider: OpenJCEPlusSemeruDefaults(-[A-F0-9]+)?");
            outputAnalyzer.shouldContain("SUCCESS: Algorithm test passed");
            outputAnalyzer.shouldHaveExitValue(0);
        }
    }

    public static void main(String[] args) throws Exception {
        if ((args.length > 0) && "providerLoad".equals(args[0])) {
            checkProviderLoad();
        } else if ((args.length > 0) && "pbeAlgorithm".equals(args[0])) {
            testPBEAlgorithm();
        }
    }
}
