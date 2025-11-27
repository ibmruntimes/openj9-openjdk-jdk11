/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2024, 2025 All Rights Reserved
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
 * @summary Test Restricted Security Mode Properties
 * @library /test/lib
 * @run junit TestProperties
 */

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.security.Provider;
import java.security.Security;

import java.util.stream.Stream;

import jdk.test.lib.process.OutputAnalyzer;
import jdk.test.lib.process.ProcessTools;

public class TestProperties {

    private static Stream<Arguments> patternMatches_expectedExitValue0() {
        return Stream.of(
                // 1 - Test property - Same beginnings of the profile name without version.
                Arguments.of("Test-Profile-SameStartWithoutVersion",
                        System.getProperty("test.src") + "/property-java.security",
                        "(?s)(?=.*Sun)(?=.*\\bSunJCE\\b)(?=.*SunJSSE)")
        );
    }

    private static Stream<Arguments> patternMatches_expectedExitValue1() {
        return Stream.of(
                // 1 - Test profile - base profile misspell properties.
                Arguments.of("Test-Profile.Base",
                        System.getProperty("test.src") + "/property-java.security",
                        "The property names: RestrictedSecurity.Test-Profile.Base.tls.disabledAlgorithmsWrongTypo "
                            + "in profile RestrictedSecurity.Test-Profile.Base \\(or a base profile\\) are not recognized"),
                // 2 - Test profile - extenstion profile misspell properties.
                Arguments.of("Test-Profile.Extended_1",
                        System.getProperty("test.src") + "/property-java.security",
                        "The property names: RestrictedSecurity.Test-Profile.Extended_1.desc.nameWrongTypo, "
                            + "RestrictedSecurity.Test-Profile.Extended_1.jce.providerWrongTypo in profile "
                            + "RestrictedSecurity.Test-Profile.Extended_1 \\(or a base profile\\) are not recognized"),
                // 3 - Test profile - extension profile from another extension profile misspell properties.
                Arguments.of("Test-Profile.Extended_2",
                        System.getProperty("test.src") + "/property-java.security",
                        "The property names: RestrictedSecurity.Test-Profile.Extended_2.jce.providerWrongTypo "
                            + "in profile RestrictedSecurity.Test-Profile.Extended_2 \\(or a base profile\\) are not recognized"),
                // 4 - Test profile - profile not exist.
                Arguments.of("Test-Profile-NotExist.Base",
                        System.getProperty("test.src") + "/property-java.security",
                        "Test-Profile-NotExist.Base is not present in the java.security file."),
                // 5 - Test profile - Multi Default profile.
                Arguments.of("Test-Profile-MultiDefault",
                        System.getProperty("test.src") + "/property-java.security",
                        "Multiple default RestrictedSecurity profiles for Test-Profile-MultiDefault"),
                // 6 - Test profile - no default profile.
                Arguments.of("Test-Profile-NoDefault",
                        System.getProperty("test.src") + "/property-java.security",
                        "No default RestrictedSecurity profile was found for Test-Profile-NoDefault"),
                // 7 - Test profile - base profile does not exist.
                Arguments.of("Test-Profile.Extended_3",
                        System.getProperty("test.src") + "/property-java.security",
                        "RestrictedSecurity.Test-Profile.BaseNotExist that is supposed to extend \\'RestrictedSecurity.Test-Profile.Extended_3\\' "
                            + "is not present in the java.security file or any appended files"),
                // 8 - Test profile - base profile not full profile name.
                Arguments.of("Test-Profile.Extended_4",
                        System.getProperty("test.src") + "/property-java.security",
                        "RestrictedSecurity.BaseNotFullProfileName that is supposed to extend \\'RestrictedSecurity.Test-Profile.Extended_4\\' "
                            + "is not a full profile name"),
                // 9 - Test profile - base profile without hash value.
                Arguments.of("Test-Profile-BaseWithoutHash",
                        System.getProperty("test.src") + "/property-java.security",
                        "Test-Profile-BaseWithoutHash is a base profile, so a hash value is mandatory"),
                // 10 - Test profile - incorrect definition of hash value.
                Arguments.of("Test-Profile-Hash_1",
                        System.getProperty("test.src") + "/property-java.security",
                        "Incorrect definition of hash value for RestrictedSecurity.Test-Profile-Hash_1"),
                // 11 - Test profile - incorrect hash value.
                Arguments.of("Test-Profile-Hash_2",
                        System.getProperty("test.src") + "/property-java.security",
                        "Hex produced from profile is not the same is a base profile, so a hash value is mandatory"),
                // 12 - Test property - property not appendable.
                Arguments.of("Test-Profile-SetProperty.Extension_1",
                        System.getProperty("test.src") + "/property-java.security",
                        "Property \\'jdkSecureRandomProvider\\' is not appendable"),
                // 13 - Test property - property does not exist in parent profile, cannot append.
                Arguments.of("Test-Profile-SetProperty.Extension_2",
                        System.getProperty("test.src") + "/property-java.security",
                        "Property \\'jdkTlsDisabledNamedCurves\\' does not exist in parent profile or java.security file. Cannot append"),
                // 14 - Test property - property value is not in existing values.
                Arguments.of("Test-Profile-SetProperty.Extension_3",
                        System.getProperty("test.src") + "/property-java.security",
                        "Value \\'TestDisabledlgorithms\\' is not in existing values"),
                // 15 - Test property - policy sunset.
                Arguments.of("Test-Profile-PolicySunset.Base",
                        System.getProperty("test.src") + "/property-java.security",
                        "Use -Dsemeru.restrictedsecurity.ignoresunsetexpiration to allow Java to start while possibly using uncertified cryptography"),
                // 16 - Test property - policy sunset format.
                Arguments.of("Test-Profile-PolicySunsetFormat.Base",
                        System.getProperty("test.src") + "/property-java.security",
                        "Restricted security policy sunset date is incorrect, the correct format is yyyy-MM-dd"),
                // 17 - Test property - secure random check 1.
                Arguments.of("Test-Profile-SecureRandomCheck_1",
                        System.getProperty("test.src") + "/property-java.security",
                        "Restricted security mode secure random is missing"),
                // 18 - Test property - secure random check 2.
                Arguments.of("Test-Profile-SecureRandomCheck_2",
                        System.getProperty("test.src") + "/property-java.security",
                        "Restricted security mode secure random is missing"),
                // 19 - Test constraint - constraint check 1.
                Arguments.of("Test-Profile-Constraint_1",
                        System.getProperty("test.src") + "/property-java.security",
                        "Provider format is incorrect"),
                // 20 - Test constraint - constraint check 2.
                Arguments.of("Test-Profile-Constraint_2",
                        System.getProperty("test.src") + "/property-java.security",
                        "Incorrect constraint definition for provider"),
                // 21 - Test constraint - constraint check 3.
                Arguments.of("Test-Profile-Constraint_3",
                        System.getProperty("test.src") + "/property-java.security",
                        "Incorrect constraint definition for provider"),
                // 22 - Test constraint - constraint attributes check.
                Arguments.of("Test-Profile-Constraint_Attributes",
                        System.getProperty("test.src") + "/property-java.security",
                        "Constraint attributes format is incorrect"),
                // 23 - Test constraint - constraint changed 1.
                Arguments.of("Test-Profile-ConstraintChanged_1.Extension",
                        System.getProperty("test.src") + "/property-java.security",
                        "Cannot append or remove constraints since the provider (.*?) "
                            + "wasn't in this position in the profile extended"),
                // 24 - Test constraint - constraint changed 2.
                Arguments.of("Test-Profile-ConstraintChanged_2.Extension",
                        System.getProperty("test.src") + "/property-java.security",
                        "Constraint (.*?)is not part of existing constraints"),
                // 25 - Test constraint - constraint changed 3.
                Arguments.of("Test-Profile-ConstraintChanged_3.Base",
                        System.getProperty("test.src") + "/property-java.security",
                        "Constraints of provider not previously specified cannot be modified")
        );
    }

    private static Stream<Arguments> patternMatches_propertiesList() {
        Stream.Builder<Arguments> tests = Stream.builder();

        if (isProviderPresent("OpenJCEPlusFIPS")) {
            // 1 - The profile in propertyListA-java.security extends the profile
            // in the main java.security file, which lists 4 providers.
            tests.add(Arguments.of("Test-Profile-Property-List.A",
                    System.getProperty("test.src") + "/propertyListA-java.security",
                    "(?s)(?=.*OpenJCEPlusFIPS)(?=.*Sun)(?=.*SunJSSE)(?=.*SunEC)",
                    0));
            // 2 - The profile in propertyListB-java.security extends the profile
            // in propertyListA-java.security, which in turn extends the profile
            // in the main java.security file, listing 5 providers.
            tests.add(Arguments.of("Test-Profile-Property-List.B",
                    System.getProperty("test.src") + "/propertyListA-java.security" + File.pathSeparator
                            + System.getProperty("test.src") + "/propertyListB-java.security",
                    "(?s)(?=.*OpenJCEPlusFIPS)(?=.*Sun)(?=.*SunJSSE)(?=.*SunEC)(?=.*SunJCE)",
                    0));
        }

        // 3 - The profile in propertyListB-java.security extends the profile
        // in propertyListA-java.security, which in turn extends the main
        // java.security profile, but propertyListB-java.security file is missing.
        tests.add(Arguments.of("Test-Profile-Property-List.B",
                System.getProperty("test.src") + "/propertyListB-java.security",
                "is not present in the java.security file or any appended files",
                1));
        // 4 - The -Djava.security.propertiesList option does not support using
        // a leading '=' prefix.
        tests.add(Arguments.of("Test-Profile-Property-List.A",
                "=" + System.getProperty("test.src") + "/propertyListA-java.security",
                "java.security.propertiesList does not support '=' prefix",
                1));

        return tests.build();
    }

    @ParameterizedTest
    @MethodSource("patternMatches_expectedExitValue0")
    public void shouldContain_expectedExitValue0(String customprofile, String securityPropertyFile, String expected) throws Exception {
        OutputAnalyzer outputAnalyzer = ProcessTools.executeTestJava(
                "-Dsemeru.fips=true",
                "-Dsemeru.customprofile=" + customprofile,
                "-Djava.security.properties=" + securityPropertyFile,
                "TestProperties"
        );
        outputAnalyzer.reportDiagnosticSummary();
        outputAnalyzer.shouldHaveExitValue(0).shouldMatch(expected);
    }

    @ParameterizedTest
    @MethodSource("patternMatches_expectedExitValue1")
    public void shouldContain_expectedExitValue1(String customprofile, String securityPropertyFile, String expected) throws Exception {
        OutputAnalyzer outputAnalyzer = ProcessTools.executeTestJava(
                "-Dsemeru.fips=true",
                "-Dsemeru.customprofile=" + customprofile,
                "-Djava.security.properties=" + securityPropertyFile,
                "TestProperties"
        );
        outputAnalyzer.reportDiagnosticSummary();
        outputAnalyzer.shouldHaveExitValue(1).shouldMatch(expected);
    }

    @ParameterizedTest
    @MethodSource("patternMatches_propertiesList")
    public void shouldContain_propertiesList(String customprofile, String securityPropertyFileList,
            String expected, int exitValue) throws Exception {
        OutputAnalyzer outputAnalyzer = ProcessTools.executeTestJava(
                "-Dsemeru.fips=true",
                "-Dsemeru.customprofile=" + customprofile,
                "-Djava.security.propertiesList=" + securityPropertyFileList,
                "TestProperties");
        outputAnalyzer.reportDiagnosticSummary();
        outputAnalyzer.shouldHaveExitValue(exitValue).shouldMatch(expected);
    }

    private static boolean isProviderPresent(String providerName) {
        for (Provider provider : Security.getProviders()) {
            if (provider.getName().equalsIgnoreCase(providerName)) {
                return true;
            }
        }
        return false;
    }

    public static void main(String[] args) {
        // Something to trigger "properties" debug output.
        try {
            for (Provider provider : Security.getProviders()) {
                System.out.println("Provider Name: " + provider.getName());
                System.out.println("Provider Version: " + provider.getVersionStr());
            }
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}
