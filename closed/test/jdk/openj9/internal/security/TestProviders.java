/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2024, 2024 All Rights Reserved
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
 * @summary Test Restricted Security Mode Provider List
 * @library /test/lib
 * @run junit TestProviders
 */

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.Provider;
import java.security.Security;

import java.util.stream.Stream;

import jdk.test.lib.process.OutputAnalyzer;
import jdk.test.lib.process.ProcessTools;

public class TestProviders {

    private static Stream<Arguments> patternMatches_expectedExitValue0() {
        return Stream.of(
                // Test strict profile provider list.
                Arguments.of("TestBase.Version",
                        System.getProperty("test.src") + "/provider-java.security",
                        "(?s)(?=.*Sun)(?=.*\\bSunJCE\\b)(?=.*SunJSSE)"),
                // Test default profile provider list.
                Arguments.of("TestBase",
                        System.getProperty("test.src") + "/provider-java.security",
                        "(?s)(?=.*Sun)(?=.*SunRsaSign)(?=.*SunEC)(?=.*SunJSSE)"
                            + "(?=.*SunJCE)(?=.*SunJGSS)(?=.*SunSASL)"
                            + "(?=.*XMLDSig)(?=.*SunPCSC)(?=.*JdkLDAP)(?=.*JdkSASL)"),
                // Test extended profile provider list.
                Arguments.of("TestBase.Version-Extended",
                        System.getProperty("test.src") + "/provider-java.security",
                        "(?s)(?=.*Sun)(?=.*SunRsaSign)(?=.*SunEC)(?=.*SunJSSE)"
                            + "(?=.*SunJCE)(?=.*SunJGSS)(?=.*SunSASL)"
                            + "(?=.*XMLDSig)(?=.*SunPCSC)(?=.*JdkLDAP)(?=.*JdkSASL)"),
                // Test update provider list with value.
                Arguments.of("Test-Profile.Updated_1",
                        System.getProperty("test.src") + "/provider-java.security",
                        "(?s)(?=.*Sun)(?=.*\\bSunJCE\\b)(?=.*SunSASL)"),
                // Test update provider list with null.
                Arguments.of("Test-Profile.Updated_2",
                        System.getProperty("test.src") + "/provider-java.security",
                        "(?s)(?=.*Sun)(?=.*\\bSunJCE\\b)(?=.*SunJSSE)")
        );
    }

    private static Stream<Arguments> patternMatches_expectedExitValue1() {
        return Stream.of(
                // Test base profile - provider order numbers are not consecutive.
                Arguments.of("Test-Profile.Base",
                        System.getProperty("test.src") + "/provider-java.security",
                        "The order numbers of providers in profile RestrictedSecurity.Test-Profile.Base "
                            + "\\(or a base profile\\) are not consecutive"),
                // Test extended profile, provider order numbers are not consecutive.
                Arguments.of("Test-Profile.Extended_1",
                        System.getProperty("test.src") + "/provider-java.security",
                        "The order numbers of providers in profile RestrictedSecurity.Test-Profile.Extended_1 "
                            + "\\(or a base profile\\) are not consecutive."),
                // Test extended profile from another extended profile, provider order numbers are not consecutive.
                Arguments.of("Test-Profile.Extended_2",
                        System.getProperty("test.src") + "/provider-java.security",
                        "The order numbers of providers in profile RestrictedSecurity.Test-Profile.Extended_2 "
                            + "\\(or a base profile\\) are not consecutive."),
                // Test update provider list with empty, the empty is the last one in base profile.
                Arguments.of("Test-Profile.Updated_3",
                        System.getProperty("test.src") + "/provider-java.security",
                        "Cannot add a provider in position \\d+ after removing the ones in previous positions"),
                // Test update provider list with empty, the empty is NOT the last one in base profile.
                Arguments.of("Test-Profile.Updated_4",
                        System.getProperty("test.src") + "/provider-java.security",
                        "Cannot specify an empty provider in position \\d+ when non-empty ones are specified after it"),
                // Test base profile - one of the provider in list empty.
                Arguments.of("Test-Profile.BaseOneProviderEmpty",
                        System.getProperty("test.src") + "/provider-java.security",
                        "Cannot specify an empty provider in position \\d+. Nothing specified before"),
                // Test extended profile - one of the provider in list empty.
                Arguments.of("Test-Profile.ExtendedOneProviderEmpty",
                        System.getProperty("test.src") + "/provider-java.security",
                        "Cannot specify an empty provider in position \\d+. Nothing specified before"),
                // Test base profile - no provider list.
                Arguments.of("Test-Profile.BaseNoProviderList",
                        System.getProperty("test.src") + "/provider-java.security",
                        "No providers are specified as part of the Restricted Security profile"),
                // Test profile - provider must be specified using the fully-qualified class name.
                Arguments.of("Test-Profile.ProviderClassName",
                        System.getProperty("test.src") + "/provider-java.security",
                        "Provider must be specified using the fully-qualified class name"),
                // Test profile - provider format is incorrect.
                Arguments.of("Test-Profile.ProviderFormat",
                        System.getProperty("test.src") + "/provider-java.security",
                        "Provider format is incorrect")
        );
    }

    @ParameterizedTest
    @MethodSource("patternMatches_expectedExitValue0")
    public void shouldContain_expectedExitValue0(String customprofile, String securityPropertyFile, String expected) throws Exception {
        OutputAnalyzer outputAnalyzer = ProcessTools.executeTestJava(
                "-Dsemeru.fips=true",
                "-Dsemeru.customprofile=" + customprofile,
                "-Djava.security.properties=" + securityPropertyFile,
                "TestProviders"
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
                "TestProviders"
        );
        outputAnalyzer.reportDiagnosticSummary();
        outputAnalyzer.shouldHaveExitValue(1).shouldMatch(expected);
    }

    public static void main(String[] args) {
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
