/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2025, 2025 All Rights Reserved
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
 * @summary Test Restricted Security Mode Policy Sunset
 * @library /test/lib
 * @run junit TestPolicySunset
 */

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Provider;
import java.security.Security;
import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import jdk.test.lib.process.OutputAnalyzer;
import jdk.test.lib.process.ProcessTools;

public class TestPolicySunset {

    private static Path updateExpireSoonSunsetFile(String baseFile) {
        try {
            LocalDate soonDate = LocalDate.now(Clock.systemUTC()).plusMonths(1);
            String newDate = soonDate.format(DateTimeFormatter.ISO_DATE);

            String content = Files.readString(Paths.get(baseFile), StandardCharsets.UTF_8);
            String pattern = "(?m)^(RestrictedSecurity\\.Test-Profile-PolicySunset-ExpireSoon\\.desc\\.sunsetDate)\\s*=.*$";
            String updated = content.replaceAll(pattern, "$1 = " + newDate);

            Path tmp = Files.createTempFile("sunset-java.security.expireSoon.", ".tmp");
            Files.writeString(tmp, updated, StandardCharsets.UTF_8);
            return tmp;
        } catch (IOException e) {
            throw new RuntimeException("Failed to update sunset date for ExpireSoon profile", e);
        }
    }

    private static Stream<Arguments> patternMatches_testPolicySunset() {
        String propertyFile = System.getProperty("test.src") + "/sunset-java.security";
        String updatedPropertyFile = updateExpireSoonSunsetFile(propertyFile).toString();

        return Stream.of(
                // 1 - expired; suppress=false; ignore=true
                Arguments.of("Test-Profile-PolicySunset-Expired",
                        propertyFile,
                        "=false", "=true",
                        "WARNING: Java will start with the requested restricted security profile but uncertified cryptography may be active",
                        0),
                // 2 - expired; suppress=true; ignore=true, no warning
                Arguments.of("Test-Profile-PolicySunset-Expired",
                        propertyFile,
                        "=true", "=true",
                        "",
                        0),
                // 3 - expire soon (<=6 months); suppress=false
                Arguments.of("Test-Profile-PolicySunset-ExpireSoon",
                        updatedPropertyFile,
                        "=false", "=false",
                        "The restricted security profile RestrictedSecurity.Test-Profile-PolicySunset-ExpireSoon will expire",
                        0),
                // 4 - expire soon (<=6 months); suppress=true, no warning
                Arguments.of("Test-Profile-PolicySunset-ExpireSoon",
                        updatedPropertyFile,
                        "=true", "=false",
                        "",
                        0),
                // 5 - not expire (>6 months); no warning
                Arguments.of("Test-Profile-PolicySunset-NotExpire",
                        propertyFile,
                        "=false", "=false",
                        "",
                        0),
                // 6 - expired; property treat empty as true, no warning
                Arguments.of("Test-Profile-PolicySunset-Expired",
                        propertyFile,
                        "", "",
                        "",
                        0),
                // 7 - expired; suppress unset, ignore=true
                Arguments.of("Test-Profile-PolicySunset-Expired",
                        propertyFile,
                        null, "=true",
                        "WARNING: Java will start with the requested restricted security profile but uncertified cryptography may be active",
                        0),
                // 8 - expired; suppress=false; ignore=false
                Arguments.of("Test-Profile-PolicySunset-Expired",
                        propertyFile,
                        "=false", "=false",
                        "Use -Dsemeru.restrictedsecurity.ignoresunsetexpiration to allow Java to start while possibly using uncertified cryptography",
                        1),
                // 9 - expired; suppress=true; ignore=false, no warning
                Arguments.of("Test-Profile-PolicySunset-Expired",
                        propertyFile,
                        "=true", "=false",
                        "",
                        1),
                // 10 - expired; suppress=true, ignore unset, no warning
                Arguments.of("Test-Profile-PolicySunset-Expired",
                        propertyFile,
                        "=true", null,
                        "",
                        1),
                // 11 - expired; suppress=false; ignore unset
                Arguments.of("Test-Profile-PolicySunset-Expired",
                        propertyFile,
                        "=false", null,
                        "Use -Dsemeru.restrictedsecurity.ignoresunsetexpiration to allow Java to start while possibly using uncertified cryptography",
                        1));
    }

    @ParameterizedTest
    @MethodSource("patternMatches_testPolicySunset")
    public void shouldContain_testPolicySunset(String customprofile, String securityPropertyFile,
            String suppresssunsetwarning, String ignoresunsetexpiration, String expected, int exitValue)
            throws Exception {
        List<String> args = new ArrayList<>();

        args.add("-Dsemeru.fips=true");
        args.add("-Dsemeru.customprofile=" + customprofile);
        args.add("-Djava.security.properties=" + securityPropertyFile);
        if (suppresssunsetwarning != null) {
            args.add("-Dsemeru.restrictedsecurity.suppresssunsetwarning" + suppresssunsetwarning);
        }
        if (ignoresunsetexpiration != null) {
            args.add("-Dsemeru.restrictedsecurity.ignoresunsetexpiration" + ignoresunsetexpiration);
        }
        args.add("TestPolicySunset");

        OutputAnalyzer outputAnalyzer = ProcessTools.executeTestJvm(args);
        outputAnalyzer.reportDiagnosticSummary();
        outputAnalyzer.shouldHaveExitValue(exitValue).shouldMatch(expected);
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
