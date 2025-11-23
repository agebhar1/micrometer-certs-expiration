/*
 * Copyright © 2021 Andreas Gebhardt (agebhar1@googlemail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.github.agebhar1.demo.micrometer.security.cert;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import java.io.IOException;
import java.net.URL;

import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@AutoConfigureTestRestTemplate
@SpringBootTest(webEnvironment = RANDOM_PORT)
@DisplayName("Application")
class DemoMicrometerCertsExpirationApplicationTests {

    @BeforeAll
    public static void setupTrustStore() throws IOException {

        final URL trustStore = Thread.currentThread().getContextClassLoader().getResource("security/trustStore.jks");
        if (trustStore == null) {
            throw new IOException("Could not get TrustStore 'security/trustStore.jks'");
        }

        System.setProperty("javax.net.ssl.trustStore", trustStore.getFile());
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
        System.setProperty("javax.net.ssl.trustStoreType", "jks");
    }

    @Nested
    @DisplayName("endpoint '/actuator/prometheus'")
    public class ActuatorPrometheus {

        @LocalServerPort
        private int port;

        @Autowired
        private TestRestTemplate restTemplate;

        @Test
        @DisplayName("should expose X509 certificate expiration date for each contained in (global) trust store")
        void shouldExposeCertsMetric() {

            final String body = restTemplate.getForObject(format("http://localhost:%d/actuator/prometheus", port), String.class);

            assertThat(body.split("\n"))
                    .contains(
                            "# HELP security_cert_x509_expiration_seconds Time since the Unix epoch in seconds when the certificate is no longer valid.",
                            "# TYPE security_cert_x509_expiration_seconds gauge",
                            "security_cert_x509_expiration_seconds{subjectDN=\"CN=Amazon Root CA 4, O=Amazon, C=US\"} 2.2216032E9",
                            "security_cert_x509_expiration_seconds{subjectDN=\"CN=GlobalSign, O=GlobalSign, OU=GlobalSign Root CA - R6\"} 2.0493216E9",
                            "security_cert_x509_expiration_seconds{subjectDN=\"CN=Secure Global CA, O=SecureTrust Corporation, C=US\"} 1.893441126E9"
                    );
        }

    }

}
