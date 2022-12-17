/*
 * Copyright © 2022 Andreas Gebhardt (agebhar1@googlemail.com)
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

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URL;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static java.util.Collections.emptyMap;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.stringContainsInOrder;

@QuarkusTest
@QuarkusTestResource(DemoMicrometerCertsExpirationApplicationTests.TrustStoreResource.class)
@DisplayName("Application")
class DemoMicrometerCertsExpirationApplicationTests {

    public static class TrustStoreResource implements QuarkusTestResourceLifecycleManager {

        @Override
        public Map<String, String> start() {
            final URL trustStore = Thread.currentThread().getContextClassLoader().getResource("security/trustStore.jks");
            if (trustStore == null) {
                throw new RuntimeException(new IOException("Could not get TrustStore 'security/trustStore.jks'"));
            }

            System.setProperty("javax.net.ssl.trustStore", trustStore.getFile());
            System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
            System.setProperty("javax.net.ssl.trustStoreType", "jks");

            return emptyMap();
        }

        @Override
        public void stop() {

        }
    }

    @Nested
    @DisplayName("endpoint '/q/metrics'")
    public class ApplicationMetrics {

        @Test
        @DisplayName("should expose X509 certificate expiration date for each contained in (global) trust store")
        void shouldExposeCertsMetric() {
            given()
                    .when().get("/q/metrics")
                    .then()
                    .assertThat()
                    .statusCode(is(200))
                    .and()
                    .body(stringContainsInOrder(
                            "# HELP security_cert_x509_expiration_seconds Time since the Unix epoch in seconds when the certificate is no longer valid.",
                            "# TYPE security_cert_x509_expiration_seconds gauge",
                            "security_cert_x509_expiration_seconds{subjectDN=\"CN=Amazon Root CA 4, O=Amazon, C=US\",} 2.2216032E9",
                            "security_cert_x509_expiration_seconds{subjectDN=\"CN=GlobalSign, O=GlobalSign, OU=GlobalSign Root CA - R6\",} 2.0493216E9",
                            "security_cert_x509_expiration_seconds{subjectDN=\"CN=Secure Global CA, O=SecureTrust Corporation, C=US\",} 1.893441126E9"
                    ));
        }

    }

}