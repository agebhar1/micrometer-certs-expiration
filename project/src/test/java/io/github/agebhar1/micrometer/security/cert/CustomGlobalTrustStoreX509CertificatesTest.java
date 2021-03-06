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
package io.github.agebhar1.micrometer.security.cert;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.ClearSystemProperty;
import org.junitpioneer.jupiter.SetSystemProperty;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;

import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("CustomGlobalTrustStoreX509Certificates")
class CustomGlobalTrustStoreX509CertificatesTest {

    @Nested
    @DisplayName("readAllCertificates")
    class ReadAllCertificates {

        @Test
        @ClearSystemProperty(key = "javax.net.ssl.trustStore")
        @SetSystemProperty(key = "javax.net.ssl.trustStorePassword", value = "changeit")
        @DisplayName("should return empty collection if system property 'javax.net.ssl.trustStore' is blank")
        public void shouldReturnEmptyCollectionIfTrustStoreIsBlank() {

            assertThat(new CustomGlobalTrustStoreX509Certificates().readAllCertificates()).isEmpty();

            System.setProperty("javax.net.ssl.trustStore", "");
            assertThat(new CustomGlobalTrustStoreX509Certificates().readAllCertificates()).isEmpty();
        }

        @Test
        @SetSystemProperty(key = "javax.net.ssl.trustStore", value = "trustStore.jks")
        @ClearSystemProperty(key = "javax.net.ssl.trustStorePassword")
        @DisplayName("should return empty collection if system property 'javax.net.ssl.trustStorePassword' is blank")
        public void shouldReturnEmptyCollectionIfTrustStorePasswordIsBlank() {

            assertThat(new CustomGlobalTrustStoreX509Certificates().readAllCertificates()).isEmpty();

            System.setProperty("javax.net.ssl.trustStorePassword", "");
            assertThat(new CustomGlobalTrustStoreX509Certificates().readAllCertificates()).isEmpty();
        }

        @Test
        @ClearSystemProperty(key = "javax.net.ssl.trustStore")
        @SetSystemProperty(key = "javax.net.ssl.trustStorePassword", value = "changeit")
        @DisplayName("should return empty collection if system property 'javax.net.ssl.trustStore' is empty")
        public void shouldReturnCollection() {

            final String trustStore = requireNonNull(getClass().getClassLoader().getResource("security/trustStore.jks")).getFile();
            System.setProperty("javax.net.ssl.trustStore", trustStore);

            assertThat(new CustomGlobalTrustStoreX509Certificates().readAllCertificates())
                    .map(X509Certificate::getSubjectDN)
                    .map(Principal::getName)
                    .containsExactlyInAnyOrder(
                            "CN=Amazon Root CA 4, O=Amazon, C=US",
                            "CN=Secure Global CA, O=SecureTrust Corporation, C=US",
                            "CN=GlobalSign, O=GlobalSign, OU=GlobalSign Root CA - R6");
        }

        @Test
        @SetSystemProperty(key = "javax.net.ssl.trustStore", value = "trustStore.jks")
        @SetSystemProperty(key = "javax.net.ssl.trustStorePassword", value = "changeit")
        @DisplayName("should throw 'RuntimeException' w/ root cause 'IOException' if trust store is not available")
        public void shouldThrowRuntimeExceptionIfTrustStoreIsNotAvailable() {

            final RuntimeException exception = assertThrows(RuntimeException.class,
                    () -> new CustomGlobalTrustStoreX509Certificates().readAllCertificates());
            assertThat(exception).hasRootCauseInstanceOf(IOException.class);
        }

        @Test
        @ClearSystemProperty(key = "javax.net.ssl.trustStore")
        @SetSystemProperty(key = "javax.net.ssl.trustStorePassword", value = "does-not-match")
        @DisplayName("should throw 'RuntimeException' w/ root cause 'UnrecoverableKeyException' if trust store password does not match")
        public void shouldThrowRuntimeExceptionIfTrustStorePasswordDoesNotMatch() {

            final String trustStore = requireNonNull(getClass().getClassLoader().getResource("security/trustStore.jks")).getFile();
            System.setProperty("javax.net.ssl.trustStore", trustStore);

            final RuntimeException exception = assertThrows(RuntimeException.class,
                    () -> new CustomGlobalTrustStoreX509Certificates().readAllCertificates());
            assertThat(exception)
                    .hasRootCauseInstanceOf(UnrecoverableKeyException.class)
                    .hasMessage("java.io.IOException: Keystore was tampered with, or password was incorrect");
        }

        @Test
        @ClearSystemProperty(key = "javax.net.ssl.trustStore")
        @SetSystemProperty(key = "javax.net.ssl.trustStorePassword", value = "changeit")
        @SetSystemProperty(key = "javax.net.ssl.trustStoreType", value = "pkcs7")
        @DisplayName("should throw 'RuntimeException' w/ root cause 'NoSuchAlgorithmException' if trust store type is not supported")
        public void shouldTrowRuntimeExceptionIfTrustStoreTypeIsNotSupported() {

            final String trustStore = requireNonNull(getClass().getClassLoader().getResource("security/trustStore.jks")).getFile();
            System.setProperty("javax.net.ssl.trustStore", trustStore);

            final RuntimeException exception = assertThrows(RuntimeException.class,
                    () -> new CustomGlobalTrustStoreX509Certificates().readAllCertificates());
            assertThat(exception)
                    .hasRootCauseInstanceOf(NoSuchAlgorithmException.class)
                    .hasMessage("java.security.KeyStoreException: pkcs7 not found");
        }

    }

}