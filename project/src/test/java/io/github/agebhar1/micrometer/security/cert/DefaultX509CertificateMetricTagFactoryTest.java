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

import io.micrometer.core.instrument.Tag;
import org.assertj.core.api.Condition;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("DefaultX509CertificateMetricTagFactory")
class DefaultX509CertificateMetricTagFactoryTest {

    @Nested
    @DisplayName("buildTagsFromCertificate")
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class BuildTagsFromCertificate {

        final DefaultX509CertificateMetricTagFactory factory = new DefaultX509CertificateMetricTagFactory();

        @Test
        @DisplayName("should throw 'IllegalArgumentException' if certificate is null")
        public void contractNotNull() {

            final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> factory.buildTagsFrom(null));
            assertThat(exception).hasMessage("Certificate must not be null.");
            
        }

        @ParameterizedTest
        @MethodSource
        @DisplayName("should build tag with key 'subjectDN' and value from certificate subject principal name")
        public void shouldBuildTagWithSubjectDN(final X509Certificate certificate) {

            assertThat(factory.buildTagsFrom(certificate))
                    .hasSize(1)
                    .have(tagWith("subjectDN", certificate.getSubjectDN().getName()));
        }

        public Stream<Arguments> shouldBuildTagWithSubjectDN() {
            return Stream.of("ssl/certs/Amazon_Root_CA_4.crt", "ssl/certs/GlobalSign_Root_CA_-_R6.crt", "ssl/certs/Secure_Global_CA.crt")
                    .map(X509CertificateUtils::loadFromResource)
                    .map(Arguments::of);
        }

        private Condition<Tag> tagWith(final String key, final String value) {
            final String description = String.format("Tag with key 'subjectDN' and value '%s'", value);
            return new Condition<>(it -> it.getKey().equals(key) && it.getValue().equals(value), description);
        }

    }

}