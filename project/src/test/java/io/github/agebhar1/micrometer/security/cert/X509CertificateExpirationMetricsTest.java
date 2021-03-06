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
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.toList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("X509CertificateExpirationMetrics")
class X509CertificateExpirationMetricsTest {

    private final X509CertificateMetricTagFactory anyMetricTagFactory = it -> emptyList();

    @Nested
    @DisplayName("constructor")
    class Constructor {

        @Test
        @DisplayName("should throw 'IllegalArgumentException' if X509 certificate metric tag factory is null")
        public void contractNotNullTagFactory() {

            final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> new X509CertificateExpirationMetrics(null, Collections::emptyList));
            assertThat(exception).hasMessage("Factory for metric tags from X509 certificates must not be null.");

        }

        @Test
        @DisplayName("should throw 'IllegalArgumentException' if certificates source is null")
        public void contractNotNullCertificatesSource() {

            final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> new X509CertificateExpirationMetrics(anyMetricTagFactory, null));
            assertThat(exception).hasMessage("Certificates source must not be null.");

        }

        @Test
        @DisplayName("should throw 'IllegalArgumentException' if certificates source provided collection is null")
        public void contractNotNullCertificatesSourceCollection() {

            final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> new X509CertificateExpirationMetrics(anyMetricTagFactory, () -> null));
            assertThat(exception).hasMessage("Collection of certificates must not be null.");

        }

    }

    @Nested
    @DisplayName("bindTo")
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    class BindTo {

        @Test
        @DisplayName("should throw 'IllegalArgumentException' if registry is null")
        public void contractNotNull() {

            final X509CertificateExpirationMetrics metrics = new X509CertificateExpirationMetrics(anyMetricTagFactory, Collections::emptyList);

            final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> metrics.bindTo(null));
            assertThat(exception).hasMessage("MeterRegistry must not be null.");

        }

        @ParameterizedTest
        @MethodSource
        @DisplayName("should register gauge with value from certification expiration date (Not After)")
        public void shouldRegisterGauge(final X509Certificate certificate) {

            final Tag tag = Tag.of("key", "value");
            final X509CertificateMetricTagFactory metricTagFactory = __ -> singletonList(tag);

            final SimpleMeterRegistry registry = new SimpleMeterRegistry();
            final X509CertificateExpirationMetrics metrics = new X509CertificateExpirationMetrics(metricTagFactory, () -> singletonList(certificate));

            metrics.bindTo(registry);

            assertThat(registry.find(X509CertificateExpirationMetrics.Name).gauges())
                    .hasSize(1)
                    .allMatch(gauge -> {
                        boolean equalsValue = gauge.value() == certificate.getNotAfter().toInstant().getEpochSecond();
                        boolean equalsTags = gauge.getId().getTags().size() == 1 && gauge.getId().getTags().contains(tag);

                        return equalsValue && equalsTags;
                    });

        }

        @Test
        @DisplayName("registered gauges depends on unique tags for each certificate")
        public void contractRegisteredGauges() {

            final Tag tag = Tag.of("key", "value");
            final X509CertificateMetricTagFactory metricTagFactory = __ -> singletonList(tag);

            final SimpleMeterRegistry registry = new SimpleMeterRegistry();
            final X509CertificateExpirationMetrics metrics = new X509CertificateExpirationMetrics(metricTagFactory, () -> certificates().collect(toList()));

            metrics.bindTo(registry);

            assertThat(registry.find(X509CertificateExpirationMetrics.Name).gauges())
                    .hasSize(1);

        }

        @Test
        @DisplayName("should ignore/skip 'null' items in certifications source collection")
        public void shouldIgnoreNullItemsInCertificationsSourceCollection() {

            final AtomicInteger cnt = new AtomicInteger(0);
            final X509CertificateMetricTagFactory metricTagFactory = __ -> singletonList(Tag.of("index", Integer.toString(cnt.getAndIncrement())));

            final Collection<X509Certificate> certificates = new ArrayList<>();
            certificates().forEach(certificates::add);
            certificates.add(null);

            final SimpleMeterRegistry registry = new SimpleMeterRegistry();
            final X509CertificateExpirationMetrics metrics = new X509CertificateExpirationMetrics(metricTagFactory, () -> certificates);

            metrics.bindTo(registry);

            assertThat(registry.find(X509CertificateExpirationMetrics.Name).gauges())
                    .hasSize(3);

        }

        public Stream<X509Certificate> certificates() {
            return Stream.of("ssl/certs/Amazon_Root_CA_4.crt", "ssl/certs/GlobalSign_Root_CA_-_R6.crt", "ssl/certs/Secure_Global_CA.crt")
                    .map(X509CertificateUtils::loadFromResource);
        }

        public Stream<Arguments> shouldRegisterGauge() {
            return certificates().map(Arguments::of);
        }

    }

}