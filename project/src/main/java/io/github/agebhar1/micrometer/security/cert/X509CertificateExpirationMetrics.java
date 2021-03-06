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

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.binder.MeterBinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Objects;
import java.util.function.Supplier;

import static java.util.stream.Collectors.toList;

public class X509CertificateExpirationMetrics implements MeterBinder {

    private static final Logger logger = LoggerFactory.getLogger(X509CertificateExpirationMetrics.class);

    public static final String Name = "security.cert.x509.expiration";
    public static final String Description = "Time since the Unix epoch in seconds when the certificate is no longer valid.";

    private final Collection<Gauge.Builder<Supplier<Number>>> gauges;

    public X509CertificateExpirationMetrics(final X509CertificateMetricTagFactory metricTagFactory, final X509CertificateSource source) {

        logger.info("Create instance of class '{}'", getClass().getCanonicalName());
        if (metricTagFactory == null) {
            throw new IllegalArgumentException("Factory for metric tags from X509 certificates must not be null.");
        }
        if (source == null) {
            throw new IllegalArgumentException("Certificates source must not be null.");
        }

        gauges = populate(metricTagFactory, source.readAllCertificates());

    }

    private Collection<Gauge.Builder<Supplier<Number>>> populate(final X509CertificateMetricTagFactory metricTagFactory, final Collection<X509Certificate> certificates) {

        if (certificates == null) {
            throw new IllegalArgumentException("Collection of certificates must not be null.");
        }

        return certificates.stream()
                .filter(Objects::nonNull)
                .map(certificate -> new Object() {
                    final long epochNotAfter = certificate.getNotAfter().toInstant().getEpochSecond();
                    final Iterable<Tag> tags = metricTagFactory.buildTagsFrom(certificate);
                })
                .map(it -> Gauge.builder(Name, () -> it.epochNotAfter)
                        .description(Description)
                        .baseUnit("seconds")
                        .tags(it.tags))
                .collect(toList());
    }

    @Override
    public void bindTo(final MeterRegistry meterRegistry) {
        if (meterRegistry == null) {
            throw new IllegalArgumentException("MeterRegistry must not be null.");
        }
        gauges.forEach(gauge -> gauge.register(meterRegistry));
    }

}
