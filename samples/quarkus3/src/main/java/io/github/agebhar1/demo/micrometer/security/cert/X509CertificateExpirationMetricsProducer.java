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

import io.github.agebhar1.micrometer.security.cert.CustomGlobalTrustStoreX509Certificates;
import io.github.agebhar1.micrometer.security.cert.DefaultX509CertificateMetricTagFactory;
import io.github.agebhar1.micrometer.security.cert.X509CertificateExpirationMetrics;
import io.github.agebhar1.micrometer.security.cert.X509CertificateSource;
import io.github.agebhar1.micrometer.security.cert.X509CertificateSourceComposite;

import jakarta.enterprise.inject.Produces;

public class X509CertificateExpirationMetricsProducer {

    // tag::bean[]
    @Produces
    public X509CertificateExpirationMetrics x509CertificateExpirationMetrics() {
        final DefaultX509CertificateMetricTagFactory factory = new DefaultX509CertificateMetricTagFactory();
        final X509CertificateSource source = X509CertificateSourceComposite.of(new CustomGlobalTrustStoreX509Certificates());

        return new X509CertificateExpirationMetrics(factory, source);
    }
    // end::bean[]

}
