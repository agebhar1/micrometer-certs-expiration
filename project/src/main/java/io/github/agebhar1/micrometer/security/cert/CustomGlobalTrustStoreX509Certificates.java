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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;

import static java.util.Collections.emptyList;
import static java.util.Collections.list;

public class CustomGlobalTrustStoreX509Certificates implements X509CertificateSource {

    private static final Predicate<Certificate> isX509Certificate = it -> X509Certificate.class.isAssignableFrom(it.getClass());
    private static final Logger logger = LoggerFactory.getLogger(CustomGlobalTrustStoreX509Certificates.class);

    @Override
    public Collection<X509Certificate> readAllCertificates() {

        final String trustStore = System.getProperty("javax.net.ssl.trustStore");
        final String trustStorePassword = System.getProperty("javax.net.ssl.trustStorePassword");
        final String trustStoreType = System.getProperty("javax.net.ssl.trustStoreType", "jks");

        logger.debug("Try to load X509 certificates from javax.net.ssl.trustStore: '{}', javax.net.ssl.trustStorePassword: {}, javax.net.ssl.trustStoreType: '{}'",
                trustStore, trustStorePassword == null || trustStorePassword.trim().isEmpty() ? "<no>" : "<yes>", trustStoreType);

        if (trustStore == null || trustStore.trim().isEmpty()) {
            return emptyList();
        }
        if (trustStorePassword == null || trustStorePassword.trim().isEmpty()) {
            return emptyList();
        }

        return getX509Certificates(trustStore, trustStorePassword, trustStoreType);
    }

    private List<X509Certificate> getX509Certificates(final String trustStore, final String trustStorePassword, final String trustStoreType) {

        final List<X509Certificate> x509Certificates = new ArrayList<>();
        try {

            final KeyStore keyStore = KeyStore.getInstance(trustStoreType);
            try (InputStream stream = new FileInputStream(trustStore)) {
                keyStore.load(stream, trustStorePassword.toCharArray());
            }

            for (final String alias : list(keyStore.aliases())) {
                Optional.of(keyStore.getCertificate(alias))
                        .filter(isX509Certificate)
                        .map(X509Certificate.class::cast)
                        .ifPresent(certificate -> {
                            logger.trace("Add certificate '{}' from javax.net.ssl.trustStore: '{}'", certificate.getSubjectDN().getName(), trustStore);
                            x509Certificates.add(certificate);
                        });
            }

        } catch (final KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return x509Certificates;
    }

}
