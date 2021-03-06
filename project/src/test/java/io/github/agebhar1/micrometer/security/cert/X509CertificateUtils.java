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
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;

public final class X509CertificateUtils {

    private final static X509CertificateUtils INSTANCE = new X509CertificateUtils();

    private InputStream getResourceAsStream(String name) throws IOException {
        final InputStream stream = getClass().getClassLoader().getResourceAsStream(name);
        if (stream == null) {
            throw new IOException(format("Could not load resource '%s'", name));
        }
        return stream;
    }

    public static X509Certificate loadFromResource(final String name) {
        try (final InputStream stream = INSTANCE.getResourceAsStream(name)) {
            final CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(stream);
        } catch (final IOException | CertificateException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    @DisplayName("should be able to load all certificates")
    public void resources() {
        assertThat(Stream.of(
                "ssl/certs/Amazon_Root_CA_4.crt",
                "ssl/certs/GlobalSign_Root_CA_-_R6.crt",
                "ssl/certs/Secure_Global_CA.crt"
        ).map(X509CertificateUtils::loadFromResource)).hasSize(3);
    }

}
