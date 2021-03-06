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

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

import static java.util.function.Function.identity;
import static java.util.stream.Collectors.toList;

public class X509CertificateSourceComposite implements X509CertificateSource {

    private final Collection<X509CertificateSource> sources;

    private X509CertificateSourceComposite(final Collection<X509CertificateSource> sources) {
        this.sources = sources;
    }

    @Override
    public Collection<X509Certificate> readAllCertificates() {
        return sources.stream()
                .map(X509CertificateSource::readAllCertificates)
                .flatMap(Collection::stream)
                .collect(toList());
    }

    public static X509CertificateSource of(final X509CertificateSource... sources) {
        return new X509CertificateSourceComposite(asCollectionIfNoneNull(sources, Arrays::asList));
    }

    public static X509CertificateSource of(final Collection<X509CertificateSource> sources) {
        return new X509CertificateSourceComposite(asCollectionIfNoneNull(sources, identity()));
    }

    private static <T> Collection<X509CertificateSource> asCollectionIfNoneNull(final T value, final Function<T, Collection<X509CertificateSource>> f) {
        return Optional.ofNullable(value)
                .map(f)
                .filter(it -> it.stream().noneMatch(Objects::isNull))
                .orElseThrow(() -> new IllegalArgumentException("Any provided X509Certificate source must be not null"));
    }

}
