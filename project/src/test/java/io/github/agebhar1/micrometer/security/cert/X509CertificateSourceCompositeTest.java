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
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Stream;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class X509CertificateSourceCompositeTest {

    static class AnyX509CertificateSource implements X509CertificateSource {

        @Override
        public Collection<X509Certificate> readAllCertificates() {
            return emptyList();
        }

        @Override
        public String toString() {
            return "any";
        }

    }

    @Nested
    @DisplayName("of(X509CertificateSource... sources)")
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    public class OfVarargs {

        @ParameterizedTest
        @MethodSource
        @DisplayName("should throw 'IllegalArgumentException' if any of the provides sources is null")
        public void contractNotNull(final X509CertificateSource... sources) {

            final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                    X509CertificateSourceComposite.of(sources)
            );
            assertThat(exception).hasMessage("Any provided X509Certificate source must be not null");
        }

        @Test
        @DisplayName("should create instance of none source argument")
        public void shouldCreateWithNoArgument() {
            assertThat(X509CertificateSourceComposite.of()).isNotNull();
        }

        public Stream<Arguments> contractNotNull() {
            final AnyX509CertificateSource source = new AnyX509CertificateSource();
            return Stream.of(
                    Arguments.of((Object) null),
                    Arguments.of((Object) new X509CertificateSource[]{null, source}),
                    Arguments.of((Object) new X509CertificateSource[]{source, null})
            );
        }

    }

    @Nested
    @DisplayName("of(Collection<X509CertificateSource> sources)")
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    public class OfCollection {

        @ParameterizedTest
        @MethodSource
        @DisplayName("should throw 'IllegalArgumentException' if any of the provides sources is null")
        public void contractNotNull(final Collection<X509CertificateSource> sources) {

            final IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                    X509CertificateSourceComposite.of(sources)
            );
            assertThat(exception).hasMessage("Any provided X509Certificate source must be not null");
        }

        @Test
        @DisplayName("should create instance of empty source collection")
        public void shouldCreateWithNoArgument() {
            assertThat(X509CertificateSourceComposite.of(emptyList())).isNotNull();
        }

        public Stream<Arguments> contractNotNull() {
            final AnyX509CertificateSource source = new AnyX509CertificateSource();
            return Stream.of(
                    Arguments.of((Object) null),
                    Arguments.of(asList(null, source)),
                    Arguments.of(asList(source, null))
            );
        }

    }

    @Nested
    @DisplayName("readAllCertificates")
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    public class ReadAllCertificates {

        private final X509Certificate AmazonRootCA = X509CertificateUtils.loadFromResource("ssl/certs/Amazon_Root_CA_4.crt");
        private final X509Certificate GlobalSignRootCA = X509CertificateUtils.loadFromResource("ssl/certs/GlobalSign_Root_CA_-_R6.crt");
        private final X509Certificate SecureGlobalCA = X509CertificateUtils.loadFromResource("ssl/certs/Secure_Global_CA.crt");

        @Test
        @DisplayName("should invoke all provided sources and return collected certificates")
        public void shouldInvokeAllProvidedSources() {

            final Map<X509Certificate, Integer> invocations = new HashMap<>();

            final Function<X509Certificate, X509CertificateSource> sourceFactory = certificate -> () -> {
                invocations.computeIfPresent(certificate, (k, v) -> v + 1);
                invocations.putIfAbsent(certificate, 1);
                return singletonList(certificate);
            };

            final X509CertificateSource composite = X509CertificateSourceComposite.of(
                    sourceFactory.apply(AmazonRootCA),
                    Collections::emptyList,
                    sourceFactory.apply(GlobalSignRootCA),
                    Collections::emptyList,
                    sourceFactory.apply(SecureGlobalCA));

            assertThat(composite.readAllCertificates()).containsExactlyInAnyOrder(AmazonRootCA, GlobalSignRootCA, SecureGlobalCA);
            assertThat(invocations).containsEntry(AmazonRootCA, 1);
            assertThat(invocations).containsEntry(GlobalSignRootCA, 1);
            assertThat(invocations).containsEntry(SecureGlobalCA, 1);
        }

        @ParameterizedTest
        @MethodSource
        @DisplayName("should propagate exception from invoked X509CertificationSource")
        public void shouldPropagateException(final Collection<X509CertificateSource> sources) {

            final X509CertificateSource composite = X509CertificateSourceComposite.of(sources);

            assertThrows(RuntimeException.class, composite::readAllCertificates);
        }

        public Stream<Arguments> shouldPropagateException() {

            final X509CertificateSource empty = Collections::emptyList;
            final X509CertificateSource throwing = () -> {
                throw new RuntimeException();
            };

            return Stream.of(
                    Arguments.of(asList(throwing, empty, empty)),
                    Arguments.of(asList(empty, throwing, empty)),
                    Arguments.of(asList(empty, empty, throwing))
            );
        }

    }

}
