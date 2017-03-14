/*
 * Copyright 2017 Analytical Graphics, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.keycloak.authentication.authenticators.x509;

import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.common.util.PemException;
import org.keycloak.common.util.PemUtils;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * @author <a href="mailto:pnalyvayko@agi.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @since 3/13/2017
 */

public abstract class CertificateDataStorage {

    protected static final Logger logger = Logger.getLogger(CertificateDataStorage.class);
    /**
     * Returns a certificate and the other certificates in its chain (if any)
     * @return
     */
    public abstract X509Certificate[] getClientCertificateChain() throws GeneralSecurityException;

    private static String trimDoubleQuotes(String quotedString) {

        if (quotedString == null) return null;

        int len = quotedString.length();
        if (len > 1 && quotedString.charAt(0) == '"' &&
                quotedString.charAt(len - 1) == '"') {
            return quotedString.substring(1, len - 1);
        }
        return quotedString;
    }

    protected static X509Certificate getCertificateFromHttpHeader(HttpRequest request, String httpHeader) throws GeneralSecurityException {
        String encodedCertificate = request.getHttpHeaders().getRequestHeaders().getFirst(httpHeader);

        // Remove double quotes
        encodedCertificate = trimDoubleQuotes(encodedCertificate);

        X509Certificate sslCertificate = getCertificateFromString(encodedCertificate);
        if (sslCertificate == null) {
            logger.warnf("HTTP header \"%s\" does not contain a valid x.509 certificate",
                    httpHeader);
        } else {
            logger.debugf("Found a valid x.509 certificate in \"%s\" HTTP header",
                    httpHeader);
        }
        return sslCertificate;
    }

    protected static X509Certificate getCertificateFromString(String encodedCertificate) throws GeneralSecurityException {

        if (encodedCertificate == null ||
                encodedCertificate.trim().length() == 0) {
            return null;
        }

        X509Certificate sslCertificate;
        try {
            sslCertificate = PemUtils.decodeCertificate(encodedCertificate);
        }
        catch(PemException e) {
            logger.error(e.getMessage(), e);
            throw new GeneralSecurityException(e);
        }
        return sslCertificate;
    }

    /**
     * The storage extracts the x509 certificate chain from Two-Way SSL.
     */
    static class CertificateDataStorageMutualSSL extends CertificateDataStorage {

        public static final String JAVAX_SERVLET_REQUEST_X509_CERTIFICATE = "javax.servlet.request.X509Certificate";

        private final HttpRequest request;
        CertificateDataStorageMutualSSL(HttpRequest request) {
            if (request == null) {
                throw new NullPointerException("request");
            }

            this.request = request;
        }

        @Override
        public X509Certificate[] getClientCertificateChain() throws GeneralSecurityException {
            // Get a x509 client certificate
            X509Certificate[] certs = (X509Certificate[]) request.getAttribute(JAVAX_SERVLET_REQUEST_X509_CERTIFICATE);
            if (certs != null) {
                for (X509Certificate cert : certs) {
                    logger.debugf("[X509ClientCertificateAuthenticator:getCertificateChain] \"%s\"", cert.getSubjectDN().getName());
                }
            }
            return certs;
        }
    }

    /**
     * The storage is used to extract X509 client certificate and any
     * other certificates in its chain from a sub-set of HTTP headers
     * set by the reverse proxy
     */
    static class CertificateDataStorageFromProxiedRequest extends CertificateDataStorage {

        private static final int MAX_CERTIFICATE_DEPTH = 4;
        private final HttpRequest request;
        private final String proxySslCertHttpHeader;
        private final String proxySslCertChainHttpHeader;
        CertificateDataStorageFromProxiedRequest(HttpRequest request,
                                    String proxySslCertHttpHeader,
                                    String proxySslCertChainHttpHeader) {
            if (request == null) {
                throw new IllegalArgumentException("Http Request is invalid");
            }
            if (proxySslCertHttpHeader == null ||
                    proxySslCertHttpHeader.trim().length() == 0) {
                throw new IllegalArgumentException("SSL Client Certificate Header is null or empty");
            }

            this.request = request;
            this.proxySslCertHttpHeader = proxySslCertHttpHeader;
            this.proxySslCertChainHttpHeader = proxySslCertChainHttpHeader;
        }

        @Override
        public X509Certificate[] getClientCertificateChain() throws GeneralSecurityException {
            List<X509Certificate> chain = new ArrayList<>();

            // Get the client certificate
            X509Certificate clientCertificate = getClientCertificate();
            if (clientCertificate != null) {

                chain.add(clientCertificate);

                // Get the certificate of the client certificate chain
                for (int i = 0; i < MAX_CERTIFICATE_DEPTH; i++) {
                    try {
                        X509Certificate chainCertificate = getChainCertificate(i);
                        if (chainCertificate != null) {
                            chain.add(chainCertificate);
                        }
                    }
                    catch(GeneralSecurityException e) {
                        logger.warn(e.getMessage(), e);
                    }
                }
            }

            return chain.toArray(new X509Certificate[0]);
        }
        private X509Certificate getClientCertificate() throws GeneralSecurityException {
            return getCertificateFromHttpHeader(request, proxySslCertHttpHeader);
        }

        private X509Certificate getChainCertificate(int n) throws GeneralSecurityException {
            if (proxySslCertChainHttpHeader == null ||
                    proxySslCertChainHttpHeader.trim().length() == 0) {
                return null;
            }
            String httpHeader = String.format("%s_%d", proxySslCertChainHttpHeader, n);
            return getCertificateFromHttpHeader(request, httpHeader);
        }
    }

    // Certificate storage data builders

    public static CertificateDataStorage getCertificateFromTwoWaySSL(HttpRequest request) {
        return new CertificateDataStorageMutualSSL(request);
    }

    public static CertificateDataStorage getCertificateStorageFromProxiedRequest(
            HttpRequest request,
            String proxySslCertHeader,
            String proxySslCertChainHeader) {
        return new CertificateDataStorageFromProxiedRequest(request,
                proxySslCertHeader, proxySslCertChainHeader);
    }
}
