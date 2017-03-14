/*
 * Copyright 2016 Analytical Graphics, Inc. and/or its affiliates
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
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.LinkedList;
import java.util.List;

import static java.util.Arrays.asList;
import static org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator.*;
import static org.keycloak.provider.ProviderConfigProperty.BOOLEAN_TYPE;
import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 7/31/2016
 */

public abstract class AbstractX509ClientCertificateAuthenticatorFactory implements AuthenticatorFactory {

    protected static final Logger logger = Logger.getLogger(AbstractX509ClientCertificateAuthenticatorFactory.class);

    private static final String[] mappingSources = {
            MAPPING_SOURCE_CERT_SUBJECTDN,
            MAPPING_SOURCE_CERT_SUBJECTDN_EMAIL,
            MAPPING_SOURCE_CERT_SUBJECTDN_CN,
            MAPPING_SOURCE_CERT_ISSUERDN,
            MAPPING_SOURCE_CERT_ISSUERDN_EMAIL,
            MAPPING_SOURCE_CERT_ISSUERDN_CN,
            MAPPING_SOURCE_CERT_SERIALNUMBER
    };

    private static final String[] userModelMappers = {
            USER_ATTRIBUTE_MAPPER,
            USERNAME_EMAIL_MAPPER
    };

    protected static final List<ProviderConfigProperty> configProperties;
    static {
        List<String> mappingSourceTypes = new LinkedList<>();
        for (String s : mappingSources) {
            mappingSourceTypes.add(s);
        }
        ProviderConfigProperty mappingMethodList = new ProviderConfigProperty();
        mappingMethodList.setType(ProviderConfigProperty.LIST_TYPE);
        mappingMethodList.setName(MAPPING_SOURCE_SELECTION);
        mappingMethodList.setLabel("User Identity Source");
        mappingMethodList.setHelpText("Choose how to extract user identity from X509 certificate or the certificate fields. For example, SubjectDN will match the custom regular expression specified below to the value of certificate's SubjectDN field.");
        mappingMethodList.setDefaultValue(mappingSources[0]);
        mappingMethodList.setOptions(mappingSourceTypes);

        ProviderConfigProperty regExp = new ProviderConfigProperty();
        regExp.setType(STRING_TYPE);
        regExp.setName(REGULAR_EXPRESSION);
        regExp.setLabel("A regular expression to extract user identity");
        regExp.setDefaultValue(DEFAULT_MATCH_ALL_EXPRESSION);
        regExp.setHelpText("The regular expression to extract a user identity. The expression must contain a single group. For example, 'uniqueId=(.*?)(?:,|$)' will match 'uniqueId=somebody@company.org, CN=somebody' and give somebody@company.org");

        List<String> mapperTypes = new LinkedList<>();
        for (String m : userModelMappers) {
            mapperTypes.add(m);
        }

        List<String> certificateSources = new LinkedList<>();
        certificateSources.add(TWO_WAY_SSL_CONNECTION);
        certificateSources.add(REVERSE_PROXY_CONNECTION);

        ProviderConfigProperty userMapperList = new ProviderConfigProperty();
        userMapperList.setType(ProviderConfigProperty.LIST_TYPE);
        userMapperList.setName(USER_MAPPER_SELECTION);
        userMapperList.setHelpText("Choose how to map extracted user identities to users");
        userMapperList.setLabel("User mapping method");
        userMapperList.setDefaultValue(userModelMappers[0]);
        userMapperList.setOptions(mapperTypes);

        ProviderConfigProperty attributeOrPropertyValue = new ProviderConfigProperty();
        attributeOrPropertyValue.setType(STRING_TYPE);
        attributeOrPropertyValue.setName(CUSTOM_ATTRIBUTE_NAME);
        attributeOrPropertyValue.setDefaultValue(DEFAULT_ATTRIBUTE_NAME);
        attributeOrPropertyValue.setLabel("A name of user attribute");
        attributeOrPropertyValue.setHelpText("A name of user attribute to map the extracted user identity to existing user. The name must be a valid, existing user attribute if User Mapping Method is set to Custom Attribute Mapper.");

        ProviderConfigProperty crlCheckingEnabled = new ProviderConfigProperty();
        crlCheckingEnabled.setType(BOOLEAN_TYPE);
        crlCheckingEnabled.setName(ENABLE_CRL);
        crlCheckingEnabled.setHelpText("Enable Certificate Revocation Checking using CRL");
        crlCheckingEnabled.setLabel("CRL Checking Enabled");

        ProviderConfigProperty crlDPEnabled = new ProviderConfigProperty();
        crlDPEnabled.setType(BOOLEAN_TYPE);
        crlDPEnabled.setName(ENABLE_CRLDP);
        crlDPEnabled.setDefaultValue(false);
        crlDPEnabled.setLabel("Enable CRL Distribution Point to check certificate revocation status");
        crlDPEnabled.setHelpText("CRL Distribution Point is a starting point for CRL. CDP is optional, but most PKI authorities include CDP in their certificates.");

        ProviderConfigProperty cRLRelativePath = new ProviderConfigProperty();
        cRLRelativePath.setType(STRING_TYPE);
        cRLRelativePath.setName(CRL_RELATIVE_PATH);
        cRLRelativePath.setDefaultValue("crl.pem");
        cRLRelativePath.setLabel("CRL File path");
        cRLRelativePath.setHelpText("The path to a CRL file that contains a list of revoked certificates. Paths are assumed to be relative to $jboss.server.config.dir");

        ProviderConfigProperty oCspCheckingEnabled = new ProviderConfigProperty();
        oCspCheckingEnabled.setType(BOOLEAN_TYPE);
        oCspCheckingEnabled.setName(ENABLE_OCSP);
        oCspCheckingEnabled.setHelpText("Enable Certificate Revocation Checking using OCSP");
        oCspCheckingEnabled.setLabel("OCSP Checking Enabled");

        ProviderConfigProperty ocspResponderUri = new ProviderConfigProperty();
        ocspResponderUri.setType(STRING_TYPE);
        ocspResponderUri.setName(OCSPRESPONDER_URI);
        ocspResponderUri.setLabel("OCSP Responder Uri");
        ocspResponderUri.setHelpText("Clients use OCSP Responder Uri to check certificate revocation status.");

        ProviderConfigProperty keyUsage = new ProviderConfigProperty();
        keyUsage.setType(STRING_TYPE);
        keyUsage.setName(CERTIFICATE_KEY_USAGE);
        keyUsage.setLabel("Validate Key Usage");
        keyUsage.setHelpText("Validates that the purpose of the key contained in the certificate (encipherment, signature, etc.) matches its intended purpose. Leaving the field blank will disable Key Usage validation. For example, 'digitalSignature, keyEncipherment' will check if the digitalSignature and keyEncipherment bits (bit 0 and bit 2 respectively) are set in certificate's X509 Key Usage extension. See RFC 5280 for a detailed definition of X509 Key Usage extension.");

        ProviderConfigProperty extendedKeyUsage = new ProviderConfigProperty();
        extendedKeyUsage.setType(STRING_TYPE);
        extendedKeyUsage.setName(CERTIFICATE_EXTENDED_KEY_USAGE);
        extendedKeyUsage.setLabel("Validate Extended Key Usage");
        extendedKeyUsage.setHelpText("Validates the extended purposes of the certificate's key using certificate's Extended Key Usage extension. Leaving the field blank will disable Extended Key Usage validation. See RFC 5280 for a detailed definition of X509 Extended Key Usage extension.");

        ProviderConfigProperty identityConfirmationPageDisallowed = new ProviderConfigProperty();
        identityConfirmationPageDisallowed.setType(BOOLEAN_TYPE);
        identityConfirmationPageDisallowed.setName(CONFIRMATION_PAGE_DISALLOWED);
        identityConfirmationPageDisallowed.setLabel("Bypass identity confirmation");
        identityConfirmationPageDisallowed.setHelpText("By default, the users are prompted to confirm their identity extracted from X509 client certificate. The identity confirmation prompt is skipped if the option is switched on.");

        ProviderConfigProperty connectionTypeProperty = new ProviderConfigProperty();
        connectionTypeProperty.setType(ProviderConfigProperty.LIST_TYPE);
        connectionTypeProperty.setName(CONNECTION_TYPE);
        connectionTypeProperty.setHelpText("Choose Reverse Proxy if the server is behind a reverse proxy; otherwise choose Mutual SSL");
        connectionTypeProperty.setLabel("Connection via");
        connectionTypeProperty.setDefaultValue(TWO_WAY_SSL_CONNECTION);
        connectionTypeProperty.setOptions(certificateSources);

        ProviderConfigProperty reverseProxyHttpHeaderProperty = new ProviderConfigProperty();
        reverseProxyHttpHeaderProperty.setType(STRING_TYPE);
        reverseProxyHttpHeaderProperty.setDefaultValue(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_HEADER);
        reverseProxyHttpHeaderProperty.setName(SSL_CLIENT_CERT_PROXY_HTTP_HEADER);
        reverseProxyHttpHeaderProperty.setLabel("X-SSL-Client Header");
        reverseProxyHttpHeaderProperty.setHelpText("A special HTTP request header used by Reverse Proxy to forward X.509 client certificate data in PEM format. " +
                "Reverse proxies such as Apache, can be configured to forward the SSL client certificate data using special HTTP request headers. " +
                "Example: \"x-ssl-client-cert\": MFeewetpowetw...==");

        ProviderConfigProperty reverseProxyHttpHeaderChainProperty = new ProviderConfigProperty();
        reverseProxyHttpHeaderChainProperty.setType(STRING_TYPE);
        reverseProxyHttpHeaderChainProperty.setDefaultValue(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_CHAIN_HEADER_PREFIX);
        reverseProxyHttpHeaderChainProperty.setName(SSL_CLIENT_CERT_PROXY_HTTP_CHAIN_HEADER_PREFIX);
        reverseProxyHttpHeaderChainProperty.setLabel("X-SSL-Client-Chain Header");
        reverseProxyHttpHeaderChainProperty.setHelpText("A special HTTP header used by Reverse Proxy to forward the certificates in the SSL client certificate's chain. " +
                "Reverse Proxies such as Apache, can be configured to forward the certificates in the certificate chain of the X.509 client certificate using special HTTP request headers." +
                "Example: \"x-ssl-client-cert-chain_0\": MIfwwewposgsdgsdgsdsdg...==" +
                          "\"x-ssl-client-cert-chain_1\": O3weuposdf23235lkeweibfi...==");

        configProperties = asList(mappingMethodList,
                regExp,
                userMapperList,
                attributeOrPropertyValue,
                crlCheckingEnabled,
                crlDPEnabled,
                cRLRelativePath,
                oCspCheckingEnabled,
                ocspResponderUri,
                keyUsage,
                extendedKeyUsage,
                identityConfirmationPageDisallowed,
                connectionTypeProperty,
                reverseProxyHttpHeaderProperty,
                reverseProxyHttpHeaderChainProperty);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

}
