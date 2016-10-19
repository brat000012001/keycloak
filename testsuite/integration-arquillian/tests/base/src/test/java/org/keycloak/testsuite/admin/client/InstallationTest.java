/*
 * Copyright 2016 Red Hat Inc. and/or its affiliates and other contributors
 * as indicated by the @author tags. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package org.keycloak.testsuite.admin.client;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.arquillian.AuthServerTestEnricher;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.keycloak.testsuite.auth.page.AuthRealm.TEST;

/**
 * Test getting the installation/configuration files for OIDC and SAML.
 *
 * @author Stan Silvert ssilvert@redhat.com (C) 2016 Red Hat Inc.
 */
public class InstallationTest extends AbstractClientTest {

    private static final String OIDC_NAME = "oidcInstallationClient";
    private static final String SAML_NAME = "samlInstallationClient";

    private ClientResource oidcClient;
    private String oidcClientId;
    private ClientResource samlClient;
    private String samlClientId;

    @Before
    public void createClients() {
        oidcClientId = createOidcClient(OIDC_NAME);
        oidcClient = findClientResource(OIDC_NAME);

        samlClientId = createSamlClient(SAML_NAME);
        samlClient = findClientResource(SAML_NAME);
    }

    @After
    public void tearDown() {
        removeClient(oidcClientId);
        removeClient(samlClientId);
    }

    private String authServerUrl() {
        return AuthServerTestEnricher.getAuthServerContextRoot() + "/auth";
    }

    private String samlUrl() {
        return authServerUrl() + "/realms/master/protocol/saml";
    }

    @Test
    public void testOidcJBossXml() {
        String xml = oidcClient.getInstallationProvider("keycloak-oidc-jboss-subsystem");
        assertOidcInstallationConfig(xml);
        assertTrue(xml.contains("<secure-deployment"));
    }

    @Test
    public void testOidcJson() {
        String json = oidcClient.getInstallationProvider("keycloak-oidc-keycloak-json");
        assertOidcInstallationConfig(json);
    }

    private void assertOidcInstallationConfig(String config) {
        assertTrue(config.contains("master"));
        assertFalse(config.contains(ApiUtil.findActiveKey(testRealmResource()).getPublicKey()));
        assertTrue(config.contains(authServerUrl()));
    }

    @Test
    public void testSamlMetadataIdpDescriptor() {
        String xml = samlClient.getInstallationProvider("saml-idp-descriptor");
        assertTrue(xml.contains("<EntityDescriptor"));
        assertTrue(xml.contains("<IDPSSODescriptor"));
        assertTrue(xml.contains(ApiUtil.findActiveKey(testRealmResource()).getCertificate()));
        assertTrue(xml.contains(samlUrl()));
    }

    @Test
    public void testSamlAdapterXml() {
        String xml = samlClient.getInstallationProvider("keycloak-saml");
        assertTrue(xml.contains("<keycloak-saml-adapter>"));
        assertTrue(xml.contains(SAML_NAME));
        assertTrue(xml.contains(ApiUtil.findActiveKey(testRealmResource()).getCertificate()));
        assertTrue(xml.contains(samlUrl()));
    }

    @Test
    public void testSamlMetadataSpDescriptor() {
        String xml = samlClient.getInstallationProvider("saml-sp-descriptor");
        assertTrue(xml.contains("<EntityDescriptor"));
        assertTrue(xml.contains("<SPSSODescriptor"));
        assertTrue(xml.contains(SAML_NAME));
    }

    @Test
    public void testSamlJBossXml() {
        String xml = samlClient.getInstallationProvider("keycloak-saml-subsystem");
        assertTrue(xml.contains("<secure-deployment"));
        assertTrue(xml.contains(SAML_NAME));
        assertTrue(xml.contains(ApiUtil.findActiveKey(testRealmResource()).getCertificate()));
        assertTrue(xml.contains(samlUrl()));
    }
}
