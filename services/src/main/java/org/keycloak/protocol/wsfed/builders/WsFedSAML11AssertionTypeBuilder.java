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

package org.keycloak.protocol.wsfed.builders;

import org.jboss.logging.Logger;
import org.keycloak.dom.saml.v1.assertion.SAML11AssertionType;
import org.keycloak.dom.saml.v1.assertion.SAML11AttributeStatementType;
import org.keycloak.dom.saml.v1.assertion.SAML11AttributeType;
import org.keycloak.dom.saml.v1.assertion.SAML11StatementAbstractType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.assertion.EncryptedElementType;
import org.keycloak.models.ClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.protocol.wsfed.mappers.WSFedSAMLAttributeStatementMapper;
import org.keycloak.protocol.wsfed.mappers.WSFedSAMLRoleListMapper;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.exceptions.ProcessingException;

import javax.xml.datatype.DatatypeConfigurationException;
import java.net.URI;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @since 10/4/2016
 */

public class WsFedSAML11AssertionTypeBuilder extends WsFedSAMLAssertionTypeAbstractBuilder<WsFedSAML11AssertionTypeBuilder> {

    // TODO eventually make the attribute namespace configurable to support multiple dialects.
    private static final String ATTRIBUTE_NAMESPACE = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims";

    private static final Logger logger = Logger.getLogger(WsFedSAML11AssertionTypeBuilder.class);

    private final class SAML11AttributeArrayMapper {
        SAML11AttributeStatementType attributeStatement;
        SAML11AttributeArrayMapper(SAML11AttributeStatementType attributeStatement) {
            this.attributeStatement = attributeStatement;
        }
        void mapAttributes(AttributeStatementType saml2AttributeStatement,
                       Function<AttributeType, SAML11AttributeType> mapper) {

            if (mapper == null)
                throw new NullPointerException("Mapper cannot be null");

            for (AttributeStatementType.ASTChoiceType astChoice : saml2AttributeStatement.getAttributes()) {
                AttributeType attribute = astChoice.getAttribute();
                EncryptedElementType encryptedElement = astChoice.getEncryptedAssertion();

                if (attribute != null) {
                    SAML11AttributeType samlAttribute = mapper.apply(attribute);
                    attributeStatement.add(samlAttribute);
                }

                if (encryptedElement != null) {
                    logger.warn("Encrypted assertion attributes are not supported.");
                }
            }
        }
    }

    public SAML11AssertionType build() throws ConfigurationException, ProcessingException, DatatypeConfigurationException {
        String responseIssuer = getResponseIssuer(realm);
        String nameIdFormat = JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get();
//        String nameId = getNameId(nameIdFormat, clientSession, userSession);
        String nameId = userSession.getUser().getUsername();

        // save NAME_ID and format in clientSession as they may be persistent or transient or email and not username
        // we'll need to send this back on a logout
        clientSession.setNote(WSFED_NAME_ID, nameId);
        clientSession.setNote(WSFED_NAME_ID_FORMAT, nameIdFormat);

        SAML11AssertionTypeBuilder builder = new SAML11AssertionTypeBuilder();
        builder.issuer(responseIssuer)
                .assertionExpiration(realm.getAccessTokenLifespanForImplicitFlow())
                .nameIdentifier(nameIdFormat, nameId)
                .requestIssuer(clientSession.getClient().getClientId());

        SAML11AssertionType assertion = builder.buildModel();

        List<SamlProtocol.ProtocolMapperProcessor<WSFedSAMLAttributeStatementMapper>> attributeStatementMappers = new LinkedList<>();
        SamlProtocol.ProtocolMapperProcessor<WSFedSAMLRoleListMapper> roleListMapper = null;

        Set<ProtocolMapperModel> mappings = accessCode.getRequestedProtocolMappers();
        for (ProtocolMapperModel mapping : mappings) {

            ProtocolMapper mapper = (ProtocolMapper)session.getKeycloakSessionFactory().getProviderFactory(ProtocolMapper.class, mapping.getProtocolMapper());
            if (mapper == null) continue;
            if (mapper instanceof WSFedSAMLAttributeStatementMapper) {
                attributeStatementMappers.add(new SamlProtocol.ProtocolMapperProcessor<>((WSFedSAMLAttributeStatementMapper)mapper, mapping));
            }
            if (mapper instanceof WSFedSAMLRoleListMapper) {
                roleListMapper = new SamlProtocol.ProtocolMapperProcessor<>((WSFedSAMLRoleListMapper)mapper, mapping);
            }
        }

        transformAttributeStatement(attributeStatementMappers, assertion, session, userSession, clientSession);
        populateRoles(roleListMapper, assertion, session, userSession, clientSession);

        return assertion;
    }

    private void populateRoles(SamlProtocol.ProtocolMapperProcessor<WSFedSAMLRoleListMapper> roleListMapper,
                               SAML11AssertionType assertion,
                               KeycloakSession session,
                               UserSessionModel userSession, ClientSessionModel clientSession) {
        if (roleListMapper == null) return;

        AttributeStatementType tempAttributeStatement = new AttributeStatementType();

        // TODO should there be different mappers to support SAML1.0 and SAML2.0 formats?
        // For instance, SAML1.0 may need "AttributeNamespace" explicitly specified,
        // wherease SAML2.0 needs a format specifier which does not map to anything in SAML1.0. Or does it?
        roleListMapper.mapper.mapRoles(tempAttributeStatement, roleListMapper.model, session, userSession, clientSession);

        SAML11AttributeStatementType attributeStatement = getAttributeStatement(assertion);

        SAML11AttributeArrayMapper samlAttributeMapper = new SAML11AttributeArrayMapper(attributeStatement);
        samlAttributeMapper.mapAttributes(tempAttributeStatement, attribute -> {
            // TODO what is there to do with SAML2 attribute name format?

            // Change the role attribute name to lowercase, i.e. "Role" becomes "role"
            SAML11AttributeType samlAttribute = new SAML11AttributeType(attribute.getName().toLowerCase(), URI.create(ATTRIBUTE_NAMESPACE));
            if (!attribute.getAttributeValue().isEmpty()) {
                samlAttribute.add(attribute.getAttributeValue().get(0).toString());
            } else {
                logger.warnf("The attribute '%s' does not have a value", attribute.getName());
            }
            return samlAttribute;
        });

        if(!attributeStatement.get().isEmpty() && assertion.getStatements().isEmpty()) {
            assertion.add(attributeStatement);
        }
    }

    private SAML11AttributeStatementType getAttributeStatement(SAML11AssertionType assertion) {
        SAML11AttributeStatementType attributeStatement = null;
        List<SAML11StatementAbstractType> statements = assertion.getStatements();
        if (statements != null) {
            for (SAML11StatementAbstractType st : statements) {
                if (st instanceof SAML11AttributeStatementType) {
                    attributeStatement = (SAML11AttributeStatementType)st;
                    break;
                }
            }
        }
        if (attributeStatement == null) {
            attributeStatement = new SAML11AttributeStatementType();
        }
        return attributeStatement;
    }

    private void transformAttributeStatement(List<SamlProtocol.ProtocolMapperProcessor<WSFedSAMLAttributeStatementMapper>> attributeStatementMappers,
                                            SAML11AssertionType assertion,
                                            KeycloakSession session,
                                            UserSessionModel userSession, ClientSessionModel clientSession) {
        AttributeStatementType tempAttributeStatement = new AttributeStatementType();
        for (SamlProtocol.ProtocolMapperProcessor<WSFedSAMLAttributeStatementMapper> processor : attributeStatementMappers) {
            processor.mapper.transformAttributeStatement(tempAttributeStatement, processor.model, session, userSession, clientSession);
        }

        SAML11AttributeStatementType attributeStatement = getAttributeStatement(assertion);

        SAML11AttributeArrayMapper samlAttributeMapper = new SAML11AttributeArrayMapper(attributeStatement);
        samlAttributeMapper.mapAttributes(tempAttributeStatement, attribute -> {
            // TODO what is there to do with SAML2 attribute name format?
            String friendlyName = attribute.getFriendlyName() != null ? attribute.getFriendlyName() : attribute.getName();
            SAML11AttributeType samlAttribute = new SAML11AttributeType(friendlyName, URI.create(ATTRIBUTE_NAMESPACE));
            if (!attribute.getAttributeValue().isEmpty()) {
                samlAttribute.add(attribute.getAttributeValue().get(0).toString());
            } else {
                logger.warnf("The attribute '%s' does not have a value", attribute.getName());
            }
            return samlAttribute;
        });

        if(!attributeStatement.get().isEmpty() && assertion.getStatements().isEmpty()) {
            assertion.add(attributeStatement);
        }
    }
}
