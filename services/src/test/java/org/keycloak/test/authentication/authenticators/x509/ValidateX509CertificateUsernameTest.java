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

package org.keycloak.test.authentication.authenticators.x509;

import org.jboss.resteasy.spi.HttpRequest;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.x509.CertificateValidator;
import org.keycloak.authentication.authenticators.x509.UserIdentityExtractor;
import org.keycloak.authentication.authenticators.x509.UserIdentityToModelMapper;
import org.keycloak.authentication.authenticators.x509.ValidateX509CertificateUsername;
import org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel;
import org.keycloak.common.util.PemUtils;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.services.managers.BruteForceProtector;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;

import static org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator.DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_CHAIN_HEADER_PREFIX;
import static org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator.DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_HEADER;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @since 10/14/2016
 */

public class ValidateX509CertificateUsernameTest extends AbstractX509Test {

    private Response internalErrorResponse;
    private Response nullCertificateResponse;
    private Response configurationIsMissingResponse;
    private Response invalidDatesResponse;
    private Response nullUserIdentityResponse;
    private Response invalidUserResponse;
    private Response invalidUserCredentialsResponse;
    private Response accountDisabledResponse;
    private Response accountTemporarilyDisabledResponse;
    @Spy private ValidateX509CertificateUsername authenticator;
    @Mock private EventBuilder events;
    @Mock private UserModel user;
    @Mock private ClientSessionModel clientSession;
    @Mock private HttpRequest context;
    @Mock private AuthenticationFlowContext flowContext;
    @Mock private AuthenticatorConfigModel config;
    @Mock private UserIdentityExtractor userIdExtractor;
    @Mock private UserIdentityToModelMapper userIdModelMapper;
    @Mock private RealmModel realm;
    @Mock private BruteForceProtector bruteForceProtector;
    @Spy private CertificateValidator.CertificateValidatorBuilder validatorBuilder;
    @Mock private HttpHeaders httpHeaders;
    @Mock private MultivaluedMap<String,String> requestHeaders;

    @Before
    public void startup() throws Exception {
        MockitoAnnotations.initMocks(this);

        ValidateX509CertificateUsername temp = new ValidateX509CertificateUsername();
        nullCertificateResponse = temp.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "X509 Client certificate is missing.");
        configurationIsMissingResponse = temp.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_request", "Configuration is missing.");
        invalidDatesResponse = temp.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_request",
                String.format("Certificate validation's failed. The reason: \"%s\"", null));
        nullUserIdentityResponse = temp.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_request", "Unable to extract user identity from specified certificate");
        invalidUserResponse = temp.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_request",
                String.format("X509 certificate authentication's failed. Reason: \"%s\"", null));
        invalidUserCredentialsResponse = temp.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user credentials");
        accountDisabledResponse = temp.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_grant", "Account disabled");
        accountTemporarilyDisabledResponse = temp.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_grant", "Account temporarily disabled");
        internalErrorResponse = temp.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_request", "SSL Client Certificate Header is null or empty");

        doReturn(context).when(flowContext).getHttpRequest();
        doReturn(user).when(flowContext).getUser();
        doReturn(events).when(flowContext).getEvent();
        doReturn(clientSession).when(flowContext).getClientSession();
        doReturn(null).when(events).user(any(UserModel.class));
        doNothing().when(flowContext).failure(any(AuthenticationFlowError.class), any(Response.class));
        doNothing().when(flowContext).success();
        doReturn(config).when(flowContext).getAuthenticatorConfig();
        doNothing().when(flowContext).setUser(any());
        doReturn(null).when(config).getConfig();
        doNothing().when(clientSession).setNote(any(),any());
        doReturn(realm).when(flowContext).getRealm();
        doReturn(bruteForceProtector).when(flowContext).getProtector();

        doReturn(validatorBuilder).when(authenticator).certificateValidationParameters(any());
        doReturn(userIdExtractor).when(authenticator).getUserIdentityExtractor(any());
        doReturn(userIdModelMapper).when(authenticator).getUserIdentityToModelMapper(any());

        doReturn(httpHeaders).when(context).getHttpHeaders();
        doReturn(requestHeaders).when(httpHeaders).getRequestHeaders();

    }
    @Test
    public void testInvalidUserResponseWhenNullCertificate() throws NoSuchAlgorithmException, CertificateEncodingException {

        doReturn(nullCertificateResponse).when(authenticator).errorResponse(anyInt(), anyString(), anyString());
        doReturn(null).when(context).getAttribute(any());

        authenticator.authenticate(flowContext);

        verify(events).error(eq(Errors.USER_NOT_FOUND));
        verify(flowContext).failure(eq(AuthenticationFlowError.INVALID_USER), eq(nullCertificateResponse));
    }

    @Test
    public void testInvalidUserResponseWhenNoCertificates() throws NoSuchAlgorithmException, CertificateEncodingException {

        doReturn(nullCertificateResponse).when(authenticator).errorResponse(anyInt(), anyString(), anyString());
        doReturn(new X509Certificate[] {}).when(context).getAttribute(any());

        authenticator.authenticate(flowContext);

        verify(events).error(eq(Errors.USER_NOT_FOUND));
        verify(flowContext).failure(eq(AuthenticationFlowError.INVALID_USER), eq(nullCertificateResponse));
    }

    @Test
    public void testErrorResponseOnMissingConfiguration() {
        //parameters = new HashMap<>();

        doReturn(configurationIsMissingResponse).when(authenticator).errorResponse(anyInt(), anyString(), anyString());
        doReturn(clientCertificates).when(context).getAttribute(any());

        authenticator.authenticate(flowContext);

        verify(events).error(eq(Errors.USER_NOT_FOUND));
        verify(flowContext).failure(eq(AuthenticationFlowError.INVALID_USER), eq(configurationIsMissingResponse));
    }

    @Test
    public void testExceptionRevocationStatusFailed() throws Exception {

        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doThrow(GeneralSecurityException.class).when(mockValidator).checkRevocationStatus();

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();
        doReturn(invalidDatesResponse).when(authenticator).errorResponse(anyInt(), anyString(), anyString());

        authenticator.authenticate(flowContext);

        verify(flowContext).failure(eq(AuthenticationFlowError.INVALID_USER), eq(invalidDatesResponse));
    }

    @Test
    public void testExceptionOnInvalidKeyUsage() throws Exception {

        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doThrow(GeneralSecurityException.class).when(mockValidator).validateKeyUsage();

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();
        doReturn(invalidDatesResponse).when(authenticator).errorResponse(anyInt(), anyString(), anyString());

        authenticator.authenticate(flowContext);

        verify(flowContext).failure(eq(AuthenticationFlowError.INVALID_USER), eq(invalidDatesResponse));
    }
    @Test
    public void testExceptionOnInvalidExtendedKeyUsage() throws Exception {

        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doReturn(mockValidator).when(mockValidator).validateKeyUsage();
        doThrow(GeneralSecurityException.class).when(mockValidator).validateExtendedKeyUsage();

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();
        doReturn(invalidDatesResponse).when(authenticator).errorResponse(anyInt(), anyString(), anyString());

        authenticator.authenticate(flowContext);

        verify(flowContext).failure(eq(AuthenticationFlowError.INVALID_USER), eq(invalidDatesResponse));
    }

    @Test
    public void testExceptionDuringCertificaValidation() throws Exception {

        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doThrow(Exception.class).when(mockValidator).checkRevocationStatus();

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();
        doReturn(invalidDatesResponse).when(authenticator).errorResponse(anyInt(), anyString(), anyString());

        authenticator.authenticate(flowContext);

        verify(flowContext).failure(eq(AuthenticationFlowError.INVALID_USER), eq(invalidDatesResponse));
    }

    @Test
    public void testErrorResponseOnInvalidUserIdentity() throws Exception {

        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doReturn(mockValidator).when(mockValidator).validateKeyUsage();
        doReturn(mockValidator).when(mockValidator).validateExtendedKeyUsage();

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();
        doReturn(nullUserIdentityResponse).when(authenticator).errorResponse(anyInt(), anyString(), anyString());

        doReturn(null).when(userIdExtractor).extractUserIdentity(any());

        authenticator.authenticate(flowContext);

        verify(flowContext).failure(eq(AuthenticationFlowError.INVALID_USER), eq(nullUserIdentityResponse));
    }

    @Test
    public void testErrorResponseOnDuplicateModelException() throws Exception {
        testCanHandleExceptionWhenMappingUserIdentity(ModelDuplicateException.class);
    }

    @Test
    public void testErrorResponseOnException() throws Exception {
        testCanHandleExceptionWhenMappingUserIdentity(Exception.class);
    }
    private void testCanHandleExceptionWhenMappingUserIdentity(Class<? extends Throwable> exceptionClass) throws Exception {
        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doReturn(mockValidator).when(mockValidator).validateKeyUsage();
        doReturn(mockValidator).when(mockValidator).validateExtendedKeyUsage();

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();
        doReturn(invalidUserResponse).when(authenticator).errorResponse(anyInt(), anyString(), anyString());

        doReturn("username").when(userIdExtractor).extractUserIdentity(any());
        doReturn(null).when(events).detail(any(), any());
        doThrow(exceptionClass).when(userIdModelMapper).find(any(),any());

        authenticator.authenticate(flowContext);

        verify(events).detail(eq(Details.USERNAME),eq("username"));
        verify(clientSession).setNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME),eq("username"));
        verify(flowContext).failure(eq(AuthenticationFlowError.INVALID_USER), eq(invalidUserResponse));
    }

    @Test
    public void testErrorResponseOnInvalidUser() throws Exception {
        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doReturn(mockValidator).when(mockValidator).validateKeyUsage();
        doReturn(mockValidator).when(mockValidator).validateExtendedKeyUsage();

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();
        doReturn(invalidUserCredentialsResponse).when(authenticator).errorResponse(anyInt(), anyString(), anyString());

        doReturn("username").when(userIdExtractor).extractUserIdentity(any());
        doReturn(null).when(events).detail(any(), any());
        doReturn(null).when(userIdModelMapper).find(any(),any());

        authenticator.authenticate(flowContext);

        verify(events).error(eq(Errors.INVALID_USER_CREDENTIALS));
        verify(clientSession).setNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME),eq("username"));
        verify(flowContext).failure(eq(AuthenticationFlowError.INVALID_USER), eq(invalidUserCredentialsResponse));
    }
    @Test
    public void testErrorResponseOnUserNotEnabled() throws Exception {
        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doReturn(mockValidator).when(mockValidator).validateKeyUsage();
        doReturn(mockValidator).when(mockValidator).validateExtendedKeyUsage();

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();
        doReturn(accountDisabledResponse).when(authenticator).errorResponse(anyInt(), anyString(), anyString());

        doReturn("username").when(userIdExtractor).extractUserIdentity(any());
        doReturn(null).when(events).detail(any(), any());
        doReturn(user).when(userIdModelMapper).find(any(),any());
        doReturn(false).when(user).isEnabled();

        authenticator.authenticate(flowContext);

        verify(events).user(eq(user));
        verify(events).error(eq(Errors.USER_DISABLED));
        verify(clientSession).setNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME),eq("username"));
        verify(flowContext).failure(eq(AuthenticationFlowError.INVALID_USER), eq(accountDisabledResponse));
    }

    @Test
    public void testErrorResponseOnTemporarilyDisabledDueToBruteForceProtection() throws Exception {
        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doReturn(mockValidator).when(mockValidator).validateKeyUsage();
        doReturn(mockValidator).when(mockValidator).validateExtendedKeyUsage();

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();
        doReturn(accountTemporarilyDisabledResponse).when(authenticator).errorResponse(anyInt(), anyString(), anyString());

        doReturn("username").when(userIdExtractor).extractUserIdentity(any());
        doReturn(null).when(events).detail(any(), any());
        doReturn(user).when(userIdModelMapper).find(any(),any());
        doReturn(true).when(user).isEnabled();
        doReturn(true).when(realm).isBruteForceProtected();
        doReturn(true).when(bruteForceProtector).isTemporarilyDisabled(any(),any(),any());

        authenticator.authenticate(flowContext);

        verify(events).user(eq(user));
        verify(events).error(eq(Errors.USER_TEMPORARILY_DISABLED));
        verify(clientSession).setNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME),eq("username"));
        verify(flowContext).failure(eq(AuthenticationFlowError.INVALID_USER), eq(accountTemporarilyDisabledResponse));
    }

    @Test
    public void testSuccess() throws Exception {
        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doReturn(mockValidator).when(mockValidator).validateKeyUsage();
        doReturn(mockValidator).when(mockValidator).validateExtendedKeyUsage();

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();
        doReturn(accountTemporarilyDisabledResponse).when(authenticator).errorResponse(anyInt(), anyString(), anyString());

        doReturn("username").when(userIdExtractor).extractUserIdentity(any());
        doReturn(null).when(events).detail(any(), any());
        doReturn(user).when(userIdModelMapper).find(any(),any());
        doReturn(true).when(user).isEnabled();
        doReturn(false).when(realm).isBruteForceProtected();

        authenticator.authenticate(flowContext);

        verify(flowContext).setUser(eq(user));
        verify(events,never()).error(any());
        verify(clientSession).setNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME),eq("username"));
        verify(flowContext,never()).failure(any(),any());
        verify(flowContext).success();
    }

    @Test
    public void testReverseProxyMissingProxySslHttpHeaderConfig() throws NoSuchAlgorithmException, CertificateEncodingException {

        X509AuthenticatorConfigModel tempConfig =
                new X509AuthenticatorConfigModel().setConnectionReverseProxy();

        doReturn(tempConfig.getConfig()).when(config).getConfig();

        doReturn(internalErrorResponse).when(authenticator).errorResponse(anyInt(), anyString(), anyString());

        authenticator.authenticate(flowContext);

        verify(events, never()).error(any());
        verify(flowContext).failure(eq(AuthenticationFlowError.INTERNAL_ERROR), eq(internalErrorResponse));
        verify(context,never()).getAttribute(anyString());
        verify(context,never()).getHttpHeaders();
        verify(httpHeaders,never()).getRequestHeaders();
    }

    @Test
    public void testReverseProxyNullProxySslHttpHeader() throws NoSuchAlgorithmException, CertificateEncodingException {

        X509AuthenticatorConfigModel tempConfig =
                new X509AuthenticatorConfigModel().setConnectionReverseProxy();
        tempConfig.setReverseProxyHttpHeader(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_HEADER);
        tempConfig.setReverseProxyHttpHeaderChainPrefix(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_CHAIN_HEADER_PREFIX);

        doReturn(null).when(requestHeaders).getFirst(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_HEADER);
        doReturn(tempConfig.getConfig()).when(config).getConfig();

        doReturn(nullCertificateResponse).when(authenticator).errorResponse(anyInt(), anyString(), anyString());

        authenticator.authenticate(flowContext);

        verify(events).error(eq(Errors.USER_NOT_FOUND));
        verify(flowContext).failure(eq(AuthenticationFlowError.INVALID_USER), eq(nullCertificateResponse));
        verify(context,never()).getAttribute(anyString());
        verify(context,times(1)).getHttpHeaders();
        verify(httpHeaders,times(1)).getRequestHeaders();
    }


    private void testReverseProxySuccess(String encodedCertificate) throws Exception {

        final X509AuthenticatorConfigModel tempConfig =
                new X509AuthenticatorConfigModel().setConnectionReverseProxy();
        tempConfig.setReverseProxyHttpHeader(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_HEADER);
        tempConfig.setReverseProxyHttpHeaderChainPrefix(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_CHAIN_HEADER_PREFIX);

        doReturn(encodedCertificate).when(requestHeaders).getFirst(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_HEADER);
        doReturn(tempConfig.getConfig()).when(config).getConfig();

        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doReturn(mockValidator).when(mockValidator).validateKeyUsage();
        doReturn(mockValidator).when(mockValidator).validateExtendedKeyUsage();

        doReturn(null).when(context).getAttribute(any());
        doReturn(accountTemporarilyDisabledResponse).when(authenticator).errorResponse(anyInt(), anyString(), anyString());

        doReturn("username").when(userIdExtractor).extractUserIdentity(any());
        doReturn(null).when(events).detail(any(), any());
        doReturn(user).when(userIdModelMapper).find(any(),any());
        doReturn(true).when(user).isEnabled();
        doReturn(false).when(realm).isBruteForceProtected();

        authenticator.authenticate(flowContext);

        verify(flowContext).setUser(eq(user));
        verify(events,never()).error(any());
        verify(clientSession).setNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME),eq("username"));
        verify(flowContext,never()).failure(any(),any());
        verify(flowContext).success();
        verify(context,never()).getAttribute(anyString());
        verify(context,times(5)).getHttpHeaders();
        verify(httpHeaders,times(5)).getRequestHeaders();
        verify(requestHeaders,times(1)).getFirst(eq(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_HEADER));
        verify(requestHeaders,times(4)).getFirst(matches(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_CHAIN_HEADER_PREFIX + "_\\d+"));
    }

    @Test
    public void testReverseProxySuccess() throws Exception {
        testReverseProxySuccess(PemUtils.encodeCertificate(clientCertificates[0]));
    }

    @Test
    public void testReverseProxySuccessWithCertificateEnclosedWithDoubleQuotes() throws Exception {
        final String encodedCertificate = "\"" + PemUtils.encodeCertificate(clientCertificates[0]) + "\"";
        testReverseProxySuccess(encodedCertificate);
    }
    @Test
    public void testReverseProxySuccessForceChallengeWithCertificateEnclosedInBeginEnd() throws Exception {
        final String encodedCert = "-----BEGIN CERTIFICATE----- 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 HwCcH5Yw9rwC/6YJm9zL0sWHIrPi -----END CERTIFICATE-----";
        testReverseProxySuccess(encodedCert);
    }

}
