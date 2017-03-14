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
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.x509.CertificateValidator;
import org.keycloak.authentication.authenticators.x509.UserIdentityExtractor;
import org.keycloak.authentication.authenticators.x509.UserIdentityToModelMapper;
import org.keycloak.authentication.authenticators.x509.X509AuthenticatorConfigModel;
import org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticator;
import org.keycloak.common.util.PemUtils;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.*;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.StringTokenizer;

import static org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator.DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_CHAIN_HEADER_PREFIX;
import static org.keycloak.authentication.authenticators.x509.AbstractX509ClientCertificateAuthenticator.DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_HEADER;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.*;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 10/14/2016
 */

public class ValidateX509CertificateFormAuthenticatorTest extends AbstractX509Test {

    private Response certificateValidationErrorResponse;
    @Spy private X509ClientCertificateAuthenticator authenticator;
    @Captor ArgumentCaptor<List<FormMessage>> setErrorCaptor;
    @Captor ArgumentCaptor<String> nameCaptor;
    @Captor ArgumentCaptor<String> valueCaptor;
    @Mock private EventBuilder events;
    @Mock private UserModel user;
    @Mock private AuthenticationSessionModel clientSession;
    @Mock private HttpRequest context;
    @Mock private AuthenticationFlowContext flowContext;
    @Mock private AuthenticatorConfigModel config;
    @Mock private UserIdentityExtractor userIdExtractor;
    @Mock private UserIdentityToModelMapper userIdModelMapper;
    @Mock private RealmModel realm;
    @Mock private BruteForceProtector bruteForceProtector;
    @Mock private LoginFormsProvider loginFormsProvider;
    @Mock private AuthenticationExecutionModel executionModel;
    @Spy private CertificateValidator.CertificateValidatorBuilder validatorBuilder;
    @Mock private HttpHeaders httpHeaders;
    @Mock private MultivaluedMap<String,String> requestHeaders;


    @FunctionalInterface
    public interface ConsumerThatThrows<T> {
        public void accept(T o) throws GeneralSecurityException;
    }

    @Before
    public void startup() throws Exception {
        MockitoAnnotations.initMocks(this);

        X509ClientCertificateAuthenticator temp = new X509ClientCertificateAuthenticator();
        //certificateValidationErrorResponse = temp.createErrorResponse()

        doReturn(context).when(flowContext).getHttpRequest();
        doReturn(user).when(flowContext).getUser();
        doReturn(events).when(flowContext).getEvent();
        doReturn(clientSession).when(flowContext).getAuthenticationSession();
        doReturn(null).when(events).user(any(UserModel.class));
        doNothing().when(flowContext).failure(any(AuthenticationFlowError.class), any(Response.class));
        doNothing().when(flowContext).success();
        doNothing().when(flowContext).attempted();
        doNothing().when(flowContext).challenge(any());
        doReturn(config).when(flowContext).getAuthenticatorConfig();
        doNothing().when(flowContext).setUser(any());
        doReturn(null).when(config).getConfig();
        doNothing().when(clientSession).setAuthNote(any(),any());
        doReturn(realm).when(flowContext).getRealm();
        doReturn(bruteForceProtector).when(flowContext).getProtector();
        doReturn(loginFormsProvider).when(flowContext).form();
        doReturn(executionModel).when(flowContext).getExecution();
        doReturn("execution_1").when(executionModel).getId();

        doReturn(new StringTokenizer("")).when(context).getAttributeNames();

        doReturn(validatorBuilder).when(authenticator).certificateValidationParameters(any());
        doReturn(userIdExtractor).when(authenticator).getUserIdentityExtractor(any());
        doReturn(userIdModelMapper).when(authenticator).getUserIdentityToModelMapper(any());

        doReturn(httpHeaders).when(context).getHttpHeaders();
        doReturn(requestHeaders).when(httpHeaders).getRequestHeaders();
    }
    @Test
    public void testInvalidUserResponseWhenNullCertificate() throws NoSuchAlgorithmException, CertificateEncodingException {

        doReturn(null).when(context).getAttribute(any());

        authenticator.authenticate(flowContext);

        verify(events,never()).error(any());
        verify(flowContext).attempted();
    }
    @Test
    public void testInvalidUserResponseWhenNoCertificate() throws NoSuchAlgorithmException, CertificateEncodingException {

        doReturn(new X509Certificate[]{}).when(context).getAttribute(any());

        authenticator.authenticate(flowContext);

        verify(events,never()).error(any());
        verify(flowContext).attempted();
    }

    @Test
    public void testErrorResponseOnMissingConfiguration() {

        doReturn(clientCertificates).when(context).getAttribute(any());

        authenticator.authenticate(flowContext);

        verify(events, never()).error(any());
        verify(flowContext).attempted();
        verify(loginFormsProvider).setInfo(any());
    }

    private void testErrorResponseOnCertificateValidationException(ConsumerThatThrows<CertificateValidator> action) throws GeneralSecurityException {
        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        action.accept(mockValidator);

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();

        authenticator.authenticate(flowContext);

        verify(flowContext).attempted();
        //verify(flowContext,atLeastOnce()).challenge(any());
        verify(loginFormsProvider).setErrors(setErrorCaptor.capture());
        Assert.assertNotNull(setErrorCaptor.getValue());
        Assert.assertEquals("Certificate validation's failed.", setErrorCaptor.getValue().get(0).getMessage());
    }

    @Test
    public void testErrorResponseOnCertificateValidationBadRevocationStatus() throws Exception {

        testErrorResponseOnCertificateValidationException(mockValidator -> {
            doThrow(GeneralSecurityException.class).when(mockValidator).checkRevocationStatus();
        });
    }

    @Test
    public void testErrorResponseOnCertificateValidationBadKeyUsage() throws Exception {

        testErrorResponseOnCertificateValidationException(mockValidator -> {
            doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
            doThrow(GeneralSecurityException.class).when(mockValidator).validateKeyUsage();
        });
    }

    @Test
    public void testErrorResponseOnCertificateValidationBadExtendedKeyUsage() throws Exception {
        testErrorResponseOnCertificateValidationException(mockValidator -> {
            doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
            doReturn(mockValidator).when(mockValidator).validateKeyUsage();
            doThrow(GeneralSecurityException.class).when(mockValidator).validateExtendedKeyUsage();
        });
    }

    @Test
    public void testErrorResponseOnGenericExceptionDuringCertValidation() throws Exception {
        testErrorResponseOnCertificateValidationException(mockValidator -> {
            doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
            doThrow(Exception.class).when(mockValidator).validateKeyUsage();
        });
    }

    @Test
    public void testErrorResponseOnNullUserIdentity() throws GeneralSecurityException {
        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doReturn(mockValidator).when(mockValidator).validateKeyUsage();
        doReturn(mockValidator).when(mockValidator).validateExtendedKeyUsage();

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();
        doReturn(null).when(userIdExtractor).extractUserIdentity(any());

        authenticator.authenticate(flowContext);

        verify(flowContext).attempted();
        //verify(flowContext,atLeastOnce()).challenge(any());
        verify(loginFormsProvider).setErrors(setErrorCaptor.capture());
        Assert.assertNotNull(setErrorCaptor.getValue());
        Assert.assertEquals("Unable to extract user identity from specified certificate", setErrorCaptor.getValue().get(0).getMessage());
    }

    @Test
    public void testErrorResponseOnMissingUser() throws Exception {
        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doReturn(mockValidator).when(mockValidator).validateKeyUsage();
        doReturn(mockValidator).when(mockValidator).validateExtendedKeyUsage();

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();
        doReturn("username").when(userIdExtractor).extractUserIdentity(any());
        doReturn(null).when(userIdModelMapper).find(any(),any());

        authenticator.authenticate(flowContext);

        verify(events).detail(eq(Details.USERNAME), eq("username"));
        verify(clientSession).setAuthNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME), eq("username"));
        verify(events).error(eq(Errors.USER_NOT_FOUND));
        verify(flowContext).attempted();
        //verify(flowContext,atLeastOnce()).challenge(any());
        verify(loginFormsProvider).setErrors(setErrorCaptor.capture());
        Assert.assertNotNull(setErrorCaptor.getValue());
        Assert.assertEquals("X509 certificate authentication's failed.", setErrorCaptor.getValue().get(0).getMessage());
    }

    @Test
    public void testErrorResponseOnModelDuplicateException() throws Exception {
        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doReturn(mockValidator).when(mockValidator).validateKeyUsage();
        doReturn(mockValidator).when(mockValidator).validateExtendedKeyUsage();

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();
        doReturn("username").when(userIdExtractor).extractUserIdentity(any());
        doThrow(ModelDuplicateException.class).when(userIdModelMapper).find(any(),any());

        authenticator.authenticate(flowContext);

        verify(events).detail(eq(Details.USERNAME), eq("username"));
        verify(clientSession).setAuthNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME), eq("username"));
//        verify(events).error(eq(Errors.INVALID_USER_CREDENTIALS));
        verify(flowContext).attempted();
        //verify(flowContext,atLeastOnce()).challenge(any());
        verify(loginFormsProvider).setErrors(setErrorCaptor.capture());
        Assert.assertNotNull(setErrorCaptor.getValue());
        Assert.assertEquals("X509 certificate authentication's failed.", setErrorCaptor.getValue().get(0).getMessage());
    }
    @Test
    public void testErrorResponseOnUserIsDisable() throws Exception {
        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doReturn(mockValidator).when(mockValidator).validateKeyUsage();
        doReturn(mockValidator).when(mockValidator).validateExtendedKeyUsage();

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();
        doReturn("username").when(userIdExtractor).extractUserIdentity(any());
        doReturn(user).when(userIdModelMapper).find(any(),any());
        doReturn(false).when(user).isEnabled();

        authenticator.authenticate(flowContext);

        verify(events).detail(eq(Details.USERNAME), eq("username"));
        verify(clientSession).setAuthNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME), eq("username"));
        verify(events).user(eq(user));
        verify(events).error(eq(Errors.USER_DISABLED));
        verify(flowContext).attempted();
        //verify(flowContext,atLeastOnce()).challenge(any());
        verify(loginFormsProvider).setErrors(setErrorCaptor.capture());
        Assert.assertNotNull(setErrorCaptor.getValue());
        Assert.assertEquals("X509 certificate authentication's failed.", setErrorCaptor.getValue().get(0).getMessage());
    }
    @Test
    public void testErrorResponseOnUserIsTemporarilyDisabled() throws Exception {
        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doReturn(mockValidator).when(mockValidator).validateKeyUsage();
        doReturn(mockValidator).when(mockValidator).validateExtendedKeyUsage();

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();
        doReturn("username").when(userIdExtractor).extractUserIdentity(any());
        doReturn(user).when(userIdModelMapper).find(any(),any());
        doReturn(true).when(user).isEnabled();
        doReturn(true).when(realm).isBruteForceProtected();
        doReturn(true).when(bruteForceProtector).isTemporarilyDisabled(any(),any(),any());

        authenticator.authenticate(flowContext);

        verify(events).detail(eq(Details.USERNAME), eq("username"));
        verify(clientSession).setAuthNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME), eq("username"));
        verify(events).user(eq(user));
        verify(events).error(eq(Errors.USER_TEMPORARILY_DISABLED));
        verify(flowContext).attempted();
        //verify(flowContext,atLeastOnce()).challenge(any());
        verify(loginFormsProvider).setErrors(setErrorCaptor.capture());
        Assert.assertNotNull(setErrorCaptor.getValue());
        Assert.assertEquals("X509 certificate authentication's failed.", setErrorCaptor.getValue().get(0).getMessage());
    }
    @Test
    public void testSuccessForceChallenge() throws Exception {

        final String userName = "some_user_name";

        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doReturn(mockValidator).when(mockValidator).validateKeyUsage();
        doReturn(mockValidator).when(mockValidator).validateExtendedKeyUsage();

        doReturn(clientCertificates).when(context).getAttribute(any());
        doReturn(new HashMap<String,String>()).when(config).getConfig();
        doReturn(userName).when(userIdExtractor).extractUserIdentity(any());
        doReturn(user).when(userIdModelMapper).find(any(),any());
        doReturn(userName).when(user).getUsername();
        doReturn(true).when(user).isEnabled();
        doReturn(false).when(realm).isBruteForceProtected();
        doReturn(loginFormsProvider).when(loginFormsProvider).setAttribute(anyString(), anyString());

        authenticator.authenticate(flowContext);

        verify(events).detail(eq(Details.USERNAME), eq(userName));
        verify(clientSession).setAuthNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME), eq(userName));
        verify(events,never()).error(any());
        verify(flowContext).setUser(eq(user));
        verify(loginFormsProvider,never()).setErrors(any());

        // The call to setAuthNote has been removed from x509 authenticator by Marek Posolda
        // when calling forceChallenge
        // verify(clientSession).setAuthNote(eq(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION), eq("execution_1"));

        verify(loginFormsProvider,times(3)).setAttribute(nameCaptor.capture(), valueCaptor.capture());
        Assert.assertEquals("some_user_name", valueCaptor.getAllValues().get(0));
        Assert.assertEquals("CN=Client", valueCaptor.getAllValues().get(1));
        Assert.assertEquals(true, valueCaptor.getAllValues().get(2));

        verify(flowContext,atLeastOnce()).forceChallenge(any());

    }

    @Test
    public void testCancelLogin() throws Exception {

        MultivaluedHashMap<String, String> formData = new MultivaluedHashMap<>();
        formData.add("cancel","");
        doReturn(formData).when(context).getDecodedFormParameters();

        authenticator.action(flowContext);

        verify(flowContext).clearUser();
        verify(flowContext).attempted();
    }

    @Test
    public void testNoCancelOrValidUser() throws Exception {

        MultivaluedHashMap<String, String> formData = new MultivaluedHashMap<>();
        doReturn(formData).when(context).getDecodedFormParameters();
        doReturn(null).when(flowContext).getUser();

        authenticator.action(flowContext);

        verify(flowContext,never()).clearUser();
        verify(flowContext,never()).success();
        verify(flowContext).attempted();
    }

    @Test
    public void testSuccessfulLogin() throws Exception {

        MultivaluedHashMap<String, String> formData = new MultivaluedHashMap<>();
        doReturn(formData).when(context).getDecodedFormParameters();

        authenticator.action(flowContext);

        verify(flowContext,never()).clearUser();
        verify(flowContext,never()).attempted();
        verify(flowContext).success();
    }

    @Test
    public void testReverseProxyMissingProxySslHttpHeaderConfig() throws NoSuchAlgorithmException, CertificateEncodingException {

        X509AuthenticatorConfigModel tempConfig =
                new X509AuthenticatorConfigModel().setConnectionReverseProxy();

        doReturn(tempConfig.getConfig()).when(config).getConfig();

        authenticator.authenticate(flowContext);

        verify(events,never()).error(any());
        verify(context,never()).getAttribute(anyString());
        verify(context,never()).getHttpHeaders();
        verify(httpHeaders,never()).getRequestHeaders();
        verify(flowContext).attempted();
    }

    @Test
    public void testReverseProxyMissingSslCertChainHttpHeaderConfig() throws NoSuchAlgorithmException, CertificateEncodingException {

        X509AuthenticatorConfigModel tempConfig =
                new X509AuthenticatorConfigModel().setConnectionReverseProxy();
        tempConfig.setReverseProxyHttpHeader(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_HEADER);

        doReturn(tempConfig.getConfig()).when(config).getConfig();

        authenticator.authenticate(flowContext);

        verify(events,never()).error(any());
        verify(context,never()).getAttribute(anyString());
        verify(context,times(1)).getHttpHeaders();
        verify(httpHeaders, times(1)).getRequestHeaders();
        verify(requestHeaders,times(1)).getFirst(matches(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_HEADER));
        verify(requestHeaders,never()).getFirst(matches(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_CHAIN_HEADER_PREFIX + "_\\d+"));
        verify(flowContext).attempted();
    }

    @Test
    public void testReverseProxyNullProxySslCertHttpHeader() throws NoSuchAlgorithmException, CertificateEncodingException {

        X509AuthenticatorConfigModel tempConfig =
                new X509AuthenticatorConfigModel().setConnectionReverseProxy();
        tempConfig.setReverseProxyHttpHeader(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_HEADER);
        tempConfig.setReverseProxyHttpHeaderChainPrefix(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_CHAIN_HEADER_PREFIX);

        doReturn(null).when(requestHeaders).getFirst(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_HEADER);
        doReturn(tempConfig.getConfig()).when(config).getConfig();

        authenticator.authenticate(flowContext);

        verify(events,never()).error(any());
        verify(context,never()).getAttribute(anyString());
        verify(context).getHttpHeaders();
        verify(httpHeaders).getRequestHeaders();
        verify(flowContext).attempted();
    }

    @Test
    public void testReverseProxyMalformedProxySslCertHttpHeader() throws NoSuchAlgorithmException, CertificateEncodingException {

        X509AuthenticatorConfigModel tempConfig =
                new X509AuthenticatorConfigModel().setConnectionReverseProxy();
        tempConfig.setReverseProxyHttpHeader(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_HEADER);
        tempConfig.setReverseProxyHttpHeaderChainPrefix(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_CHAIN_HEADER_PREFIX);

        doReturn("Some bad x.509 certificate").when(requestHeaders).getFirst(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_HEADER);
        doReturn(tempConfig.getConfig()).when(config).getConfig();

        authenticator.authenticate(flowContext);

        verify(events,never()).error(any());
        verify(context,never()).getAttribute(anyString());
        verify(context).getHttpHeaders();
        verify(httpHeaders).getRequestHeaders();
        verify(flowContext).attempted();
    }

    @Test
    public void testReverseProxySuccessfulAuthentication() throws NoSuchAlgorithmException, CertificateEncodingException {

        X509AuthenticatorConfigModel tempConfig =
                new X509AuthenticatorConfigModel().setConnectionReverseProxy();
        tempConfig.setReverseProxyHttpHeader(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_HEADER);
        tempConfig.setReverseProxyHttpHeaderChainPrefix(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_CHAIN_HEADER_PREFIX);

        String encodedCertificate = PemUtils.encodeCertificate(clientCertificates[0]);

        doReturn(encodedCertificate).when(requestHeaders).getFirst(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_HEADER);
        doReturn(tempConfig.getConfig()).when(config).getConfig();

        authenticator.authenticate(flowContext);

        verify(events,never()).error(any());
        verify(context,never()).getAttribute(anyString());
        verify(context,times(5)).getHttpHeaders();
        verify(httpHeaders,times(5)).getRequestHeaders();
        verify(requestHeaders,times(1)).getFirst(eq(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_HEADER));
        verify(requestHeaders,times(4)).getFirst(matches(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_CHAIN_HEADER_PREFIX + "_\\d+"));
        verify(flowContext).attempted();
    }

    private void testReverseProxySuccessForceChallenge(String encodedCertificate,
                                                       String subjectCN) throws Exception {

        final X509AuthenticatorConfigModel tempConfig =
                new X509AuthenticatorConfigModel().setConnectionReverseProxy();
        tempConfig.setReverseProxyHttpHeader(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_HEADER);
        tempConfig.setReverseProxyHttpHeaderChainPrefix(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_CHAIN_HEADER_PREFIX);

        final String userName = "some_user_name";

        doReturn(encodedCertificate).when(requestHeaders).getFirst(DEFAULT_SSL_CLIENT_CERT_PROXY_HTTP_HEADER);
        doReturn(tempConfig.getConfig()).when(config).getConfig();

        CertificateValidator mockValidator = spy(new CertificateValidator());
        doReturn(mockValidator).when(validatorBuilder).build(any());

        doReturn(mockValidator).when(mockValidator).checkRevocationStatus();
        doReturn(mockValidator).when(mockValidator).validateKeyUsage();
        doReturn(mockValidator).when(mockValidator).validateExtendedKeyUsage();

        doReturn(userName).when(userIdExtractor).extractUserIdentity(any());
        doReturn(user).when(userIdModelMapper).find(any(),any());
        doReturn(userName).when(user).getUsername();
        doReturn(true).when(user).isEnabled();
        doReturn(false).when(realm).isBruteForceProtected();
        doReturn(loginFormsProvider).when(loginFormsProvider).setAttribute(anyString(), anyString());

        authenticator.authenticate(flowContext);

        verify(events).detail(eq(Details.USERNAME), eq(userName));
        verify(clientSession).setAuthNote(eq(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME), eq(userName));
        verify(events,never()).error(any());
        verify(flowContext).setUser(eq(user));
        verify(loginFormsProvider,never()).setErrors(any());

        // The call to setAuthNote has been removed from x509 authenticator by Marek Posolda
        // when calling forceChallenge
        // verify(clientSession).setAuthNote(eq(AuthenticationProcessor.CURRENT_AUTHENTICATION_EXECUTION), eq("execution_1"));

        verify(loginFormsProvider,times(3)).setAttribute(nameCaptor.capture(), valueCaptor.capture());
        Assert.assertEquals("some_user_name", valueCaptor.getAllValues().get(0));
        Assert.assertEquals(subjectCN, valueCaptor.getAllValues().get(1));
        Assert.assertEquals(true, valueCaptor.getAllValues().get(2));

        verify(flowContext,atLeastOnce()).forceChallenge(any());

        verify(events,never()).error(any());
        verify(context,never()).getAttribute(anyString());
        verify(context,times(5)).getHttpHeaders();
        verify(httpHeaders,times(5)).getRequestHeaders();
        verify(flowContext,never()).attempted();
    }

    @Test
    public void testReverseProxySuccessForceChallenge() throws Exception {
        testReverseProxySuccessForceChallenge(
                PemUtils.encodeCertificate(clientCertificates[0]), "CN=Client");
    }

    @Test
    public void testReverseProxySuccessForceChallengeWithCertificateEnclosedWithDoubleQuotes() throws Exception {
        final String encodedCertificate = "\"" + PemUtils.encodeCertificate(clientCertificates[0]) + "\"";
        testReverseProxySuccessForceChallenge(encodedCertificate, "CN=Client");
    }

    @Test
    public void testReverseProxySuccessForceChallengeWithCertificateEnclosedInBeginEnd() throws Exception {
        final String encodedCert = "-----BEGIN CERTIFICATE----- MIIGcTCCBFmgAwIBAgICEBQwDQYJKoZIhvcNAQELBQAwgZAxCzAJBgNVBAYTAlVT MRUwEwYDVQQIDAxQZW5uc3lsdmFuaWExIjAgBgNVBAoMGUFuYWx5dGljYWwgR3Jh cGhpY3MsIEluYy4xDDAKBgNVBAsMA0RldjEYMBYGA1UEAwwPQXV0aCBJc3N1aW5n IENBMR4wHAYJKoZIhvcNAQkBFg9zdXBwb3J0QGFnaS5jb20wHhcNMTYwNTE0MjEx MTU1WhcNMjYwMzIzMjExMTU1WjCBkzELMAkGA1UEBhMCVVMxFTATBgNVBAgMDFBl bm5zeWx2YW5pYTEiMCAGA1UECgwZQW5hbHl0aWNhbCBHcmFwaGljcywgSW5jLjEM MAoGA1UECwwDRGV2MRgwFgYDVQQDDA9QZXRlciBOYWx5dmF5a28xITAfBgkqhkiG 9w0BCQEWEnBuYWx5dmF5a29AYWdpLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIP ADCCAgoCggIBALaYmsbpDf6J9tDYnSYuKQDJXqm7jx6331gN98g49Ofz0YtSzPxb 7HD7gEbbYFWW44ME+/qsWctLSPWnLAijZ2MikfG38PFHSbTNYR5zqYRPUwx7Ez/7 31U5wsiRba8Uy0W8E/jMyJ7hInByKwPsrrNmLHruKFwtvoKFe/m4lvqPzMjtCl8q KOdcQZDLPXFpf8xQjMt9l5BZlomjgUM+wQ26USXvO9UhsI1v+dtENnbA47sMCB8F gUTGLRWqy1mqGedvd1F4sbxQ2tKPnSk0RLmYdzt9ScDsNO/ZCiwK1qzJoOOpEvaj a2rt9iBZekm7lJE/B9PchO8RAcH/GynbEqZNwp4umlsKutzdgbjpV1/cqzaxpF+v Aas+wck1w9sdiv8+nFKOwGkfcmAYw3zPvFsbNZf6CmZVo5qeZraW0klx/tnt3Fky yXT7T8wkdZgrFH4w8Nfzpv2QNmEhkbXFb2+wyx/mR+V11fyOLjtNlRfcfE6JRpYq CpIRcZMmgrGmHjibVAYnRDFmR6kf0vGBONMkH8ieJKc8HpVcQbtUqBtDA+o80Frs pPU9Dman6o6cTfurZlD+zEtoilwMlxv6k5j50kdgB5m+erVuOXIewwDzs624pf7v yZeGc7ai3T4dPn4VQLeFD1A4FVSVXQWUVz2TmNOY2fYcqmjg8GsorKMrAgMBAAGj gc8wgcwwCQYDVR0TBAIwADARBglghkgBhvhCAQEEBAMCBaAwCwYDVR0PBAQDAgXg MB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDBDAhBglghkgBhvhCAQ0EFBYS Q2xpZW50IENlcnRpZmljYXRlMB0GA1UdDgQWBBSvFG7lT6/0Rj4yrylXjJWj2UG0 JTAfBgNVHSMEGDAWgBSz6/Fchz+L0Ot3vvvGZSIfGuHsEzAdBgNVHREEFjAUgRJw bmFseXZheWtvQGFnaS5jb20wDQYJKoZIhvcNAQELBQADggIBAKh3S24Ng1JcgvbH DXUNuldbgHL62ciXr3aB3abhnbZaRVojrX38AIow9+/gC8SiIHBx8IXfC5ucDi// g1JRwQ7b2X+98/sTiZZKSGfY4iSJnoqu7cXco/HPcGKybdQdLdy9/FwfsHmoJcfP pVZy91+BGU/m3/LuEMQgDcdXDQYJbLFqN8u/u0WfUaW7cAxPj9E/gdtveBuRNKLl CZah4cdDZjv2QR/bp9Ph1E/ElZB1SJlOx5WT2UEeRMzupmTifvtkcYDPDkfkRIby bDM7IoHB1+efQejFvif8Mzgk3WDPGUPoqZLWuR7/NFp1A4B9Ug3AyMdVhztLxZYl JON16GirUXq/E/8q1K2E5w3sPN4NKYKz3d6IAhSsTT80vujpnAJUhX5TBb1Jvc4C PKaZ59O3hu1XPxM59Tg5t4TzWe6MnSqKI2wgq7E4x9HLzgqsHrSk+ogV9KBIjYJk 5zf98FR0kb2NvstUAHSDxf8SX3MO84GAVILk4UVZl5RSbHAVEWipGU1zTRkXqmWY YNRdIdBIO65aMpbqSZBbyOYWcmbSxZm0w08BNfiuUteyYyASFgWFtPlxb9UcjMyR ESuLDfBnnP8zLsdp+n4d7PY1rShUJ6d7T642DqQ8hK6KFaw2ofMKnceDfTy8rp5b HwCcH5Yw9rwC/6YJm9zL0sWHIrPi -----END CERTIFICATE-----";
        final String subjectCN = "C=US,ST=Pennsylvania,O=Analytical Graphics\\, Inc.,OU=Dev,CN=Peter Nalyvayko,E=pnalyvayko@agi.com";
        testReverseProxySuccessForceChallenge(encodedCert, subjectCN);
    }
}
