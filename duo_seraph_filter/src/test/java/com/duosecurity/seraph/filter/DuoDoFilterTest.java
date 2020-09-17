package com.duosecurity.seraph.filter;

import javax.servlet.FilterChain;
import com.duosecurity.model.Token;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Matchers.anyString;

class DoFilterTest {
  private DuoAuthFilter duoAuthFilter;
  private DuoAuthFilter duoAuthFilterSpy;
  private MockFilterConfig filterConfig;
  private HttpServletResponse response;
  private HttpServletRequest request;
  private HttpSession session;
  private FilterChain chain;
  private Principal principal;
  private String clientId = "DIXXXXXXXXXXXXXXXXXX";
  private String clientSecret = "clientsecretclientsecretclientsecretclie";
  private String host = "admin-test.duosecurity.com";
  private String redirectUri = "http://localhost:8080/secure/Dashboard.jspa";
  private String contextPath = "example.com";
  private String requestUri = "example.com/secure/Dashboard.jspa";
  private String unprotectedRequestUri = "example.com/rest/gadget/1.0/login";
  private String originalUrl = "example.com/example?user=username";
  private String originalRequestUri = "example.com/example";
  private String originalQueryString = "user=username";
  private String duoHealthCheckError = "Failclosed for user: null";
  private String stateGood = "goodstategoodstategoodstategoods";
  private String stateBad = "badstatebadstatebadstatebadstate";
  private String duoCodeGood = "goodcodegoodcodegoodcodegoodcode";
  private String username = "Mama Gorg";

  private Map<String, String> defaultInitParameters = new HashMap<String, String> () {{
    put("host", host);
    put("client.Id", clientId);
    put("client.Secret", clientSecret);
    put("redirecturi", redirectUri);
    put("bypass.APIs", "true");
  }};


  @BeforeEach
  void setUp() throws javax.servlet.ServletException {
    duoAuthFilter = new DuoAuthFilter();
    filterConfig = new MockFilterConfig(defaultInitParameters);
    response = Mockito.mock(HttpServletResponse.class);
    request = Mockito.mock(HttpServletRequest.class);
    chain = Mockito.mock(FilterChain.class);
    session = Mockito.mock(HttpSession.class); 
    principal = Mockito.mock(Principal.class);

    Mockito.when(request.getContextPath()).thenReturn(contextPath);
    Mockito.when(request.getSession()).thenReturn(session);
    Mockito.when(request.getUserPrincipal()).thenReturn(principal);
    Mockito.when(request.getRequestURI()).thenReturn(originalRequestUri);
    Mockito.when(request.getQueryString()).thenReturn(originalQueryString);
    Mockito.when(principal.getName()).thenReturn(username);

    duoAuthFilter.init(filterConfig);
    duoAuthFilterSpy = Mockito.spy(duoAuthFilter);
  }

  void assertDuoPerformed()
  throws java.io.IOException, javax.servlet.ServletException
  {
    // Asserts that the duo redirect function was called and that we
    // break out of the chain and do not call any more filters
    Mockito.verify(duoAuthFilterSpy, Mockito.times(1)).redirectDuoPrompt(principal, session, response);
    Mockito.verify(chain, Mockito.times(0)).doFilter(request, response);
  }

  void assertDuoPerformedBeforeCallback()
  throws java.io.IOException, javax.servlet.ServletException
  {
    // Assert that Duo was performed and that we set the original url in the session
    assertDuoPerformed();
    Mockito.verify(session, Mockito.times(1)).setAttribute(duoAuthFilterSpy.DUO_ORIGINAL_URL_KEY, originalUrl);
  }

  @Test
  void unprotectedPageTest()
  throws java.io.IOException, javax.servlet.ServletException {
    // Unprotected pages get no Duo on them

    Mockito.when(request.getRequestURI()).thenReturn(unprotectedRequestUri);

    duoAuthFilter.doFilter(request, response, chain);

    // This shows we aren't checking the status of auth
    Mockito.verify(request, Mockito.times(0)).getAttribute(duoAuthFilter.OS_AUTHSTATUS_KEY);
    // This shows we just move onto the next filter
    Mockito.verify(chain, Mockito.times(1)).doFilter(request, response);
  }

  @Test
  void previousOAuthSuccessTest()
  throws java.io.IOException, javax.servlet.ServletException {
    // If the request has already gone through OAuth then we don't try to add 2fa

    Mockito.when(request.getAttribute(duoAuthFilter.OS_AUTHSTATUS_KEY)).thenReturn("success");

    duoAuthFilter.doFilter(request, response, chain);

    // Verify that a previous OAuth success invokes the next filter in the chain without setting a successful Duo auth
    Mockito.verify(session, Mockito.times(0)).getAttribute(duoAuthFilterSpy.DUO_AUTH_SUCCESS_KEY);
    Mockito.verify(chain, Mockito.times(1)).doFilter(request, response);
  }

  @Test
  void oAuthSuccessBypassApiFalseTest()
  throws java.io.IOException, javax.servlet.ServletException {
    // Verify if there was an OAuth success but apiBypassEnabled is false then we continue to auth with Duo

    duoAuthFilterSpy.apiBypassEnabled = false;
    Mockito.when(request.getAttribute(duoAuthFilterSpy.OS_AUTHSTATUS_KEY)).thenReturn("success");
    Mockito.doReturn(true).when(duoAuthFilterSpy).duoHealthCheck(anyString());

    duoAuthFilterSpy.doFilter(request, response, chain);

    assertDuoPerformed();
  }

  @Test
  void oAuthSuccessPrincipalEmptyTest()
  throws java.io.IOException, javax.servlet.ServletException {
    // Verify if there was an OAuth success but the principal user is empty then continue to the next chain without setting a successful Duo auth

    Mockito.when(request.getAttribute(duoAuthFilterSpy.OS_AUTHSTATUS_KEY)).thenReturn("success");

    duoAuthFilterSpy.doFilter(request, response, chain);

    Mockito.verify(session, Mockito.times(0)).getAttribute(duoAuthFilterSpy.DUO_AUTH_SUCCESS_KEY);
    Mockito.verify(chain, Mockito.times(1)).doFilter(request, response);
  }

  @Test
  void oAuthFailedTest() {
    // Verify that a previous OAuth failure throws an error

    Mockito.when(request.getAttribute(duoAuthFilter.OS_AUTHSTATUS_KEY)).thenReturn("fail");
    try {
      duoAuthFilter.doFilter(request, response, chain);
      Assertions.fail();
    } catch (Exception e) {
      assertTrue(e.getMessage().contains(duoAuthFilter.OAUTH_FAIL));
    }
  }

  @Test
  void noPrincipalUserTest()
  throws java.io.IOException, javax.servlet.ServletException {
    // verify that we continue to the next chain without passing a Duo auth

    Mockito.when(request.getUserPrincipal()).thenReturn(null);

    duoAuthFilter.doFilter(request, response, chain);

    Mockito.verify(session, Mockito.times(0)).getAttribute(duoAuthFilter.DUO_AUTH_SUCCESS_KEY);
    Mockito.verify(chain, Mockito.times(1)).doFilter(request, response);
  }

  @Test
  void previousDuoSuccessTest()
  throws java.io.IOException, javax.servlet.ServletException {
    // Verify that we bypass the Duo part of the auth and just call the next filter.

    Mockito.when(session.getAttribute(duoAuthFilter.DUO_AUTH_SUCCESS_KEY)).thenReturn("true");

    duoAuthFilter.doFilter(request, response, chain);

    Mockito.verify(duoAuthFilterSpy, Mockito.times(0)).redirectDuoPrompt(principal, session, response);
    Mockito.verify(chain, Mockito.times(1)).doFilter(request, response);
  }

  @Test
  void healthCheckFailOpenTest()
  throws java.io.IOException, javax.servlet.ServletException {
    // In a fail open scenario we will verify that the Duo redirect is not called but the auth success key is still
    // set to true. This allows the user to get in without Duo. The next filter will still be called.

    Mockito.doReturn(false).when(duoAuthFilterSpy).duoHealthCheck(anyString());

    duoAuthFilterSpy.doFilter(request, response, chain);

    Mockito.verify(duoAuthFilterSpy, Mockito.times(0)).redirectDuoPrompt(principal, session, response);
    Mockito.verify(chain, Mockito.times(1)).doFilter(request, response);
    Mockito.verify(session, Mockito.times(1)).setAttribute(duoAuthFilterSpy.DUO_AUTH_SUCCESS_KEY, true);
  }

  @Test
  void healthCheckFailClosedTest() {
    try {
      Mockito.doThrow(new ServletException(duoHealthCheckError)).when(duoAuthFilterSpy).duoHealthCheck(anyString());
      duoAuthFilterSpy.doFilter(request, response, chain);
      Assertions.fail();
    } catch (Exception e) {
      // Verify that an error is thrown when Duo is down and the failmode is closed
      assertTrue(e.getMessage().contains(duoHealthCheckError));
    }
  }

  @Test
  void healthCheckSuccessTest()
  throws java.io.IOException, javax.servlet.ServletException {
    // Successful health check leads us to perform a Duo auth
    Mockito.doReturn(true).when(duoAuthFilterSpy).duoHealthCheck(anyString());

    duoAuthFilterSpy.doFilter(request, response, chain);

    assertDuoPerformedBeforeCallback();
  }

  @Test
  void statesNotEqualTest()
  throws java.io.IOException, javax.servlet.ServletException {
    // On our second pass through the plugin if the states are not equal then redirect to the prompt and try another auth
    Mockito.when(session.getAttribute(duoAuthFilterSpy.DUO_SAVED_STATE_KEY)).thenReturn(stateGood);
    Mockito.when(request.getParameter("state")).thenReturn(stateBad);
    Mockito.when(request.getParameter("duo_code")).thenReturn(duoCodeGood);
    Mockito.doReturn(true).when(duoAuthFilterSpy).duoHealthCheck(anyString());

    duoAuthFilterSpy.doFilter(request, response, chain);

    assertDuoPerformedBeforeCallback();
  }

  @Test
  void stateExistsCodeNullTest()
  throws java.io.IOException, javax.servlet.ServletException {
    // On our second pass through:
    // Verify that if the duo_code is null even if the state exists we redirect to the prompt and try another auth
    Mockito.when(session.getAttribute(duoAuthFilterSpy.DUO_SAVED_STATE_KEY)).thenReturn(stateGood);
    Mockito.when(request.getParameter("state")).thenReturn(stateGood);
    Mockito.doReturn(true).when(duoAuthFilterSpy).duoHealthCheck(anyString());

    duoAuthFilterSpy.doFilter(request, response, chain);

    assertDuoPerformedBeforeCallback();
  }

  @Test
  void noQueryParamOriginalUrlTest()
  throws java.io.IOException, javax.servlet.ServletException {
    Mockito.doReturn(true).when(duoAuthFilterSpy).duoHealthCheck(anyString());
    Mockito.when(request.getQueryString()).thenReturn(null);

    duoAuthFilterSpy.doFilter(request, response, chain);

    Mockito.verify(session, Mockito.times(1)).setAttribute(duoAuthFilterSpy.DUO_ORIGINAL_URL_KEY, originalRequestUri);
  }

  @Test
  void queryParamOriginalUrlTest()
  throws java.io.IOException, javax.servlet.ServletException {
    Mockito.doReturn(true).when(duoAuthFilterSpy).duoHealthCheck(anyString());

    duoAuthFilterSpy.doFilter(request, response, chain);

    Mockito.verify(session, Mockito.times(1)).setAttribute(duoAuthFilterSpy.DUO_ORIGINAL_URL_KEY, originalUrl);
  }
  @Test
  void tokenIsNullTest()
  throws java.io.IOException, javax.servlet.ServletException {
    // On our second pass through:
    // Verify that if the token is null then we redirect to the prompt and try another auth
    Mockito.when(session.getAttribute(duoAuthFilterSpy.DUO_SAVED_STATE_KEY)).thenReturn(stateGood);
    Mockito.when(request.getParameter("state")).thenReturn(stateGood);
    Mockito.when(request.getParameter("duo_code")).thenReturn(duoCodeGood);
    Mockito.doReturn(null).when(duoAuthFilterSpy).exchangeDuoToken(session, duoCodeGood, "username");

    duoAuthFilterSpy.doFilter(request, response, chain);

    assertDuoPerformed();
  }

  @Test
  void duoTokenExchangeSuccess()
  throws java.io.IOException, javax.servlet.ServletException {
    Token token = Mockito.mock(Token.class);
    Mockito.when(session.getAttribute(duoAuthFilterSpy.DUO_SAVED_STATE_KEY)).thenReturn(stateGood);
    Mockito.when(request.getParameter("state")).thenReturn(stateGood);
    Mockito.when(request.getParameter("duo_code")).thenReturn(duoCodeGood);
    Mockito.when(session.getAttribute(duoAuthFilterSpy.DUO_ORIGINAL_URL_KEY)).thenReturn(originalUrl);
    Mockito.doReturn(token).when(duoAuthFilterSpy).exchangeDuoToken(session, duoCodeGood, username);

    duoAuthFilterSpy.doFilter(request, response, chain);

    // Verify that we set a successful auth and continued to next filter with doFilter
    Mockito.verify(session, Mockito.times(1)).setAttribute(duoAuthFilterSpy.DUO_AUTH_SUCCESS_KEY, true);
    Mockito.verify(response, Mockito.times(1)).sendRedirect(originalUrl);
  }
}
