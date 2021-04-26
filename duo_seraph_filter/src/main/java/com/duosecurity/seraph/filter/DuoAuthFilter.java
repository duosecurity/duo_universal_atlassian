package com.duosecurity.seraph.filter;

import static java.lang.String.format;

import com.duosecurity.Client;
import com.duosecurity.model.HealthCheckResponse;
import com.duosecurity.model.Token;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.log4j.Category;

@SuppressWarnings("UnusedDeclaration")
public class DuoAuthFilter implements javax.servlet.Filter {
  private static final Category log = Category.getInstance(DuoAuthFilter.class);

  public static final String OS_AUTHSTATUS_KEY = "os_authstatus";
  public static final String LOGIN_SUCCESS = "success";
  protected static final String DUO_FAILCLOSED = "Duo healthcheck status failed";
  protected static final String OAUTH_FAIL = "OAuth authentication failed";
  protected static final String DUO_CONFIG_ERROR = "Invalid Duo Config";

  /** keys in a session where Duo attributes are stored. */
  public static final String DUO_AUTH_SUCCESS_KEY = "duo.authsuccess.key";
  public static final String DUO_SAVED_STATE_KEY = "duo.savedstate.key";
  public static final String DUO_ORIGINAL_URL_KEY = "duo.originalurl.key";

  /* page used for mobile login */
  private String mobileLoginUrl = "/plugins/servlet/mobile/login";
  protected Client duoClient;
  protected String[] defaultUnprotectedDirs = {
    "/rest/gadget/1.0/login"
  };
  protected ArrayList<String> unprotectedDirs;
  protected boolean apiBypassEnabled = false;
  protected boolean failOpen = true;
  private static final String USER_AGENT_LIB = "duo_universal_atlassian";
  private static final String USER_AGENT_VERSION = "2.0.3";

  /**
   * Return true if url should not be protected by Duo auth, even if we have
   * a local user.
   *
   * @param url The url of the request
   *
   * @return Return true if the page is unprotected, otherwise return false
   */
  private boolean isUnprotectedPage(String url) {
    // Is this url used for Duo auth?
    for (String dir : unprotectedDirs) {
      if (url.startsWith(dir)) {
        return true;
      }
    }
    // Is this url used for mobile login?
    // This url is POSTed to after we have a user, but we'd rather not send
    // the user from here to the Duo auth, because there could be
    // credentials in the parameters that we'd want to take out of the URL
    // we redirect back to.
    if (url.equals(mobileLoginUrl)) {
      return true;
    }
    return false;
  }

  private static String createUserAgentString() {
    return format("%s/%s", USER_AGENT_LIB, USER_AGENT_VERSION);
  }

  /**
   * Check if there was a successful OAuth request previously.
   *
   * @return If there was a successful OAuth request return true
   *          otherwise return false
   */
  private static boolean checkOAuthSuccess(ServletRequest request) {
    if (request.getAttribute(OS_AUTHSTATUS_KEY).equals(LOGIN_SUCCESS)) {
      return true;
    }
    return false;
  }

  /**
   * Check to see if we are in the callback after the prompt.
   *
   * @param duoCode  The duo_code returned from Duo after the prompt
   * @param duoState The state returned from Duo after the prompt
   *
   * @return If this is the response after the prompt then return true, otherwise return false
   */
  private static boolean callbackAfterPrompt(String duoCode, String duoState) {
    if (duoCode != null && duoState != null) {
      return true;
    }
    return false;
  }

  private static boolean validateDuoConfig(String clientId, String clientSecret,
                                           String host, String redirectUri) {
    if (clientId != null && !clientId.isEmpty()
        && clientSecret != null && !clientSecret.isEmpty()
        && host != null && !host.isEmpty()
        && redirectUri != null && !redirectUri.isEmpty()) {
      return true;
    }
    return false;
  }

  /**
   * Check to see if the saved state is equal to the state returned by Duo.
   *
   * @param duoState       The state returned from Duo after the prompt
   * @param duoSavedState  The state previously saved before redirecting to the prompt
   *
   * @return If duoSavedState exists and the states are the same return true
   *           otherwise return false
   */
  private static boolean validateState(String duoState, String duoSavedState) {
    if (duoSavedState != null && duoState.equals(duoSavedState)) {
      return true;
    }
    return false;
  }

  /**
   * Check the token's auth result to make sure it's correctly provided
   * and reports a successful auth.
   * 
   * @param token Contains contextual information about the auth.
   *                This was given by Duo in exchange for the duo_code
   * 
   * @return true if the token exists, is correctly structured, and indicates a successful auth;
   *         false otherwise
   */
  private static boolean validateTokenAuthResult(Token token) {
    return token != null
           && token.getAuth_result() != null
           && "ALLOW".equalsIgnoreCase(token.getAuth_result().getStatus());
  }

  /**
   * Construct and save the URL user is trying to go to.
   */
  private static void constructOriginalUrl(HttpServletRequest httpServletRequest,
                                           HttpSession session) {
    final String originalUrl = httpServletRequest.getRequestURI()
        + (httpServletRequest.getQueryString() == null ? "" : "?"
        + httpServletRequest.getQueryString());
    session.setAttribute(DUO_ORIGINAL_URL_KEY, originalUrl);
  }

  /**
   * Generate state and save it to the session.
   *
   * @param session  The http session for this request
   *
   * @return Return the generated state
   */
  private String generateDuoState(HttpSession session) {
    String duoSavedState = duoClient.generateState();
    session.setAttribute(DUO_SAVED_STATE_KEY, duoSavedState);
    return duoSavedState;
  }

  /**
   * Reach out to Duo to see if it is feasable to auth.
   *
   * @return If Duo is up then return true and if Duo is down and the failmode is open return false
   * @throws javax.servlet.ServletExceptionThrow Thrown when Duo is down and the failmode is closed
   */
  protected boolean duoHealthCheck(String duoUsername)
        throws javax.servlet.ServletException {
    try {
      HealthCheckResponse healthCheckResponse = duoClient.healthCheck();
      // The healthCheckResponse status will be "FAIL" if Duo is not available
      if (healthCheckResponse == null || "FAIL".equalsIgnoreCase(healthCheckResponse.getStat())) {
        throw new ServletException(DUO_FAILCLOSED);
      }
    } catch (Exception e) {
      if (failOpen) {
        log.error("Duo error. Fail open for user " + duoUsername + "\n" + e);
        return false;
      }
      log.error("Duo error. Fail closed for user " + duoUsername + "\n" + e);
      throw new ServletException(e);
    }
    return true;
  }

  /**
   * Exchange the duo_code returned from Duo for a token that contains contextual information
   * about the auth.
   *
   * @param session The http session for the request
   * @param duoCode  The duo_code returned from Duo after the prompt
   * @param username The username we expect to have authenticated
   *
   * @return If we need to reauth because of an invalid token return null
   *            If this was after the prompt and the Token was decoded successfuly then return true
   */
  protected Token exchangeDuoToken(HttpSession session, String duoCode, String username) {
    try {
      Token token = duoClient.exchangeAuthorizationCodeFor2FAResult(duoCode, username);
      if (!validateTokenAuthResult(token)) {
        throw new ServletException("Duo Token is not valid");
      }
      return token;
    } catch (Exception e) {
      log.error(e);
      return null;
    }
  }

  /**
   * Generate a url to the prompt then redirect to the prompt if the request has not been committed.
   */
  protected void redirectDuoPrompt(Principal principal, HttpSession session,
                                 HttpServletResponse httpServletResponse)
        throws java.io.IOException {
    // Redirect to prompt if we can.  If the request is committed,
    // we can't, possibly because there's already a redirection in
    // progress; this is what Seraph's SecurityFilter does.
    if (!httpServletResponse.isCommitted()) {
      try {
        // Step 2: Generate and save a state
        String duoSessionState = generateDuoState(session);
        // Step 3: Create a url and use it to redirect to the prompt
        String duoRedirect = duoClient.createAuthUrl(principal.getName(), duoSessionState);
        httpServletResponse.sendRedirect(duoRedirect);
      } catch (Exception e) {
        log.warn(e);
      }
    } else {
      log.warn("Could not redirect to Duo auth page.");
    }
  }

  @Override public void doFilter(ServletRequest request, ServletResponse response,
                                 FilterChain chain)
        throws java.io.IOException, javax.servlet.ServletException {
    HttpServletRequest httpServletRequest = (HttpServletRequest) request;
    HttpServletResponse httpServletResponse = (HttpServletResponse) response;

    HttpSession session = httpServletRequest.getSession();
    Principal principal = httpServletRequest.getUserPrincipal();

    String contextPath = httpServletRequest.getContextPath();

    if (!isUnprotectedPage(httpServletRequest.getRequestURI().replaceFirst(contextPath, ""))) {
      if (request.getAttribute(OS_AUTHSTATUS_KEY) != null
          && apiBypassEnabled && principal != null) {
        // Request has gone through OAuth, we're done if it succeeded
        if (!checkOAuthSuccess(request)) {
          throw new ServletException(OAUTH_FAIL);
        }
      } else if (principal != null) {
        // User has logged in locally, has there been a Duo auth?
        if (session.getAttribute(DUO_AUTH_SUCCESS_KEY) == null) {
          // There has not been a successful Duo auth
          try {
            String duoCode = httpServletRequest.getParameter("duo_code");
            String duoState = httpServletRequest.getParameter("state");
            String duoSavedState = (String) session.getAttribute(DUO_SAVED_STATE_KEY);
            // Check to see if we are in the response after the prompt
            // Step 4: Make sure the state saved is the same as the state returned from Duo
            // during the redirect back from the prompt
            if (!callbackAfterPrompt(duoCode, duoState)
                || !validateState(duoState, duoSavedState)) {
              //Save the original URL to redirect to after a successful auth
              constructOriginalUrl(httpServletRequest, session);
              // Step 1: We have not had a successful auth with Duo yet
              // If the health check is successful then redirect to Duo
              // If the health check fails and it's failopen then bypass Duo
              // otherwise throw an error
              if (duoHealthCheck(principal.getName())) {
                redirectDuoPrompt(principal, session, httpServletResponse);
                return;
              } else {
                // If Duo is down and we have our failmode to fail open
                // Set our auth success key to true and invoke next chain in the filter
                session.setAttribute(DUO_AUTH_SUCCESS_KEY, true);
              }
            } else {
              // Step 5: If this is part of the callback from Duo and the states are equal
              // then exchange the code for the auth token and log the token
              // If the token was successfully exchanged and decoded
              // then succeed the second factor auth otherwise try to auth with Duo again
              String username = principal.getName();
              Token token = exchangeDuoToken(session, duoCode, username);
              if (token == null) {
                // Intentionally not doing a health check here because we did one on
                // the previous call.
                redirectDuoPrompt(principal, session, httpServletResponse);
                return;
              }
              log.info(token);
              session.setAttribute(DUO_AUTH_SUCCESS_KEY, true);
              String originalUrl = (String) session.getAttribute(DUO_ORIGINAL_URL_KEY);
              httpServletResponse.sendRedirect(originalUrl);
              return;
            }
          } catch (Exception e) {
            throw new ServletException(e);
          }
        } // user has already authed with us this session
      } // no user -> Seraph has not required auth -> we don't either,
      // or user came from OAuth and we're configured to not require 2fa for that
    } // There is gadget health check running

    // Step 6: Invoke next filter in the chain
    chain.doFilter(request, response);
  }

  @Override public void init(final FilterConfig filterConfig)
        throws javax.servlet.ServletException {
    String clientId = filterConfig.getInitParameter("client.Id");
    String clientSecret = filterConfig.getInitParameter("client.Secret");
    String host = filterConfig.getInitParameter("host");
    String redirectUri = filterConfig.getInitParameter("redirecturi");

    // The client validates the clientId, clientSecret, and redirect uri for us
    // but we should make sure that the host is valid as well
    if (!validateDuoConfig(clientId, clientSecret, host, redirectUri)) {
      throw new ServletException(DUO_CONFIG_ERROR);
    }
    try {
      duoClient = new Client(clientId, clientSecret, host, redirectUri);
      duoClient.appendUserAgentInfo(createUserAgentString());
    } catch (Exception e) {
      throw new ServletException(e);
    }

    // Init our unprotected endpoints
    unprotectedDirs = new ArrayList<String>(Arrays.asList(defaultUnprotectedDirs));

    if (filterConfig.getInitParameter("unprotected.dirs") != null) {
      String[] userSpecifiedUnprotectedDirs = filterConfig.getInitParameter(
                                                           "unprotected.dirs").split(" ");
      unprotectedDirs.addAll(Arrays.asList(userSpecifiedUnprotectedDirs));
    }

    if (filterConfig.getInitParameter("bypass.APIs") != null) {
      apiBypassEnabled = Boolean.parseBoolean(filterConfig.getInitParameter("bypass.APIs"));
    }

    if (filterConfig.getInitParameter("fail.Open") != null) {
      failOpen = Boolean.parseBoolean(filterConfig.getInitParameter("fail.Open"));
    }
  }

  @Override public void destroy() {

  }
}
