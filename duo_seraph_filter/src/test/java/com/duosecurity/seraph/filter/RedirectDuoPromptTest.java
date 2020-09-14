package com.duosecurity.seraph.filter;

import com.duosecurity.Client;
import com.duosecurity.exception.DuoException;
import javax.servlet.http.HttpSession;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.security.Principal;
import org.mockito.Mockito;
import static org.mockito.Matchers.anyString;

class RedirectDuoPromptTest {
  private DuoAuthFilter duoAuthFilter;
  private HttpSession session;
  private String duoState = "deadbeefdeadbeefdeadbeefdeadbeef";
  private String authUrl = "https://api-xxxxxxx.duosecurity.com";
  private String exampleUser = "exampleUser";
  private Principal principal;
  private HttpServletResponse httpServletResponse;

  @BeforeEach
  void setUp() {
    duoAuthFilter = new DuoAuthFilter();
    session = Mockito.mock(HttpSession.class);
    principal = Mockito.mock(Principal.class);
    session = Mockito.mock(HttpSession.class);
    httpServletResponse = Mockito.mock(HttpServletResponse.class);
    duoAuthFilter.duoClient = Mockito.mock(Client.class);
  }

  @Test
  void successfulRedirectTest() throws java.io.IOException, DuoException {
    Mockito.when(httpServletResponse.isCommitted()).thenReturn(false);
    Mockito.when(principal.getName()).thenReturn(exampleUser);
    Mockito.when(duoAuthFilter.duoClient.generateState()).thenReturn(duoState);
    Mockito.when(duoAuthFilter.duoClient.createAuthUrl(anyString(), anyString())).thenReturn(authUrl);

    duoAuthFilter.redirectDuoPrompt(principal, session, httpServletResponse);

    Mockito.verify(httpServletResponse, Mockito.times(1)).sendRedirect(authUrl);
  }

  @Test
  void isCommittedNoRedirectTest() throws java.io.IOException {
    Mockito.when(httpServletResponse.isCommitted()).thenReturn(true);

    duoAuthFilter.redirectDuoPrompt(principal, session, httpServletResponse);

    Mockito.verify(httpServletResponse, Mockito.times(0)).sendRedirect(authUrl);
  }
}
