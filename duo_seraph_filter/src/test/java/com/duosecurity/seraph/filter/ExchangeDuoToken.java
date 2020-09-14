package com.duosecurity.seraph.filter;

import com.duosecurity.model.Token;
import com.duosecurity.model.AuthResult;
import com.duosecurity.Client;
import com.duosecurity.exception.DuoException;
import javax.servlet.http.HttpSession;
import java.security.Principal;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.mockito.Matchers.anyString;
import static org.junit.jupiter.api.Assertions.*;

class ExchangeDuoTokenTest {
  private DuoAuthFilter duoAuthFilter;
  private HttpSession session;
  private String duoCode = "deadbeefdeadbeefdeadbeefdeadbeef";
  private String tokenUsername = "Junior Gorg";
  private Token token;
  private AuthResult authResult;

  @BeforeEach
  void setUp() {
    duoAuthFilter = new DuoAuthFilter();
    token = Mockito.mock(Token.class);
    authResult = Mockito.mock(AuthResult.class);
    session = Mockito.mock(HttpSession.class);
    duoAuthFilter.duoClient = Mockito.mock(Client.class);
    Mockito.doReturn(authResult).when(token).getAuth_result();
    Mockito.doReturn(tokenUsername).when(token).getSub();
  }

  @Test
  void exchangeTokenNullTokenTest() throws DuoException {
    Mockito.when(duoAuthFilter.duoClient.exchangeAuthorizationCodeFor2FAResult(anyString(), anyString())).thenReturn(null);

    assertNull(duoAuthFilter.exchangeDuoToken(session, duoCode, tokenUsername));
  }

  @Test
  void exchangeTokenNullAuthStatusTest() throws DuoException {
    Mockito.when(duoAuthFilter.duoClient.exchangeAuthorizationCodeFor2FAResult(anyString(), anyString())).thenReturn(token);
    Mockito.when(token.getAuth_result()).thenReturn(null);

    assertNull(duoAuthFilter.exchangeDuoToken(session, duoCode, tokenUsername));
  }

  @Test
  void exchangeTokenNullStatusTest() throws DuoException {
    Mockito.when(duoAuthFilter.duoClient.exchangeAuthorizationCodeFor2FAResult(anyString(), anyString())).thenReturn(token);
    Mockito.when(authResult.getStatus()).thenReturn(null);

    assertNull(duoAuthFilter.exchangeDuoToken(session, duoCode, tokenUsername));
  }

  @Test
  void exchangeTokenStatusFailTest() throws DuoException {
    Mockito.when(duoAuthFilter.duoClient.exchangeAuthorizationCodeFor2FAResult(anyString(), anyString())).thenReturn(token);
    Mockito.when(authResult.getStatus()).thenReturn("FAIL");

    assertNull(duoAuthFilter.exchangeDuoToken(session, duoCode, tokenUsername));
  }

  @Test
  void exchangeTokenNullExpectedUsernameFailTest() throws DuoException {
    Mockito.when(duoAuthFilter.duoClient.exchangeAuthorizationCodeFor2FAResult(anyString(), anyString())).thenReturn(token);
    Mockito.when(authResult.getStatus()).thenReturn("ALLOW");

    assertNull(duoAuthFilter.exchangeDuoToken(session, duoCode, null));
  }

  @Test
  void exchangeTokenBlankExpectedUsernameFailTest() throws DuoException {
    Mockito.when(duoAuthFilter.duoClient.exchangeAuthorizationCodeFor2FAResult(anyString(), anyString())).thenReturn(token);
    Mockito.when(authResult.getStatus()).thenReturn("ALLOW");

    assertNull(duoAuthFilter.exchangeDuoToken(session, duoCode, ""));
  }

  @Test 
  void exchangeTokenUsernameMismatchFailTest() throws DuoException {
    Mockito.when(duoAuthFilter.duoClient.exchangeAuthorizationCodeFor2FAResult(anyString(), anyString())).thenReturn(token);
    Mockito.when(authResult.getStatus()).thenReturn("ALLOW");

    assertNull(duoAuthFilter.exchangeDuoToken(session, duoCode, "not"+tokenUsername));
  }

  @Test
  void exchangeTokenSuccess() throws DuoException {
    Mockito.when(duoAuthFilter.duoClient.exchangeAuthorizationCodeFor2FAResult(anyString(), anyString())).thenReturn(token);
    Mockito.when(authResult.getStatus()).thenReturn("ALLOW");

    assertNotNull(duoAuthFilter.exchangeDuoToken(session, duoCode, tokenUsername));
  }
}
