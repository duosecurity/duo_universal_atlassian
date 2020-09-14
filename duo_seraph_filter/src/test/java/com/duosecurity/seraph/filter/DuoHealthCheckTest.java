package com.duosecurity.seraph.filter;

import com.duosecurity.model.HealthCheckResponse;
import com.duosecurity.exception.DuoException;
import com.duosecurity.Client;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Matchers.anyString;

class DuoHealthCheckTest {
  private DuoAuthFilter duoAuthFilter;
  private HealthCheckResponse healthCheckResponse;
  private String duoUsername = "testUser";
  private String duoClientHealthCheckError = "Network unreachable";
  private String duoHealthCheckError = "Duo error. Fail closed for user " + duoUsername + "\n" + duoClientHealthCheckError;

  @BeforeEach
  void setUp() {
    duoAuthFilter = new DuoAuthFilter();
    duoAuthFilter.duoClient = Mockito.mock(Client.class);
    healthCheckResponse = Mockito.mock(HealthCheckResponse.class);
  }

  @Test
  void healthCheckNullResponseFailOpenedTest()
  throws javax.servlet.ServletException, DuoException {
    Mockito.when(duoAuthFilter.duoClient.healthCheck()).thenReturn(null);

    assertFalse(duoAuthFilter.duoHealthCheck(duoUsername));
  }

  @Test
  void healthCheckNullResponseFailClosedTest() {
    try {
      duoAuthFilter.failOpen = false;
      Mockito.when(duoAuthFilter.duoClient.healthCheck()).thenReturn(null);

      duoAuthFilter.duoHealthCheck(duoUsername);
    } catch (Exception e) {
      assertTrue(e.getMessage().contains(duoAuthFilter.DUO_FAILCLOSED));
    }
  }

  @Test
  void healthCheckFailResponseFailOpenedTest()
  throws javax.servlet.ServletException, DuoException {
    // Not setting failmode specifically because it should default to True
    Mockito.doReturn("FAIL").when(healthCheckResponse).getStat();

    Mockito.when(duoAuthFilter.duoClient.healthCheck()).thenReturn(healthCheckResponse);

    assertFalse(duoAuthFilter.duoHealthCheck(duoUsername));
  }

  @Test
  void healthCheckFailResponseFailClosedTest() {
    Mockito.doReturn("FAIL").when(healthCheckResponse).getStat();
    try {
      duoAuthFilter.failOpen = false;
      Mockito.when(duoAuthFilter.duoClient.healthCheck()).thenReturn(healthCheckResponse);

      duoAuthFilter.duoHealthCheck(duoUsername);
    } catch (Exception e) {
      assertTrue(e.getMessage().contains(duoAuthFilter.DUO_FAILCLOSED));
    }
  }

  @Test
  void healthCheckFailThrowExceptionFailClosedTest() {
    Mockito.doReturn("FAIL").when(healthCheckResponse).getStat();
    try {
      duoAuthFilter.failOpen = false;
      Mockito.doThrow(new DuoException(duoClientHealthCheckError)).when(duoAuthFilter.duoClient).healthCheck();

      duoAuthFilter.duoHealthCheck(duoUsername);
    } catch (Exception e) {
      assertTrue(e.getMessage().contains(duoClientHealthCheckError));
    }
  }

  @Test
  void healthCheckFailThrowExceptionFailOpenTest()
  throws javax.servlet.ServletException, DuoException {
    Mockito.doReturn("FAIL").when(healthCheckResponse).getStat();
    duoAuthFilter.failOpen = true;
    Mockito.doThrow(new DuoException(duoClientHealthCheckError)).when(duoAuthFilter.duoClient).healthCheck();

    assertFalse(duoAuthFilter.duoHealthCheck(duoUsername));
  }

  @Test
  void healthCheckSuccess()
  throws javax.servlet.ServletException, DuoException {
    Mockito.doReturn("SUCCESS").when(healthCheckResponse).getStat();
    Mockito.when(duoAuthFilter.duoClient.healthCheck()).thenReturn(healthCheckResponse);

    assertTrue(duoAuthFilter.duoHealthCheck(duoUsername));
  }
}
