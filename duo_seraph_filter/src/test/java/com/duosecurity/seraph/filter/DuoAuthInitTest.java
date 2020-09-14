package com.duosecurity.seraph.filter;

import javax.servlet.ServletException;
import java.util.HashMap;
import java.util.Map;
import java.util.Arrays;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.mockito.ArgumentCaptor;
import static org.junit.jupiter.api.Assertions.*;

class TestDuoAuthFilterInit {
  private DuoAuthFilter duoAuthFilter;
  private MockFilterConfig filterConfig;
  private String clientId = "DIXXXXXXXXXXXXXXXXXX";
  private String clientSecret = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
  private String host = "admin-test.duosecurity.com";
  private String redirectUri = "http://localhost:8080/secure/Dashboard.jspa";
  private Map<String, String> defaultInitParameters = new HashMap<String, String> () {{
    put("host", host);
    put("client.Id", clientId);
    put("client.Secret", clientSecret);
    put("redirecturi", redirectUri);
    put("bypass.APIs", "true");
  }};

  @BeforeEach
  void setUp() {
    duoAuthFilter = new DuoAuthFilter();
    filterConfig = new MockFilterConfig(defaultInitParameters);
  }

  @Test
  void configNullHostTest() {
    filterConfig.update("host", null);
    try {
      duoAuthFilter.init(filterConfig);
      Assertions.fail();
    } catch (ServletException e) {
      assertTrue(e.getMessage().contains(duoAuthFilter.DUO_CONFIG_ERROR));
    }
  }

  @Test
  void configEmptyHostTest() {
    filterConfig.update("host", "");
    try {
      duoAuthFilter.init(filterConfig);
      Assertions.fail();
    } catch (ServletException e) {
      assertTrue(e.getMessage().contains(duoAuthFilter.DUO_CONFIG_ERROR));
    }
}

  @Test
  void configNullIkeyTest() {
    filterConfig.update("client.Id", null);
    try {
      duoAuthFilter.init(filterConfig);
      Assertions.fail();
    } catch (ServletException e) {
      assertTrue(e.getMessage().contains(duoAuthFilter.DUO_CONFIG_ERROR));
    }
  }

  @Test
  void configEmptyIkeyTest() {
    filterConfig.update("client.Id", "");
    try {
      duoAuthFilter.init(filterConfig);
      Assertions.fail();
    } catch (ServletException e) {
      assertTrue(e.getMessage().contains(duoAuthFilter.DUO_CONFIG_ERROR));
    }
  }

  @Test
  void configNullSkeyTest() {
    filterConfig.update("client.Secret", null);
    try {
      duoAuthFilter.init(filterConfig);
      Assertions.fail();
    } catch (ServletException e) {
      assertTrue(e.getMessage().contains(duoAuthFilter.DUO_CONFIG_ERROR));
    }
  }

  @Test
  void configEmptySkeyTest() {
    filterConfig.update("client.Secret", "");
    try {
      duoAuthFilter.init(filterConfig);
      Assertions.fail();
    } catch (ServletException e) {
      assertTrue(e.getMessage().contains(duoAuthFilter.DUO_CONFIG_ERROR));
    }
  }

  @Test
  void configNullRedirectUriTest() {
    filterConfig.update("redirecturi", null);
    try {
      duoAuthFilter.init(filterConfig);
      Assertions.fail();
    } catch (ServletException e) {
      assertTrue(e.getMessage().contains(duoAuthFilter.DUO_CONFIG_ERROR));
    }
  }

  @Test
  void configEmptyRedirectUriTest() {
    filterConfig.update("redirecturi", "");
    try {
      duoAuthFilter.init(filterConfig);
      Assertions.fail();
    } catch (ServletException e) {
      assertTrue(e.getMessage().contains(duoAuthFilter.DUO_CONFIG_ERROR));
    }
  }

  @Test
  void configSuccessTest() throws javax.servlet.ServletException {
    duoAuthFilter.init(filterConfig);
  }

  @Test
  void defaultUnprotectedDirsSuccessTest() throws javax.servlet.ServletException {
    duoAuthFilter.init(filterConfig);

    assertTrue(duoAuthFilter.unprotectedDirs.containsAll(Arrays.asList(duoAuthFilter.defaultUnprotectedDirs)));
  }

  @Test
  void addingUnprotectedDirsSuccessTest() throws javax.servlet.ServletException {
    filterConfig.update("unprotected.dirs", "first second");

    duoAuthFilter.init(filterConfig);

    assertTrue(duoAuthFilter.unprotectedDirs.contains("second"));
    assertTrue(duoAuthFilter.unprotectedDirs.contains("first"));
    assertTrue(duoAuthFilter.unprotectedDirs.containsAll(Arrays.asList(duoAuthFilter.defaultUnprotectedDirs)));
  }

  @Test
  void bypassApiConfigTrueTest() throws javax.servlet.ServletException {
    filterConfig.update("bypass.APIs", "true");

    duoAuthFilter.init(filterConfig);

    assertTrue(duoAuthFilter.apiBypassEnabled);
  }

  @Test
  void bypassApiConfigFalseTest() throws javax.servlet.ServletException {
    filterConfig.update("bypass.APIs", "false");

    duoAuthFilter.init(filterConfig);

    assertFalse(duoAuthFilter.apiBypassEnabled);
  }

  @Test
  void failOpenConfigTest() throws javax.servlet.ServletException {
    filterConfig.update("fail.Open", "true");

    duoAuthFilter.init(filterConfig);

    assertTrue(duoAuthFilter.failOpen);
  }

  @Test
  void failClosedConfigTest() throws javax.servlet.ServletException {
    filterConfig.update("fail.Open", "false");

    duoAuthFilter.init(filterConfig);

    assertFalse(duoAuthFilter.failOpen);
  }
}
