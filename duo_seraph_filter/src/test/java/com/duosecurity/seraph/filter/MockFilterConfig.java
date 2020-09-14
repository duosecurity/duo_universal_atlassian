package com.duosecurity.seraph.filter;

import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import java.util.Enumeration;
import java.util.Map;

class MockFilterConfig implements FilterConfig {
  private final Map<String, String> entries;
  
  public MockFilterConfig(Map<String, String> entries) {
    this.entries = entries;
  }
  public void update(String key, String value) {
    entries.put(key, value);
  }
  
  public String getFilterName() {
    // Not used in test
    return "MockFilterConfig";
  }
  
  public String getInitParameter(String name) {
    if (entries.containsKey(name)) {
      return entries.get(name);
    }
    else {
      // What do we want here?
      return name + " not set";
    }
  }
  
  public Enumeration<String> getInitParameterNames() {
    // Not used in test
    return null;
  }
  
  public ServletContext getServletContext() {
    // Not used in test
    return null;
  }
  
}
