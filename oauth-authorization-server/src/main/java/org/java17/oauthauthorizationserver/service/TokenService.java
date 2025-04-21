package org.java17.oauthauthorizationserver.service;

import org.springframework.security.oauth2.core.OAuth2AccessToken;

public interface TokenService {
  OAuth2AccessToken getToken(String userId);
}
