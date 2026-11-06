// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.application;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

/**
 * Lets a public client (client_id only, auth method {@code none}) use the jwt-bearer grant. Spring
 * Authorization Server only allows public clients for authorization code with PKCE.
 *
 * <p>
 * Interim solution: to be replaced by attestation-based client authentication.
 */
public final class PublicClientAuthentication {

  private static final String GRANT_TYPE = "grant_type";

  private PublicClientAuthentication() {}

  /** Matches jwt-bearer token requests that carry a client_id and no other client credentials. */
  public static class Converter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
      if (!AuthorizationGrantType.JWT_BEARER.getValue().equals(request.getParameter(GRANT_TYPE))
          || request.getHeader("Authorization") != null
          || request.getParameter("client_secret") != null
          || request.getParameter("client_assertion") != null) {
        return null;
      }
      String[] clientIds = request.getParameterValues("client_id");
      if (clientIds == null) {
        return null;
      }
      if (clientIds.length != 1 || !StringUtils.hasText(clientIds[0])) {
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
      }
      return new OAuth2ClientAuthenticationToken(clientIds[0], ClientAuthenticationMethod.NONE,
          null, Map.of(GRANT_TYPE, AuthorizationGrantType.JWT_BEARER.getValue()));
    }
  }

  /** Authenticates the public client if it is registered for auth method none. */
  public static class Provider implements AuthenticationProvider {

    private final RegisteredClientRepository clients;

    public Provider(RegisteredClientRepository clients) {
      this.clients = clients;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
      if (!(authentication instanceof OAuth2ClientAuthenticationToken token)
          || !ClientAuthenticationMethod.NONE.equals(token.getClientAuthenticationMethod())
          || !AuthorizationGrantType.JWT_BEARER.getValue()
              .equals(token.getAdditionalParameters().get(GRANT_TYPE))) {
        return null;
      }
      if (!(token.getPrincipal() instanceof String clientId)) {
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
      }
      RegisteredClient client = clients.findByClientId(clientId);
      if (client == null
          || !client.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE)) {
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
      }
      return new OAuth2ClientAuthenticationToken(client, ClientAuthenticationMethod.NONE, null);
    }

    @Override
    public boolean supports(Class<?> authentication) {
      return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
    }
  }
}
