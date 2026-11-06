// SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
//
// SPDX-License-Identifier: EUPL-1.2

package se.digg.wallet.authorizationserver.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

class PublicClientAuthenticationTest {

  private static final String JWT_BEARER = AuthorizationGrantType.JWT_BEARER.getValue();

  @Nested
  class A_jwt_bearer_request {

    private final PublicClientAuthentication.Converter converter =
        new PublicClientAuthentication.Converter();

    @Test
    void with_a_client_id_and_no_credentials_identifies_a_public_client() {
      var request = tokenRequest();
      request.addParameter("client_id", "wallet-app");

      var authentication = converter.convert(request);

      assertThat(authentication).isInstanceOfSatisfying(OAuth2ClientAuthenticationToken.class,
          token -> assertThat(token.getPrincipal()).isEqualTo("wallet-app"));
    }

    @Test
    void with_a_client_secret_is_left_to_other_client_authentication() {
      var request = tokenRequest();
      request.addParameter("client_id", "wallet-app");
      request.addParameter("client_secret", "secret");

      var authentication = converter.convert(request);

      assertThat(authentication).isNull();
    }

    @Test
    void with_two_client_ids_is_rejected() {
      var request = tokenRequest();
      request.addParameter("client_id", "wallet-app", "other-app");

      assertThatThrownBy(() -> converter.convert(request))
          .isInstanceOfSatisfying(OAuth2AuthenticationException.class,
              ex -> assertThat(ex.getError().getErrorCode()).isEqualTo("invalid_request"));
    }

    private static MockHttpServletRequest tokenRequest() {
      var request = new MockHttpServletRequest("POST", "/oauth2/token");
      request.addParameter("grant_type", JWT_BEARER);
      return request;
    }
  }

  @Nested
  class A_public_client {

    @Test
    void registered_for_auth_method_none_is_authenticated() {
      var provider = providerWith(ClientAuthenticationMethod.NONE);

      var authentication = provider.authenticate(clientToken("wallet-app"));

      assertThat(authentication.isAuthenticated()).isTrue();
    }

    @Test
    void that_is_not_registered_is_rejected() {
      var provider = providerWith(ClientAuthenticationMethod.NONE);

      assertThatThrownBy(() -> provider.authenticate(clientToken("unknown-app")))
          .isInstanceOfSatisfying(OAuth2AuthenticationException.class,
              ex -> assertThat(ex.getError().getErrorCode()).isEqualTo("invalid_client"));
    }

    @Test
    void registered_with_a_client_secret_is_rejected() {
      var provider = providerWith(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

      assertThatThrownBy(() -> provider.authenticate(clientToken("wallet-app")))
          .isInstanceOfSatisfying(OAuth2AuthenticationException.class,
              ex -> assertThat(ex.getError().getErrorCode()).isEqualTo("invalid_client"));
    }

    private static PublicClientAuthentication.Provider providerWith(
        ClientAuthenticationMethod method) {
      RegisteredClient client = RegisteredClient.withId("id")
          .clientId("wallet-app")
          .clientSecret("{noop}secret")
          .clientAuthenticationMethod(method)
          .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
          .build();
      return new PublicClientAuthentication.Provider(
          new InMemoryRegisteredClientRepository(client));
    }

    private static OAuth2ClientAuthenticationToken clientToken(String clientId) {
      return new OAuth2ClientAuthenticationToken(clientId, ClientAuthenticationMethod.NONE, null,
          Map.of("grant_type", JWT_BEARER));
    }
  }
}
